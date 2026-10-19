#!/usr/bin/env python3
"""The CLI's exit code is the only thing CI and an operator's shell can see (agents-5grx0).

agents-lbgso found that a silent station (engine exits 0, writes nothing) is treated as a plumbing failure:
retried once, then named in failure_reason.txt, degraded to ERROR and continued as INCOMPLETE. The run
directory tells that story well - and none of it reaches a caller that only looks at `factory run`'s exit
status. Measured before writing this: a silent engine exits **2**. That number is what makes a broken nightly
fail a pipeline instead of reporting a clean run, and nothing pinned it: flipping the handler at factory's
`except (StationTimeout, StationError)` branch from sys.exit(2) to sys.exit(0) left the whole andon suite green.

These tests drive the real CLI as a subprocess (the andon suite calls run_line in-process, so it cannot see an
exit code at all) with a stub engine, and assert the code rather than the prose.
"""

import json
import stat
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from containment_harness import ContainmentHarness  # noqa: E402

AGENT_YAML = """name: probe
class: proposer
plane: [local]
containment: t2-local
triggers: [manual]
blocking: false
short_circuit_empty: false
summary: exit-code probe
capabilities:
  write: false
  network: false
  browser: false
  requires: []
budget:
  max_minutes: 2
output:
  schema: report.schema.json
"""

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ProbeReport",
    "type": "object",
    "required": ["summary", "target", "findings"],
    "properties": {
        "summary": {"type": "string"},
        "target": {"type": "string"},
        "findings": {"type": "array", "items": {"type": "object"}},
    },
}

PREPASS = """
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
open(args.output, "w", encoding="utf-8").write(json.dumps(
    {"candidates": [{"candidate_id": "cand-x-001", "rule_id": "r", "path": "a.py"}]}))
"""

SILENT_STUB = "#!/usr/bin/env bash\ncat >/dev/null\nexit 0\n"
CRASHING_STUB = "#!/usr/bin/env bash\ncat >/dev/null\necho 'engine exploded' >&2\nexit 97\n"


class StationExitCodes(ContainmentHarness):
    def station(self, stub_body):
        self.agent(AGENT_YAML)
        directory = self.root / "agents" / "probe"
        (directory / "report.schema.json").write_text(json.dumps(SCHEMA), encoding="utf-8")
        (directory / "scripts").mkdir(exist_ok=True)
        (directory / "scripts" / "prepass.py").write_text(PREPASS, encoding="utf-8")
        stub = self.bin / "pi"
        stub.write_text(stub_body, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def test_a_silent_station_fails_the_run_with_exit_code_two(self):
        self.station(SILENT_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2,
                         f"a silent station must not look like a clean run: rc={res.returncode}, "
                         f"stdout={res.stdout[-400:]!r} stderr={res.stderr[-400:]!r}")
        self.assertIn("station failure", res.stderr.lower())
        self.assertIn("produced no verdict or output", res.stderr)

    def test_a_crashing_engine_also_fails_the_run_with_exit_code_two(self):
        # The other end of the same handler: a non-zero engine exit is a StationError, so it must reach the
        # caller the same way. Pinned separately because a future edit could special-case one and not the
        # other - and 'the station failed' is the property a pipeline depends on, not the shape of the ring.
        self.station(CRASHING_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, f"rc={res.returncode}, stderr={res.stderr[-400:]!r}")
        self.assertIn("station failure", res.stderr.lower())


if __name__ == "__main__":
    unittest.main()
