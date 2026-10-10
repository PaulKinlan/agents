"""agents-q0mt: every producer that reaches the binder EMITS a candidate identity.

The pin is EXECUTABLE, not a source check. Each station is run against a minimal target and the
id is read out of the artefact it actually wrote, so this fails if the station stops emitting -
not merely if the text of the call changes.

The scheme field is asserted even where a fixture yields no candidates, because
``artefact_scheme_fields()`` is only reachable through the conversion: the field itself proves the
call ran. Where a fixture does yield candidates, the per-candidate assertion proves the call ran
over the list that was actually written - which is the half a scheme field alone cannot show.

Coverage is by SET, not by convenience (agents-q0mt, coord ruling): every deterministic first-order
producer whose candidates are location-shaped and reach the binder is in this table. log-check and
issue-triage are absent because they emit neither rule_id nor path, so ``load_candidate_index``
returns None at lib/findings.py:195-196 and no consumer can bind them - N/A, not unconverted.
docs-write and perf-hillclimb are transparent pass-throughs and pr-fixer/vuln-verify/vuln-verify's
store path are second-order (agents-p8og).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (station, script path, target flag, fixture files, minimum candidates the fixture must yield)
#
# A minimum of 0 is honest rather than lazy: it means "this fixture is not guaranteed to trip a
# rule", and for those rows the scheme field plus the per-candidate assertion carry the pin. It is
# NOT a claim that the station was checked - the station is still run and its artefact still read.
STATIONS = [
    ("secret-scan", "agents/secret-scan/scripts/scan.py", "--target",
     {"src/config.js": "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\nexport default AWS_KEY;\n"}, 0),
    ("docs-drift", "agents/docs-drift/scripts/check_docs.py", "--target",
     {"docs/guide.md": "# Guide\n\nSee [the module](../src/does_not_exist.py) for details.\n"}, 1),
    ("modern-web", "agents/modern-web/scripts/scan_modern_web.py", "--target",
     {"index.html": "<!doctype html><html><head><title>t</title></head>"
                    "<body><img src='a.png'></body></html>\n"}, 0),
    ("deps-supply-chain", "agents/deps-supply-chain/scripts/audit_deps.py", "--target",
     {"package.json": json.dumps({"name": "t", "version": "1.0.0",
                                  "dependencies": {"lodash": "4.17.11"}}) + "\n"}, 0),
    ("ui-ux-audit", "agents/ui-ux-audit/scripts/scan_ui_ux.py", "--target",
     {"page.html": "<!doctype html><html><head><title>t</title></head>"
                   "<body><button style='color:#ff0000'>x</button></body></html>\n"}, 0),
    ("accessibility", "agents/accessibility/scripts/audit_a11y.py", "--target-dir",
     {"index.html": "<!doctype html><html><head><title>t</title></head>"
                    "<body><img src='a.png'></body></html>\n"}, 0),
    ("memory-profile", "agents/memory-profile/scripts/scan_memory_leaks.py", "--target",
     {"app.js": "window.addEventListener('resize', function () { redraw(); });\n"}, 0),
    ("perf-review", "agents/perf-review/scripts/scan_perf_changes.py", "--target",
     {"src/app.js": "const items = [];\nfor (const el of items) { document.body.append(el); }\n"}, 0),
    ("qa-station", "agents/qa-station/scripts/audit_factory_quality.py", "--target",
     {"README.md": "# target\n"}, 0),
    ("resilience", "agents/resilience/scripts/scan_resilience.py", "--target",
     {"index.html": "<!doctype html><html><body><script>fetch('/api');</script></body></html>\n"}, 0),
    ("test-gap", "agents/test-gap/scripts/find_untested.py", "--target",
     {"src/untested.py": "def f():\n    return 1\n"}, 0),
]


class TestEveryBinderReachingProducerEmitsAnIdentity(unittest.TestCase):
    """agents-rdyb emits the id; agents-q0mt is the coverage half that makes it consumable."""

    def test_each_producer_writes_a_scheme_and_identifies_its_candidates(self):
        failures = []
        for name, script, flag, fixture, minimum in STATIONS:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                target = tmp / "target"
                for rel, body in fixture.items():
                    p = target / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(body, encoding="utf-8")
                # perf-review reads git context from the target; an uninitialised repo is not a
                # failure of the station, so give it one rather than letting it error out.
                if shutil.which("git"):
                    subprocess.run(["git", "init", "-q"], cwd=target, capture_output=True)
                    subprocess.run(["git", "add", "-A"], cwd=target, capture_output=True)
                    subprocess.run(["git", "-c", "user.email=t@e", "-c", "user.name=t",
                                    "commit", "-qm", "fixture"], cwd=target, capture_output=True)
                out = tmp / "out.json"
                proc = subprocess.run(
                    [sys.executable, str(ROOT / script), flag, str(target), "--output", str(out)],
                    capture_output=True, text=True, cwd=str(ROOT), timeout=120,
                )
                if proc.returncode != 0:
                    failures.append(f"{name}: exited {proc.returncode}: {proc.stderr.strip()[:200]}")
                    continue
                if not out.exists():
                    failures.append(f"{name}: no artefact written")
                    continue
                artefact = json.loads(out.read_text(encoding="utf-8"))
                if artefact.get("candidate_id_scheme") != 1:
                    failures.append(
                        f"{name}: artefact has no candidate_id_scheme=1 "
                        f"(got {artefact.get('candidate_id_scheme')!r}) - the identity call did "
                        f"not run at the artefact assembly point"
                    )
                    continue
                candidates = artefact.get("candidates") or []
                unlabelled = [c for c in candidates
                              if not isinstance(c, dict) or not c.get("candidate_id")]
                if unlabelled:
                    failures.append(f"{name}: {len(unlabelled)} of {len(candidates)} candidates "
                                    f"carry no candidate_id")
                if len(candidates) < minimum:
                    failures.append(f"{name}: fixture must yield at least {minimum} candidates, "
                                    f"got {len(candidates)} - the pin went vacuous")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_station_order_does_not_change_the_ids(self):
        """The helper is order-independent, so re-emitting the same set twice must be identical.

        This is the property the pin depends on: an id that moved with the list order would make
        every artefact a fresh identity and the whole consume step pointless.
        """
        sys.path.insert(0, str(ROOT))
        from lib.candidate_identity import assign_candidate_ids

        base = [
            {"rule_id": "doc-broken-link", "path": "docs/a.md", "snippet": "see [x](missing.py)"},
            {"rule_id": "doc-broken-link", "path": "docs/a.md", "snippet": "see [x](missing.py)"},
            {"rule_id": "doc-broken-link", "path": "docs/b.md", "snippet": "see [y](gone.py)"},
        ]
        first = [dict(c) for c in base]
        assign_candidate_ids(first)
        second = [dict(c) for c in reversed(base)]
        assign_candidate_ids(second)
        self.assertEqual(sorted(c["candidate_id"] for c in first),
                         sorted(c["candidate_id"] for c in second))
        # The two identical matches must not share an id, or one finding would be absorbed.
        self.assertEqual(len({c["candidate_id"] for c in first}), 3)


if __name__ == "__main__":
    unittest.main()
