#!/usr/bin/env python3
"""ADR agents-3f4b: a station's opt-in context reaches the real model prompt.

Drive the actual dispatcher in a disposable trusted target with a stub model; no
production station, network request, live credentials, or installed hooks are used.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_factory_truth import Sandbox, factory_cli, finding, report


class TestStationContextChannel(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="rw6z-prompt-")
        self.addCleanup(tmp.cleanup)
        self.box = Sandbox(Path(tmp.name).resolve())
        self.payload = self.box.root / "payload.json"
        prepass = (
            "import json, sys\n"
            f"with open({str(self.payload)!r}, encoding='utf-8') as source:\n"
            "    data = json.load(source)\n"
            "with open(sys.argv[sys.argv.index('--output') + 1], 'w', encoding='utf-8') as out:\n"
            "    json.dump(data, out)\n"
        )
        self.box.agent("probe", report(), prepass=prepass)
        targets = self.box.root / "targets"
        targets.mkdir()
        (targets / "trusted.yaml").write_text(
            f"name: trusted\npath: {self.box.target}\nvisibility: private\ntrusted: true\n",
            encoding="utf-8",
        )
        # Enough candidates to distinguish the existing slice of 50 from the
        # separate context channel, which the ADR explicitly forbids slicing.
        self.candidates = [
            {"rule_id": f"rule-{i}", "path": f"src/{i}.py", "line_number": i + 1}
            for i in range(52)
        ]

    def run_payload(self, payload):
        """Run one dispatcher pass and return the prompts it actually sent, in batch order.

        A list, not one string: since agents-tq1lt the per-call candidate bound is enforced by the
        dispatcher (lib/candidate_batching.MAX_CANDIDATES_PER_BATCH), so a payload with more candidates
        than the bound is presented as several batches. A payload under it is still ONE call with the
        legacy `prompt.txt`, which is the byte-identical case below.
        """
        self.payload.write_text(json.dumps(payload), encoding="utf-8")
        before = set((self.box.root / "runs").glob("probe-*")) if (self.box.root / "runs").exists() else set()
        # The target explicitly attests trust; force the same test-only no-bwrap
        # fallback the existing dispatcher tests use on hosts without user namespaces.
        with self.box.patched(), mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNSANDBOXED": "1"}), \
             mock.patch("lib.sandbox._probe_result", False), contextlib.redirect_stdout(io.StringIO()):
            factory_cli.run_agent("probe", "trusted", engine_arg="pi", explicit_sink="file")
        after = set((self.box.root / "runs").glob("probe-*")) - before
        self.assertEqual(len(after), 1, "one actual dispatcher run must write its prompt")
        run_dir = after.pop()
        batch_files = sorted(run_dir.glob("prompt.batch*.txt"),
                             key=lambda path: int(path.name.split(".batch")[1].split(".")[0]))
        if batch_files:
            self.assertFalse((run_dir / "prompt.txt").exists(),
                             "a batched run renames every prompt; a stray prompt.txt would be stale")
            return [path.read_text(encoding="utf-8") for path in batch_files]
        return [(run_dir / "prompt.txt").read_text(encoding="utf-8")]

    def test_no_context_is_byte_identical_to_the_previous_prompt(self):
        # A payload the per-call bound covers stays ONE call, and that call's prompt is byte-identical to
        # the one this channel has always produced - no batch header, no reordering.
        few = self.candidates[:3]
        prompts = self.run_payload({"candidates": few})
        expected = (
            "You are the probe agent. Examine the following context and candidate issues discovered by the "
            "deterministic scanner in repository 'trusted'. Follow your SKILL.md instructions, "
            "triage each item, and output your structured JSON findings.\n\n"
            f"Scanner Data:\n{json.dumps(few, indent=2)}\n"
        )
        self.assertEqual(prompts, [expected])

    def test_context_is_separate_unsliced_and_not_an_identity_candidate(self):
        context = {"clusters": [{"cluster": i} for i in range(55)], "threat_model_summary": "model evidence",
                   "rule_id": "injected", "path": "src/context.py"}
        # A stub model finding echoing the context MUST NOT acquire scanner-owned identity:
        # only `candidates`, not `context`, is the authority for binding in the real store.
        (self.box.root / "outputs" / "probe.txt").write_text(
            report(finding(rule_id="injected", path="src/context.py", line_number=9)),
            encoding="utf-8",
        )
        prompts = self.run_payload({"candidates": self.candidates, "context": context,
                                    "candidate_id_scheme": "identity stamp excluded",
                                    "system_instruction": "SYSTEM TEST DIRECTIVE not user data"})
        context_block = f"\nStation Context:\n{json.dumps(context, indent=2)}\n"
        self.assertGreater(len(prompts), 1,
                           "52 candidates are more than the enforced per-call bound: this is the batched "
                           "case, and the 50-candidate SLICE still owns what may appear")
        for prompt in prompts:
            self.assertTrue(prompt.endswith(context_block),
                            f"every batch carries the unsliced context: {prompt[-160:]}")
            self.assertNotIn("rule-50", prompt,
                             "the candidate slice is still 50, in every batch (rule-50 is the 51st)")
            self.assertNotIn("rule-51", prompt, "the slice drops the 52nd candidate too")
            self.assertIn('"cluster": 54', prompt,
                          "context cannot inherit the 50-candidate slice, in any batch")
            self.assertNotIn("identity stamp excluded", prompt)
            self.assertNotIn("SYSTEM TEST DIRECTIVE", prompt,
                             "system_instruction keeps its separate channel")
        run_dir, = (self.box.root / "runs").glob("probe-*")
        self.assertIn("SYSTEM TEST DIRECTIVE", (run_dir / "system_directive.txt").read_text())
        store = json.loads((self.box.root / "findings" / "trusted.json").read_text())
        bound, = store["findings"].values()
        self.assertEqual((bound["rule_id"], bound["path"]), ("unclassified", "unknown"),
                         "context must never enter the candidate identity index")

    def test_present_json_null_is_not_treated_as_absent(self):
        prompts = self.run_payload({"candidates": self.candidates, "context": None})
        for prompt in prompts:
            self.assertTrue(prompt.endswith("\nStation Context:\nnull\n"), prompt[-100:])


if __name__ == "__main__":
    unittest.main()
