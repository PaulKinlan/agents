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

from lib.findings import load_candidate_index
from tests.test_factory_truth import Sandbox, factory_cli, report


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
        self.payload.write_text(json.dumps(payload), encoding="utf-8")
        before = set((self.box.root / "runs").glob("probe-*")) if (self.box.root / "runs").exists() else set()
        # The target explicitly attests trust; force the same test-only no-bwrap
        # fallback the existing dispatcher tests use on hosts without user namespaces.
        with self.box.patched(), mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNSANDBOXED": "1"}), \
             mock.patch("lib.sandbox._probe_result", False), contextlib.redirect_stdout(io.StringIO()):
            factory_cli.run_agent("probe", "trusted", engine_arg="pi", explicit_sink="file")
        after = set((self.box.root / "runs").glob("probe-*")) - before
        self.assertEqual(len(after), 1, "one actual dispatcher run must write one prompt")
        return (after.pop() / "prompt.txt").read_text(encoding="utf-8")

    def test_no_context_is_byte_identical_to_the_previous_prompt(self):
        prompt = self.run_payload({"candidates": self.candidates})
        expected = (
            "You are the probe agent. Examine the following context and candidate issues discovered by the "
            "deterministic scanner in repository 'trusted'. Follow your SKILL.md instructions, "
            "triage each item, and output your structured JSON findings.\n\n"
            f"Scanner Data:\n{json.dumps(self.candidates[:50], indent=2)}\n"
        )
        self.assertEqual(prompt, expected)
        self.assertNotIn("rule-50", prompt, "candidate slice remains 50")

    def test_context_is_separate_unsliced_and_not_an_identity_candidate(self):
        context = {"clusters": [{"cluster": i} for i in range(55)], "threat_model_summary": "model evidence"}
        prompt = self.run_payload({"candidates": self.candidates, "context": context,
                                   "candidate_id_scheme": "identity stamp excluded",
                                   "system_instruction": "SYSTEM TEST DIRECTIVE not user data"})
        expected_base = (
            "You are the probe agent. Examine the following context and candidate issues discovered by the "
            "deterministic scanner in repository 'trusted'. Follow your SKILL.md instructions, "
            "triage each item, and output your structured JSON findings.\n\n"
            f"Scanner Data:\n{json.dumps(self.candidates[:50], indent=2)}\n"
        )
        self.assertEqual(prompt, expected_base + f"\nStation Context:\n{json.dumps(context, indent=2)}\n")
        self.assertNotIn("rule-50", prompt)
        self.assertIn('"cluster": 54', prompt, "context cannot inherit the 50-candidate slice")
        self.assertNotIn("identity stamp excluded", prompt)
        self.assertNotIn("SYSTEM TEST DIRECTIVE", prompt, "system_instruction keeps its separate channel")
        run_dir, = (self.box.root / "runs").glob("probe-*")
        self.assertIn("SYSTEM TEST DIRECTIVE", (run_dir / "system_directive.txt").read_text())

    def test_context_never_becomes_identity_evidence(self):
        self.payload.write_text(json.dumps({
            "candidates": [{"rule_id": "real", "path": "src/real.py", "line_number": 1}],
            "context": {"rule_id": "injected", "path": "src/context.py"},
        }), encoding="utf-8")
        index = load_candidate_index(self.payload)
        self.assertEqual(index["rule_ids"], {"real"})
        self.assertEqual(index["paths"], {"src/real.py"})
        self.payload.write_text(json.dumps({"context": {"rule_id": "injected"}}), encoding="utf-8")
        self.assertIsNone(load_candidate_index(self.payload))

    def test_present_json_null_is_not_treated_as_absent(self):
        prompt = self.run_payload({"candidates": self.candidates, "context": None})
        self.assertTrue(prompt.endswith("\nStation Context:\nnull\n"), prompt[-100:])


if __name__ == "__main__":
    unittest.main()
