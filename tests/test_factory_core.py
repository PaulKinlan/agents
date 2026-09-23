#!/usr/bin/env python3
"""Unit tests for the Software Factory core library (findings store, YAML parser, containment)."""

import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path

from lib.findings import FindingsStore, compute_fingerprint, normalize_text

FACTORY_ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("factory_cli", str(FACTORY_ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)


class TestSoftwareFactoryCore(unittest.TestCase):
    def test_fingerprint_line_number_independence(self):
        """Fingerprints must be identical across line shifts and whitespace reformatting."""
        fp1 = compute_fingerprint("secret-scan", "generic-key", "./src/config.js", "const key = 'abc';")
        fp2 = compute_fingerprint("secret-scan", "generic-key", "src/config.js", "  const   key = 'abc'; \n")
        self.assertEqual(fp1, fp2)

    def test_findings_lifecycle_transitions(self):
        """Verify new -> unchanged -> fixed -> regressed state machine transitions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("test-target", findings_dir=Path(tmpdir))
            sample = [{
                "rule_id": "xss-sink",
                "path": "app.js",
                "line_number": 10,
                "snippet": "el.innerHTML = user;",
                "severity": "high",
                "title": "DOM XSS"
            }]

            # Run 1: new
            _, stats1, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats1["new"], 1)

            # Run 2: unchanged (even if line_number changes)
            sample[0]["line_number"] = 42
            _, stats2, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats2["unchanged"], 1)
            self.assertEqual(stats2["new"], 0)

            # Run 3: empty findings -> fixed
            _, stats3, fixed = store.process_run("vuln-discovery", [])
            self.assertEqual(stats3["fixed"], 1)
            self.assertEqual(len(fixed), 1)

            # Run 4: reappears -> regressed
            _, stats4, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats4["regressed"], 1)

    def test_indentation_aware_yaml_parser(self):
        """Verify nested maps (schedule:, budget:) and lists parse properly."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(
                "name: fauxmium\n"
                "visibility: public\n"
                "agents:\n"
                "  - secret-scan\n"
                "  - test-gap\n"
                "schedule:\n"
                "  secret-scan:\n"
                "    interval: 86400\n"
                "    hour: 7\n"
            )
            tf_path = Path(tf.name)

        try:
            parsed = factory_cli.load_yaml_simple(tf_path)
            self.assertEqual(parsed["name"], "fauxmium")
            self.assertEqual(parsed["agents"], ["secret-scan", "test-gap"])
            self.assertIsInstance(parsed["schedule"], dict)
            self.assertEqual(parsed["schedule"]["secret-scan"]["interval"], 86400)
            self.assertEqual(parsed["schedule"]["secret-scan"]["hour"], 7)
        finally:
            tf_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
