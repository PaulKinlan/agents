"""Tests for agents/bundle-size/scripts/measure_bundle.py find_baseline (agents-gog).

The canonical baseline lives in FACTORY_ROOT/findings/<target>-bundle-baseline.json and is
factory-owned. A baseline committed inside the measured tree is self-declared and must never
win over the canonical one; when it is the only baseline, it is flagged as non-canonical.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "measure_bundle", ROOT / "agents" / "bundle-size" / "scripts" / "measure_bundle.py")
mb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mb)


def _write(path: Path, raw_bytes: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"total_raw_bytes": raw_bytes}), encoding="utf-8")


class FindBaselineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.target = self.root / "myapp"
        self.target.mkdir()
        self.findings = self.root / "findings"
        self.findings.mkdir()
        self._orig_root = mb.FACTORY_ROOT
        mb.FACTORY_ROOT = self.root

    def tearDown(self):
        mb.FACTORY_ROOT = self._orig_root
        self._tmp.cleanup()

    def _baseline(self, explicit=None):
        return mb.find_baseline("myapp", self.target, explicit)

    def test_canonical_findings_baseline_beats_a_target_dir_baseline(self):
        # agents-gog: the self-declared in-tree baseline must not win over the canonical one.
        _write(self.target / ".bundle-baseline.json", 1000)
        _write(self.target / "bundle-baseline.json", 1100)
        _write(self.findings / "myapp-bundle-baseline.json", 2000)
        data, path, source = self._baseline()
        self.assertEqual(data["total_raw_bytes"], 2000)
        self.assertEqual(source, "findings")

    def test_target_dir_baseline_is_a_flagged_fallback(self):
        # No canonical baseline -> the in-tree baseline is used, but flagged non-canonical.
        _write(self.target / ".bundle-baseline.json", 1000)
        data, path, source = self._baseline()
        self.assertEqual(data["total_raw_bytes"], 1000)
        self.assertEqual(source, "target-dir")

    def test_explicit_path_wins_over_everything(self):
        explicit = self.root / "explicit-baseline.json"
        _write(explicit, 3000)
        _write(self.findings / "myapp-bundle-baseline.json", 2000)
        _write(self.target / ".bundle-baseline.json", 1000)
        data, path, source = self._baseline(str(explicit))
        self.assertEqual(data["total_raw_bytes"], 3000)
        self.assertEqual(source, "explicit")

    def test_no_baseline_returns_none(self):
        self.assertEqual(self._baseline(), (None, None, None))

    def test_a_corrupt_target_dir_baseline_falls_through_to_findings(self):
        (self.target / ".bundle-baseline.json").write_text("{not json", encoding="utf-8")
        _write(self.findings / "myapp-bundle-baseline.json", 2000)
        data, path, source = self._baseline()
        self.assertEqual(data["total_raw_bytes"], 2000)
        self.assertEqual(source, "findings")


if __name__ == "__main__":
    unittest.main(verbosity=2)
