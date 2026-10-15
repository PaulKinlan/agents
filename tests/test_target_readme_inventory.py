"""Pin the sink claims in the target inventory to the named target manifests."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "targets" / "README.md"
_ROW = re.compile(r"^\|\s*`([^`]+\.yaml)`\s*\|\s*`([^`]+)`\s*\|", re.MULTILINE)
_SINK = re.compile(r"^sink:\s*([^\s#]+)", re.MULTILINE)


class TestTargetReadmeInventory(unittest.TestCase):
    def test_listed_target_sinks_match_their_manifests(self):
        rows = _ROW.findall(README.read_text(encoding="utf-8"))
        self.assertTrue(rows, "target inventory must list at least one named target")
        names = [name for name, _ in rows]
        self.assertEqual(len(names), len(set(names)), "target inventory repeats a target")

        for name, documented_sink in rows:
            with self.subTest(target=name):
                self.assertEqual(Path(name).name, name, "target inventory must name a local manifest")
                manifest = ROOT / "targets" / name
                self.assertTrue(manifest.is_file(), f"{name}: documented target does not exist")
                declared = _SINK.search(manifest.read_text(encoding="utf-8"))
                self.assertIsNotNone(declared, f"{name}: target does not declare a sink")
                self.assertEqual(documented_sink, declared.group(1),
                                 f"{name}: README sink differs from the target manifest")


if __name__ == "__main__":
    unittest.main()
