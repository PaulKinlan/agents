#!/usr/bin/env python3
"""Tests for lib/yaml_mini.py (stdlib-only YAML subset parser)."""

import tempfile
import unittest
from pathlib import Path

from lib.yaml_mini import load_yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION_YML = ROOT / ".github" / "actions" / "factory" / "action.yml"


class TestYamlMiniBlockChomping(unittest.TestCase):
    def _parse_yaml_str(self, content: str):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = Path(f.name)
        try:
            return load_yaml(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_block_scalar_clip_chomping(self):
        """Default clip chomping '|' must end in exactly one newline, without duplicating trailing newlines."""
        # Standard block
        res = self._parse_yaml_str("script: |\n  echo first\n  echo second\n")
        self.assertEqual(res["script"], "echo first\necho second\n")

        # Block with trailing blank lines
        res = self._parse_yaml_str("script: |\n  echo first\n  echo second\n  \n  \n")
        self.assertEqual(res["script"], "echo first\necho second\n")

        # Block with next key after trailing blank lines
        doc = "script: |\n  echo first\n  echo second\n  \n  \nnext: val\n"
        res = self._parse_yaml_str(doc)
        self.assertEqual(res["script"], "echo first\necho second\n")
        self.assertEqual(res["next"], "val")

    def test_block_scalar_strip_chomping(self):
        """Strip chomping '|-' must remove all trailing newlines."""
        res = self._parse_yaml_str("script: |-\n  echo first\n  echo second\n")
        self.assertEqual(res["script"], "echo first\necho second")

        res = self._parse_yaml_str("script: |-\n  echo first\n  echo second\n  \n  \n")
        self.assertEqual(res["script"], "echo first\necho second")

    def test_block_scalar_keep_chomping(self):
        """Keep chomping '|+' must preserve all trailing newlines."""
        res = self._parse_yaml_str("script: |+\n  echo first\n  echo second\n")
        self.assertEqual(res["script"], "echo first\necho second\n")

        res = self._parse_yaml_str("script: |+\n  echo first\n  echo second\n  \n")
        self.assertEqual(res["script"], "echo first\necho second\n\n")

        res = self._parse_yaml_str("script: |+\n  echo first\n  echo second\n  \n  \n")
        self.assertEqual(res["script"], "echo first\necho second\n\n\n")

    def test_action_yml_parity_with_pyyaml(self):
        """If PyYAML is installed, load_yaml on action.yml must be byte-identical to safe_load."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed in environment")

        mini_data = load_yaml(ACTION_YML)
        with open(ACTION_YML, "r", encoding="utf-8") as f:
            pyy_data = yaml.safe_load(f)

        self.assertEqual(mini_data, pyy_data)


if __name__ == "__main__":
    unittest.main()
