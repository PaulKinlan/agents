#!/usr/bin/env python3
"""Tests for lib/yaml_mini.py (stdlib-only YAML subset parser)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.yaml_mini import load_yaml

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
        """If PyYAML is installed, load_yaml on action.yml must produce identical data structure to safe_load."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed in environment")

        mini_data = load_yaml(ACTION_YML)
        with open(ACTION_YML, "r", encoding="utf-8") as f:
            pyy_data = yaml.safe_load(f)

        self.assertEqual(mini_data, pyy_data)

    def test_case1_folded_keep_chomping_with_trailing_blank_line(self):
        """Case 1 (agents-4me): folded '>+' with trailing blank lines preserves newlines."""
        # Single trailing blank line yields 2 newlines (last line + trailing blank)
        doc1 = "key: >+\n  first line\n  second line\n\n"
        res1 = self._parse_yaml_str(doc1)
        self.assertEqual(res1["key"], "first line second line\n\n")

        # Two trailing blank lines yield 3 newlines
        doc2 = "key: >+\n  first line\n  second line\n\n\n"
        res2 = self._parse_yaml_str(doc2)
        self.assertEqual(res2["key"], "first line second line\n\n\n")

        # Blank line between text yields newline separating paragraphs
        doc3 = "key: >+\n  first line\n\n  second line\n\n"
        res3 = self._parse_yaml_str(doc3)
        self.assertEqual(res3["key"], "first line\nsecond line\n\n")

        # More-indented lines are preserved with newlines rather than folded into spaces
        doc4 = "key: >\n  first line\n    indented line\n  second line\n"
        res4 = self._parse_yaml_str(doc4)
        self.assertEqual(res4["key"], "first line\n  indented line\nsecond line\n")

    def test_case2_blank_only_scalar_keep_chomping(self):
        """Case 2 (agents-4me): blank-only '|+' and '>+' scalars preserve newlines vs '' for clip/strip."""
        # 1 blank line with newline
        self.assertEqual(self._parse_yaml_str("key: |+\n\n")["key"], "\n")
        self.assertEqual(self._parse_yaml_str("key: >+\n\n")["key"], "\n")
        self.assertEqual(self._parse_yaml_str("key: |\n\n")["key"], "")
        self.assertEqual(self._parse_yaml_str("key: |-\n\n")["key"], "")
        self.assertEqual(self._parse_yaml_str("key: >\n\n")["key"], "")
        self.assertEqual(self._parse_yaml_str("key: >-\n\n")["key"], "")

        # 2 blank lines with newline
        self.assertEqual(self._parse_yaml_str("key: |+\n\n\n")["key"], "\n\n")
        self.assertEqual(self._parse_yaml_str("key: >+\n\n\n")["key"], "\n\n")
        self.assertEqual(self._parse_yaml_str("key: |\n\n\n")["key"], "")
        self.assertEqual(self._parse_yaml_str("key: |-\n\n\n")["key"], "")

        # Blank lines followed by next key
        doc = "key: |+\n\n\nother: val\n"
        res = self._parse_yaml_str(doc)
        self.assertEqual(res["key"], "\n\n")
        self.assertEqual(res["other"], "val")

    def test_case3_eof_without_trailing_newline(self):
        """Case 3 (agents-4me): block scalar at EOF without trailing newline."""
        # Without trailing newline at EOF, no extra newline is appended
        self.assertEqual(self._parse_yaml_str("key: |\n  hello")["key"], "hello")
        self.assertEqual(self._parse_yaml_str("key: |-\n  hello")["key"], "hello")
        self.assertEqual(self._parse_yaml_str("key: |+\n  hello")["key"], "hello")
        self.assertEqual(self._parse_yaml_str("key: >\n  hello")["key"], "hello")
        self.assertEqual(self._parse_yaml_str("key: >-\n  hello")["key"], "hello")
        self.assertEqual(self._parse_yaml_str("key: >+\n  hello")["key"], "hello")

        # Multi-line without trailing newline at EOF
        self.assertEqual(self._parse_yaml_str("key: |\n  first\n  second")["key"], "first\nsecond")
        self.assertEqual(self._parse_yaml_str("key: >\n  first\n  second")["key"], "first second")

        # Contrast with trailing newline at EOF
        self.assertEqual(self._parse_yaml_str("key: |\n  hello\n")["key"], "hello\n")
        self.assertEqual(self._parse_yaml_str("key: |+\n  hello\n")["key"], "hello\n")
        self.assertEqual(self._parse_yaml_str("key: >\n  hello\n")["key"], "hello\n")

    def test_comprehensive_matrix_parity_with_pyyaml(self):
        """Test exhaustive matrix of indicators, bodies, and EOF conditions against PyYAML."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed in environment")

        indicators = ["|", "|-", "|+", ">", ">-", ">+"]
        bodies = [
            "  hello",
            "  hello\n",
            "  first line\n  second line\n",
            "  first line\n  second line",
            "  first line\n  second line\n\n",
            "  first line\n  second line\n  ",
            "  first line\n\n  second line\n",
            "  first line\n\n  second line",
            "  \n  ",
            "  \n  \n",
            "\n",
            "\n\n",
        ]

        for ind in indicators:
            for body in bodies:
                doc = f"key: {ind}\n{body}"
                with self.subTest(indicator=ind, body=body):
                    expected = yaml.safe_load(doc)["key"]
                    actual = self._parse_yaml_str(doc)["key"]
                    self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
