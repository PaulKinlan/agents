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

        indicators = ["|", "|-", "|+", ">", ">-", ">+",
                      # Explicit indentation indicators: no body in this matrix used to
                      # exercise them (agents-m8h), so `|2`/`>2` were never read by anything
                      # here. Digits are 1-2 only: 9 would make PyYAML refuse the document,
                      # and the matrix compares against PyYAML rather than against an error.
                      "|1", "|2", "|1-", "|2-", "|1+", "|2+", ">1", ">2", ">1-", ">2-", ">1+", ">2+"]
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
            # More-indented lines, which the matrix also never had: this is the shape that hid
            # the folded blank-then-more-indented divergence (agents-m8h).
            "  first line\n    more indented\n",
            "  first line\n\n    more indented\n",
            "  first line\n    more indented\n  second line\n",
            "  first line\n    more indented\n\n    another\n",
            "  first line\n\n\n    deeper\n",
        ]

        for ind in indicators:
            for body in bodies:
                doc = f"key: {ind}\n{body}"
                with self.subTest(indicator=ind, body=body):
                    expected = yaml.safe_load(doc)["key"]
                    actual = self._parse_yaml_str(doc)["key"]
                    self.assertEqual(actual, expected)


class TestYamlMiniFoldedAndIndicatorDivergences(unittest.TestCase):
    """The two residual PyYAML divergences (agents-m8h), and the shapes they sit among.

    Both were pre-existing and both were invisible to the matrix above, for one shared
    reason: no body in it contained a MORE-INDENTED line, and no indicator carried a digit.
    The expectations here are hard-coded rather than taken from PyYAML, so a failure is
    legible on a machine without PyYAML installed - which is the whole point of the module.
    Every value was read from PyYAML 6.0.1 first, and the broader sweep that reproduced them
    (29,058 generated documents) is what forced the three sibling rules below to be exact.
    """

    def _parse(self, content: str):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = Path(f.name)
        try:
            return load_yaml(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_folded_blank_then_more_indented_keeps_two_newlines(self):
        """Divergence 1: the blank line AND the preserved break, not just one of them."""
        self.assertEqual(self._parse("k: >\n  a\n\n    ind\n")["k"], "a\n\n  ind\n")

    def test_folded_sibling_shapes_are_exact(self):
        """The rules either side of it, so the two-newline case cannot be over-applied."""
        cases = {
            "k: >\n  a\n  b\n": "a b\n",                  # break folds to a space
            "k: >\n  a\n\n  b\n": "a\nb\n",               # an empty line is one newline
            "k: >\n  a\n\n\n  b\n": "a\n\nb\n",          # one per empty line
            "k: >\n  a\n    ind\n": "a\n  ind\n",         # indented line is not folded onto
            "k: >\n  a\n    ind\n\n  b\n": "a\n  ind\n\nb\n",   # break after it is preserved
            "k: >\n  a\n    ind\n\n    ind\n": "a\n  ind\n\n  ind\n",  # at most ONE extra
        }
        for doc, expected in cases.items():
            with self.subTest(doc=doc):
                self.assertEqual(self._parse(doc)["k"], expected)

    def test_folded_leading_blank_line_is_content(self):
        """An empty line before the first content line is content, not padding."""
        self.assertEqual(self._parse("k: >\n\n  a\n")["k"], "\na\n")

    def test_explicit_indentation_indicator_is_read(self):
        """Divergence 2: `|2` fixes the content indent, so deeper indentation is content."""
        self.assertEqual(self._parse("k: |2\n    text\n")["k"], "  text\n")
        self.assertEqual(self._parse("k: |1\n    text\n")["k"], "   text\n")
        self.assertEqual(self._parse("k: >2\n    text\n")["k"], "  text\n")
        # When the indicator agrees with the first line, nothing changes.
        self.assertEqual(self._parse("k: |2\n  text\n")["k"], "text\n")
        # The declared indent is relative to the parent node, not to the document.
        self.assertEqual(self._parse("m:\n  k: |2\n      text\n")["m"]["k"], "  text\n")
        # A leading empty line is content here too: the declared indent cannot be postponed.
        self.assertEqual(self._parse("k: |2\n\n    text\n")["k"], "\n  text\n")

    def test_explicit_indentation_indicator_errors(self):
        """`0` is invalid YAML, and content above the declared indent is an error, not a guess."""
        from lib.yaml_mini import YamlParseError

        with self.assertRaises(YamlParseError):
            self._parse("k: |0\n  text\n")
        with self.assertRaises(YamlParseError):
            self._parse("k: |2\n text\n")


if __name__ == "__main__":
    unittest.main()
