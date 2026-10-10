#!/usr/bin/env python3
"""The shared line-sentinel rule (agents-ghtz).

vuln-verify's `usable_line_number` (agents-fy26) and vuln-triage's `_parse_line_number`
(agents-ajt4) were two copies of one rule; these pin the single copy both now import, and the
ordering it implies for a mixed numeric / "?" / missing candidate list.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.line_numbers import line_number_sort_key, usable_line_number  # noqa: E402


class TestUsableLineNumber(unittest.TestCase):
    def test_positive_ints_are_the_line(self):
        for value, expected in ((1, 1), (5, 5), (9999999, 9999999)):
            with self.subTest(value=value):
                self.assertEqual(usable_line_number(value), expected)

    def test_non_positive_ints_are_unknown(self):
        # 0 is not line 0 - it is a non-positive value, and agents-ajt4 existed because a sentinel
        # coerced to line 0 falsely clusters with every real finding within 15 lines.
        for value in (0, -1, -42):
            with self.subTest(value=value):
                self.assertIsNone(usable_line_number(value))

    def test_digit_strings_are_accepted(self):
        for value, expected in (("1", 1), ("5", 5), (" 42 ", 42)):
            with self.subTest(value=value):
                self.assertEqual(usable_line_number(value), expected)

    def test_non_positive_digit_strings_are_unknown(self):
        for value in ("0", " 0 ", "-3", "-0"):
            with self.subTest(value=value):
                self.assertIsNone(usable_line_number(value))

    def test_unknown_marker_and_non_numeric_strings_are_unknown(self):
        # "?" is lib/redaction.publishable_line_number's own unknown marker.
        for value in ("?", "?", "", "N/A", "3.5", "²", "0x10"):
            with self.subTest(value=value):
                self.assertIsNone(usable_line_number(value))

    def test_none_booleans_and_non_ints_are_unknown(self):
        # True is an int in Python (`True > 0`); a bool where a line was expected is a shape error.
        for value in (None, True, False, 5.0, [], {}):
            with self.subTest(value=value):
                self.assertIsNone(usable_line_number(value))


class TestLineNumberSortKey(unittest.TestCase):
    def test_known_lines_order_by_number(self):
        values = [30, 5, 12, "7"]
        ordered = sorted(values, key=line_number_sort_key)
        self.assertEqual(ordered, [5, "7", 12, 30])

    def test_unknown_locations_sort_after_every_known_line(self):
        values = ["?", None, 5, 1]
        ordered = sorted(values, key=line_number_sort_key)
        self.assertEqual(ordered[:2], [1, 5])
        self.assertEqual(set(ordered[2:]), {"?", None})

    def test_mixed_candidate_list_sorts_without_raising(self):
        """numeric + "?" + missing in one list must not raise TypeError (agents-fy26/fleet-wis0)."""
        candidates = [
            {"path": "a.py", "line_number": 20},
            {"path": "a.py", "line_number": "?"},
            {"path": "a.py"},  # missing line_number -> .get() -> None
            {"path": "a.py", "line_number": 3},
        ]
        ordered = sorted(candidates, key=lambda c: line_number_sort_key(c.get("line_number")))
        self.assertEqual([c.get("line_number") for c in ordered], [3, 20, "?", None])


if __name__ == "__main__":
    unittest.main()
