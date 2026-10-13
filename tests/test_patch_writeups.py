"""Pin the patches/ directory shape (agents-hzug).

patches/README.md used to be a single 587-line file that every patch delivery appended a section
to. Two deliveries in flight meant one of them rebased, and a rebase invalidates the gate and the
verdict a reviewer already gave, so a shared append point is a scheduling defect and not just an
untidy file. agents-cchd's design split it: each patch's write-up is its own file, named after the
artifact it belongs to, and the markdown boundary became a filesystem boundary.

This pins the two properties that design was accepted for, plus the convention that makes a
write-up findable. It deliberately does NOT pin the README's wording or length: a test that breaks
when someone improves a sentence gets deleted, and then it catches nothing.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

PATCHES = Path(__file__).resolve().parent.parent / "patches"
FENCE = re.compile(r"^\s*```")
ARTIFACT = re.compile(r"([a-z0-9][a-z0-9-]*\.patch)")

#: A write-up may cover more than one artifact when they were delivered as one change (the join is
#: what makes that expressible in a filename), so this is a row count, not a floor on coverage.
EXPECTED_MINIMUM_WRITEUPS = 5


def _writeups() -> list[Path]:
    return sorted(p for p in PATCHES.glob("*.md") if p.name != "README.md")


class TestPatchDirectoryShape(unittest.TestCase):
    def test_each_writeup_is_a_markdown_section(self):
        """A write-up is a section, so it starts at its own heading - that is what makes it
        findable by looking at the directory rather than by scrolling a shared file."""
        for path in _writeups():
            with self.subTest(path.name):
                first = path.read_text(encoding="utf-8").split("\n", 1)[0]
                self.assertTrue(first.startswith("## "), f"{path.name} does not start with a section heading")

    def test_no_writeup_ends_inside_a_fence(self):
        """The fence-state check coord named, now per file. In the shared file an unclosed fence
        bled into the NEXT section, which is how two real defects were produced; here the worst
        case is contained in the file that caused it."""
        for path in PATCHES.glob("*.md"):
            with self.subTest(path.name):
                fences = sum(1 for line in path.read_text(encoding="utf-8").split("\n") if FENCE.match(line))
                self.assertEqual(fences % 2, 0, f"{path.name} ends inside a code fence")

    def test_every_patch_artifact_is_named_by_a_writeup(self):
        """Each artifact stays reachable from its explanation. This is the property the split must
        not lose, because the point of the directory is that the diff and its reasoning sit
        together."""
        named = set()
        for path in _writeups():
            heading = path.read_text(encoding="utf-8").split("\n", 1)[0]
            named.update(ARTIFACT.findall(heading))
        artifacts = {p.name for p in PATCHES.glob("*.patch")}
        self.assertTrue(artifacts, "no patch artifacts found - this test would be vacuous")
        self.assertEqual(artifacts - named, set(), "artifacts with no write-up naming them")

    def test_the_readme_points_at_the_directory_and_names_no_individual_patch(self):
        """The README is the one shared file left, so it must not creep back into being an index:
        an index is the append point this split exists to remove. It says how to find a write-up
        and leaves the listing to the filesystem."""
        text = (PATCHES / "README.md").read_text(encoding="utf-8")
        self.assertIn("patches/", text)
        listed = set(ARTIFACT.findall(text))
        self.assertEqual(listed, set(), f"README.md names individual artifacts again: {sorted(listed)}")
        self.assertLess(len(text.split("\n")), 60, "README.md is growing back into the shared file")

    def test_each_writeup_ends_with_a_newline(self):
        """Round 2 of agents-hzug: the separator lives in the file, not in a join rule.

        Round 1's assertion was strict and answered the wrong question - it was about MY joining
        rule, and a reviewer running a plain concatenation measured a different number. The
        migration is now exact: the write-ups, in the order the replaced file listed them,
        concatenate to it byte for byte (54695 bytes, delta 0), which is a property any consumer
        can check without knowing a rule.

        This test pins only what a directory can state about itself - that no write-up is trunca-
        ted mid-line. It deliberately does NOT pin the separator: the source's separators were NOT
        uniform (ten write-ups end with a blank line and two end with just a newline, because those
        two sections were followed by a heading that had no preceding blank), so a uniform rule
        would have been a claim that was false of the artifact it described. The exact reconstruction
        needs the ORIGINAL ORDER, which the file does not carry, so the byte-exact check is a
        one-time migration assertion recorded on the bead rather than a property of this directory.
        """
        for path in _writeups():
            with self.subTest(path.name):
                self.assertTrue(path.read_text(encoding="utf-8").endswith("\n"),
                                f"{path.name} does not end with a newline - it was truncated")

    def test_the_directory_is_not_trivially_empty(self):
        self.assertGreaterEqual(len(_writeups()), EXPECTED_MINIMUM_WRITEUPS)


if __name__ == "__main__":
    unittest.main()
