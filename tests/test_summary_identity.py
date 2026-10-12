#!/usr/bin/env python3
"""Pin the identity of the gate's summary files (agents-qtnv).

WHY THIS EXISTS: a summary file could not be matched to the cached verdict it belonged to.
Measured on the live checks directory - 474 summary files parsed, ZERO paired with a record by
the number in their name, and 462 of them had no record at all to pair with, because `pid` is
populated only while a run is in flight and the cache is keyed per tree. One tree carried 13
such files with no way to tell which run was which.

WHY IT IS A SOURCE-SHAPE PIN RATHER THAN A RUN, STATED SO ITS LIMIT IS NOT OVERREAD: the tee
writes a summary file only AFTER the runner starts, and `FAST_GATE_DRY_RUN=1` exits before that
block on purpose - so a behavioural pin would have to execute a whole suite, turning a cheap gate
expensive for a P3. What is pinned here is the property that was missing: the NAME carries the
run's identity, and the file OPENS with that identity. The runtime half is the before/after pair
on a real tree recorded in the agents-qtnv hand-off, not this file.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent

# These two are the only users of FLEET_CHECKS_DIR in the repo, so pinning both pins the surface.
# The full gate writes .summary.txt (agents-j1te, tools/check.conf); the fast gate writes
# .fast.summary.txt (agents-6jmx, tools/fast-gate.sh).
WRITERS = ("tools/fast-gate.sh", "tools/check.conf")

# The fields that identify a run. tree and lane narrow a file to a set of runs; sha PAIRS it with
# the cached record, which carries `sha`; the stamp orders it for a human; the pid disambiguates.
# Each field accepts every spelling the writers use: a value is referenced as a variable in
# fast-gate.sh (`${summary_sha}`) and inline in check.conf, where `$` is escaped as `\$`.
IDENTITY_FIELDS = (
    ("tree", ("HEAD^{tree}",)),
    ("sha", ("rev-parse --short=12",)),
    ("start stamp", ("date -u +%Y%m%dT%H%M%SZ",)),
    ("lane", ("FLEET_LANE",)),
    ("pid", ("$$", "\\$\\$")),
)

# The header's own content markers, checked where the header is written.
HEADER_MARKERS = ("tree=", "sha=", "lane=", "started=", "pid=")


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _naming_lines(src):
    """Lines that ASSIGN a summary file path - where the identity has to live."""
    return [ln for ln in src.splitlines() if ".summary.txt" in ln and "=" in ln]


def _redirects_to_file(src, var):
    """True if the writer sends something straight into the file variable `var`.

    Checked in all three spellings the two writers use, because a pin that silently stops
    matching would pass while the behaviour it guards is gone: `> "$var"`, `> \\"$var\\"`
    and `> \\"\\$var\\"` (the last two are how the escaped one-liner in check.conf reads).
    """
    return any(
        pat in src
        for pat in (
            f'> "${var}"',
            f'> \\"${var}\\"',
            f'> \\"\\${var}\\"',
            f'}} > "${var}"',
        )
    )


class TestSummaryFileNameCarriesRunIdentity(unittest.TestCase):
    def test_each_writer_names_the_file_with_the_run_identity(self):
        """The identity may be inline in the name (check.conf) or in the variables the name
        expands (fast-gate.sh), so the property is asserted over the naming line and the lines
        that feed it rather than over one line's exact text."""
        for rel in WRITERS:
            with self.subTest(writer=rel):
                lines = _src(rel).splitlines()
                naming_idx = [i for i, ln in enumerate(lines) if ".summary.txt" in ln and "=" in ln]
                self.assertTrue(naming_idx, f"{rel}: no line assigns a .summary.txt path at all")
                start = max(0, naming_idx[0] - 8)
                blob = "\n".join(lines[start : naming_idx[0] + 1])
                for field, needles in IDENTITY_FIELDS:
                    self.assertTrue(
                        any(n in blob for n in needles),
                        f"{rel}: the name has lost the {field} field (any of {needles!r}), so a "
                        "summary file can no longer be told apart from another run's (agents-qtnv)",
                    )

    def test_the_file_answers_for_itself_and_not_on_the_terminal(self):
        """The run's identity is written INTO the file, so a file with no cached record still
        says which run it came from - the 462-of-474 case."""
        for rel in WRITERS:
            with self.subTest(writer=rel):
                src = _src(rel)
                var = "summary_file" if "summary_file" in src else "f"
                self.assertTrue(
                    _redirects_to_file(src, var),
                    f"{rel}: nothing is written straight into ${var}, so the summary file cannot "
                    "say which run it came from (agents-qtnv)",
                )
                # The header sits on the same line as the redirect (check.conf) or in the block
                # immediately above it (fast-gate.sh); check both by looking at the redirect line
                # and the eight lines before it.
                lines = src.splitlines()
                idx = [
                    i
                    for i, ln in enumerate(lines)
                    if any(p in ln for p in (f'> "${var}"', f'> \\"${var}\\"', f'> \\"\\${var}\\"', f'}} > "${var}"'))
                ]
                self.assertTrue(idx, f"{rel}: cannot locate the redirect to ${var}")
                window = "\n".join(lines[max(0, idx[0] - 8) : idx[0] + 1])
                for marker in HEADER_MARKERS:
                    self.assertIn(
                        marker,
                        window,
                        f"{rel}: the header written to ${var} does not carry {marker!r}, so the file "
                        "does not identify its run (agents-qtnv)",
                    )

    def test_the_tee_appends_so_it_cannot_truncate_the_header(self):
        """A plain `tee` truncates the file on the runner's first byte, erasing the header."""
        for rel in WRITERS:
            with self.subTest(writer=rel):
                src = _src(rel)
                for var in ("$f", "$summary_file"):
                    self.assertNotIn(
                        f"| tee \\\"{var}\\\"",
                        src,
                        f"{rel}: `tee` without -a truncates the header this bead added (agents-qtnv)",
                    )
                self.assertIn("tee -a", src, f"{rel}: the tee to the summary file is missing altogether")


if __name__ == "__main__":
    unittest.main()
