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

# The old IDENTITY_FIELDS/HEADER_MARKERS blocks are superseded by NAME_FIELD_TOKENS,
# DERIVATION_TOKENS and the header checks below (agents-undf).


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")

def _header_format_line(src):
    """The statement that WRITES the run identity - the artefact this property is about.

    agents-dvpk measured why a window around the redirect is the wrong subject: dropping `sha=%s`
    from the header printf still passed, because `summary_sha="$(...)"` sits in the same window and
    contains the substring `sha=`. The same is true of `tree=`. The marker was supplied by the
    ASSIGNMENT rather than by the header, which is exactly the failure family this file exists to
    avoid. So the assertion is narrowed to the line that formats the header, and it must be found:
    a pin that silently stops matching is indistinguishable from one that passes.
    """
    for line in _code_only(src).splitlines():
        if "printf" in line and "run:" in line:
            return line
    return ""


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


# Each field of the identity, with the spellings the two writers use ON THE NAMING LINE ITSELF.
# Asserting on the NAME and not on a window around it is the point: agents-undf measured that a field
# dropped from the name still passed while its ASSIGNMENT remained nearby (the sha removed with
# `sed 's/-${summary_sha}-/-/'` went green), which is a false green about exactly the property the file
# exists to protect.
NAME_FIELD_TOKENS = (
    ("tree", ("${tree}", "${summary_tree}")),
    ("sha", ("${sha}", "${summary_sha}")),
    ("start stamp", ("${stamp}", "${summary_stamp}")),
    ("lane", ("FLEET_LANE",)),
    ("pid", ("$$", "\\$\\$")),
)

# Where each field is DERIVED. Separate from the naming line on purpose: a field must both be computed
# and be referenced by the name, and conflating the two is what let the first version pass.
DERIVATION_TOKENS = (
    ("tree", ("HEAD^{tree}",)),
    ("sha", ("rev-parse --short=12",)),
    ("start stamp", ("date -u +%Y%m%dT%H%M%SZ",)),
)


# The header's own content markers, checked where the header is written.
HEADER_MARKERS = ("tree=", "sha=", "lane=", "started=", "pid=")


def _code_only(src):
    """Source with whole-line comments removed.

    agents-undf found that `assertIn("tee -a", src)` was satisfied by the COMMENT this change added
    describing `tee -a` - a test reading the fix's prose instead of the fix. Same failure family as
    agents-pdth's first oracle, which counted an import written inside a docstring: the instrument
    read the wrong thing. Whole-line comments only, so a trailing `#` in legitimate code is untouched.
    """
    return "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))


def _naming_line(src):
    """The line that ASSIGNS the summary path - the line the identity has to be visible on."""
    for ln in _code_only(src).splitlines():
        if ".summary.txt" in ln and "=" in ln:
            return ln
    return ""


class TestSummaryFileNameCarriesRunIdentity(unittest.TestCase):
    def test_each_writer_names_the_file_with_the_run_identity(self):
        """The NAME must reference every field, and each field must be derived somewhere.

        Two assertions, because a field can be lost in either place and the first version only checked
        a window that covered both: `sed 's/-${summary_sha}-/-/'` removed the sha from the name and
        still passed (agents-undf, measured).
        """
        for rel in WRITERS:
            with self.subTest(writer=rel):
                code = _code_only(_src(rel))
                name = _naming_line(_src(rel))
                self.assertTrue(name, f"{rel}: no line assigns a .summary.txt path at all")
                for field, needles in NAME_FIELD_TOKENS:
                    self.assertTrue(
                        any(n in name for n in needles),
                        f"{rel}: the NAMING LINE no longer references the {field} field (any of "
                        f"{needles!r}). It is: {name.strip()[:150]} - a field dropped from the name "
                        "leaves a summary file that cannot be told apart from another run's "
                        "(agents-qtnv, agents-undf)",
                    )
                for field, needles in DERIVATION_TOKENS:
                    self.assertTrue(
                        any(n in code for n in needles),
                        f"{rel}: the {field} field is no longer DERIVED anywhere (any of {needles!r}), "
                        "so the name cannot be carrying a real value (agents-qtnv, agents-undf)",
                    )

    def test_the_file_answers_for_itself_and_not_on_the_terminal(self):
        """The run's identity is written INTO the file, so a file with no cached record still
        says which run it came from - the 462-of-474 case. The control for this one goes red when the
        header block is deleted, which agents-undf measured and I keep."""
        for rel in WRITERS:
            with self.subTest(writer=rel):
                src = _src(rel)
                var = "summary_file" if "summary_file" in src else "f"
                self.assertTrue(
                    _redirects_to_file(src, var),
                    f"{rel}: nothing is written straight into ${var}, so the summary file cannot "
                    "say which run it came from (agents-qtnv)",
                )
                lines = _code_only(src).splitlines()
                idx = [
                    i
                    for i, ln in enumerate(lines)
                    if any(p in ln for p in (f'> "${var}"', f'> \\"${var}\\"', f'> \\"\\${var}\\"', f'}} > "${var}"'))
                ]
                self.assertTrue(idx, f"{rel}: cannot locate the redirect to ${var}")
                fmt = _header_format_line(src)
                self.assertTrue(
                    fmt,
                    f"{rel}: cannot locate the statement that writes the header, so this pin is no "
                    "longer checking anything (a pin that silently stops matching reads exactly like "
                    "one that passes) - agents-dvpk",
                )
                for marker in HEADER_MARKERS:
                    field = f"{marker}%s"
                    self.assertIn(
                        field,
                        fmt,
                        f"{rel}: the HEADER'S OWN FORMAT does not carry the {field!r} field, so the "
                        "file written to ${var} cannot identify its run. Asserted on the FIELD (%s)" 
                        "and not on the bare marker: agents-dvpk measured that dropping `sha=%s` passed "
                        "because the assignment `summary_sha=` supplied the substring from a nearby "
                        "line - and for check.conf's single-line writer, from the SAME line "
                        "(agents-qtnv, agents-dvpk)",
                    )

    def test_the_tee_appends_so_it_cannot_truncate_the_header(self):
        """A plain `tee` truncates the file on the runner's first byte, erasing the header.

        Asserted on the RUNNER COMMAND, not the file: agents-undf measured that `assertIn("tee -a",
        src)` passed with a plain `tee` because the comment this change added contains the words
        'tee -a'. A comment cannot satisfy an assertion that only reads the command line.
        """
        for rel in WRITERS:
            with self.subTest(writer=rel):
                code = _code_only(_src(rel))
                runner_lines = [ln for ln in code.splitlines() if "unittest" in ln]
                self.assertTrue(runner_lines, f"{rel}: no runner command found to check")
                runner = "\n".join(runner_lines)
                self.assertIn(
                    "tee -a",
                    runner,
                    f"{rel}: the runner command does not tee into the summary file with -a, so the "
                    "header this bead added is truncated on the runner's first byte (agents-qtnv, "
                    "agents-undf)",
                )
                for var in ("$f", "$summary_file"):
                    self.assertNotIn(
                        f"| tee \\\"{var}\\\"",
                        runner,
                        f"{rel}: `tee` without -a truncates the header this bead added (agents-qtnv)",
                    )


if __name__ == "__main__":
    unittest.main()
