#!/usr/bin/env python3
"""Tests for tools/docs-text-floor.sh - the rendered text-floor sweep.

The tool exists because a rule that scans CSS declarations cannot see what actually RENDERS: `.72rem` appeared four
times in docs/css/factory.css while the four sites it hit rendered at 11.52px, and a declaration scan is blind to
which elements a font-size lands on. These tests drive the tool with a STUB CHROME on PATH, so the fast gate never
launches a browser. What they pin is the tool's own plumbing - which docs it read, that the injected control site
reached the file that was measured, and its exit codes. The rendering itself was measured against real Chrome and
the numbers are recorded with the change (before: index 5, lines 4, stations 113, use/help/install 1, all 11.52px;
after: every page below=0; control: below=1 [p.__fifth_site=11.00px]).

The stub is the honest instrument for that split. A browser decides what is below the floor; no assertion here
claims otherwise. What the stub CAN testify about is the class of defect the tool is capable of - reading a docs
tree it did not resolve, reporting a verdict about a copy it never measured, or applying a control that never
landed. So each fixture page carries a marker the stub looks for, and the stub logs whether the measured file had
it: a sweep that read the repository's real docs instead of the resolved fixture shows up as a run with no markers.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "docs-text-floor.sh"

# Marks a page as belonging to this test's fixture, so "which docs did it read" is an observable fact rather than
# an inference from a path (the tool measures a COPY, so paths alone cannot answer it after the run).
FIXTURE_MARKER = "fixture-page-marker"

# Stands in for Chrome. It prints the marker the tool greps for, in the shape the tool expects (the marker id is
# what it matches, not the script source that carries the same literal), reports the injected site exactly when the
# file it was handed contains it, and logs the measured path plus whether that file was one of our pages.
STUB_CHROME = """#!/usr/bin/env bash
file=""
for arg in "$@"; do case "$arg" in file://*) file="${arg#file://}";; esac; done
page="$(basename "$file")"
if grep -q '__fifth_site' "$file" 2>/dev/null; then below=1; list=' [p.__fifth_site=11.00px]'; else below=0; list=''; fi
if grep -q 'FIXTURE_MARKER' "$file" 2>/dev/null; then marker=1; else marker=0; fi
[ -n "$STUB_CHROME_LOG" ] && printf '%s=%s\\n' "$marker" "$page" >> "$STUB_CHROME_LOG"
# Two shapes the tool must refuse: a page whose payload counted nothing, and a verdict that does not say how many
# elements it counted at all.
counted=3
grep -q 'ZERO_COUNT' "$file" 2>/dev/null && counted=0
grep -q 'NO_COUNT_FIELD' "$file" 2>/dev/null && counted=
if [ -z "$counted" ]; then
  echo '<div id="__floor_result">FLOOR_RESULT page='"$page"' floor=12px below='"$below"'</div>'
else
  echo '<div id="__floor_result">FLOOR_RESULT page='"$page"' floor=12px counted='"$counted"' below='"$below""$list"'</div>'
fi
exit 0
"""

PAGES = ("index.html", "stations.html", "lines.html", "use.html", "help.html", "install.html")


class DocsTextFloorBase(unittest.TestCase):
    """A tree shaped like the repository: a copy of the tool under <tmp>/tools, pages under <tmp>/docs with a
    css/factory.css and a proper `</body>` (the control patches both), and a stub chrome on PATH."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        (self.tmp / "tools").mkdir()
        (self.tmp / "tools" / "docs-text-floor.sh").write_bytes(TOOL.read_bytes())
        self.tool = self.tmp / "tools" / "docs-text-floor.sh"
        self.docs = self.tmp / "docs"
        (self.docs / "css").mkdir(parents=True)
        (self.docs / "css" / "factory.css").write_text("/* fixture */\n", encoding="utf-8")
        for page in PAGES:
            (self.docs / page).write_text(
                f"<!doctype html><!-- {FIXTURE_MARKER} --><body><p>text</p></body>\n", encoding="utf-8")
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        stub = self.bin / "google-chrome"
        stub.write_text(STUB_CHROME.replace("FIXTURE_MARKER", FIXTURE_MARKER), encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        self.empty = self.tmp / "empty-bin"
        self.empty.mkdir()
        self.log = self.tmp / "chrome-measured.log"
        self.addCleanup(self._tmp.cleanup)

    def run_tool(self, *args, path=None):
        env = dict(os.environ)
        # `path` is the WHOLE PATH (the no-browser case needs the real chrome to be absent, not merely
        # preceded); the default prepends the stub so the real chrome is never reached.
        env["PATH"] = str(path) if path else str(self.bin) + os.pathsep + env.get("PATH", "")
        env["STUB_CHROME_LOG"] = str(self.log)
        return subprocess.run(["/bin/bash", str(self.tool), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def measured(self):
        """[(marker, page)] for every file the stub was handed, in order."""
        if not self.log.exists():
            return []
        return [tuple(line.split("=", 1)) for line in self.log.read_text().splitlines() if line]

    def results(self, stdout):
        return [line for line in stdout.splitlines() if "FLOOR_RESULT" in line]


class TestTheSweepVerdictAndItsControl(DocsTextFloorBase):

    def test_a_clean_tree_reports_zero_below_and_exits_zero(self):
        done = self.run_tool()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        results = self.results(done.stdout)
        self.assertEqual(len(results), len(PAGES), "every page in the docs dir must be measured")
        for line in results:
            self.assertIn("below=0", line)

    def test_the_injected_control_site_turns_it_red_and_reaches_the_measured_copy(self):
        """It fails only when the injected label is in the file the stub was handed, so it cannot pass by the tool
        printing a verdict about a copy it never measured."""
        self.assertEqual(self.run_tool().returncode, 0)
        red = self.run_tool("--inject-fifth-site")
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn("__fifth_site", red.stdout)
        self.assertIn("below=1", red.stdout)

    def test_the_control_measures_a_copy_and_never_the_repositorys_docs(self):
        self.run_tool("--inject-fifth-site")
        self.assertTrue(self.measured())
        for marker, page in self.measured():
            self.assertEqual(marker, "1", f"{page} was measured from a file that is not one of our pages")

    def test_a_page_below_the_floor_fails_the_run(self):
        for page in self.docs.glob("*.html"):
            page.write_text(f"<!doctype html><body><p class='__fifth_site'>x</p></body>\n", encoding="utf-8")
        done = self.run_tool()
        self.assertEqual(done.returncode, 1)
        self.assertIn("below=1", done.stdout)


class TestAVerdictMustSayWhatItLookedAt(DocsTextFloorBase):

    def test_a_verdict_that_counted_nothing_is_not_a_pass(self):
        """The failure the reviewer named before it ran: a page whose payload silently counted no element used to
        report below=0 and read as a clean sweep. A floor over nothing proves nothing."""
        (self.docs / "index.html").write_text(
            "<!doctype html><body><!-- ZERO_COUNT --><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool()
        self.assertEqual(done.returncode, 1)
        self.assertIn("counted=0", done.stdout)
        self.assertIn("proves nothing", done.stdout + done.stderr)

    def test_a_verdict_that_does_not_report_its_count_is_not_a_pass(self):
        """A clean sweep has to say what it looked at: a verdict with no counted= field cannot be told apart from
        one that measured nothing, so it is a NO RESULT."""
        (self.docs / "index.html").write_text(
            "<!doctype html><body><!-- NO_COUNT_FIELD --><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool()
        self.assertEqual(done.returncode, 1)
        self.assertIn("did not report how many elements it counted", done.stdout + done.stderr)

    def test_an_honest_verdict_reports_a_count(self):
        done = self.run_tool()
        self.assertEqual(done.returncode, 0)
        for line in self.results(done.stdout):
            self.assertIn("counted=", line)


class TestTheSummarySaysWhetherTheSweepWasComplete(DocsTextFloorBase):
    """coord, on the count contract: a count that is TRUE but misleading is the same defect as no count. `counted`
    is per page, and a reader who sees a large count must not be able to read it as coverage of pages that produced
    no verdict at all - so the run ends with pages, verdicts and a status."""

    def test_the_summary_reports_pages_verdicts_and_status(self):
        done = self.run_tool()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(f"FLOOR_SUMMARY pages={len(PAGES)} verdicts={len(PAGES)} below_total=0 viewport=1280,900 status=OK",
                      done.stdout, "the summary must state the viewport its counts are true for")

    def test_a_page_without_a_verdict_makes_the_run_incomplete(self):
        """One page reports no count, so the counts of the other five must not be readable as coverage of six."""
        (self.docs / "index.html").write_text(
            "<!doctype html><body><!-- NO_COUNT_FIELD --><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool()
        self.assertEqual(done.returncode, 1)
        self.assertIn(f"pages={len(PAGES)} verdicts={len(PAGES) - 1}", done.stdout)
        self.assertIn("status=INCOMPLETE", done.stdout)

    def test_a_page_that_counted_nothing_also_makes_it_incomplete(self):
        (self.docs / "stations.html").write_text(
            "<!doctype html><body><!-- ZERO_COUNT --><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool()
        self.assertEqual(done.returncode, 1)
        self.assertIn("status=INCOMPLETE", done.stdout)

    def test_the_summary_below_total_adds_up_the_per_page_verdicts(self):
        done = self.run_tool()
        self.assertEqual(done.returncode, 0)
        self.assertIn("below_total=0", done.stdout)
        for page in self.docs.glob("*.html"):
            page.write_text("<!doctype html><body><p class='__fifth_site'>x</p></body>\n", encoding="utf-8")
        red = self.run_tool()
        self.assertIn(f"below_total={len(PAGES)}", red.stdout, "each page's below-count must reach the summary")
        self.assertEqual(red.returncode, 1)


class TestTheSweepReadsTheDocsItResolved(DocsTextFloorBase):

    def test_the_default_docs_dir_is_resolved_from_the_tools_own_location(self):
        done = self.run_tool()
        self.assertEqual(done.returncode, 0, done.stderr)
        measured = self.measured()
        self.assertEqual([page for _marker, page in measured], sorted(PAGES),
                         "the tool must measure the pages of the tree it lives in")
        self.assertEqual([marker for marker, _page in measured], ["1"] * len(PAGES),
                         "a page measured without the fixture marker means it read docs this test did not provide")

    def test_the_marker_check_can_see_a_tree_that_is_not_ours(self):
        """The control for the assertion above: pointed at pages without the marker, the same check reports 0, so a
        green sweep cannot be explained by the marker test being unable to fail."""
        other = self.tmp / "other-docs"
        (other / "css").mkdir(parents=True)
        (other / "css" / "factory.css").write_text("/* other */\n", encoding="utf-8")
        (other / "index.html").write_text("<!doctype html><body><p>no marker here</p></body>\n", encoding="utf-8")
        done = self.run_tool("--docs", str(other))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.measured(), [("0", "index.html")])

    def test_an_explicit_docs_dir_is_the_one_measured(self):
        other = self.tmp / "elsewhere"
        other.mkdir()
        (other / "only.html").write_text("<!doctype html><body><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool("--docs", str(other))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([page for _marker, page in self.measured()], ["only.html"])

    def test_a_missing_docs_dir_is_an_error_not_an_empty_pass(self):
        done = self.run_tool("--docs", str(self.tmp / "nope"))
        self.assertEqual(done.returncode, 2)

    def test_a_docs_dir_with_no_pages_cannot_report_a_clean_sweep(self):
        """A sweep that measures nothing cannot fail, so it must not report a verdict. Measured before this guard:
        the empty dir left the glob literal and the tool measured a file called `*.html`, then exited 0."""
        empty = self.tmp / "no-pages"
        empty.mkdir()
        done = self.run_tool("--docs", str(empty))
        self.assertEqual(done.returncode, 2)
        self.assertIn("nothing to measure", done.stdout + done.stderr)
        self.assertEqual(self.measured(), [], "it must not measure something that does not exist")


class TestTheSweepIsLoudAboutItsOwnMisuse(DocsTextFloorBase):

    def test_no_browser_on_path_exits_two_and_says_so(self):
        """The tool cannot measure without a browser, so it says that instead of reporting a clean sweep."""
        done = self.run_tool("--docs", str(self.docs), path=self.empty)
        self.assertEqual(done.returncode, 2)
        self.assertIn("chrome", (done.stdout + done.stderr).lower())

    def test_the_control_refuses_loudly_when_it_cannot_be_applied(self):
        """Measured before this guard: a tree without css/factory.css made the control die mid-flight - a shell
        'No such file or directory' and exit 1 with NO RESULT on every page, i.e. a control that reports nothing.
        It now refuses by name, and the sweep still works without it."""
        stripped = self.tmp / "no-css-docs"
        (stripped / "css").mkdir(parents=True)
        (stripped / "index.html").write_text("<!doctype html><body><p>text</p></body>\n", encoding="utf-8")
        done = self.run_tool("--docs", str(stripped), "--inject-fifth-site")
        self.assertEqual(done.returncode, 2)
        self.assertIn("CONTROL UNAVAILABLE", done.stdout + done.stderr)
        self.assertEqual(self.results(done.stdout), [],
                         "a control that could not be applied must not report page results as if it had been")
        self.assertEqual(self.run_tool("--docs", str(stripped)).returncode, 0, "the sweep itself still runs")

    def test_the_control_refuses_when_the_label_cannot_reach_the_page(self):
        no_body = self.tmp / "no-body-docs"
        (no_body / "css").mkdir(parents=True)
        (no_body / "css" / "factory.css").write_text("/* x */\n", encoding="utf-8")
        (no_body / "index.html").write_text("<!doctype html><p>no closing body tag</p>\n", encoding="utf-8")
        done = self.run_tool("--docs", str(no_body), "--inject-fifth-site")
        self.assertEqual(done.returncode, 2)
        self.assertIn("CONTROL UNAVAILABLE", done.stdout + done.stderr)

    def test_an_unknown_option_is_refused(self):
        done = self.run_tool("--not-an-option")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
