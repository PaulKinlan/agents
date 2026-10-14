"""A wrapper must not report success for a run that did not happen - agents-p1gv.

Instance 3 of this shape was mine: a sweep went out with a positional arg instead of --docs, so the tool
exited 2 ON USAGE, while the message a reader saw said "exit 0 after 0s". A status is the fleet's primary
evidence that something ran, so a wrapper that reports a status it did not observe turns "no evidence" into
"evidence of success". The same failure class as the fixture [check] (agents-97kx), the frozen updated_at
reader (agents-gezf) and the invented branch (agents-odrf): a control reporting a fact it never observed.

Two properties are pinned here, both over the real tree rather than a fixture:

1. PIPES ARE HANDLED EXPLICITLY. A wrapper that pipes and then reads a status must set pipefail, or the rc it
   reports belongs to the last element of the pipeline rather than to the tool. Files are read from tools/*.sh,
   comment lines are skipped, and the test fails if it examined no files at all - a guard that checks nothing
   must not report that all is well.
2. A PATH THAT CANNOT RUN IS NOT A PASS. tools/docs-text-floor.sh is driven through every input that makes a
   measurement impossible - an unknown flag, a missing docs dir, an empty one - and must exit non-zero and
   name the reason. Its no-args path is deliberately NOT in this list: measured, it defaults to <repo>/docs and
   genuinely runs (6 FLOOR_RESULT lines plus the SUMMARY), so an exit 0 there is a real run and calling it a
   defect would be this suite's own false finding.

The third test is the control: the criterion above is a function, and it is run against a fixture wrapper that
reports success without running anything, so the suite can be shown to go red for the shape it guards.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
WRAPPER = TOOLS / "docs-text-floor.sh"

PIPELINE = re.compile(r"\|")

# The shapes that must be reported as a failure, as (argv-extra, expected fragment of stderr). The empty docs
# dir is built per-run in a tmpdir so the test owns no machine state and cannot read another agent's files.
def non_executing_cases(empty_dir: Path):
    return [
        (["--docs", str(empty_dir)], "nothing to measure"),
        (["--docs", str(empty_dir / "absent")], "no docs dir"),
        (["--not-a-real-flag"], "usage"),
    ]


def piping_wrappers_without_pipefail(tools_dir: Path):
    """THE PIPELINE CRITERION. Returns (how many piping wrappers were examined, the ones that do not set
    pipefail). The count is returned rather than implied so a caller can refuse a vacuous result."""
    examined, offenders = 0, []
    for f in sorted(tools_dir.glob("*.sh")):
        text = f.read_text()
        code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        if not any(PIPELINE.search(ln) for ln in code):
            continue
        examined += 1
        if "pipefail" not in text:
            offenders.append(f.name)
    return examined, offenders


def run_case(wrapper: Path, extra):
    return subprocess.run(["bash", str(wrapper)] + list(extra), capture_output=True, text=True, timeout=120)


def a_non_run_reported_as_success(wrapper: Path, empty_dir: Path):
    """THE CRITERION. Returns the list of inputs for which the wrapper claimed success without running."""
    bad = []
    for extra, _fragment in non_executing_cases(empty_dir):
        p = run_case(wrapper, extra)
        if p.returncode == 0:
            bad.append(" ".join(extra))
    return bad


class TestNoWrapperReportsSuccessForARunThatDidNotHappen(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.empty = Path(self._tmp.name) / "empty-docs"
        self.empty.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_all_wrappers_set_pipefail_when_they_pipe(self):
        examined, offenders = piping_wrappers_without_pipefail(TOOLS)
        self.assertGreater(
            examined, 0,
            "examined no piping wrapper at all - the check would pass vacuously, which is the failure mode it exists to catch")
        self.assertEqual(
            offenders, [],
            "these wrappers pipe but do not set pipefail, so any rc they report may belong to the last "
            "element of the pipeline rather than to the tool: %s" % ", ".join(offenders))

    def test_the_pipeline_criterion_can_go_red(self):
        # THE SECOND CONTROL: the criterion above must catch a wrapper that pipes and reads a status without
        # pipefail, or it is an assertion rather than a guard.
        d = Path(self._tmp.name) / "fake-tools"
        d.mkdir()
        (d / "pipes-without-pipefail.sh").write_text("#!/usr/bin/env bash\nfoo | tail -1\nrc=$?\nexit $rc\n")
        found = []
        (d / "honest.sh").write_text("#!/usr/bin/env bash\nset -euo pipefail\nfoo | tail -1\n")
        examined, offenders = piping_wrappers_without_pipefail(d)
        # BOTH fixtures pipe; only one sets pipefail. So this asserts the criterion is about pipefail and not
        # merely about the presence of a pipe - a distinction the first version of this fixture got wrong and
        # this assertion caught (it expected 1 examined and got 2, which is the honest number).
        self.assertEqual(examined, 2, "expected both fixture wrappers to pipe, saw %d examined" % examined)
        self.assertEqual(offenders, ["pipes-without-pipefail.sh"], "the pipeline criterion did not catch the fixture")

    def test_a_path_that_cannot_run_is_not_a_pass(self):
        for extra, fragment in non_executing_cases(self.empty):
            p = run_case(WRAPPER, extra)
            self.assertNotEqual(
                p.returncode, 0,
                "%s %s reported success (%s) for a run that could not happen" % (WRAPPER.name, " ".join(extra), p.returncode))
            self.assertIn(
                fragment, p.stderr.lower(),
                "%s %s failed but did not name the reason (stderr: %r)" % (WRAPPER.name, " ".join(extra), p.stderr[:200]))

    def test_the_criterion_can_go_red(self):
        # THE CONTROL: a wrapper that takes the same inputs and reports success while running nothing must be
        # caught by the criterion above, or every assertion in this file proves nothing.
        liar = Path(self._tmp.name) / "liar.sh"
        liar.write_text("#!/usr/bin/env bash\necho 'all good' >/dev/null\nexit 0\n")
        caught = a_non_run_reported_as_success(liar, self.empty)
        self.assertEqual(
            len(caught), len(non_executing_cases(self.empty)),
            "the criterion missed a wrapper that reports success without running anything: caught %r" % (caught,))


if __name__ == "__main__":
    unittest.main()
