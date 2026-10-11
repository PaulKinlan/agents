"""agents-2iwf: an engine's stderr must not be readable as the model's answer.

FOUR SITES, ONE DEFECT: the run line at pi.sh:147 / claude.sh:251 / antigravity.sh:87 /
deepseek.sh:93 sent the engine's stdout AND stderr into one file and then printed the
PATH, which the dispatcher reads as the model's output. So an engine that exited 0 and
wrote ONLY to stderr (a rate-limit notice, a traceback) left a non-empty file that the
read-back accepted as the answer. Measured on pi.sh before the fix: an engine writing
"provider error: 429 rate limited" to stderr alone produced rc=0 with a 44-byte
model_output.txt, i.e. a delivery.

Each site is tested against the REAL adapter, and every probe below has a CONTROL arm
whose failure mode is different from the defect's - a silent engine (rc=1 for a reason
the fix cannot manufacture) sits alongside the stderr-only engine, so a bare failure
cannot pass for the one under test.

ANTIGRAVITY IS DIFFERENT AND THE DIFFERENCE IS STATED RATHER THAN HIDDEN: its adapter
refuses EVERY tool policy at :43-49 and exits 3 BEFORE its guard (:65) and its redirect
(:87), so there is no policy value that reaches the code under test. Its tests therefore
use TWO arms:
  * a reachability test on the UNMODIFIED file, asserting the refusal precedes both
    lines - which is the fact that makes the copy legitimate and the fact that would
    change if the refusal were weakened; and
  * an ORDER test on a TEST-LOCAL COPY with that refusal block removed. THE COPY
    DISCHARGES THE ORDER OF THE GUARDS, NOT THE REACHABILITY OF THE LINES: it exercises
    the real file contents below the refusal, but it cannot show that a dispatch reaches
    them on the unmodified adapter. Any test name or assertion message that implied
    otherwise would be the third shape of this defect family - a test that cannot fail on
    the pre-fix tree because the pre-fix tree cannot reach the line.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = ROOT / "lib" / "adapters"

# The engine stub bodies. Each one is the WHOLE input contract: read stdin, write (or not)
# to stdout, write (or not) to stderr, exit.
SILENT = "#!/bin/sh\ncat >/dev/null 2>&1\nexit 0\n"
STDERR_ONLY = "#!/bin/sh\ncat >/dev/null 2>&1\necho 'provider error: 429 rate limited' >&2\nexit 0\n"
ANSWERS = "#!/bin/sh\ncat >/dev/null 2>&1\necho 'the answer'\nexit 0\n"


class _Sandbox:
    """A minimal run directory plus a stub engine, for one adapter invocation."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.run_dir = root / "run"
        self.target = root / "target"
        self.skill = root / "skill"
        for d in (self.run_dir, self.target, self.skill):
            d.mkdir(parents=True, exist_ok=True)

    def engine(self, body: str) -> Path:
        path = self.root / "engine"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def invoke(self, adapter: Path, prompt: str, engine: Path, env: dict) -> subprocess.CompletedProcess:
        """Run one adapter. RUN_DIR IS ABSOLUTE: these adapters cd "$TARGET_DIR" first, so
        a relative run dir is resolved against the target and the output file cannot be
        created - a harness error that looks like an adapter failure."""
        full = {"PATH": "/usr/bin:/bin", "HOME": str(self.root),
                "FACTORY_ENGINE_BIN": str(engine), "FACTORY_TOOL_POLICY": "read-only"}
        full.update(env)
        return subprocess.run(
            ["bash", str(adapter), "probe", str(self.target), str(self.skill), str(self.run_dir)],
            input=prompt, capture_output=True, text=True, timeout=60, env=full,
        )

    def output(self) -> Path:
        return self.run_dir / "model_output.txt"

    def stderr_file(self) -> Path:
        return self.run_dir / "model_stderr.txt"


class TestStderrIsNotAnAnswer(unittest.TestCase):
    """pi and claude: the same shape, reachable today."""

    def _adapter(self, name: str) -> Path:
        return ADAPTERS / f"{name}.sh"

    def _cases(self, name: str, env: dict | None = None):
        for label, body, want_rc in (
            ("CONTROL silent engine -> refused", SILENT, 1),
            ("stderr-only engine -> refused", STDERR_ONLY, 1),
            ("engine that answers -> delivered", ANSWERS, 0),
        ):
            with self.subTest(adapter=name, case=label), \
                    tempfile.TemporaryDirectory() as tmpdir:
                box = _Sandbox(Path(tmpdir))
                res = box.invoke(self._adapter(name), "a real prompt", box.engine(body), env or {})
                yield label, res, want_rc, box

    def test_pi_stderr_is_not_the_answer(self):
        for label, res, want_rc, box in self._cases("pi"):
            with self.subTest(case=label):
                self.assertEqual(res.returncode, want_rc,
                                 f"{label}: rc was {res.returncode}, stderr={res.stderr[:300]}")
                if want_rc == 1:
                    # THE DEFECT ITSELF: the output file must stay EMPTY, because the
                    # engine put nothing on stdout. Before the fix this arm produced a
                    # non-empty file (44 bytes for the stub above) and rc=0.
                    self.assertEqual(box.output().stat().st_size, 0,
                                     f"{label}: stdout file must be empty, got "
                                     f"{box.output().read_text()!r}")
                    self.assertIn("wrote no output", res.stderr)
                    self.assertTrue(box.stderr_file().exists(),
                                    f"{label}: the separated stderr file must exist")
                    # A DIAGNOSTIC IS PRESERVED AND SEPARATED, not stored as the answer.
                    # Only for the arm whose stub WRITES one: the silent control's file is
                    # legitimately empty, and asserting content there would make this test
                    # pass or fail for a reason unrelated to the defect.
                    if "stderr-only" in label:
                        self.assertIn("429", box.stderr_file().read_text(),
                                      f"{label}: the engine's diagnostic must be kept")

    def test_claude_stderr_is_not_the_answer(self):
        # The adapter refuses without a credential BEFORE the run, so the harness supplies
        # one: without it every arm below would fail for a reason unrelated to the split.
        for label, res, want_rc, box in self._cases("claude", {"ANTHROPIC_API_KEY": "test-key"}):
            with self.subTest(case=label):
                self.assertEqual(res.returncode, want_rc,
                                 f"{label}: rc was {res.returncode}, stderr={res.stderr[:300]}")
                if want_rc == 1:
                    self.assertEqual(box.output().stat().st_size, 0,
                                     f"{label}: stdout file must be empty, got "
                                     f"{box.output().read_text()!r}")
                    self.assertIn("wrote no output", res.stderr)

    def test_claude_shows_the_engines_stderr_on_a_successful_run(self):
        """The split must not SILENTLY DROP the diagnostic on the success path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            box = _Sandbox(Path(tmpdir))
            engine = box.engine("#!/bin/sh\ncat >/dev/null 2>&1\necho 'a cost note' >&2\n"
                                "echo 'the answer'\nexit 0\n")
            res = box.invoke(self._adapter("claude"), "a real prompt", engine,
                             {"ANTHROPIC_API_KEY": "test-key"})
            self.assertEqual(res.returncode, 0, res.stderr[:300])
            self.assertIn("a cost note", res.stderr,
                          "the engine's stderr must reach the operator, not vanish")



class TestDeepSeekStderrIsNotTheAnswer(TestStderrIsNotAnAnswer):
    # agents-2plj: DEEPSEEK WAS NAMED IN PROSE AND NEVER INVOKED. The single grep hit for it
    # was the module docstring, while the fast-gate wildcard arm selects this file for a
    # deepseek.sh change - so the map named a suite that cannot discriminate on the file
    # that triggered it. The absent edge is what a grep cannot show.
    #
    # Two facts the harness has to satisfy, BOTH LEARNED FROM THE ADAPTER'S OWN REFUSALS
    # rather than from reading it: it refuses BY NAME without DEEPSEEK_BASE_URL, and it
    # shells out to python for the API call. The second is why the harness points
    # FACTORY_PYTHON_BIN at a stub interpreter - without it the arm makes a REAL network
    # call and fails on connection refused. The redirect under test is in the SHELL below
    # that call, so stubbing the call still exercises it.

    DEEPSEEK_ENV = {"DEEPSEEK_BASE_URL": "http://127.0.0.1:1", "DEEPSEEK_API_KEY": "test-key"}

    def _cases(self, name, env=None):
        for label, body, want_rc in (
            ("CONTROL silent engine -> refused", SILENT, 1),
            ("stderr-only engine -> refused", STDERR_ONLY, 1),
            ("engine that answers -> delivered", ANSWERS, 0),
        ):
            with self.subTest(adapter=name, case=label), \
                    tempfile.TemporaryDirectory() as tmpdir:
                box = _Sandbox(Path(tmpdir))
                stub = box.root / "python-stub"
                stub.write_text('#!/bin/sh\nexec "$FACTORY_ENGINE_BIN"\n', encoding="utf-8")
                stub.chmod(0o755)
                engine = box.engine(body)
                env2 = dict(env or {})
                env2["FACTORY_PYTHON_BIN"] = str(stub)
                res = box.invoke(self._adapter(name), "a real prompt", engine, env2)
                yield label, res, want_rc, box

    def test_deepseek_stderr_is_not_the_answer(self):
        seen = 0
        for label, res, want_rc, box in self._cases("deepseek", self.DEEPSEEK_ENV):
            seen += 1
            with self.subTest(case=label):
                self.assertEqual(res.returncode, want_rc,
                                 f"deepseek {label}: rc={res.returncode} stderr={res.stderr[:300]}")
        self.assertEqual(seen, 3, "the deepseek arm must run all three cases")

class TestAntigravityIsRefusedToday(unittest.TestCase):
    """The fact that makes the copy legitimate, and the fact that would change first."""

    def test_the_policy_refusal_precedes_the_guard_and_the_redirect(self):
        """agents-2iwf: antigravity refuses EVERY policy at :43-49 and exits 3 before its
        prompt guard (:65) and its output redirect (:87). That is why its two lines are
        UNREACHABLE TODAY, and it is the assertion that would fail if someone later gave
        the case an accepted branch - at which point those defects become LIVE rather
        than on a timer, and this test is where that change shows up."""
        adapter = ADAPTERS / "antigravity.sh"
        text = adapter.read_text(encoding="utf-8")
        refusal = text.index("agentapi has no tool controls")
        guard = text.index('if [ -z "$PROMPT" ]; then')
        redirect = text.index('new-conversation "$PROMPT"')
        self.assertLess(refusal, guard,
                        "the tool-policy refusal must precede the prompt guard")
        self.assertLess(refusal, redirect,
                        "the tool-policy refusal must precede the output redirect")
        with tempfile.TemporaryDirectory() as tmpdir:
            box = _Sandbox(Path(tmpdir))
            res = box.invoke(adapter, "a real prompt", box.engine(ANSWERS), {})
            self.assertEqual(res.returncode, 3,
                             "the unmodified adapter must refuse before the engine runs")
            self.assertIn("Refusing", res.stderr)


class TestAntigravityOrderOnACopy(unittest.TestCase):
    """The ORDER of the guards, discharged on a copy. NOT reachability."""

    # The block removed from the copy. If the adapter's refusal is ever reworded this
    # substitution fails loudly rather than silently testing an unmodified file.
    _REFUSAL = (
        'case "$TOOL_POLICY" in\n'
        '  *)\n'
    )

    def _copy_without_refusal(self, dest: Path) -> Path:
        text = (ADAPTERS / "antigravity.sh").read_text(encoding="utf-8")
        start = text.index(self._REFUSAL)
        end = text.index("esac", start) + len("esac")
        copy = dest / "antigravity-norefuse.sh"
        copy.write_text(
            text[:start]
            + "# (test copy) the tool-policy refusal is DELIBERATELY REMOVED here so the\n"
              "# lines below it are reachable. See this module's docstring: this copy\n"
              "# discharges the ORDER of the guards, not the reachability of the lines.\n"
            + text[end:],
            encoding="utf-8",
        )
        return copy

    def test_order_on_the_copy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            copy = self._copy_without_refusal(root)
            # CONTROL first: the copy must actually RUN, or a failure below would tell us
            # nothing about the guards.
            ctrl_box = _Sandbox(root / "ctrl")
            ctrl = ctrl_box.invoke(copy, "a real prompt", ctrl_box.engine(ANSWERS), {})
            self.assertEqual(ctrl.returncode, 0,
                             f"CONTROL: the un-refused copy must run; stderr={ctrl.stderr[:300]}")

            box = _Sandbox(root / "case")
            res = box.invoke(copy, "a real prompt", box.engine(STDERR_ONLY), {})
            self.assertEqual(res.returncode, 1,
                             "an engine writing only to stderr must not be delivered")
            self.assertEqual(box.output().stat().st_size, 0)
            self.assertIn("wrote no output", res.stderr)


if __name__ == "__main__":
    unittest.main()
