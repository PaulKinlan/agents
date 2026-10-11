"""agents-ut3v: antigravity's prompt guard must test CONTENT of the FINAL prompt.

THE DEFECT: the guard sat above the reassembly and tested the stdin value for EMPTINESS.
So a prompt of spaces passed, and the guard tested a string the reassembly may replace.

THE TWO ARMS, AND THE SECOND IS NOT OPTIONAL (agents-ut3v review): a test that only proves
the bad input is refused would also pass if the adapter refused EVERYTHING. Arm A is the
other half and is the one that catches an over-correction:
  arm A  whitespace stdin WITH a system directive  -> MUST RUN. The reassembled prompt
         carries the directive's content, and the directive IS the instruction.
  arm B  whitespace stdin with NO directive        -> MUST BE REFUSED. Nothing is
         reassembled, so the engine would get nothing to act on. This is the defect.
  ctrl   a real prompt, no directive               -> MUST RUN.
Each is the other's control; neither is vacuous alone.

WHY A TEST-LOCAL COPY: this adapter refuses EVERY tool policy at its policy case and exits
3 before reaching the guard or the redirect, so there is no front door to the code under
test. The copy removes ONLY that refusal, editing the real file contents below it. THE COPY
DISCHARGES THE ORDER OF THE GUARDS, NOT THE REACHABILITY OF THE LINES - on the unmodified
adapter they are unreachable today. If the refusal ever gains an accepted branch, the lines
become live and this test is already the coverage for them.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "lib" / "adapters" / "antigravity.sh"

_REFUSAL = 'case "$TOOL_POLICY" in\n  *)\n'
_ANSWERS = "#!/bin/sh\ncat >/dev/null 2>&1\necho the answer\nexit 0\n"


class _Box:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.run_dir = root / "run"
        self.target = root / "target"
        self.skill = root / "skill"
        for d in (self.run_dir, self.target, self.skill):
            d.mkdir(parents=True, exist_ok=True)
        self.engine = root / "engine"
        self.engine.write_text(_ANSWERS, encoding="utf-8")
        self.engine.chmod(0o755)

    def invoke(self, adapter: Path, prompt: str, directive: Path | None):
        # RUN_DIR IS ABSOLUTE: these adapters cd "$TARGET_DIR" first, so a relative run dir
        # is resolved against the target and the output file cannot be created.
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root),
               "FACTORY_ENGINE_BIN": str(self.engine), "FACTORY_TOOL_POLICY": "read-only"}
        if directive is not None:
            env["FACTORY_SYSTEM_DIRECTIVE_FILE"] = str(directive)
        return subprocess.run(
            ["bash", str(adapter), "probe", str(self.target), str(self.skill), str(self.run_dir)],
            input=prompt, capture_output=True, text=True, timeout=60, env=env,
        )


def _copy_without_refusal(dest: Path) -> Path:
    text = ADAPTER.read_text(encoding="utf-8")
    start = text.index(_REFUSAL)
    end = text.index("esac", start) + len("esac")
    copy = dest / "antigravity-norefuse.sh"
    copy.write_text(
        text[:start]
        + "# (test copy) the tool-policy refusal is DELIBERATELY REMOVED so the lines below\n"
          "# it are reachable. See this module's docstring: the copy discharges the ORDER of\n"
          "# the guards, NOT the reachability of the lines on the unmodified adapter.\n"
        + text[end:], encoding="utf-8")
    return copy


class TestPromptContentGuard(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.adapter = _copy_without_refusal(self.root)
        self.directive = self.root / "directive.txt"
        self.directive.write_text("a real directive\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_control_a_real_prompt_runs(self):
        """Without this, a failure below could be the harness rather than the guard."""
        box = _Box(self.root / "ctrl")
        res = box.invoke(self.adapter, "a real prompt", None)
        self.assertEqual(res.returncode, 0,
                         f"CONTROL: a real prompt must run; stderr={res.stderr[:300]}")

    def test_arm_a_whitespace_with_a_directive_MUST_RUN(self):
        """THE ANTI-OVER-CORRECTION ARM. A content test placed below the reassembly admits
        this because the reassembled prompt carries the directive. If a change makes this
        refuse, it has broken the directive path - and a test with only arm B would have
        called that a pass."""
        box = _Box(self.root / "armA")
        res = box.invoke(self.adapter, "   \n\t\n", self.directive)
        self.assertEqual(res.returncode, 0,
                         "whitespace stdin WITH a directive is a legitimate run: the "
                         f"directive is the instruction. stderr={res.stderr[:300]}")

    def test_arm_b_whitespace_with_no_directive_MUST_BE_REFUSED(self):
        """THE DEFECT. Measured before the fix: rc=0 and the engine RAN with '   '."""
        box = _Box(self.root / "armB")
        res = box.invoke(self.adapter, "   \n\t\n", None)
        self.assertEqual(res.returncode, 2,
                         "with no directive nothing is reassembled, so a whitespace prompt "
                         "leaves the engine nothing to act on and must be refused "
                         f"(pre-fix this returned 0 and ran): rc={res.returncode}")
        self.assertRegex(res.stderr, r"content|blank|whitespace",
                         f"the refusal must name the reason: {res.stderr[:300]}")
        self.assertFalse((box.run_dir / "model_output.txt").exists()
                         and (box.run_dir / "model_output.txt").stat().st_size > 0,
                         "the engine must not have produced an answer")


if __name__ == "__main__":
    unittest.main()
