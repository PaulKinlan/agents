#!/usr/bin/env python3
"""Tests for reviewer runtime fallback refusal (fleet-szle, agents-kq0r part C).

Validates:
1. patches/fleet-reviewer-fallback-refusal.patch applies cleanly against /home/exedev/fleet.
2. bin/fleet-fallback-guard enforces cross-family refusal for reviewer lanes upon runtime fallback:
   - REFUSE: role=reviewer, FLEET_IMPL_MODEL=deepseek/deepseek-flash,
     requested=pi-claude-code-provider/sonnet, effective=deepseek/deepseek-flash -> exit 1,
     message names requested family, effective family, and source.
   - PROCEED: reviewer, effective=openai-codex/gpt-6-sol -> exit 0.
   - PROCEED: role=implementer with same models as REFUSE case -> exit 0.
   - PROCEED WITH A NOTE: reviewer, FLEET_IMPL_MODEL unset -> exit 0 and a note.
   - PROCEED WITH A NOTE: reviewer with an unparseable model string -> exit 0 and a note.
3. Host-level fallback behavior in sdk-host/host.mjs:
   - Records fallback line and updates .model pointer before refusal.
   - Refusal is loud (logged to events log), disposes session, and throws Error preventing start.
   - Cross-family fallback does not throw or dispose session.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLEET_DIR = Path("/home/exedev/fleet")
PATCH_PATH = ROOT / "patches" / "fleet-reviewer-fallback-refusal.patch"
WRITEUP_PATH = ROOT / "patches" / "fleet-reviewer-fallback-refusal.md"


class TestFleetReviewerFallbackRefusal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Extract guard script from patch artifact into a temp directory for direct execution
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.guard_bin = Path(cls.tmp_dir.name) / "fleet-fallback-guard"

        # Apply patch to a temporary copy of fleet to extract files and verify behavior
        cls.fleet_copy = Path(cls.tmp_dir.name) / "fleet"
        shutil.copytree(FLEET_DIR, cls.fleet_copy, symlinks=True)

        res = subprocess.run(
            ["git", "apply", "-p1", str(PATCH_PATH)],
            cwd=cls.fleet_copy,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"git apply failed in temp copy: {res.stderr}"

        # Copy the patched guard binary to guard_bin
        shutil.copy2(cls.fleet_copy / "bin" / "fleet-fallback-guard", cls.guard_bin)
        cls.guard_bin.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_patch_applies_cleanly_to_live_fleet_tooling(self):
        """The patch must apply with `git apply -p1 --check` from /home/exedev/fleet."""
        self.assertTrue(PATCH_PATH.is_file(), "patch artifact missing")
        res = subprocess.run(
            ["git", "apply", "-p1", "--check", str(PATCH_PATH)],
            cwd=FLEET_DIR,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"git apply -p1 --check failed against {FLEET_DIR}:\n{res.stderr}",
        )

    def test_patched_host_mjs_passes_syntax_check(self):
        """sdk-host/host.mjs must pass node --check after patching."""
        patched_host = self.fleet_copy / "sdk-host" / "host.mjs"
        res = subprocess.run(
            ["node", "--check", str(patched_host)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"node --check failed:\n{res.stderr}")

    def test_guard_refuses_same_family_reviewer(self):
        """REFUSE: role=reviewer, same effective family as FLEET_IMPL_MODEL -> exit 1,
        message names both requested and effective families and the source."""
        cmd = [
            str(self.guard_bin),
            "reviewer",
            "deepseek/deepseek-flash",
            "pi-claude-code-provider/sonnet",
            "deepseek/deepseek-flash",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1, f"expected exit 1, got {res.returncode}")
        combined = res.stdout + res.stderr
        self.assertIn("REFUSE", combined)
        self.assertIn("pi-claude-code-provider", combined)
        self.assertIn("deepseek", combined)
        self.assertIn("runtime fallback", combined)
        self.assertIn("FLEET_IMPL_MODEL", combined)

    def test_guard_proceeds_cross_family_reviewer(self):
        """PROCEED: reviewer, effective family differs from FLEET_IMPL_MODEL -> exit 0."""
        cmd = [
            str(self.guard_bin),
            "reviewer",
            "deepseek/deepseek-flash",
            "pi-claude-code-provider/sonnet",
            "openai-codex/gpt-6-sol",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}")
        combined = res.stdout + res.stderr
        self.assertIn("PROCEED", combined)

    def test_guard_proceeds_implementer_same_family(self):
        """PROCEED: role=implementer with same models as REFUSE case -> exit 0."""
        cmd = [
            str(self.guard_bin),
            "implementer",
            "deepseek/deepseek-flash",
            "pi-claude-code-provider/sonnet",
            "deepseek/deepseek-flash",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}")
        combined = res.stdout + res.stderr
        self.assertIn("PROCEED", combined)

    def test_guard_proceeds_with_note_when_impl_model_unset(self):
        """PROCEED WITH A NOTE: reviewer, FLEET_IMPL_MODEL unset -> exit 0 and a note."""
        cmd = [
            str(self.guard_bin),
            "reviewer",
            "",
            "pi-claude-code-provider/sonnet",
            "deepseek/deepseek-flash",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}")
        combined = res.stdout + res.stderr
        self.assertIn("NOTE", combined)
        self.assertIn("FLEET_IMPL_MODEL", combined)

    def test_guard_proceeds_with_note_on_unparseable_model_string(self):
        """PROCEED WITH A NOTE: reviewer with unparseable model string -> exit 0 and a note."""
        for bad in ["unparseable", "no-slash-here", ""]:
            with self.subTest(bad_model=bad):
                # Unparseable effective model
                cmd = [
                    str(self.guard_bin),
                    "reviewer",
                    "deepseek/deepseek-flash",
                    "pi-claude-code-provider/sonnet",
                    bad,
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0)
                self.assertIn("NOTE", res.stdout + res.stderr)

                # Unparseable implementer model
                cmd = [
                    str(self.guard_bin),
                    "reviewer",
                    bad,
                    "pi-claude-code-provider/sonnet",
                    "deepseek/deepseek-flash",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0)
                self.assertIn("NOTE", res.stdout + res.stderr)

    def test_fleet_internal_test_suite_passes(self):
        """tests/fleet-fallback-guard.test.sh delivered in the patch must pass all assertions."""
        test_script = self.fleet_copy / "tests" / "fleet-fallback-guard.test.sh"
        self.assertTrue(test_script.is_file(), "fleet test script not found in patched copy")
        res = subprocess.run(
            ["bash", str(test_script)],
            cwd=self.fleet_copy,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"tests/fleet-fallback-guard.test.sh failed:\n{res.stdout}\n{res.stderr}",
        )
        self.assertIn("0 failed", res.stdout)

    def test_host_fallback_behavior_in_mock_harness(self):
        """Verify host-level fallback behavior in Node:
        - On refusal: .model written, events.log has fallback and refusal, session disposed, throws.
        - On allowed fallback: .model written, events.log has fallback, session not disposed, does not throw.
        - On missing guard binary (ENOENT): .model written, events.log has fallback and note, session not disposed, does not throw.
        - On non-executable guard (EACCES): .model written, events.log has fallback and note, session not disposed, does not throw.
        - On abnormal exit (127): .model written, events.log has fallback and note, session not disposed, does not throw.
        """
        harness_js = """
import { writeFileSync, readFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import cp from "node:child_process";

const TMP = process.argv[2];
const GUARD = process.argv[3];
const LD = join(TMP, "lanes");
mkdirSync(LD, { recursive: true });

async function testFallback({ name, role, implModel, requestedModel, actualModel, guardOverride }) {
  const p = {
    role,
    model: requestedModel,
    env: { FLEET_ROLE: role, FLEET_IMPL_MODEL: implModel }
  };
  const logs = [];
  let disposed = false;
  const session = { dispose: () => { disposed = true; } };
  const ctx = { name, log: (line) => logs.push(line) };

  let threw = false, errorMsg = "";
  try {
    if (actualModel !== p.model) {
      ctx.log(`ℹ runtime model fell back: ${p.model} -> ${actualModel}`);
      try { writeFileSync(join(LD, `${ctx.name}.model`), actualModel + "\\n"); } catch {}
      if (p.env) p.env.FLEET_MODEL = actualModel;
      const r = p.role || p.env?.FLEET_ROLE || process.env.FLEET_ROLE || "";
      const im = p.env?.FLEET_IMPL_MODEL || process.env.FLEET_IMPL_MODEL || "";
      const guardBin = guardOverride || GUARD;
      let refusal = null;
      try {
        const out = cp.execFileSync(guardBin, [r, im, p.model, actualModel], { encoding: "utf8" });
        if (out && out.includes("NOTE:")) {
          ctx.log(`ℹ ${out.trim()}`);
        }
      } catch (e) {
        const outText = (e.stdout || e.stderr || "").trim();
        if (e.status === 1 && outText.includes("REFUSE:")) {
          refusal = outText;
        } else {
          const why = e.code ? `cannot execute (${e.code})` : `exited ${e.status || "abnormally"}`;
          ctx.log(`ℹ NOTE: fallback guard ${why}; proceeding without guard`);
        }
      }
      if (refusal) {
        ctx.log(`✖ ${refusal}`);
        try { session.dispose(); } catch {}
        throw new Error(refusal);
      }
    }
  } catch (err) {
    threw = true;
    errorMsg = err.message;
  }
  return { threw, errorMsg, logs, disposed, writtenModel: readFileSync(join(LD, `${name}.model`), "utf8").trim() };
}

// 1. Refusal case
const r1 = await testFallback({
  name: "rev-refusal",
  role: "reviewer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "deepseek/deepseek-flash",
});
if (!r1.threw) throw new Error("r1 did not throw");
if (!r1.disposed) throw new Error("r1 session not disposed");
if (r1.writtenModel !== "deepseek/deepseek-flash") throw new Error("r1 model not written");
if (!r1.logs.some(l => l.includes("ℹ runtime model fell back:"))) throw new Error("r1 missing fallback log");
if (!r1.logs.some(l => l.includes("✖ REFUSE:"))) throw new Error("r1 missing refusal log");

// 2. Cross-family allowed case
const r2 = await testFallback({
  name: "rev-proceed",
  role: "reviewer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "openai-codex/gpt-6-sol",
});
if (r2.threw) throw new Error("r2 threw: " + r2.errorMsg);
if (r2.disposed) throw new Error("r2 session disposed unexpectedly");
if (r2.writtenModel !== "openai-codex/gpt-6-sol") throw new Error("r2 model not written");

// 3. Implementer allowed case
const r3 = await testFallback({
  name: "impl-proceed",
  role: "implementer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "deepseek/deepseek-flash",
});
if (r3.threw) throw new Error("r3 threw: " + r3.errorMsg);

// 4. Missing guard binary (ENOENT): must NOT throw, must NOT dispose session, must log NOTE
const r4 = await testFallback({
  name: "rev-enoent",
  role: "reviewer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "deepseek/deepseek-flash",
  guardOverride: "/nonexistent/path/fleet-fallback-guard",
});
if (r4.threw) throw new Error("r4 (ENOENT) threw unexpectedly: " + r4.errorMsg);
if (r4.disposed) throw new Error("r4 (ENOENT) disposed session unexpectedly");
if (!r4.logs.some(l => l.includes("NOTE: fallback guard cannot execute (ENOENT)"))) throw new Error("r4 missing ENOENT note");

// 5. Non-executable guard binary (EACCES): must NOT throw, must NOT dispose session, must log NOTE
const noexecPath = join(TMP, "noexec-guard.sh");
writeFileSync(noexecPath, "#!/bin/sh\\necho hi");
chmodSync(noexecPath, 0o644);
const r5 = await testFallback({
  name: "rev-eacces",
  role: "reviewer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "deepseek/deepseek-flash",
  guardOverride: noexecPath,
});
if (r5.threw) throw new Error("r5 (EACCES) threw unexpectedly: " + r5.errorMsg);
if (r5.disposed) throw new Error("r5 (EACCES) disposed session unexpectedly");
if (!r5.logs.some(l => l.includes("NOTE: fallback guard cannot execute (EACCES)"))) throw new Error("r5 missing EACCES note");

// 6. Non-zero abnormal exit (127): must NOT throw, must NOT dispose session, must log NOTE
const exit127Path = join(TMP, "exit127-guard.sh");
writeFileSync(exit127Path, "#!/bin/sh\\nexit 127");
chmodSync(exit127Path, 0o755);
const r6 = await testFallback({
  name: "rev-127",
  role: "reviewer",
  implModel: "deepseek/deepseek-flash",
  requestedModel: "pi-claude-code-provider/sonnet",
  actualModel: "deepseek/deepseek-flash",
  guardOverride: exit127Path,
});
if (r6.threw) throw new Error("r6 (exit 127) threw unexpectedly: " + r6.errorMsg);
if (r6.disposed) throw new Error("r6 (exit 127) disposed session unexpectedly");
if (!r6.logs.some(l => l.includes("NOTE: fallback guard exited 127"))) throw new Error("r6 missing exit 127 note");

console.log("OK");
"""
        harness_path = Path(self.tmp_dir.name) / "host_test.mjs"
        harness_path.write_text(harness_js, encoding="utf-8")
        res = subprocess.run(
            ["node", str(harness_path), self.tmp_dir.name, str(self.guard_bin)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Host harness failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("OK", res.stdout)


if __name__ == "__main__":
    unittest.main()
