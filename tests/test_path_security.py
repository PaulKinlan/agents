#!/usr/bin/env python3
"""Path confinement for finding-supplied file locations (agents-075, agents-t9w).

``lib.path_security.resolve_within_target`` is the single shared guard used by every pre-pass
that joins a target directory with a model/finding-supplied path. These tests pin that helper's
semantics directly and drive pr-fixer's collect_failures.py (agents-t9w) end-to-end, asserting
that a ``../`` traversal or an absolute path never leaks outside file content into the pre-pass
output. vuln-verify's consumer is covered by ``TestPathConfinement`` in
``tests/test_vuln_verify_prepass.py`` (agents-075).
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.path_security import resolve_within_target  # noqa: E402

PATH_SECURITY = ROOT / "lib" / "path_security.py"
COLLECT_SCRIPT = ROOT / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"


def _copy_script_and_helper(sandbox: Path, script_src: Path, script_rel: str) -> Path:
    """Copy a pre-pass script and the shared helper into a disposable sandbox so the
    script's FACTORY_ROOT (derived from __file__) resolves to the sandbox tree."""
    script = sandbox / script_rel
    script.parent.mkdir(parents=True)
    shutil.copyfile(script_src, script)
    helper = sandbox / "lib" / "path_security.py"
    helper.parent.mkdir(parents=True)
    shutil.copyfile(PATH_SECURITY, helper)
    return script


class TestResolveWithinTarget(unittest.TestCase):
    """Direct semantics of the shared confinement helper."""

    def _target(self, tmp: Path) -> Path:
        target = tmp / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "app.js").write_text("el.innerHTML = user;\n", encoding="utf-8")
        return target

    def test_normal_in_target_path_resolves(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            resolved = resolve_within_target(target, "src/app.js")
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved, (target / "src" / "app.js").resolve())

    def test_traversal_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            self.assertIsNone(resolve_within_target(target, "../canary.txt"))
            self.assertIsNone(resolve_within_target(target, "../../../../etc/passwd"))

    def test_indirect_traversal_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            self.assertIsNone(resolve_within_target(target, "a/../../b"))
            self.assertIsNone(resolve_within_target(target, "src/../../b"))

    def test_absolute_path_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target = self._target(tmp)
            secret = tmp / "secret.txt"
            secret.write_text("SECRET\n", encoding="utf-8")
            self.assertIsNone(resolve_within_target(target, str(secret)))
            self.assertIsNone(resolve_within_target(target, "/etc/passwd"))

    def test_symlink_chain_outside_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target = self._target(tmp)
            outside = tmp / "linked.txt"
            outside.write_text("LINKED\n", encoding="utf-8")
            hop = target / "src" / "hop"
            hop.symlink_to(outside)
            link = target / "src" / "evil"
            link.symlink_to(hop)
            self.assertIsNone(resolve_within_target(target, "src/evil"))
            self.assertIsNone(resolve_within_target(target, "src/evil/../app.js"))

    def test_symlink_to_dir_outside_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target = self._target(tmp)
            outside_dir = tmp / "outside"
            outside_dir.mkdir()
            (outside_dir / "secret.txt").write_text("DIR-SECRET\n", encoding="utf-8")
            link = target / "src" / "evil-dir"
            link.symlink_to(outside_dir, target_is_directory=True)
            self.assertIsNone(resolve_within_target(target, "src/evil-dir/secret.txt"))

    def test_trailing_slash_on_outside_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target = self._target(tmp)
            outside = tmp / "linked.txt"
            outside.write_text("LINKED\n", encoding="utf-8")
            link = target / "src" / "evil"
            link.symlink_to(outside)
            self.assertIsNone(resolve_within_target(target, "src/evil/"))

    def test_resolve_to_target_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            self.assertIsNone(resolve_within_target(target, "."))
            self.assertIsNone(resolve_within_target(target, "src/.."))
            self.assertIsNone(resolve_within_target(target, ""))

    def test_embedded_nul_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            self.assertIsNone(resolve_within_target(target, "src/\x00app.js"))

    def test_encoded_traversal_is_not_decoded(self):
        # %2e%2e and unicode look-alike dots are literal path components, not traversal, so
        # they stay inside the target (or resolve to a nonexistent in-target file).
        with tempfile.TemporaryDirectory() as tmpdir:
            target = self._target(Path(tmpdir))
            root = target.resolve()
            for path in ("%2e%2e/canary.txt", "．．/canary.txt", "src/%2e%2e/app.js"):
                resolved = resolve_within_target(target, path)
                self.assertIsNotNone(resolved, path)
                self.assertTrue(resolved.is_relative_to(root), path)
                self.assertNotEqual(resolved, root, path)


class TestCollectFailuresPathConfinement(unittest.TestCase):
    """agents-t9w: a findings-supplied path must never read outside the target.

    This is the exact bug fixed here: collect_failures.py joined the finding's path onto
    target_dir without confinement, so a `../` or absolute path read arbitrary files on the
    unsandboxed path.
    """

    def _sandbox(self, tmp: Path):
        sandbox = tmp / "sandbox"
        script = _copy_script_and_helper(sandbox, COLLECT_SCRIPT, "agents/pr-fixer/scripts/collect_failures.py")
        target = sandbox / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "app.js").write_text(
            "const el = document.body;\nel.innerHTML = user;\n", encoding="utf-8")
        return sandbox, target, script

    def _finding(self, path, line_number=1):
        return {
            "fingerprint": "a" * 64,
            "agent": "vuln-discovery",
            "rule_id": "dom-injection-sink",
            "path": path,
            "line_number": line_number,
            "snippet": "x",
            "severity": "high",
            "state": "new",
        }

    def _run(self, sandbox: Path, target: Path, findings) -> dict:
        out = sandbox / "out.json"
        findings_dir = sandbox / "findings"
        findings_dir.mkdir()
        store = findings_dir / f"{target.name}-findings.json"
        store.write_text(json.dumps({f["fingerprint"]: f for f in findings}), encoding="utf-8")
        cmd = [sys.executable,
               str(sandbox / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"),
               "--target", str(target), "--output", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_traversal_path_does_not_leak_outside_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target, _ = self._sandbox(Path(tmpdir))
            outside = sandbox / "canary.txt"
            outside.write_text("CANARY-SECRET-DO-NOT-READ\n", encoding="utf-8")

            bundle = self._run(sandbox, target, [self._finding("../canary.txt")])

            self.assertEqual(bundle["fixable_candidates_count"], 0)
            self.assertNotIn("CANARY-SECRET-DO-NOT-READ", json.dumps(bundle))

    def test_absolute_path_does_not_leak_outside_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target, _ = self._sandbox(Path(tmpdir))
            secret = sandbox / "secret.txt"
            secret.write_text("ABSOLUTE-SECRET\n", encoding="utf-8")

            bundle = self._run(sandbox, target, [self._finding(str(secret))])

            self.assertEqual(bundle["fixable_candidates_count"], 0)
            self.assertNotIn("ABSOLUTE-SECRET", json.dumps(bundle))

    def test_normal_in_target_path_still_reads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target, _ = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [self._finding("src/app.js", line_number=2)])

            self.assertEqual(bundle["fixable_candidates_count"], 1)
            self.assertIn("el.innerHTML = user;", bundle["candidates"][0]["source_context"])


if __name__ == "__main__":
    unittest.main()
