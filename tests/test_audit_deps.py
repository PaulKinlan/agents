#!/usr/bin/env python3
"""Tests for audit_deps.py lockfile vs shipped artifact version divergence (agents-gtq)."""

import importlib.machinery
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = ROOT / "agents" / "deps-supply-chain" / "scripts" / "audit_deps.py"

loader = importlib.machinery.SourceFileLoader("audit_deps", str(SCANNER_PATH))
spec = importlib.util.spec_from_loader("audit_deps", loader)
audit_deps = importlib.util.module_from_spec(spec)
loader.exec_module(audit_deps)


class TestStdoutChannelDropsTheMatch(unittest.TestCase):
    """agents-qslz: the station's stdout goes through lib/redaction.stdout_safe_report.

    Driven through the real CLI with no --output, because the defect was a raw `print(output_json)`
    in exactly that branch, and a unit test of stdout_safe_report cannot see which branch ran.
    """

    def test_stdout_has_no_candidate_id_and_no_match_text(self):
        """Load-bearing: change the else branch back to `print(output_json)` and this fails with
        `AssertionError: 'candidate_id' unexpectedly found in ...` - the confirmation oracle
        reached the station's stdout (the snippet assert fails next).

        The fixture is requirements.txt plus a divergent shipped wheel, so the npm path is never
        entered and no external tool runs. The --output branch is NOT redacted on purpose - it is
        the raw local record - so the fixture is read from stdout only.
        """
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "requirements.txt").write_text("requests==2.25.1\n", encoding="utf-8")
            dist = repo / "dist"
            dist.mkdir()
            whl = dist / "sample-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(whl, "w") as z:
                z.writestr("sample-1.0.0.dist-info/METADATA", """Metadata-Version: 2.1
Name: sample
Version: 1.0.0
Requires-Dist: requests == 2.28.0
""")
            result = subprocess.run(
                [sys.executable, str(SCANNER_PATH), "--target", str(repo)],
                capture_output=True, text=True, timeout=120, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        artefact = json.loads(result.stdout)
        matched = [c for c in artefact["candidates"]
                   if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertTrue(matched, artefact["candidates"])
        for candidate in matched:
            # The allowlist drops the match and its derived digest OUTRIGHT - the keys are
            # absent, not masked in place (agents-h0mb).
            self.assertNotIn("candidate_id", candidate,
                             "the confirmation oracle reached the station's stdout")
            self.assertNotIn("snippet", candidate)
            # The channel must stay usable: the location still ships.
            self.assertTrue(candidate["path"].endswith("sample-1.0.0-py3-none-any.whl"),
                            candidate["path"])
        self.assertIn("stdout redacts matched values", result.stderr)


class TestLockfileShippedArtifactDivergence(unittest.TestCase):
    """Test detection of divergence between lockfiles and shipped artifacts (agents-gtq)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_lockfile_shipped_version_divergence_dist_package_json(self):
        """[agents-gtq] dist/package.json declaring a different version than lockfile surfaces divergence."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "sample-app",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "sample-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"lodash": "^4.17.21"}},
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "sample-app-dist",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.15"}
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 1)
        cand = divergence[0]
        self.assertEqual(cand["type"], "coverage-gap")
        self.assertEqual(cand["severity"], "medium")
        self.assertEqual(cand["package"], "lodash")
        self.assertIn("4.17.15 vs 4.17.21", cand["title"])
        self.assertEqual(cand["path"], "dist/package.json")
        self.assertIn("dist/package.json", manifests)

    def test_lockfile_shipped_version_matching_dist_package_json(self):
        """[agents-gtq] When shipped artifact version matches the lockfile, no divergence is emitted."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "sample-app",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "sample-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"lodash": "^4.17.21"}},
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "sample-app-dist",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.21"}
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 0)
        self.assertIn("dist/package.json", manifests)

    def test_lockfile_shipped_version_divergence_bundle_header(self):
        """[agents-gtq] Bundled JS banner with divergent version is detected."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "bundled-app",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "bundled-app",
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "bundle.js").write_text("""/*! lodash v4.17.11 (Custom Build) | MIT */
(function() { console.log('bundled lodash'); })();
""", encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 1)
        self.assertEqual(divergence[0]["package"], "lodash")
        self.assertIn("4.17.11 vs 4.17.21", divergence[0]["title"])
        self.assertEqual(divergence[0]["path"], "dist/bundle.js")

    def test_lockfile_shipped_version_divergence_chrome_manifest(self):
        """[agents-gtq] Chrome extension manifest declaring divergent dependencies surfaces divergence."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "ext",
            "dependencies": {"dompurify": "^2.4.0"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "ext",
            "packages": {
                "node_modules/dompurify": {"version": "2.4.0"}
            }
        }), encoding="utf-8")
        (self.repo / "manifest.json").write_text(json.dumps({
            "manifest_version": 3,
            "name": "My Extension",
            "version": "1.0.0",
            "dependencies": {"dompurify": "2.0.0"}
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 1)
        self.assertEqual(divergence[0]["package"], "dompurify")
        self.assertIn("2.0.0 vs 2.4.0", divergence[0]["title"])
        self.assertEqual(divergence[0]["path"], "manifest.json")
        self.assertIn("manifest.json", manifests)

    def test_shipped_artifacts_unverified_coverage_gap(self):
        """[agents-gtq] Shipped dist/ artifacts without extractable version metadata surface an unverified coverage gap."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "opaque-bundle-app",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "opaque-bundle-app",
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "main.js").write_text("console.log('minified bundle with no headers');", encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 1)
        self.assertEqual(divergence[0]["type"], "coverage-gap")
        self.assertEqual(divergence[0]["severity"], "info")
        self.assertIn("unverified", divergence[0]["title"])
        self.assertEqual(divergence[0]["path"], "dist")

    def test_python_requirements_vs_wheel_divergence(self):
        """[agents-gtq] Python requirements.txt vs wheel Requires-Dist divergence is detected."""
        (self.repo / "requirements.txt").write_text("requests==2.25.1\nurllib3==1.26.5\n", encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        whl = dist / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as z:
            z.writestr("sample-1.0.0.dist-info/METADATA", """Metadata-Version: 2.1
Name: sample
Version: 1.0.0
Requires-Dist: requests == 2.28.0
Requires-Dist: urllib3 == 1.26.5
""")

        candidates, manifests = audit_deps.audit_python(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]

        self.assertEqual(len(divergence), 1)
        self.assertEqual(divergence[0]["package"], "requests")
        self.assertIn("2.28.0 vs 2.25.1", divergence[0]["title"])
        self.assertIn("sample-1.0.0-py3-none-any.whl", divergence[0]["path"])

    def test_python_prefix_specifier_does_not_emit_divergence(self):
        """[agents-nna] A requirements prefix-match ('foo == 1.*') must not become an empty baseline.

        Mirrors the npm null-version test: an empty cleaned semver must be dropped, not stored
        as '' and then compared against a real shipped version (false medium divergence).
        """
        (self.repo / "requirements.txt").write_text("foo == 1.*\n", encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        whl = dist / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as z:
            z.writestr("sample-1.0.0.dist-info/METADATA", """Metadata-Version: 2.1
Name: sample
Version: 1.0.0
Requires-Dist: foo == 1.0.0
""")

        candidates, _ = audit_deps.audit_python(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(divergence, [])

    def test_python_wheel_non_concrete_version_does_not_emit_medium_divergence(self):
        """[agents-nna] A wheel Requires-Dist that is not a concrete version must not be stored.

        Without the guard, shipped_versions[pkg] = ('', rel) compares '' against the real
        requirements version and emits a false medium divergence; with it, only the info
        coverage-gap (version unverified) remains.
        """
        (self.repo / "requirements.txt").write_text("foo==1.0.0\n", encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        whl = dist / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as z:
            z.writestr("sample-1.0.0.dist-info/METADATA", """Metadata-Version: 2.1
Name: sample
Version: 1.0.0
Requires-Dist: foo == 1.*
""")

        candidates, _ = audit_deps.audit_python(self.repo)
        medium = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"
                  and c.get("severity") == "medium"]
        self.assertEqual(medium, [])

    def test_peer_dependency_range_not_treated_as_shipped_version(self):
        """[agents-gtq review P2] A peerDependencies RANGE is not the shipped version.

        Regression: peers were merged over dependencies, so dist peer ">=16" was compared as
        version "16" against lockfile 18.2.0 and emitted a false medium divergence.
        """
        (self.repo / "package.json").write_text(json.dumps({
            "name": "peer-app",
            "dependencies": {"react": "^18.0.0"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "peer-app",
            "packages": {
                "": {"dependencies": {"react": "^18.0.0"}},
                "node_modules/react": {"version": "18.2.0"}
            }
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "peer-app-dist",
            "dependencies": {"react": "18.2.0"},
            "peerDependencies": {"react": ">=16"}
        }), encoding="utf-8")

        candidates, _ = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(divergence, [])

    def test_peer_dependency_range_only_does_not_emit_medium_divergence(self):
        """[agents-gtq review P2] A peer-only dist manifest never emits a medium divergence."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "peer-only-app",
            "dependencies": {"react": "^18.0.0"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "peer-only-app",
            "packages": {"node_modules/react": {"version": "18.2.0"}}
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "peer-only-app-dist",
            "peerDependencies": {"react": ">=16"}
        }), encoding="utf-8")

        candidates, _ = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual([c for c in divergence if c.get("severity") == "medium"], [])

    def test_null_lockfile_version_does_not_emit_divergence(self):
        """[agents-gtq review P2] A null lockfile version must not become an empty baseline.

        Regression: an empty baseline poisoned the comparison and flagged a real shipped
        version as divergent against "".
        """
        (self.repo / "package.json").write_text(json.dumps({
            "name": "null-version-app",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "null-version-app",
            "packages": {"node_modules/lodash": {"version": None}}
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "null-version-app-dist",
            "dependencies": {"lodash": "4.17.21"}
        }), encoding="utf-8")

        candidates, _ = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(divergence, [])

    def test_version_range_specifiers_rejected_by_clean_semver(self):
        """[agents-gtq review P2] Ranges, specifiers and non-strings are not versions."""
        for raw in [">=16", "^17 || ^18", "~1.2.3", "latest", "workspace:*", "", "   "]:
            self.assertEqual(audit_deps.clean_semver(raw), "", raw)
        for raw in [None, ["4.0.0"], 4.17, {"v": "1.0.0"}, True]:
            self.assertEqual(audit_deps.clean_semver(raw), "", repr(raw))
        self.assertEqual(audit_deps.clean_semver("1.2.3"), "1.2.3")
        self.assertEqual(audit_deps.clean_semver(" v18.2.0 "), "18.2.0")
        self.assertEqual(audit_deps.clean_semver("18.2.0-beta.1"), "18.2.0-beta.1")
        self.assertEqual(audit_deps.clean_semver("1.2"), "1.2")

    def test_shipped_range_does_not_emit_false_divergence(self):
        """[agents-gtq review P2] A shipped dependency RANGE is not a shipped version."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "range-app",
            "dependencies": {"react": "^18.0.0"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "range-app",
            "packages": {"node_modules/react": {"version": "18.2.0"}}
        }), encoding="utf-8")

        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "package.json").write_text(json.dumps({
            "name": "range-app-dist",
            "dependencies": {"react": "^18.0.0"}
        }), encoding="utf-8")

        candidates, _ = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual([c for c in divergence if c.get("severity") == "medium"], [])

    def test_generic_manifest_without_manifest_version_not_a_shipped_artifact(self):
        """[agents-gtq review P2] A generic manifest.json (no manifest_version) is not an artifact."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "pwa-app",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "pwa-app",
            "packages": {"node_modules/lodash": {"version": "4.17.21"}}
        }), encoding="utf-8")
        (self.repo / "manifest.json").write_text(json.dumps({
            "name": "My PWA",
            "start_url": "/",
            "icons": []
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(divergence, [])
        self.assertNotIn("manifest.json", manifests)

    def test_no_shipped_artifacts_no_spurious_candidates(self):
        """[agents-gtq] Clean package without shipped artifacts does not emit spurious divergence candidates."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "library",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        (self.repo / "package-lock.json").write_text(json.dumps({
            "name": "library",
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(len(divergence), 0)

    def test_no_artifact_no_gap(self):
        """[agents-gtq] Negative test: target without any dist/ or manifest.json emits 0 divergence candidates."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "plain-node-app",
            "dependencies": {"express": "^4.18.2"}
        }), encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(len(divergence), 0)

    def test_empty_or_assets_only_dist_no_gap(self):
        """[agents-gtq] dist/ directory with no bundle files or package.json does not emit spurious candidates."""
        (self.repo / "package.json").write_text(json.dumps({
            "name": "static-site",
            "dependencies": {"lodash": "^4.17.21"}
        }), encoding="utf-8")
        dist = self.repo / "dist"
        dist.mkdir()
        (dist / "style.css").write_text("body { color: red; }", encoding="utf-8")

        candidates, manifests = audit_deps.audit_npm(self.repo)
        divergence = [c for c in candidates if c.get("rule_id") == "lockfile-shipped-version-divergence"]
        self.assertEqual(len(divergence), 0)


if __name__ == "__main__":
    unittest.main()
