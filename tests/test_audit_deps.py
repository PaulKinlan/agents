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
        self.assertEqual(divergence[0]["severity"], "low")
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


if __name__ == "__main__":
    unittest.main()
