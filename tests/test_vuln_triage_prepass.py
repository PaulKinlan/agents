#!/usr/bin/env python3
"""Tests for vuln-triage pre-pass deterministic clustering (agents-ajt4).

Covers:
- agents-ajt4: cluster_deterministic handling of findings with non-numeric line numbers
  (specifically the '?' sentinel used by dependency findings).
- Prevents TypeError when sorting or comparing mixed numeric and non-numeric line numbers.
- Ensures unknown-location findings are NOT coerced to line 0 or merged into proximity clusters.
- Ensures deterministic cluster IDs across runs.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agents" / "vuln-triage" / "scripts"))

import triage  # noqa: E402


class TestVulnTriageClustering(unittest.TestCase):
    """agents-ajt4: test cluster_deterministic handling of numeric and non-numeric line numbers."""

    def test_reproduction_mixed_numeric_and_question_mark(self):
        """Coord reproduction: a file containing both a numeric line number and '?'
        must not raise TypeError: '<' not supported between instances of 'str' and 'int'.
        """
        findings = [
            {"path": "a.py", "line_number": 10, "rule_id": "r1"},
            {"path": "a.py", "line_number": "?", "rule_id": "dep1"},
        ]
        clusters = triage.cluster_deterministic(findings)
        self.assertEqual(len(clusters), 2)

        # C1 has the numeric finding at line 10
        self.assertEqual(clusters[0]["cluster_id"], "C1")
        self.assertEqual(clusters[0]["file"], "a.py")
        self.assertEqual(clusters[0]["count"], 1)
        self.assertEqual(clusters[0]["items"][0]["line_number"], 10)

        # C2 has the unknown-location finding '?'
        self.assertEqual(clusters[1]["cluster_id"], "C2")
        self.assertEqual(clusters[1]["file"], "a.py")
        self.assertEqual(clusters[1]["count"], 1)
        self.assertEqual(clusters[1]["items"][0]["line_number"], "?")

    def test_mixed_close_numeric_pair_and_question_mark(self):
        """A mixed list in the same file with a close numeric pair and an unknown location '?'.
        The close numeric pair (within 15 lines) MUST cluster together, while the '?' finding
        must NOT be merged into the numeric cluster.
        """
        findings = [
            {"path": "src/app.py", "line_number": 20, "rule_id": "sql-injection", "fingerprint": "fp1"},
            {"path": "src/app.py", "line_number": "?", "rule_id": "vulnerable-dep", "fingerprint": "fp2"},
            {"path": "src/app.py", "line_number": 24, "rule_id": "command-injection", "fingerprint": "fp3"},
        ]
        clusters = triage.cluster_deterministic(findings)

        # Must produce exactly 2 clusters: 1 for lines 20 & 24, and 1 for '?'
        self.assertEqual(len(clusters), 2)

        # Cluster 1: numeric close pair
        c_num = clusters[0]
        self.assertEqual(c_num["cluster_id"], "C1")
        self.assertEqual(c_num["file"], "src/app.py")
        self.assertEqual(c_num["count"], 2)
        lines = [item["line_number"] for item in c_num["items"]]
        self.assertEqual(lines, [20, 24])

        # Cluster 2: unknown location '?'
        c_unk = clusters[1]
        self.assertEqual(c_unk["cluster_id"], "C2")
        self.assertEqual(c_unk["file"], "src/app.py")
        self.assertEqual(c_unk["count"], 1)
        self.assertEqual(c_unk["items"][0]["rule_id"], "vulnerable-dep")
        self.assertEqual(c_unk["items"][0]["line_number"], "?")

    def test_question_mark_is_not_coerced_to_zero(self):
        """Findings with line_number '?' near line 0/small lines (1, 5) must NOT be coerced to 0,
        which would have erroneously clustered '?' with lines <= 15 (abs(line - 0) <= 15).
        """
        findings = [
            {"path": "main.py", "line_number": 1, "rule_id": "r1"},
            {"path": "main.py", "line_number": 5, "rule_id": "r2"},
            {"path": "main.py", "line_number": "?", "rule_id": "dep-cve"},
        ]
        clusters = triage.cluster_deterministic(findings)
        self.assertEqual(len(clusters), 2)

        # Lines 1 and 5 cluster together (count: 2)
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual([i["line_number"] for i in clusters[0]["items"]], [1, 5])

        # '?' is in its own cluster (count: 1)
        self.assertEqual(clusters[1]["count"], 1)
        self.assertEqual(clusters[1]["items"][0]["line_number"], "?")

    def test_single_question_mark_alone(self):
        """A finding with '?' alone in a file forms a single cluster."""
        findings = [{"path": "requirements.txt", "line_number": "?", "rule_id": "dep-vuln"}]
        clusters = triage.cluster_deterministic(findings)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["cluster_id"], "C1")
        self.assertEqual(clusters[0]["file"], "requirements.txt")
        self.assertEqual(clusters[0]["count"], 1)
        self.assertEqual(clusters[0]["items"][0]["rule_id"], "dep-vuln")
        self.assertEqual(clusters[0]["items"][0]["line_number"], "?")

    def test_many_question_mark_items(self):
        """Many '?' items in the same file each receive their own single-item cluster,
        consistently and deterministically ordered by rule_id and fingerprint.
        """
        findings = [
            {"path": "package.json", "line_number": "?", "rule_id": "cve-3", "fingerprint": "c"},
            {"path": "package.json", "line_number": "?", "rule_id": "cve-1", "fingerprint": "a"},
            {"path": "package.json", "line_number": "?", "rule_id": "cve-2", "fingerprint": "b"},
        ]
        clusters = triage.cluster_deterministic(findings)
        self.assertEqual(len(clusters), 3)

        self.assertEqual(clusters[0]["cluster_id"], "C1")
        self.assertEqual(clusters[0]["count"], 1)
        self.assertEqual(clusters[0]["items"][0]["rule_id"], "cve-1")

        self.assertEqual(clusters[1]["cluster_id"], "C2")
        self.assertEqual(clusters[1]["count"], 1)
        self.assertEqual(clusters[1]["items"][0]["rule_id"], "cve-2")

        self.assertEqual(clusters[2]["cluster_id"], "C3")
        self.assertEqual(clusters[2]["count"], 1)
        self.assertEqual(clusters[2]["items"][0]["rule_id"], "cve-3")

    def test_various_non_numeric_and_numeric_shapes(self):
        """Handles diverse line_number types (None, empty string, string digits, boolean, strings)."""
        findings = [
            {"path": "f.py", "line_number": None, "rule_id": "r-none"},
            {"path": "f.py", "line_number": "", "rule_id": "r-empty"},
            {"path": "f.py", "line_number": "²", "rule_id": "r-superscript"},
            {"path": "f.py", "line_number": False, "rule_id": "r-bool"},
            {"path": "f.py", "line_number": "N/A", "rule_id": "r-na"},
            {"path": "f.py", "line_number": "42", "rule_id": "r-digit-str"},
            {"path": "f.py", "line_number": 45, "rule_id": "r-int"},
        ]
        clusters = triage.cluster_deterministic(findings)

        # Lines '42' (parsed as 42) and 45 are within 15 lines: 1 numeric cluster of count 2
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual([i["rule_id"] for i in clusters[0]["items"]], ["r-digit-str", "r-int"])

        # The other 5 items are non-numeric: 5 separate single-item clusters
        non_num_clusters = clusters[1:]
        self.assertEqual(len(non_num_clusters), 5)
        for c in non_num_clusters:
            self.assertEqual(c["count"], 1)

    def test_determinism_across_input_order(self):
        """Input findings arriving in different orders must produce byte-identical cluster output."""
        list_a = [
            {"path": "b.py", "line_number": 100, "rule_id": "r1"},
            {"path": "a.py", "line_number": 10, "rule_id": "r2"},
            {"path": "a.py", "line_number": "?", "rule_id": "r3"},
            {"path": "b.py", "line_number": "?", "rule_id": "r4"},
            {"path": "a.py", "line_number": 15, "rule_id": "r5"},
        ]
        list_b = list(reversed(list_a))

        clusters_a = triage.cluster_deterministic(list_a)
        clusters_b = triage.cluster_deterministic(list_b)

        self.assertEqual(clusters_a, clusters_b)

    def test_end_to_end_script_execution(self):
        """triage.py runs end-to-end via CLI in an isolated sandbox, loading threat model and clusters."""
        import shutil

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            mock_root = tmp_path / "mock_root"
            mock_script = mock_root / "agents" / "vuln-triage" / "scripts" / "triage.py"
            mock_script.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "agents" / "vuln-triage" / "scripts" / "triage.py", mock_script)

            mock_findings = mock_root / "findings"
            mock_findings.mkdir(parents=True)
            (mock_findings / "target.json").write_text(json.dumps({
                "target": "target",
                "findings": {
                    "fp1": {"path": "a.py", "line_number": 10, "state": "new", "rule_id": "r1"},
                    "fp2": {"path": "a.py", "line_number": "?", "state": "new", "rule_id": "dep1"},
                    "fp3": {"path": "a.py", "line_number": 12, "state": "new", "rule_id": "r2"},
                }
            }), encoding="utf-8")

            target_dir = tmp_path / "target"
            target_dir.mkdir(parents=True)
            (target_dir / "THREAT_MODEL.md").write_text("# Target Threat Model\nExternal untrusted inputs.\n")

            out_file = tmp_path / "clusters.json"

            res = subprocess.run([
                sys.executable,
                str(mock_script),
                "--target", str(target_dir),
                "--output", str(out_file),
            ], capture_output=True, text=True, check=True)

            self.assertIn("3 findings grouped into 2 deterministic clusters", res.stdout)
            payload = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_active_findings"], 3)
            self.assertEqual(payload["cluster_count"], 2)
            self.assertEqual(len(payload["clusters"]), 2)


if __name__ == "__main__":
    unittest.main()
