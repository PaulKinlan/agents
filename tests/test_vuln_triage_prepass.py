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
from tests.sandbox_fixtures import copy_station_script  # noqa: E402


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

    def test_zero_line_is_unknown_not_line_zero(self):
        """agents-ghtz: consolidating onto lib.line_numbers made 0/"0" UNKNOWN, not line 0.

        The old private copy accepted 0 as a line, which is the coercion agents-ajt4 existed to
        remove: line 0 is within 15 of the real findings at lines 1-5, so it must not merge with
        them. Unknown stays unknown and gets its own cluster.
        """
        findings = [
            {"path": "z.py", "line_number": 1, "rule_id": "r1"},
            {"path": "z.py", "line_number": 5, "rule_id": "r2"},
            {"path": "z.py", "line_number": 0, "rule_id": "r-zero"},
            {"path": "z.py", "line_number": "0", "rule_id": "r-zero-str"},
        ]
        clusters = triage.cluster_deterministic(findings)

        self.assertEqual([i["rule_id"] for i in clusters[0]["items"]], ["r1", "r2"])
        self.assertEqual([i["line_number"] for i in clusters[0]["items"]], [1, 5])
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual(len(clusters), 3)
        self.assertEqual([c["items"][0]["rule_id"] for c in clusters[1:]],
                         ["r-zero", "r-zero-str"])
        self.assertTrue(all(c["count"] == 1 for c in clusters[1:]))

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
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            mock_root = tmp_path / "mock_root"
            # The sandbox mirrors the repo layout so the script's FACTORY_ROOT (derived from
            # __file__) resolves to this tree; the shared builder (agents-8ztd, census in
            # agents-r2ne) copies triage.py's lib import closure rather than a hand-maintained
            # list, so a new shared import reaches this sandbox without a fixture edit.
            mock_script = copy_station_script(
                mock_root,
                ROOT / "agents" / "vuln-triage" / "scripts" / "triage.py",
                "agents/vuln-triage/scripts/triage.py",
            )

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
            self.assertEqual(payload["candidate_id_scheme"], 1)
            self.assertEqual(len(payload["candidates"]), 2)
            self.assertEqual(payload["context"]["cluster_count"], 2)
            self.assertEqual(payload["context"]["total_active_findings"], 3)
            self.assertEqual(len(payload["context"]["clusters"]), 2)
            self.assertIn("Target Threat Model", payload["context"]["threat_model_summary"])
            self.assertEqual(payload["context"]["threat_model_file"],
                             str((target_dir / "THREAT_MODEL.md").resolve()))
            self.assertEqual([set(c) for c in payload["candidates"]],
                             [{"candidate_id", "rule_id", "path", "line_number"}] * 2)
            self.assertEqual(len(payload["candidates"][0]["candidate_id"]), 16)

    def test_end_to_end_does_not_reingest_its_own_findings(self):
        """agents-3o86: triage's stored output cannot feed its next pre-pass."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            mock_root = tmp_path / "mock_root"
            mock_script = copy_station_script(
                mock_root,
                ROOT / "agents" / "vuln-triage" / "scripts" / "triage.py",
                "agents/vuln-triage/scripts/triage.py",
            )
            store = mock_root / "findings"
            store.mkdir(parents=True)
            (store / "target.json").write_text(json.dumps({"findings": {
                "self-new": {"agent": "vuln-triage", "state": "new", "path": "self.py",
                             "line_number": "?", "rule_id": "unclassified"},
                "self-regressed": {"agent": "vuln-triage", "state": "regressed", "path": "self.py",
                                   "line_number": 10, "rule_id": "vuln-triage/prior"},
                "self-accepted": {"agent": "vuln-triage", "state": "accepted", "path": "self.py",
                                  "line_number": 20, "rule_id": "vuln-triage/accepted"},
                "discovery": {"agent": "vuln-discovery", "state": "new", "path": "a.py",
                              "line_number": 10, "rule_id": "discovery"},
                "verified": {"agent": "vuln-verify", "state": "accepted", "path": "b.py",
                             "line_number": 20, "rule_id": "verified"},
                "legacy-null": {"agent": None, "state": "regressed", "path": "c.py",
                                "line_number": "?", "rule_id": "legacy-null"},
                "legacy-absent": {"state": "new", "path": "d.py",
                                  "line_number": 30, "rule_id": "legacy-absent"},
                "inactive": {"agent": "secret-scan", "state": "fixed", "path": "e.py",
                             "line_number": 40, "rule_id": "inactive"},
            }}), encoding="utf-8")
            target = tmp_path / "target"
            target.mkdir()
            output = tmp_path / "result.json"
            result = subprocess.run([sys.executable, str(mock_script), "--target", str(target),
                                     "--output", str(output)], capture_output=True, text=True, check=True,
                                    timeout=15)
            payload = json.loads(output.read_text(encoding="utf-8"))
            items = [item for cluster in payload["context"]["clusters"] for item in cluster["items"]]
            self.assertFalse(any(item.get("agent") == "vuln-triage" for item in items),
                             "self-origin vuln-triage records re-entered the candidate pre-pass")
            self.assertEqual({item["rule_id"] for item in items},
                             {"discovery", "verified", "legacy-null", "legacy-absent"})
            self.assertEqual(payload["total_active_findings"], 4)
            self.assertEqual(payload["context"]["total_active_findings"], 4)
            self.assertEqual(payload["context"]["clusters"], payload["clusters"])
            self.assertNotIn("prior_verifications", payload["context"],
                             "legacy stores have no verification ledger")
            self.assertIn("4 findings grouped into", result.stdout)

    def test_prior_verdicts_reach_context_without_changing_candidate_identities(self):
        """agents-b5ec7: downstream triage can weigh a disproved verdict after run-dir pruning."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            root = base / "mock_root"
            script = copy_station_script(root, ROOT / "agents/vuln-triage/scripts/triage.py",
                                         "agents/vuln-triage/scripts/triage.py")
            (root / "findings").mkdir(parents=True)
            (root / "findings/target.json").write_text(json.dumps({
                "findings": {"discovery": {"agent": "vuln-discovery", "state": "new",
                                           "candidate_id": "c0", "rule_id": "r1", "path": "a.py",
                                           "line_number": 7}},
                "verifications": {"v0": {"agent": "vuln-verify", "candidate_id": "c0",
                                          "verdict": "disproved", "confidence": "high",
                                          "disproving_factors": ["auth_gate"],
                                          "reasoning": "do not inject legacy raw prose",
                                          "last_seen": "2026-10-17T05:00:00+00:00"}},
            }), encoding="utf-8")
            target = base / "target"
            target.mkdir()
            output = base / "result.json"
            subprocess.run([sys.executable, str(script), "--target", str(target),
                            "--output", str(output)], capture_output=True, text=True, check=True,
                           timeout=15)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["candidates"], [
                {"candidate_id": "c0", "rule_id": "r1", "path": "a.py", "line_number": 7}])
            self.assertEqual(payload["context"]["prior_verifications"][0]["verdict"], "disproved")
            self.assertEqual(payload["context"]["prior_verifications"][0]["disproving_factors"],
                             ["auth_gate"])
            self.assertNotIn("reasoning", payload["context"]["prior_verifications"][0])
            self.assertEqual(payload["cluster_count"], 1,
                             "verdict evidence is not a synthetic finding/cluster")


class TestAnchoredClusterCandidates(unittest.TestCase):
    """agents-69k9: clusters get a persisted, monotone primary identity."""

    def finding(self, line, when, fingerprint, **extra):
        return {"path": "lib/sandbox.py", "line_number": line,
                "rule_id": "same-rule", "fingerprint": fingerprint,
                "first_seen": when, "title": fingerprint, "snippet": "[withheld]",
                "severity": "medium", **extra}

    def test_oldest_active_member_wins_even_if_a_new_member_sorts_first(self):
        older = self.finding(72, "2026-10-01T10:00:00+00:00", "old", candidate_id="upstream-old")
        new = self.finding(60, "2026-10-14T10:00:00+00:00", "new", candidate_id="upstream-new")
        clusters = triage.cluster_deterministic([new, older])
        self.assertEqual(len(clusters), 1)
        self.assertEqual(triage.cluster_candidates(clusters), [
            {"candidate_id": "upstream-old", "rule_id": "same-rule",
             "path": "lib/sandbox.py", "line_number": 72}])

    def test_joining_does_not_rekey_an_anchor_but_removing_it_does(self):
        anchor = self.finding(72, "2026-09-01T00:00:00Z", "stable")
        joining = self.finding(60, "2026-10-01T00:00:00Z", "later")
        before = triage.cluster_candidates(triage.cluster_deterministic([anchor]))[0]
        together = triage.cluster_candidates(triage.cluster_deterministic([anchor, joining]))[0]
        after = triage.cluster_candidates(triage.cluster_deterministic([joining]))[0]
        self.assertEqual(before, together)
        self.assertEqual(len(before["candidate_id"]), 16)
        self.assertNotEqual(after["candidate_id"], before["candidate_id"])

    def test_undated_members_sort_after_dated_and_ties_are_deterministic(self):
        dated = self.finding(72, "2026-10-01", "dated")
        undated = self.finding(60, None, "undated", candidate_id="not-anchor")
        same_date = self.finding(70, "2026-10-01T00:00:00Z", "tie", candidate_id="upstream-tie")
        # A tie in first_seen chooses the lower line, then rule_id/fingerprint/title.
        original = triage.cluster_candidates(triage.cluster_deterministic([undated, dated, same_date]))
        shuffled = triage.cluster_candidates(triage.cluster_deterministic([same_date, dated, undated]))
        self.assertEqual(original, shuffled)
        self.assertEqual(original[0]["line_number"], 70)
        self.assertEqual(original[0]["candidate_id"], "upstream-tie")

    def test_anchor_line_is_normalized_to_report_schema_location(self):
        numeric = self.finding("42", "2026-10-01", "number")
        unknown = {**self.finding("?", "2026-10-02", "unknown"), "path": "THREAT_MODEL.md"}
        emitted = triage.cluster_candidates(triage.cluster_deterministic([numeric, unknown]))
        self.assertEqual({candidate["path"]: candidate["line_number"] for candidate in emitted},
                         {"lib/sandbox.py": 42, "THREAT_MODEL.md": None})
        for candidate in emitted:
            self.assertNotIn("snippet", candidate)
            self.assertNotIn("severity", candidate)

    def test_two_stations_rows_of_one_candidate_are_one_cluster(self):
        """[agents-np8dl] A candidate_id names a CANDIDATE, so two agents' rows of it are one cluster.

        MEASURED in the factory's own store: in findings/agents-factory-factory.json the ids
        50a8a7c8990e463f and effe7026c6ffc948 each carry a vuln-discovery row and a vuln-verify row.
        Proximity clustering is line-based, so a stale or unknown line put such a pair in two clusters,
        both anchors presented the same id, and the duplicate guard killed the whole pre-pass. This
        replaces the earlier contract (that shape raised), because the raise was the crash: one
        candidate has to be claimed once (the station declares candidate_accounting: aggregate-claimed).
        """
        a = self.finding(20, "2026-10-01", "discovery", candidate_id="shared", agent="vuln-discovery")
        b = self.finding(80, "2026-10-02", "verify", candidate_id="shared", agent="vuln-verify")
        clusters = triage.cluster_deterministic([a, b])
        self.assertEqual(len(clusters), 1, "two rows of one candidate must not be presented twice")
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual(clusters[0]["cluster_id"], "C1")
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual([c["candidate_id"] for c in emitted], ["shared"])
        # The anchor is still the deterministic one: the OLDER row (line 20) wins over line order.
        self.assertEqual(emitted[0]["line_number"], 20)

    def test_an_unknown_line_row_folds_into_its_candidate_cluster(self):
        """[agents-np8dl] The '?' shape of the same collision: unknown-line rows are their own cluster."""
        numeric = self.finding(10, "2026-10-01", "discovery", candidate_id="shared")
        unknown = {**self.finding("?", "2026-10-02", "verify", candidate_id="shared"),
                   "path": "lib/sandbox.py"}
        clusters = triage.cluster_deterministic([numeric, unknown])
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["candidate_id"], "shared")
        self.assertEqual(emitted[0]["line_number"], 10, "the known line is the anchor's, not None")

    def test_legacy_rows_of_one_rule_get_distinct_occurrence_ids(self):
        """[agents-np8dl] Two legacy rows (no stored id) must not compute the same identity.

        candidate_identity's ordinal exists for exactly this, but the pre-pass passed the default 1, so
        two rows of one rule+path+fingerprint collided with each other and killed the run. The store
        carries 7/19/53 such rows across three targets, so this is ordinary data.
        """
        first = self.finding(10, "2026-10-01", "same-fingerprint")
        second = self.finding(100, "2026-10-02", "same-fingerprint")
        clusters = triage.cluster_deterministic([first, second])
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual(len(clusters), 2, "legacy rows keep their proximity clusters")
        ids = [c["candidate_id"] for c in emitted]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2, f"two occurrences must not share one id: {ids}")

    def test_a_stored_id_and_a_legacy_row_that_share_an_ordinal_are_one_candidate(self):
        """[agents-yn00b, found by rev-np8dl] A stored id and a derived one can name the same ordinal.

        A station that writes candidate_identity(..., ordinal=1) is indistinguishable from a legacy row
        that happens to be occurrence 1 of the same rule+path+fingerprint, so counting occurrences over
        LEGACY ROWS ONLY (the first version of the agents-np8dl fix) left this mixed-version case
        colliding and the pre-pass still crashing. Stored rows therefore occupy their ordinal, and one
        resolution of identity feeds both the fold and the projector.
        """
        from lib.candidate_identity import candidate_identity
        stored = candidate_identity("same-rule", "lib/sandbox.py", "same-fingerprint", 1)
        with_id = self.finding(100, "2026-10-01", "same-fingerprint", candidate_id=stored)
        legacy = self.finding(10, "2026-10-02", "same-fingerprint")
        clusters = triage.cluster_deterministic([with_id, legacy])
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual(len(clusters), 1, "one candidate by the scheme's own identity, so one cluster")
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual([c["candidate_id"] for c in emitted], [stored])

    def test_occurrences_are_counted_over_stored_rows_too(self):
        """A stored row OCCUPIES its ordinal, so a legacy row after it is a different occurrence.

        The mirror of the test above, and the one that pins the counting rule itself: with a stored id at
        line 10 (the station's occurrence 1) and a legacy row at line 100, the legacy row is occurrence 2
        and must keep its own identity. Counting only legacy rows would derive occurrence 1 for it, equal
        the stored id, and collapse two real occurrences into one candidate.
        """
        from lib.candidate_identity import candidate_identity
        stored = candidate_identity("same-rule", "lib/sandbox.py", "same-fingerprint", 1)
        with_id = self.finding(10, "2026-10-01", "same-fingerprint", candidate_id=stored)
        legacy = self.finding(100, "2026-10-02", "same-fingerprint")
        clusters = triage.cluster_deterministic([with_id, legacy])
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual(len(clusters), 2, "two occurrences in file order are two candidates")
        ids = [c["candidate_id"] for c in emitted]
        self.assertEqual(len(set(ids)), 2, f"occurrences must not collapse onto one id: {ids}")
        self.assertIn(stored, ids)

    def test_the_guard_still_refuses_duplicate_and_malformed_ids(self):
        """The line judge's invariant still has teeth: the guard fires on input that really is bad."""
        row = self.finding(1, "2026-10-01", "fp", candidate_id="dup")
        with self.assertRaisesRegex(ValueError, "duplicate candidate_id"):
            triage.cluster_candidates([
                {"cluster_id": "C1", "file": "lib/sandbox.py", "count": 1, "items": [row]},
                {"cluster_id": "C2", "file": "lib/sandbox.py", "count": 1,
                 "items": [{**row, "line_number": 200}]},
            ])
        padded = self.finding(1, "2026-10-01", "fp", candidate_id=" padded ")
        with self.assertRaisesRegex(ValueError, "malformed source identity"):
            triage.cluster_candidates([{"cluster_id": "C1", "file": "lib/sandbox.py",
                                         "count": 1, "items": [padded]}])

    def test_context_keeps_more_clusters_than_the_shown_candidate_slice(self):
        source = [{**self.finding(1, "2026-10-01", f"fp-{i}"), "path": f"p{i:02}.py"}
                  for i in range(52)]
        clusters = triage.cluster_deterministic(source)
        emitted = triage.cluster_candidates(clusters)
        self.assertEqual((len(clusters), len(emitted)), (52, 52))
        self.assertEqual(len({c["candidate_id"] for c in emitted}), 52)
        self.assertNotIn(emitted[50]["candidate_id"],
                         {c["candidate_id"] for c in emitted[:50]},
                         "the unsliced context must not make the 51st candidate a shown ID")

    def test_station_declaration_and_report_fields_are_explicit(self):
        station = ROOT / "agents" / "vuln-triage"
        manifest = (station / "agent.yaml").read_text(encoding="utf-8")
        self.assertIn("candidate_accounting: aggregate-claimed\n", manifest)
        self.assertIn("output:\n  schema: report.schema.json\n", manifest)
        schema = json.loads((station / "report.schema.json").read_text(encoding="utf-8"))
        items = schema["properties"]["findings"]["items"]
        cover = items["properties"]["covered_candidate_ids"]
        self.assertEqual(cover["type"], "array")
        self.assertEqual(cover["items"], {"type": "string", "minLength": 1})
        self.assertEqual(items["properties"]["anchor_candidate_id"]["type"], "string")
        self.assertEqual(items["properties"]["false_positive"]["type"], "boolean")
        # Omission is line-level INCOMPLETE, whereas a malformed declared field
        # is a schema-invalid NO VERDICT. Unsupported schema keywords would be
        # refused by tests.test_report_schema, not used as fake validators.
        self.assertNotIn("covered_candidate_ids", items.get("required", []))
        self.assertNotIn("anchor_candidate_id", items.get("required", []))
        self.assertNotIn("minItems", cover)
        self.assertNotIn("uniqueItems", cover)
        skill = (station / "SKILL.md").read_text(encoding="utf-8")
        for required in ("covered_candidate_ids", "anchor_candidate_id", "false_positive",
                         "first 50", "PRIMARY IDENTITY",
                         "An anchor by itself never covers a candidate"):
            self.assertIn(required, skill)

    def test_colocated_input_anchor_locations_are_carried_by_candidates(self):
        source = [
            {"candidate_id": "source-sandbox", "rule_id": "source-sandbox", "fingerprint": "sfp",
             "path": "lib/sandbox.py", "line_number": 72, "first_seen": "2026-10-01T00:00:00Z"},
            {"candidate_id": "source-threat", "rule_id": "source-threat", "fingerprint": "tfp",
             "path": "THREAT_MODEL.md", "line_number": 1, "first_seen": "2026-10-01T00:00:00Z"},
        ]
        candidates = triage.cluster_candidates(triage.cluster_deterministic(source))
        self.assertEqual({(c["candidate_id"], c["path"], c["line_number"]) for c in candidates},
                         {("source-sandbox", "lib/sandbox.py", 72),
                          ("source-threat", "THREAT_MODEL.md", 1)})


class TestThreatModelContextSummary(unittest.TestCase):
    """agents-tawg: test visible summarization path and findings-store threat model copy."""

    def test_large_threat_model_has_visible_summary_notice(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            target_dir = tmp_path / "target"
            target_dir.mkdir()
            large_text = "# THREAT MODEL\n" + "x" * 5000
            (target_dir / "THREAT_MODEL.md").write_text(large_text, encoding="utf-8")

            out_file = tmp_path / "output" / "clusters.json"
            out_file.parent.mkdir()

            res = subprocess.run([
                sys.executable,
                str(ROOT / "agents" / "vuln-triage" / "scripts" / "triage.py"),
                "--target", str(target_dir),
                "--output", str(out_file),
            ], capture_output=True, text=True, check=True)

            payload = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["candidates"], [])
            self.assertEqual(payload["context"]["clusters"], [])
            summary = payload["context"]["threat_model_summary"]
            self.assertIn("[THREAT_MODEL.md summarised: showing first 3000 of 5015 bytes", summary)
            self.assertIn("TRUNCATED", summary)
            self.assertEqual(payload["context"]["threat_model_file"],
                             str((target_dir / "THREAT_MODEL.md").resolve()))

    def test_findings_store_threat_model_copied_to_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            orig_root = triage.FACTORY_ROOT
            try:
                triage.FACTORY_ROOT = tmp_path
                findings_dir = tmp_path / "findings"
                findings_dir.mkdir()
                target_name = "proj-x"
                store_tm = findings_dir / f"{target_name}-THREAT_MODEL.md"
                store_tm.write_text("# Stored TM Content", encoding="utf-8")

                target_dir = tmp_path / target_name
                target_dir.mkdir()

                out_file = tmp_path / "run" / "clusters.json"
                out_file.parent.mkdir()

                text, rel = triage.load_threat_model(target_name, target_dir, output_file=out_file)
                self.assertEqual(text, "# Stored TM Content")
                copied = out_file.parent / "THREAT_MODEL.md"
                self.assertEqual(rel, str(copied.resolve()))
                self.assertTrue(copied.exists())
                self.assertEqual(copied.read_text(encoding="utf-8"), "# Stored TM Content")
            finally:
                triage.FACTORY_ROOT = orig_root


if __name__ == "__main__":
    unittest.main()
