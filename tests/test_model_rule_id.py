"""agents-ag4: keep the model's own rule label without faking scanner provenance.

`bind_candidates` refuses a model rule id it cannot bind to a deterministic candidate and stores
`unclassified` - correct, because a model-invented scanner rule id makes a report look like the
scanner found it. But the label itself was then lost to triage, which was the real complaint
behind agents-v4q/agents-ag4. The fix is a SEPARATE field, `model_rule_id`, that can never be read
as scanner provenance.

Additive means provable, so these tests pin the four properties the bead's scope statement set out:
  * identity is unchanged - the field is not an input to compute_fingerprint, so re-running the
    same finding does not re-book it (no new/fixed churn);
  * routing is unchanged - the credential/security hint classification reads `rule_id`, so a
    hostile label cannot move a finding's routing severity or its publication outcome;
  * the label is masked and shape-checked like every other rendered model string, because
    redact_finding copies fields wholesale and an unmasked field would be a new smuggling channel;
  * it is surfaced where triage reads, which is the entire point of keeping it.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.embargo import effective_severity  # noqa: E402
from lib.findings import (  # noqa: E402
    FindingsStore,
    compute_fingerprint,
    identity_snippet,
)
from lib.redaction import (  # noqa: E402
    IDENTITY_SHAPES,
    RENDERED_TEXT_FIELDS,
    is_credential_finding,
    redact_finding,
)

# The real context-shaped index that started this: vuln-discovery's candidates file holds one
# entry, the threat-model CONTEXT, so its `rule_ids` is meaningless and every model label is
# refused today.
CONTEXT_INDEX = {"rule_ids": {"threat-model-context"}, "paths": {"THREAT_MODEL.md"}}
STATS = {"new": 1, "regressed": 0, "fixed": 0, "unchanged": 0, "suppressed": 0,
         "false_positive": 0}
REFUSED_LABEL = "scanner-self-output-not-excluded"


def finding(**overrides):
    item = {
        "rule_id": REFUSED_LABEL,
        "path": "lib/bench/runner.py",
        "title": "the model's own label",
        "description": "d",
        "severity": "low",
        "snippet": "s",
        "line_number": 7,
    }
    item.update(overrides)
    return item


class ModelRuleIdTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "target"
        (self.target / "lib" / "bench").mkdir(parents=True)
        (self.target / "lib" / "bench" / "runner.py").write_text("x = 1\n")
        self.store_dir = self.root / "findings"

    def tearDown(self):
        self.tmp.cleanup()

    def run_store(self, agent="vuln-discovery", item=None, index=CONTEXT_INDEX):
        store = FindingsStore(agent, findings_dir=self.store_dir)
        try:
            processed, stats, _ = store.process_run(
                agent=agent,
                raw_findings=[item if item is not None else finding()],
                candidate_index=index,
                target_dir=self.target,
            )
        finally:
            store.close()
        return processed[0], stats

    # --- the motivating case ---------------------------------------------------------------
    def test_a_refused_model_label_is_kept_in_its_own_field(self):
        record, _ = self.run_store()
        self.assertEqual(record["rule_id"], "unclassified")   # the guard is intact
        self.assertEqual(record["path"], "lib/bench/runner.py")  # agents-0tl is intact
        self.assertEqual(record["model_rule_id"], REFUSED_LABEL)  # and the label survives

    def test_an_accepted_label_is_not_duplicated(self):
        """When the label IS the rule id, the field stays empty - it means 'the label refused'."""
        index = {"rule_ids": {REFUSED_LABEL}, "paths": {"lib/bench/runner.py"}}
        record, _ = self.run_store(index=index)
        self.assertEqual(record["rule_id"], REFUSED_LABEL)
        self.assertEqual(record["model_rule_id"], "")

    def test_no_candidate_set_at_all_keeps_the_label_as_the_rule_id(self):
        """No index means nothing to bind to: the model's value passes through, as before."""
        record, _ = self.run_store(index=None)
        self.assertEqual(record["rule_id"], REFUSED_LABEL)
        self.assertEqual(record["model_rule_id"], "")

    # --- identity is untouched (no re-booking, no migration churn) --------------------------
    def test_the_field_is_not_part_of_the_fingerprint(self):
        record, _ = self.run_store()
        expected = compute_fingerprint(
            agent="vuln-discovery", rule_id=record["rule_id"], path=record["path"],
            snippet=identity_snippet(finding(), record["rule_id"], record["path"], CONTEXT_INDEX),
        )
        self.assertEqual(record["fingerprint"], expected)

    def test_a_second_run_is_unchanged_not_rebooked(self):
        """The proof obligation: the field must not re-identify the record."""
        first, stats1 = self.run_store()
        second, stats2 = self.run_store()
        self.assertEqual(stats1["new"], 1)
        self.assertEqual((stats2["new"], stats2["fixed"]), (0, 0))
        self.assertEqual(stats2["unchanged"], 1)
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    # --- routing cannot be moved by the label ---------------------------------------------
    def test_a_hostile_label_cannot_move_routing_severity(self):
        """A label full of credential words is only ever a display string."""
        hostile = finding(rule_id="openai-secret-token-password")
        neutral = finding(rule_id=REFUSED_LABEL)
        hostile_record, _ = self.run_store(item=hostile)
        neutral_record, _ = self.run_store(item=neutral)
        self.assertEqual(hostile_record["routing_severity"], neutral_record["routing_severity"])
        self.assertEqual(hostile_record["rule_id"], "unclassified")

    def test_the_credential_hint_classifier_does_not_read_the_new_field(self):
        """The guard still classifies by `rule_id` alone, so a refused label cannot fake it."""
        self.assertTrue(is_credential_finding({"agent": "docs-drift", "rule_id": "openai-key"}))
        self.assertFalse(is_credential_finding({"agent": "docs-drift", "rule_id": "unclassified",
                                                "model_rule_id": "openai-key"}))
        self.assertEqual(
            effective_severity({"agent": "docs-drift", "severity": "low",
                                "rule_id": "unclassified", "model_rule_id": "openai-key"}),
            effective_severity({"agent": "docs-drift", "severity": "low",
                                "rule_id": "unclassified"}),
        )

    # --- it is a rendered model string, so it gets the same two layers ---------------------
    def test_the_field_is_declared_as_rendered_and_shape_checked(self):
        """Meta-test: adding the record field without these two entries would open a smuggling
        channel, because redact_finding copies every field of the record."""
        self.assertIn("model_rule_id", RENDERED_TEXT_FIELDS)
        self.assertIn("model_rule", IDENTITY_SHAPES)

    def test_a_malformed_label_falls_back_to_no_label(self):
        # docs-drift, not vuln-discovery: a security agent drops the label unconditionally, which
        # would make this loop pass for valid and invalid labels alike (review P2).
        for bad in ("no spaces allowed", "a" * 40, "with\nnewline", "semi;colon"):
            redacted = redact_finding({"agent": "docs-drift", "rule_id": "unclassified",
                                       "model_rule_id": bad})
            self.assertEqual(redacted["model_rule_id"], "", f"{bad!r} should not survive")
        good = redact_finding({"agent": "docs-drift", "rule_id": "unclassified",
                               "model_rule_id": "unhandled-url-construction"})
        self.assertEqual(good["model_rule_id"], "unhandled-url-construction")

    def test_the_persisted_store_carries_the_redacted_label(self):
        """For an ordinary station - a security-sensitive one is covered below, and drops it."""
        self.run_store(agent="docs-drift", item=finding(rule_id="unhandled-url-construction"))
        persisted = json.loads((self.store_dir / "docs-drift.json").read_text())
        record = next(iter(persisted["findings"].values()))
        self.assertEqual(record["model_rule_id"], "unhandled-url-construction")

    def test_the_persisted_store_does_not_carry_a_malformed_label(self):
        self.run_store(agent="docs-drift", item=finding(rule_id="no spaces allowed here"))
        persisted = json.loads((self.store_dir / "docs-drift.json").read_text())
        record = next(iter(persisted["findings"].values()))
        self.assertEqual(record["model_rule_id"], "")

    # --- and it is actually shown to triage, which is the point ----------------------------
    def test_the_delta_report_shows_the_label_as_not_scanner_provenance(self):
        """docs-drift, because this must exercise the rendered output of a station that actually
        publishes labels: for a security agent redact_finding blanks the field before rendering,
        so rendering the raw in-memory record would prove nothing (review P2)."""
        from lib.findings import _render_delta_report
        record, _ = self.run_store(agent="docs-drift")
        report = _render_delta_report("t", [record], STATS, [])
        self.assertIn(REFUSED_LABEL, report)
        self.assertIn("not scanner provenance", report)

    def test_the_delta_report_says_nothing_extra_when_the_label_was_accepted(self):
        from lib.findings import _render_delta_report
        index = {"rule_ids": {REFUSED_LABEL}, "paths": {"lib/bench/runner.py"}}
        record, _ = self.run_store(index=index)
        report = _render_delta_report("t", [record], STATS, [])
        self.assertNotIn("not scanner provenance", report)


if __name__ == "__main__":
    unittest.main()


class ModelRuleIdSecurityTestCase(unittest.TestCase):
    """The review's P0/P1: a model-authored label is prose, and prose is not published for
    credential or security-sensitive findings - so the label must not be either.

    These are the tests whose absence let the first version through: 12 green tests, and a
    credential finding that rewritten its title to scanner text while still carrying the raw
    secret in the label.
    """

    SECRET = "token_xyz_987654321"   # under 20 chars, delimiter-broken: evades OPAQUE_RUN

    def test_a_credential_finding_does_not_publish_the_labels_text(self):
        redacted = redact_finding({
            "agent": "secret-scan", "rule_id": "unclassified", "model_rule_id": self.SECRET,
            "path": "config.py", "line_number": 10, "title": "t", "description": "d",
            "snippet": f"SECRET = {self.SECRET}", "raw_match": f"SECRET = {self.SECRET}",
        })
        self.assertEqual(redacted["model_rule_id"], "")
        self.assertNotIn(self.SECRET, json.dumps(redacted))

    def test_a_security_sensitive_finding_does_not_publish_the_labels_text(self):
        redacted = redact_finding({
            "agent": "vuln-discovery", "rule_id": "unclassified", "model_rule_id": self.SECRET,
            "path": "server.py", "line_number": 42, "title": "t",
            "description": f"found {self.SECRET}", "snippet": f"connect(pass={self.SECRET})",
        })
        self.assertEqual(redacted["model_rule_id"], "")
        self.assertNotIn(self.SECRET, json.dumps(redacted))

    def test_a_known_pattern_secret_is_masked_even_for_an_ordinary_agent(self):
        """Defence in depth: the drop rule covers credential/security agents, masking covers the
        rest. A recognised key shape is masked wherever it appears, label included."""
        redacted = redact_finding({"agent": "docs-drift", "rule_id": "unclassified",
                                   "model_rule_id": "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
                                   "path": "README.md", "line_number": 1})
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz012345", json.dumps(redacted))

    def test_an_ordinary_finding_keeps_its_label(self):
        """...and the feature still works where the threat model allows model prose."""
        redacted = redact_finding({"agent": "docs-drift", "rule_id": "unclassified",
                                   "model_rule_id": "doc-broken-link", "path": "README.md",
                                   "line_number": 1, "title": "t", "description": "d",
                                   "snippet": "s"})
        self.assertEqual(redacted["model_rule_id"], "doc-broken-link")

    def test_the_persisted_store_never_carries_a_security_label(self):
        """End-to-end, because the store file is TRACKED in this repo: a leak here is published."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            (target / "lib").mkdir(parents=True)
            (target / "lib" / "real.py").write_text("x = 1\n")
            store = FindingsStore("vuln-discovery", findings_dir=root / "findings")
            try:
                store.process_run(
                    agent="vuln-discovery",
                    raw_findings=[finding(rule_id=self.SECRET, path="lib/real.py")],
                    candidate_index=CONTEXT_INDEX, target_dir=target,
                )
            finally:
                store.close()
            persisted = (root / "findings" / "vuln-discovery.json").read_text()
            self.assertNotIn(self.SECRET, persisted)

    def test_the_fingerprint_survives_a_changed_label_between_runs(self):
        """Review P2: the earlier additivity test replayed an identical label, so it would pass
        even if the field were folded into the fingerprint. A model's wording drifts; identity
        must not."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            (target / "lib").mkdir(parents=True)
            (target / "lib" / "real.py").write_text("x = 1\n")
            store = FindingsStore("docs-drift", findings_dir=root / "findings")
            try:
                kwargs = dict(agent="docs-drift", candidate_index=CONTEXT_INDEX, target_dir=target)
                first, s1, _ = store.process_run(
                    raw_findings=[finding(rule_id="doc-broken-link", path="lib/real.py")], **kwargs)
                second, s2, _ = store.process_run(
                    raw_findings=[finding(rule_id="doc-deleted-reference", path="lib/real.py")],
                    **kwargs)
                first_record, second_record = first[0], second[0]
            finally:
                store.close()
            self.assertEqual(s1["new"], 1)
            self.assertEqual((s2["new"], s2["fixed"], s2["regressed"]), (0, 0, 0))
            self.assertEqual(s2["unchanged"], 1)
            self.assertEqual(first_record["fingerprint"], second_record["fingerprint"])
            self.assertEqual(first_record["model_rule_id"], "doc-broken-link")
            self.assertEqual(second_record["model_rule_id"], "doc-deleted-reference")

    def test_the_unchanged_section_shows_the_label(self):
        from lib.findings import _render_delta_report
        record = {"fingerprint": "f" * 64, "agent": "docs-drift", "rule_id": "unclassified",
                  "model_rule_id": "doc-broken-link", "path": "README.md", "line_number": 1,
                  "title": "t", "description": "d", "snippet": "s", "severity": "low",
                  "routing_severity": "low", "state": "new", "change": "unchanged"}
        report = _render_delta_report("t", [record], {"new": 0, "regressed": 0, "fixed": 0,
                                                      "unchanged": 1, "suppressed": 0,
                                                      "false_positive": 0}, [])
        self.assertIn("doc-broken-link", report)
        self.assertIn("not scanner provenance", report)
