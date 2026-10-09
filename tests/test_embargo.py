#!/usr/bin/env python3
"""Publication embargo: the routing decision, independent of any sink call.

End-to-end coverage of the guard lives in tests/test_sinks.py and tests/test_redaction.py.
These are the unit cases for the policy itself, including every fail-closed path.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.embargo import (  # noqa: E402
    EMBARGOED_SEVERITIES,
    IDENTITY_CRITICAL_AGENTS,
    VALID_SEVERITIES,
    effective_severity,
    embargo_reason,
    is_false_positive,
    normalize_severity,
    normalize_visibility,
    reported_severity,
)


def finding(**overrides):
    base = {"agent": "lint", "rule_id": "unused-export", "severity": "medium"}
    base.update(overrides)
    return base


class TestNormalizeSeverity(unittest.TestCase):
    def test_valid_values_round_trip(self):
        for severity in VALID_SEVERITIES:
            with self.subTest(severity=severity):
                self.assertEqual(normalize_severity(severity), severity)

    def test_case_and_whitespace_are_normalised(self):
        self.assertEqual(normalize_severity("HIGH"), "high")
        self.assertEqual(normalize_severity("  Critical  "), "critical")

    def test_absent_value_fails_closed(self):
        """The old default was medium — the exact band the public sinks publish (SF-03)."""
        for absent in (None, "", "   "):
            with self.subTest(value=absent):
                self.assertEqual(normalize_severity(absent), "critical")

    def test_unrecognised_values_fail_closed(self):
        for bad in ("sev:1", "urgent", "p0", 7, 2.5, {"level": "high"}, ["high"], True, False):
            with self.subTest(value=bad):
                self.assertEqual(normalize_severity(bad), "critical")

    def test_embargoed_bands_are_critical_and_high(self):
        self.assertEqual(EMBARGOED_SEVERITIES, frozenset({"critical", "high"}))


class TestVisibility(unittest.TestCase):
    def test_recognised_values_are_normalised(self):
        self.assertEqual(normalize_visibility("public"), "public")
        self.assertEqual(normalize_visibility(" PRIVATE "), "private")

    def test_missing_or_unrecognised_values_fail_closed_to_public(self):
        for bad in (None, "", "internal", "pubilc", 1, True, {"v": "private"}):
            with self.subTest(value=bad):
                self.assertEqual(normalize_visibility(bad), "public")


class TestEffectiveSeverity(unittest.TestCase):
    def test_security_agents_are_critical_whatever_the_model_labelled_it(self):
        """Identity, a deterministic fact, outranks the model's self-report (SF-03)."""
        for agent in ("secret-scan", "vuln-discovery", "vuln-verify", "vuln-triage", "threat-model"):
            for label in ("critical", "high", "medium", "low", "info", None, "urgent", {"x": 1}):
                with self.subTest(agent=agent, label=label):
                    self.assertEqual(
                        effective_severity(finding(agent=agent, severity=label)),
                        "critical",
                    )

    def test_identity_set_covers_credentials_and_vulnerabilities(self):
        for agent in ("secret-scan", "vuln-discovery", "vuln-verify", "vuln-triage", "threat-model"):
            with self.subTest(agent=agent):
                self.assertIn(agent, IDENTITY_CRITICAL_AGENTS)

    def test_ordinary_agent_keeps_a_valid_label(self):
        self.assertEqual(effective_severity(finding(agent="docs-drift", severity="low")), "low")

    def test_missing_label_on_an_ordinary_agent_is_critical(self):
        self.assertEqual(effective_severity(finding(severity=None)), "critical")


class TestDummyCredentialFalsePositive(unittest.TestCase):
    """Obvious test-fixture/dummy keys are false positives, not live secrets (agents-3r7)."""

    def test_obvious_dummy_markers_are_false_positives(self):
        dummies = [
            'output = "No API key found for sk-ant-secret-token-1234567890\\n"',
            '"anthropic": "sk-ant-REAL-DO-NOT-LEAK",',
            '"ANTHROPIC_API_KEY": "sk-test-placeholder"}',
            'real_key = "sk-ant-REALKEY-do-not-leak"',
            'self.assertIsNotNone(rule.search(\'key = "sk-proj-abcdefghijklmnop1234"\'))',
            'res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"})',
        ]
        for snippet in dummies:
            with self.subTest(snippet=snippet[:40]):
                self.assertTrue(
                    is_false_positive(finding(agent="secret-scan", snippet=snippet)))

    def test_dummy_raw_match_beats_a_masked_snippet(self):
        # The model can mask its snippet; the scanner's raw match is the faithful value.
        self.assertTrue(is_false_positive(finding(
            agent="secret-scan", snippet="sk-ant-***",
            raw_match="sk-ant-secret-token-1234567890")))

    def test_realistic_keys_are_not_false_positives(self):
        realistic = [
            'token = "sk-ant-api03-7xK9mP2qR5tV8wY3zB6nH1jL4cF0dG7s"',
            'key = "AKIAIOSFODNN7EXAMPL3"',
            'ghp_1a2B3c4D5e6F7g8H9i0Jk1Lm2Nn3Oo4Pq5Rs',
            'authorization = "Bearer sk-proj-9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
        ]
        for snippet in realistic:
            with self.subTest(snippet=snippet[:40]):
                self.assertFalse(
                    is_false_positive(finding(agent="secret-scan", snippet=snippet)))

    def test_dummy_credential_is_not_routed_critical(self):
        # A dummy key is not a key: identity-critical agents must not route it critical.
        for item in (finding(agent="secret-scan", snippet="sk-test-placeholder"),
                     finding(agent="secret-scan", raw_match="sk-ant-secret-token-1234567890")):
            with self.subTest(item=item):
                self.assertEqual(effective_severity(item), "info")

    def test_dummy_credential_reports_info(self):
        self.assertEqual(
            reported_severity(finding(agent="secret-scan", snippet="sk-test-placeholder")),
            "info")


class TestEmbargoReason(unittest.TestCase):
    def test_critical_and_high_are_embargoed_from_trackers(self):
        for severity in ("critical", "high"):
            for sink in ("beads", "github-issues"):
                with self.subTest(severity=severity, sink=sink):
                    self.assertIsNotNone(embargo_reason(finding(severity=severity), sink))

    def test_medium_and_low_may_publish(self):
        for severity in ("medium", "low", "info"):
            for sink in ("beads", "github-issues"):
                with self.subTest(severity=severity, sink=sink):
                    self.assertIsNone(embargo_reason(finding(severity=severity), sink))

    def test_the_local_file_sink_is_never_embargoed(self):
        """The delta report and findings store are the operator's evidence trail."""
        self.assertIsNone(embargo_reason(finding(severity="critical"), "file"))
        self.assertIsNone(embargo_reason(finding(agent="secret-scan"), "file"))

    def test_explicit_public_target_publishes_high_critical_and_security_identity(self):
        """Paul explicitly approved public issues even for sensitive findings (agents-559)."""
        for item in (finding(severity="high"), finding(severity="critical"),
                     finding(agent="secret-scan", severity="low")):
            with self.subTest(item=item):
                self.assertIsNone(embargo_reason(item, "github-issues", visibility="public"))

    def test_a_private_target_may_publish_the_embargoed_bands(self):
        """A private tracker is not a public disclosure: visibility is the primary input."""
        for severity in ("critical", "high"):
            for sink in ("beads", "github-issues"):
                with self.subTest(severity=severity, sink=sink):
                    self.assertIsNone(
                        embargo_reason(finding(severity=severity), sink, visibility="private")
                    )

    def test_a_private_target_may_publish_security_agents(self):
        for agent in ("secret-scan", "vuln-discovery", "vuln-verify", "vuln-triage", "threat-model"):
            with self.subTest(agent=agent):
                self.assertIsNone(
                    embargo_reason(finding(agent=agent, severity="low"), "beads",
                                   visibility="private")
                )

    def test_missing_or_unrecognised_visibility_is_public(self):
        for value in (None, "internal", ""):
            with self.subTest(value=value):
                self.assertIsNotNone(
                    embargo_reason(finding(severity="critical"), "beads", visibility=value)
                )

    def test_the_local_file_sink_is_never_embargoed_either_way(self):
        for visibility in ("public", "private", None):
            with self.subTest(visibility=visibility):
                self.assertIsNone(
                    embargo_reason(finding(severity="critical"), "file", visibility=visibility)
                )

    def test_unknown_sinks_fail_closed(self):
        self.assertIsNotNone(embargo_reason(finding(severity="critical"), "some-new-tracker"))
        self.assertIsNone(embargo_reason(finding(severity="medium"), "some-new-tracker"))


if __name__ == "__main__":
    unittest.main()
