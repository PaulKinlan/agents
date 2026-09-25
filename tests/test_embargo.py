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
    VALID_SEVERITIES,
    effective_severity,
    embargo_reason,
    normalize_severity,
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


class TestEffectiveSeverity(unittest.TestCase):
    def test_credential_agent_is_critical_whatever_the_model_labelled_it(self):
        """Identity, a deterministic fact, outranks the model's self-report (SF-03)."""
        for label in ("critical", "high", "medium", "low", "info", None, "urgent", {"x": 1}):
            with self.subTest(label=label):
                self.assertEqual(
                    effective_severity(finding(agent="secret-scan", severity=label)),
                    "critical",
                )

    def test_ordinary_agent_keeps_a_valid_label(self):
        self.assertEqual(effective_severity(finding(agent="vuln-verify", severity="low")), "low")

    def test_missing_label_on_an_ordinary_agent_is_critical(self):
        self.assertEqual(effective_severity(finding(severity=None)), "critical")


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

    def test_unknown_sinks_fail_closed(self):
        self.assertIsNotNone(embargo_reason(finding(severity="critical"), "some-new-tracker"))
        self.assertIsNone(embargo_reason(finding(severity="medium"), "some-new-tracker"))


if __name__ == "__main__":
    unittest.main()
