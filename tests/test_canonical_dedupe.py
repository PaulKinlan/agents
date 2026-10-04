#!/usr/bin/env python3
"""Canonical-feature-id dedupe for the beads sink (audio-feed-9ara).

The daily modern-web audit re-emitted candidates whose canonical feature id was already on a
bead — including beads CLOSED as duplicates — and the silent closures left the next lane to
re-derive the premise. These tests pin the lookup and the skip, with a fake `bd` so the sink's
real subprocess path is exercised (not a mocked-out one).
"""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib.findings import (
    _dispatch_beads,
    canonical_feature_id,
    existing_canonical_ids,
)


def _fake_bd(tmp: Path, list_stdout: str, list_returncode: int = 0) -> Path:
    """A `bd` that answers `list` from a fixture and logs every `create`."""
    bindir = tmp / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    script = bindir / "bd"
    log = tmp / "created.log"
    payload = tmp / "list.json"
    payload.write_text(list_stdout, encoding="utf-8")
    script.write_text(
        "#!/usr/bin/env bash\n"
        "if [ \"$1\" = \"list\" ]; then\n"
        f"  cat {payload}\n"
        f"  exit {list_returncode}\n"
        "fi\n"
        "if [ \"$1\" = \"create\" ]; then\n"
        f"  echo \"$@\" >> {log}\n"
        "  echo 'Created issue'\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return bindir


def _finding(title: str, severity: str = "medium") -> dict:
    return {
        "agent": "modern-web",
        "rule_id": "custom-modal-missing-closedby",
        "title": title,
        "description": "A custom modal container instead of the declarative dialog.",
        "path": "src/app.ts",
        "line_number": 10,
        "snippet": "<div class=\"modal\">",
        "severity": severity,
        "state": "new",
        "fingerprint": "0123456789abcdef",
        "dispatched_sinks": [],
    }


class TestCanonicalFeatureId(unittest.TestCase):
    def test_extracts_the_trailing_parenthetical(self):
        self.assertEqual(canonical_feature_id("Use <dialog> (dialog-closedby)"), "dialog-closedby")
        self.assertEqual(
            canonical_feature_id("Replace Scroll Listener with Container Scroll-State Query (container-scroll-state)"),
            "container-scroll-state",
        )
        # A trailing space or newline does not hide it.
        self.assertEqual(canonical_feature_id("Something (anchor-positioning)  "), "anchor-positioning")

    def test_no_parenthetical_is_none(self):
        self.assertIsNone(canonical_feature_id("A title with no id"))
        # A parenthetical in the middle is prose, not the id.
        self.assertIsNone(canonical_feature_id("Use (this) somewhere in the middle"))
        self.assertIsNone(canonical_feature_id(""))
        self.assertIsNone(canonical_feature_id(None))

    def test_bead_prefix_does_not_confuse_it(self):
        # The bead title the sink builds is "[modern-web] <title> (<id>)" — still the last group.
        self.assertEqual(
            canonical_feature_id("[modern-web] Add IME Guard (ime-safe-enter-submit)"),
            "ime-safe-enter-submit",
        )


class TestExistingCanonicalIds(unittest.TestCase):
    def test_reads_every_state_and_keeps_the_first_bead(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = json.dumps([
                {"id": "audio-feed-e21x", "title": "[modern-web] Use <dialog> (dialog-closedby)", "status": "closed"},
                {"id": "audio-feed-d5c", "title": "[modern-web] Use closedby (dialog-closedby)", "status": "closed"},
                {"id": "audio-feed-pzwe", "title": "[modern-web] Anchor (anchor-positioning)", "status": "in_progress"},
                {"id": "audio-feed-9zzz", "title": "A bead with no canonical id", "status": "open"},
            ])
            bindir = _fake_bd(tmp, payload)
            found = existing_canonical_ids(tmp, str(bindir / "bd"))
            self.assertEqual(found, {"dialog-closedby": "audio-feed-e21x", "anchor-positioning": "audio-feed-pzwe"})

    def test_accepts_the_issues_wrapper_shape(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = json.dumps({"issues": [{"id": "x-1", "title": "T (some-guide-id)"}]})
            bindir = _fake_bd(tmp, payload)
            self.assertEqual(existing_canonical_ids(tmp, str(bindir / "bd")), {"some-guide-id": "x-1"})

    def test_a_failed_lookup_fails_open(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bindir = _fake_bd(tmp, "", list_returncode=1)
            self.assertEqual(existing_canonical_ids(tmp, str(bindir / "bd")), {})

    def test_non_json_fails_open(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bindir = _fake_bd(tmp, "not json at all")
            self.assertEqual(existing_canonical_ids(tmp, str(bindir / "bd")), {})


class TestBeadsSinkSkip(unittest.TestCase):
    def _run(self, tmp: Path, findings, payload: str):
        (tmp / ".beads").mkdir(parents=True, exist_ok=True)
        bindir = _fake_bd(tmp, payload)
        with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ.get('PATH', '')}"}):
            _dispatch_beads(tmp, findings, visibility="public")
        log = tmp / "created.log"
        return log.read_text(encoding="utf-8") if log.exists() else ""

    def test_a_closed_duplicate_is_not_re_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = json.dumps([
                {"id": "audio-feed-e21x", "title": "[modern-web] Use <dialog> (dialog-closedby)", "status": "closed"},
            ])
            finding = _finding("Use declarative closedby=\"any\" on <dialog> (dialog-closedby)")
            created = self._run(tmp, [finding], payload)
            self.assertEqual(created, "", "no bead may be created for a canonical id already on a bead")
            self.assertIn("beads:duplicate", finding["dispatched_sinks"])

    def test_an_open_bead_with_the_id_also_blocks_emission(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = json.dumps([
                {"id": "audio-feed-txcz", "title": "[modern-web] Scroll state (container-scroll-state)", "status": "in_progress"},
            ])
            created = self._run(tmp, [_finding("Style headers (container-scroll-state)")], payload)
            self.assertEqual(created, "")

    def test_a_new_canonical_id_is_still_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = json.dumps([
                {"id": "audio-feed-e21x", "title": "[modern-web] Use <dialog> (dialog-closedby)", "status": "closed"},
            ])
            finding = _finding("Style headers when stuck (container-scroll-state)")
            created = self._run(tmp, [finding], payload)
            self.assertIn("--title", created)
            self.assertIn("container-scroll-state", created)
            self.assertEqual(finding["dispatched_sinks"], ["beads"])

    def test_a_title_without_a_canonical_id_is_unaffected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            created = self._run(tmp, [_finding("Plain secret-scan finding")], "[]")
            self.assertIn("--title", created)


if __name__ == "__main__":
    unittest.main()
