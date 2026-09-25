#!/usr/bin/env python3
"""Print a scanner candidate report as a counts-and-locations summary.

Never print a candidate's `snippet` or `raw_match`. For `secret-scan` those fields hold the
matched credential itself, and this output lands in GitHub Actions logs and step summaries,
which are public on a public repository. Only a whitelist of identifying fields (rule id, path,
line) is read here — anything added to a scanner's output later cannot leak through this script
by accident.

Identity fields are not trusted either. A `path` can carry the credential itself (a file named
after the key), a `rule_id` arrives as text, and a `line_number` can be any JSON value. All of
them go through lib/redaction.py, the module that already owns value masking and identity shape
checks, so there is one policy rather than a second one here.

Usage: candidate_summary.py <candidates.json>
"""

import json
import sys
from pathlib import Path
from typing import Any

try:  # lib/ on sys.path (script directory), or the repo root on it
    from lib.redaction import mask_text, publishable_line_number, sanitise_identity
except ImportError:  # pragma: no cover - covered by the CLI test and a direct run
    from redaction import mask_text, publishable_line_number, sanitise_identity


def _identity_text(value: Any, kind: str) -> str:
    """One identity field, rendered so it cannot carry a matched value.

    A recognised credential shape is masked in place (the label is safe to print); anything
    unrecognised that still looks like an opaque blob falls back to lib/redaction's placeholder.
    """
    if not isinstance(value, str) or not value.strip():
        return "?"
    masked = mask_text(value)
    if masked != value:
        return masked
    return str(sanitise_identity(value, kind))


def summarise(report_path: Path) -> str:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    candidates = report.get("candidates", []) if isinstance(report, dict) else report
    if not isinstance(candidates, list):
        candidates = []

    scanner_raw = report.get("scanner") if isinstance(report, dict) else ""
    scanner = _identity_text(scanner_raw, "rule") if scanner_raw else ""
    lines = [f"{len(candidates)} candidate(s) in {report_path.name}" + (f" [{scanner}]" if scanner else "")]

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rule = _identity_text(candidate.get("rule_id"), "rule")
        location = _identity_text(candidate.get("path"), "path")
        line_number = publishable_line_number(candidate.get("line_number"))
        if line_number != "?":
            location += f":{line_number}"
        severity_raw = candidate.get("severity")
        severity = _identity_text(severity_raw, "rule") if severity_raw else "unrated"
        lines.append(f"  - {rule}  {location}  ({severity})")

    # Counts only: matched values are deliberately never echoed (see module docstring).
    lines.append("  (values intentionally not printed)")
    return "\n".join(lines)


def main(argv) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: candidate_summary.py <candidates.json>\n")
        return 2
    path = Path(argv[1])
    if not path.exists():
        sys.stderr.write(f"candidate report not found: {path}\n")
        return 1
    print(summarise(path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
