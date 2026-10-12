"""agents-5vun: audit the pins file a run would USE against a fresh derivation.

WHAT THIS IS, AND WHAT IT IS NOT - stated here because a detector described as a fix is
worse than no detector at all:

    5vun's finding is that a pins file written BEFORE the oc3q hardening is still trusted
    identically. The loader inspects no provenance (no mtime, no uid, no stamp, no version
    field - the generator's header is comments and the parser drops them), so a pre-fix file
    and a post-fix file are indistinguishable, and a self-consistent forged entry (a pin at
    a binary the attacker supplies, carrying that binary's own digest) resolves, PASSES
    verify_pin, and is executed.

    NO LOCAL CHANGE CLOSES THAT HOLE. The pins file IS the root of trust for tool identity
    and nothing in-process can authenticate it. This module DETECTS AND REPORTS; it does not
    close the code-execution path, and the report says so in its own words rather than
    leaving a reader to infer it.

WHAT IT CHECKS (two independent checks, both measured against real files):

    1. RE-DERIVATION. Run tools/generate-tool-pins.sh into a temporary file with the SAME
       lookup dirs, parse both, and diff the entries. This catches a pin at a path the
       current lookup would not choose - the forged-path shape that agents-5vun measured
       (/usr/bin/git versus a planted /tmp/.../git) - and a digest a fresh derivation does
       not produce.
    2. RE-HASH. Hash the binary at each pinned path and compare with the file's digest. This
       is independent of the lookup dirs, so it catches a binary that changed after the file
       was written even when re-derivation agrees.

WHAT IT CANNOT CHECK, AND SAYS SO: whether the file was written by the hardened generator.
A self-consistent forged entry whose path the lookup ALSO chooses is accepted here - and by
verify_pin - because there is no trust anchor outside the file. `tests/test_pins_audit.py`
pins that limit in a test so it cannot be quietly claimed away.

EXIT CODES (the detector must be able to fail a gate; a report that exits 0 is decoration):

    0  the file in use agrees with a fresh derivation, or there is no file in use
    1  the re-derivation or the re-hash DISAGREES (this is the audit's finding)
    2  the audit could not run (generator failed, pins file unreadable or malformed)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "generate-tool-pins.sh"

# The lookup the fleet provisions with. Stated in the report, because a difference is only
# meaningful next to the dirs that were searched: a fresh derivation that omitted an
# operator dir WILL disagree with a file generated when it was included.
DEFAULT_LOOKUP = os.pathsep.join([
    str(Path.home() / ".local" / "bin"),
    str(Path.home() / ".local" / "pi"),
])

# HOW LONG THE RE-DERIVATION MAY TAKE (agents-u4k7). REQUIRED, not decorative: this module
# shells out to the generator, and the repo's own guard
# (tests/test_budget.py::TestNoUnboundedSubprocess) refuses an unbounded subprocess call - it
# caught this call and was right to. CHOSEN, NOT COPIED: the real tools/generate-tool-pins.sh
# takes ~6.0 s on this host (measured, 9 tools resolved and hashed), and this VM runs parallel
# lanes plus one heavy-gate slot, so 120 s is 20x the measured cost - room for a host 20x
# slower, while a generator that genuinely hangs still surfaces as "cannot run" well inside the
# fast gate's own 360 s bound instead of hanging a gate.
GENERATOR_TIMEOUT_SECONDS = 120


def _tp():
    """Import lib.tool_pins with the repo root importable (the CLI is run from anywhere)."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import lib.tool_pins  # noqa: PLC0415 - deferred so the module is importable standalone
    return lib.tool_pins


@dataclass
class EntryDiff:
    name: str
    in_use: Optional[Dict[str, str]]
    rederived: Optional[Dict[str, str]]

    def describe(self) -> str:
        def one(e: Optional[Dict[str, str]]) -> str:
            if e is None:
                return "absent"
            return f"path={e.get('path', '-')} sha256={(e.get('sha256') or '-')[:16]}…"

        if self.in_use is not None and self.rederived is not None:
            return f"{self.name}: in use {one(self.in_use)} | re-derived {one(self.rederived)}"
        if self.in_use is not None:
            return (f"{self.name}: in use {one(self.in_use)} | re-derived absent - a fresh "
                    "derivation with these lookup dirs does not produce this entry")
        return (f"{self.name}: in use absent | re-derived {one(self.rederived)} - the file "
                "in use is NARROWER than this lookup (a run needing this tool that tools.yaml "
                "does not cover fails closed) or the tool appeared since the file was written")


@dataclass
class AuditReport:
    pins_path: Optional[Path]
    route: str
    lookup: str
    in_use: Dict[str, Dict[str, str]] = field(default_factory=dict)
    rederived: Dict[str, Dict[str, str]] = field(default_factory=dict)
    differences: List[EntryDiff] = field(default_factory=list)
    hash_mismatches: List[str] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    rederivation_error: Optional[str] = None

    @property
    def disagrees(self) -> bool:
        return bool(self.differences or self.hash_mismatches or self.unreadable)


def select_pins(pins_arg: Optional[str]) -> "tuple[Optional[Path], str, List[str]]":
    """Mirror the CLI entry point and report HOW the audited file was selected.

    ``factory`` calls ``configure_host_pins(args.tool_pins)`` with the argument defaulting to
    None, so this does the same: an audit that selected the file differently from the
    dispatcher would audit a file the run does not use.
    """
    tp = _tp()
    notes: List[str] = []
    child_name = os.environ.get(tp.VERIFIED_PINS_ENV, "").strip()
    legacy_name = os.environ.get(tp.HOST_PINS_ENV, "").strip()
    tp.configure_host_pins(pins_arg)
    if pins_arg:
        route = f"explicit --pins {pins_arg}"
    elif legacy_name:
        route = (f"legacy {tp.HOST_PINS_ENV} (the dispatcher's fallback to an environment "
                 f"name; deprecated - agents-uekw removes it)")
    else:
        route = f"none (no --pins and no {tp.HOST_PINS_ENV})"
    if child_name:
        notes.append(
            f"{tp.VERIFIED_PINS_ENV}={child_name} is set, but this is a DISPATCHER-shaped "
            "run: configure_host_pins() drops that child-only name, so it is NOT the file "
            "audited here")
    return tp.host_pins_path(), route, notes


def _rederive(lookup: str, tmpdir: str) -> "tuple[Dict[str, Dict[str, str]], Optional[str]]":
    tp = _tp()
    out = Path(tmpdir) / "rederived.yaml"
    try:
        proc = subprocess.run(
            ["bash", str(GENERATOR), str(out), "--lookup-path", lookup],
            cwd=str(ROOT), capture_output=True, text=True,
            timeout=GENERATOR_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # THE BOUND IS REPORTED, NOT RAISED (agents-u4k7). tests/test_budget.py's rule requires
        # the timeout= to exist; this is what happens AT it. A generator that hangs must leave
        # the audit saying "cannot run" (exit 2 via rederivation_error), because a traceback is a
        # crash and a silently skipped re-derivation would read as "the file agrees".
        return {}, (f"{GENERATOR.name} did not finish within {GENERATOR_TIMEOUT_SECONDS}s "
                    "(measured: 6.0s on an idle host) - the fresh derivation is UNKNOWN, "
                    "NOT an agreement")
    if proc.returncode != 0 or not out.exists():
        return {}, (f"{GENERATOR.name} exited {proc.returncode}: "
                    f"{(proc.stderr or proc.stdout).strip()[-200:]}")
    return tp._parse_pins_file(out, "re-derived pins"), None


def audit(pins_arg: Optional[str] = None, lookup: str = DEFAULT_LOOKUP) -> AuditReport:
    tp = _tp()
    path, route, notes = select_pins(pins_arg)
    report = AuditReport(pins_path=path, route=route, lookup=lookup, notes=notes)
    if path is None:
        return report
    # _parse_pins_file is used deliberately: this must see the file IN USE, not
    # load_tool_pins()' merged view, which also carries the committed tools.yaml entries and
    # would report every repo pin as a difference.
    try:
        report.in_use = tp._parse_pins_file(path, f"pins file in use ({path})")
    except Exception as e:  # ToolPinError and anything the reader degrades on
        report.error = f"{type(e).__name__}: {e}"
        return report
    with tempfile.TemporaryDirectory(prefix="pins-audit-") as tmp:
        report.rederived, report.rederivation_error = _rederive(lookup, tmp)
    for name in sorted(set(report.in_use) | set(report.rederived)):
        a, b = report.in_use.get(name), report.rederived.get(name)
        if a != b:
            report.differences.append(EntryDiff(name, a, b))
    for name, entry in sorted(report.in_use.items()):
        pinned = entry.get("path")
        digest = entry.get("sha256")
        if not pinned or not digest:
            continue
        target = Path(pinned)
        if not target.is_file():
            report.unreadable.append(f"{name}: {pinned} is not a regular file")
        elif tp.sha256_file(target) != digest:
            report.hash_mismatches.append(
                f"{name}: {pinned} hashes to {tp.sha256_file(target)[:16]}…, "
                f"not the file's {digest[:16]}…")
    return report


NOT_CHECKED = (
    "NOT CHECKED: whether this file was written by the hardened generator. The loader "
    "inspects no provenance (no mtime, no uid, no stamp, no version field) and the pins "
    "file IS the root of trust for tool identity, so a SELF-CONSISTENT forged entry whose "
    "path these lookup dirs also choose is accepted here - and by verify_pin. No local "
    "change closes that; only a trust anchor outside the file would (agents-5vun)."
)


def render(report: AuditReport) -> str:
    lines = ["pins audit (agents-5vun): detect, and report what could not be checked", ""]
    lines.append("INSPECTED")
    lines.append(f"  file in use : {report.pins_path if report.pins_path else 'NONE'}")
    lines.append(f"  selected by : {report.route}")
    for note in report.notes:
        lines.append(f"  note        : {note}")
    if report.error:
        lines += ["", f"CANNOT AUDIT: {report.error}", "", NOT_CHECKED]
        return "\n".join(lines)
    if report.pins_path is None:
        lines.append("  nothing to audit: no host pins file is selected, so the committed "
                     "tools.yaml pins apply (it ships none, so a trusted tool resolves only "
                     "under the fast-gate waiver)")
        lines += ["", NOT_CHECKED]
        return "\n".join(lines)
    lines += [
        "",
        "RE-DERIVED",
        f"  command     : tools/generate-tool-pins.sh <tmp> --lookup-path {report.lookup!r}",
        f"  entries     : {len(report.in_use)} in use, {len(report.rederived)} re-derived",
    ]
    if report.rederivation_error:
        lines.append(f"  FAILED      : {report.rederivation_error}")
    if not report.disagrees:
        lines.append("  RESULT      : AGREES - every entry matches a fresh derivation and "
                     "every pinned binary hashes to the digest in the file")
    else:
        lines.append("  RESULT      : DISAGREES")
        for diff in report.differences:
            lines.append(f"    DIFFERS   : {diff.describe()}")
        for mismatch in report.hash_mismatches:
            lines.append(f"    RE-HASH   : {mismatch}")
        for bad in report.unreadable:
            lines.append(f"    UNREADABLE: {bad}")
    lines += ["", NOT_CHECKED]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools/audit-tool-pins.sh",
        description="Audit the pins file this run would use against a fresh derivation "
                    "(agents-5vun). Detects and reports; it does not authenticate the file.")
    parser.add_argument("--pins", default=None, metavar="PATH",
                        help="the pins file to audit (default: the dispatcher's own selection)")
    parser.add_argument("--lookup-path", default=DEFAULT_LOOKUP, metavar="DIRS",
                        help=f"lookup dirs for the fresh derivation (default: {DEFAULT_LOOKUP})")
    args = parser.parse_args(argv)
    report = audit(pins_arg=args.pins, lookup=args.lookup_path)
    print(render(report))
    if report.error:
        return 2
    if report.rederivation_error:
        return 2
    return 1 if report.disagrees else 0


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI wrapper
    sys.exit(main())
