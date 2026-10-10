"""The line-number sentinel rule, in one place (agents-ghtz).

WHY THIS EXISTS. "Is this a line number, or is the location unknown?" is one rule, and it was
written twice: vuln-verify's `usable_line_number` (agents-fy26) and vuln-triage's
`_parse_line_number` (agents-ajt4). Two copies of one rule drift, and these already had - the
triage copy accepted `0` as a line where the verifier's rejected it. A rule about untrusted
location data is not a place to leave a second spelling.

THE RULE. A usable line is a 1-based positive int. `"?"` is the factory's own unknown marker -
`lib/redaction.publishable_line_number` returns it rather than publish a line it cannot trust -
so `"?"`, `None`, booleans, non-numeric strings and non-positive numbers are all UNKNOWN. The
distinction is the whole point: unknown is NOT line 1 (agents-fy26: it fabricated a location at
the top of the file) and it is NOT line 0 (agents-ajt4: 0 is within 15 of every small line, so a
sentinel coerced to 0 falsely clusters with real findings). Neither direction is allowed - a
caller that wants line 0 has made a category error, not found an edge case.

NOT A CONTAINMENT BOUNDARY. This decides whether a value is a *plausible* line, not whether it
is safe to read: a produced line still goes through `resolve_within_target` to reach the file.
"""

from typing import Any, Optional, Tuple

# The unknown marker lib/redaction.publishable_line_number emits. Named once here so a reader can
# see what "unknown" actually looks like on the wire, rather than inferring it from a rejection
# branch.
UNKNOWN_LINE_MARKER = "?"


def usable_line_number(value: Any) -> Optional[int]:
    """The line as a 1-based positive int, or None when the location is unknown.

    Booleans are rejected before ints because `True` is an int in Python (`True > 0`), and a
    bool that arrived where a line was expected is a shape error, not line 1. Digit strings are
    accepted (scanners emit both), ASCII-only, so a digit-like character that `int()` would
    reject (`"²"`) is unknown rather than a crash.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isascii() and stripped.isdigit():
            number = int(stripped)
            return number if number > 0 else None
    return None


def line_number_sort_key(value: Any) -> Tuple[int, int]:
    """The rule expressed as an ordering: known lines by number, unknown locations LAST.

    A caller that sorted candidates by `value or 0` made an unknown location sort as line 0 -
    which is both wrong (0 is not a line) and dangerous (it lands ahead of every real finding,
    and would compare a string against an int and raise if a marker ever arrived). The leading
    element keeps unknown values in one deterministic block, ordered after every known line, so
    the second element is only ever compared against another unknown and stays a constant.
    """
    line = usable_line_number(value)
    if line is None:
        return (1, 0)
    return (0, line)
