#!/usr/bin/env python3
"""Structural redaction for everything the factory publishes.

A finding's `snippet` is whatever the deterministic scanner matched — for `secret-scan`
that is the credential itself. Three boundaries decide what happens to it: the local delta
report (which the composite action appends to a public step summary), tracker sinks
(beads / GitHub Issues), and scanner stdout. Scanner stdout is the strict one — it carries
no matched text at all, dropping the match fields rather than masking them, because a
terminal or CI log cannot be un-published (see `stdout_safe_report`, agents-qslz).

THE RULE IS PER CHANNEL (agents-qslz, second review): dropping `candidate_id` is SECRECY on
scanner stdout and HYGIENE on the sink and report channels. Stdout runs on raw candidates
before ingestion, so it carries NO fingerprint — the id is the only digest of the matched
text in that payload, and dropping it is what keeps a confirmation oracle off the terminal.
The sink and report channels publish the fingerprint by design (THREAT_MODEL.md), and for an
id-bound row that fingerprint is already an oracle over the same value, so withholding the
id there is hygiene. The same drop is a different kind of rule per channel; do not collapse
them.

The rule here is structural, never a prompt. Non-negotiable #2: a model is not a
containment boundary, so nothing relies on the triage model choosing not to repeat what
it was shown. Two layers:

1. `CREDENTIAL_AGENTS` are agents whose candidates are credentials by construction.
   Their snippets never leave as text at all — replaced wholesale with a location, so an
   unrecognised credential format cannot slip through either.
2. Every other published string is passed through `mask_text`, which masks anything
   shaped like a credential a model may have echoed into a title, description or
   remediation.

Raw values stay in the local, gitignored run artifacts and findings store: a human has to
be able to see what leaked in order to rotate it. Redaction applies at the publish
boundary, not at ingestion, so fingerprints and the lifecycle stay stable.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Agents whose candidate snippets are credentials by construction (see agents/*/SKILL.md).
CREDENTIAL_AGENTS = frozenset({"secret-scan"})

# Second, independent trigger: the scanner rule that matched. Either signal can be absent,
# so a finding is treated as credential-bearing when either one fires. Over-dropping a
# snippet is the safe failure — the rule, location, description and remediation still ship.
CREDENTIAL_RULE_HINTS = ("key", "secret", "token", "credential", "password", "private")

# Broader than CREDENTIAL_AGENTS: agents whose findings carry raw source excerpts or model
# prose that can quote a secret whose shape the patterns do not recognise (a DB URL with a
# password, a JWT, a private key quoted in prose). Their snippet, description and raw context
# are withheld at rest (see redact_for_storage) — a model is not a containment boundary, so
# none of that prose is trusted for these (agents-4zg). lib/embargo.py's identity-critical
# routing uses the same agent set.
SECURITY_SENSITIVE_AGENTS = CREDENTIAL_AGENTS | frozenset({
    "threat-model",
    "vuln-discovery",
    "vuln-triage",
    "vuln-verify",
})

# Rule-id hints that mark a finding security-sensitive even when the agent is unknown. Over-
# matching only withholds more prose, never less (agents-4zg).
SECURITY_RULE_HINTS = CREDENTIAL_RULE_HINTS + ("tm-", "threat", "vuln", "exploit", "cve")

# Kept aligned with the scanner's own suite in agents/secret-scan/scripts/scan.py, so the
# factory masks exactly the shapes it claims to detect. Add a pattern in both places.
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("github-pat", re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    ("generic-api-key", re.compile(r"""(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,80}['"]""")),
    ("jwt-token", re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# A value does not only leak through the assignment the scanner matched: a triage model that has
# been shown a candidate can quote the value on its own in prose ('the key is sk-…'), which the
# assignment-shaped patterns above do not see. These match vendor prefixes anywhere in a string,
# and PEM blocks whole rather than only their header.
BARE_PATTERNS = [
    ("openai-key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}")),
    ("stripe-key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("google-oauth", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("gitlab-pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{36}")),
]

# Whole-block shapes must run before any pattern that matches only their header, or the header is
# replaced first and the body can no longer be recognised (agents-tcd re-review).
BLOCK_PATTERNS = [
    ("pem-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
]

ALL_PATTERNS = BLOCK_PATTERNS + BARE_PATTERNS + PATTERNS

# Derived text for a credential finding: scanner-controlled facts only. The triage model's own
# words are never published for these, because they cannot be checked for an echo of a value
# whose shape is unknown. The local run artifact keeps the model's notes for the responder.
WITHHELD_NOTE = (
    "Published summaries withhold the matched value and the triage notes for credential "
    "findings; both remain in the local run artifact."
)
GENERIC_REMEDIATION = "Rotate the credential, remove it from source, and re-run the scan."

# Every field that is *rendered* into a published surface. Identity fields are in here on purpose:
# `path`, `rule_id` and `severity` reach this layer as model-returned strings — process_run does not
# bind them to scanner output — so a value can be smuggled through any of them, and the reviews
# proved it for `path`, `rule_id` and for non-string containers anywhere in the set. `state` and
# `change` are store-controlled enums rather than model output, but they are rendered, so they are
# coerced too; the dispatch filters that read them simply match nothing if one is malformed.
# CHECKLIST FOR ADDING A RENDERED FIELD (agents-ag4, after a review found a real leak):
# a field on a finding record is a publication channel by default - redact_finding copies every
# field of the record, and the store, the delta report and the step summary are all rendered from
# its output. Before adding one:
#   1. add it to RENDERED_TEXT_FIELDS below, or it is copied verbatim;
#   2. add an IDENTITY_SHAPES entry if its legitimate shape is known, with a FAIL-CLOSED EMPTY
#      fallback rather than a placeholder a reader could mistake for a real value;
#   3. decide explicitly whether it belongs in lib/findings.py compute_fingerprint. Model-supplied
#      text must NOT: the fingerprint is identity (dedup, the new/fixed/regressed delta, suppression
#      keying), so folding one in re-books every stored record;
#   4. if it is model prose, decide whether it may be published at all. Where prose cannot be checked
#      for an echo of a value whose shape is unknown - a credential finding, or any security-sensitive
#      agent - it must be DROPPED, not masked. model_rule_id is the worked example; see
#      redact_finding's two withholding branches and tests/test_model_rule_id.py.
RENDERED_TEXT_FIELDS = (
    "agent", "title", "description", "remediation", "snippet",
    "path", "rule_id", "model_rule_id", "severity", "suppression_reason", "line_number",
    "state", "change",
)

# THE STDOUT CHANNEL IS AN ALLOWLIST, not a denylist (agents-h0mb, coord's ruling after the
# iukb census). The function's own docstring always described an allowlist - "the channel carries
# the keys its readers need and nothing else" - while the implementation was a denylist (drop the
# named match fields, mask every other string), and the census proved the gap: eight fields across
# the real stations carry repository-derived free text under names no drop list knew
# (context_snippet, source_context, context_window, preview_head, recent_diff_excerpt,
# readme_excerpt, body, comments). Naming them would fix eight instances and keep the defect for
# the ninth field added next month, so the policy is inverted: a key survives on stdout only
# because a READER of the channel consumes it, and everything else is dropped whatever its name
# and whatever its shape. The reader census behind STDOUT_REPORT_KEYS is recorded in
# stdout_safe_report's docstring and pinned by tests/test_redaction.py.
#
# The keys a reader of the stdout channel consumes: the identity of each candidate (rule, path,
# location, severity) for the terminal/CI reader, and nothing else. Every other string is dropped
# unnamed; a container is dropped unnamed (nested containers are a consequence, not a special
# case); only small non-string scalars pass by shape, because a number, bool or None cannot carry
# repository-derived text. The --output file keeps the raw record, so dropping here removes no
# information a human needs to rotate a credential.
STDOUT_REPORT_KEYS = frozenset({"rule_id", "path", "line_number", "severity"})

# The one container the channel carries: the candidate list itself, which is what every reader
# (the terminal, and the tests that parse a station's stdout) actually consumes. Each item is a
# candidate dict and gets the same allowlist, so a list item is held to exactly the rule a
# top-level field is held to.
STDOUT_CANDIDATES_KEY = "candidates"


# Identity fields (`agent`, `rule_id`, `path`) are rendered, and they reach this layer as
# strings the triage model returned — process_run does not bind them to scanner output — so a value
# can be smuggled through them. They are the only fields where the *shape* of a legitimate value is
# known, so they get a shape check as well as masking: a long opaque run is not a rule id or a
# path segment, and the field falls back to a placeholder rather than publishing it. Fail-closed,
# and cosmetic only — the raw value is still in the local run artifact.
IDENTITY_SHAPES = {
    "agent": (re.compile(r"[A-Za-z0-9_.-]{1,64}"), "unknown-agent"),
    "rule": (re.compile(r"[A-Za-z0-9_.:-]{1,64}"), "unclassified"),
    # The model's own label, treated exactly like a rule id - same shape, same fail-closed
    # fallback - except that a refused label becomes empty rather than "unclassified": there
    # is no label to show, and inventing one would be the thing this field exists to avoid.
    # ACCEPTED LIMIT, stated here because this is where the shape is declared: for a credential
    # finding and for any security-sensitive agent the label is DROPPED OUTRIGHT in
    # redact_finding, never masked, so for those records this shape is never what saves it. The
    # reason is that these are exactly the cases where the shape of a value cannot be known - a
    # label under 20 characters, or one broken up by delimiters, matches this pattern and
    # OPAQUE_RUN both while still being a secret, and a mask that cannot be proven sufficient is
    # not a mask. The raw label stays in the model's own output in the run artifact.
    "model_rule": (re.compile(r"[A-Za-z0-9_.:-]{1,64}"), ""),
    "path": (re.compile(r"[A-Za-z0-9_. /-]{1,200}"), "unknown"),
}
OPAQUE_RUN = re.compile(r"[A-Za-z0-9]{20,}")


def sanitise_identity(value: Any, kind: str) -> Any:
    """Return `value` if it looks like the identity field it claims to be, else a placeholder."""
    if not isinstance(value, str) or not value.strip():
        return value
    pattern, placeholder = IDENTITY_SHAPES[kind]
    if pattern.fullmatch(value) and not OPAQUE_RUN.search(value):
        return value
    return placeholder


# A rendered field that is not text still reaches an f-string, which serialises its repr — so a
# dict or list carrying the matched value publishes the value. Only scalars may become text; a
# container becomes a placeholder. (agents-tcd third review: the type boundary, not the text.)
PLACEHOLDER = "[redacted:value]"


def publishable_text(value: Any) -> Any:
    """Coerce one rendered field to text, or to a placeholder if it is not a scalar."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        return str(value)
    return PLACEHOLDER


# A line number is a small positive integer. The bound applies to ints as well as to numeric
# strings, because an integer carries a matched value just as happily as text does — and being
# non-text it never reaches literal masking on its own (agents-tcd fourth review).
MAX_LINE_NUMBER = 9_999_999


def publishable_line_number(value: Any, literals: set = frozenset()) -> Any:
    """A line number in range, or the unknown marker. Never a value that could carry a secret.

    Delegates line validity to lib.line_numbers.usable_line_number (agents-ghtz, agents-wnad):
    a usable line is a 1-based positive int. 0 and negative values are unknown location markers
    ('?'). Values exceeding MAX_LINE_NUMBER or matching secret literals are also redacted to '?'.
    """
    try:
        from lib.line_numbers import UNKNOWN_LINE_MARKER, usable_line_number
    except ImportError:
        try:
            from line_numbers import UNKNOWN_LINE_MARKER, usable_line_number
        except ImportError:
            UNKNOWN_LINE_MARKER = "?"

            def usable_line_number(v: Any) -> Optional[int]:
                if isinstance(v, bool):
                    return None
                if isinstance(v, int):
                    return v if v > 0 else None
                if isinstance(v, str):
                    s = v.strip()
                    if s.isascii() and s.isdigit():
                        n = int(s)
                        return n if n > 0 else None
                return None

    number = usable_line_number(value)
    if number is None or not (1 <= number <= MAX_LINE_NUMBER):
        return UNKNOWN_LINE_MARKER
    # Same protection every other rendered field gets: if the number *is* a value the scanner
    # matched, it does not get published just because it happens to be small.
    rendered = str(number)
    if mask_literals(rendered, literals) != rendered:
        return UNKNOWN_LINE_MARKER
    return number


def mask_text(value: Any) -> Any:
    """Mask anything credential-shaped in `value`. Non-strings pass through untouched."""
    if not isinstance(value, str):
        return value
    masked = value
    for name, pattern in ALL_PATTERNS:
        masked = pattern.sub(f"[redacted:{name}]", masked)
    return masked


def matched_literals(finding: Dict[str, Any]) -> set:
    """The values this finding's scanner actually matched.

    A model shown a candidate can quote the value on its own in prose ('the key is zkq…'), which
    no pattern sees because the assignment context is gone. So collect the value the scanner
    handed us, and — when a credential pattern matched somewhere in the same text — every
    token-shaped run in it, which is what a bare echo of that value looks like.
    """
    literals = set()
    texts = []
    for field in ("snippet", "raw_match"):
        value = finding.get(field)
        if isinstance(value, str) and value.strip():
            texts.append(value)
            if field == "raw_match":
                literals.add(value.strip())

    pattern_matched = False
    for value in texts:
        for _, pattern in ALL_PATTERNS:
            for match in pattern.findall(value):
                pattern_matched = True
                matched = match if isinstance(match, str) else "".join(match)
                literals.add(matched)
                # The value inside an assignment is a separate literal from the assignment.
                literals.update(re.findall(r"""['"]([^\s'"]{8,})['"]""", matched))

    if pattern_matched:
        for value in texts:
            literals.update(re.findall(r"[A-Za-z0-9_\-/+=]{16,}", value))
    else:
        # No known pattern matched, so this came from a scanner whose rules we do not share
        # (gitleaks). Its candidates hand us the value itself, so a short whitespace-free
        # snippet is the literal to mask wherever it is echoed.
        snippet = finding.get("snippet")
        if isinstance(snippet, str):
            snippet = snippet.strip()
            if 8 <= len(snippet) <= 200 and not re.search(r"\s", snippet):
                literals.add(snippet)

    return {literal for literal in literals if isinstance(literal, str) and len(literal) >= 8}


def mask_literals(value: Any, literals: set) -> Any:
    if not isinstance(value, str):
        return value
    masked = value
    for literal in sorted(literals, key=len, reverse=True):
        if literal in masked:
            masked = masked.replace(literal, "[redacted:value]")
    return masked


def is_credential_finding(finding: Dict[str, Any]) -> bool:
    """True when this finding's matched text is a credential by construction."""
    if str(finding.get("agent") or "") in CREDENTIAL_AGENTS:
        return True
    rule_id = str(finding.get("rule_id") or "").lower()
    return any(hint in rule_id for hint in CREDENTIAL_RULE_HINTS)


def is_security_sensitive_finding(finding: Dict[str, Any]) -> bool:
    """True when a finding's raw material must never leave this machine unredacted.

    Credentials (secret-scan or a credential rule hint) plus security findings by construction
    (threat-model, vuln-*). For these the snippet and model prose can quote a secret whose
    shape the patterns do not recognise, so they are withheld wholesale rather than masked.
    """
    if str(finding.get("agent") or "") in SECURITY_SENSITIVE_AGENTS:
        return True
    rule_id = str(finding.get("rule_id") or "").lower()
    return any(hint in rule_id for hint in SECURITY_RULE_HINTS)


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a publishable copy of `finding` with credential-bearing text removed.

    A copy, because the caller persists delivery receipts and keeps the raw local record.

    Every rendered field is masked, identity fields included, and a credential finding
    (by agent or by rule id) publishes **derived text only**: its rule, location, severity
    and fingerprint. The triage model's own words are never published for those, because
    prose cannot be checked for an echo of a value whose shape is unknown; the value and
    the notes stay in the local run artifact for whoever has to rotate the credential.
    """
    published = dict(finding)
    # The candidate id is an INTERNAL identity key, scanner-owned rather than model prose, so this is
    # not a masking case under the checklist - it is withheld outright, the same shape as
    # model_rule_id's withholding branches (agents-p8og). It stays in the LOCAL store, where the
    # second-order stations read it, and is never a publication channel.
    #
    # WHY IT GOES, and this is HYGIENE, NOT SECRECY (coord's channel standard, agents-qslz): a
    # published consumer has no use for an internal key, and this channel's readers are not among its
    # consumers. Withholding it does NOT protect the match. For a row bound by its candidate id the
    # PUBLISHED fingerprint is sha256(agent:rule:path:candidate_id) - a digest of this same value,
    # printed right beside the same rule and path - so that oracle is already public and anyone can
    # test a guess against it without ever seeing the id. Removing a rawer digest that no reader of
    # this channel needs is harm reduction; it is not containment, and the next reader must not
    # reason from it as though it were.
    published.pop("candidate_id", None)
    agent = str(finding.get("agent") or "")
    literals = matched_literals(finding)
    credential = is_credential_finding(finding)
    security = is_security_sensitive_finding(finding) and not credential

    # Untrusted text goes through both layers: known shapes, and the literal the scanner
    # matched wherever a model has re-quoted it. Non-strings (line numbers) pass through.
    for field in RENDERED_TEXT_FIELDS:
        if field not in published:
            continue
        if field == "line_number":
            published[field] = publishable_line_number(published[field], literals)
            continue
        published[field] = mask_literals(mask_text(publishable_text(published[field])), literals)

    # Shape-check the fields whose legitimate form is known. After masking, so a recognised
    # shape is reported as masked rather than dropped.
    for field, kind in (("agent", "agent"), ("rule_id", "rule"),
                        ("model_rule_id", "model_rule"), ("path", "path")):
        if field in published:
            published[field] = sanitise_identity(published[field], kind)

    # Derived text is built from the *masked* values, so it cannot reintroduce anything.
    location = f"{published.get('path')}:{published.get('line_number', '?')}"
    rule = published.get("rule_id") or "credential"

    if credential:
        published["snippet"] = f"[redacted:{agent or 'credential'} match at {location}]"
        published["title"] = f"{rule} match at {location}"
        # agents-ag4, review P0: a model-authored label is prose, and prose cannot be checked for
        # an echo of a value whose shape is unknown - which is why this branch publishes derived
        # text only. A label under 20 chars, or one broken up by delimiters, evades both the
        # pattern mask and OPAQUE_RUN, so it must not be kept here at all. The raw label is still
        # in the local run artifact for whoever has to rotate the credential.
        published["model_rule_id"] = ""
        # agents-5gg: non-secret-scan agents are models, not deterministic scanners;
        # report their origin faithfully rather than attributing to a scanner.
        if agent in CREDENTIAL_AGENTS:
            published["description"] = (
                f"The deterministic scanner matched `{rule}` at `{location}`. {WITHHELD_NOTE}"
            )
        else:
            published["description"] = (
                f"The {agent or 'credential'} agent reported `{rule}` at `{location}`. {WITHHELD_NOTE}"
            )
        published["remediation"] = GENERIC_REMEDIATION
    elif security:
        # A non-credential security finding (threat-model, vuln-*): its snippet and
        # description are model prose that can quote a secret whose shape the patterns do not
        # recognise, so drop the raw source excerpt and the prose wholesale. The title is kept
        # (it is the short human label the store and andon display on) — only masked.
        published["snippet"] = "[withheld]"
        published["description"] = "[withheld]"
        published["remediation"] = "[withheld]"
        # agents-ag4, review P1: same reason - this branch withholds model prose wholesale
        # because it can quote a secret of unrecognised shape, and a label is model prose.
        published["model_rule_id"] = ""

    if "raw_match" in published:
        published["raw_match"] = (
            "[redacted]" if (credential or security) else mask_literals(published["raw_match"], literals)
        )

    return published


def redact_for_storage(finding: Dict[str, Any]) -> Dict[str, Any]:
    """The at-rest scrubber: `redact_finding` PLUS what the LOCAL store must keep (agents-p8og).

    There are two boundaries and they are not the same one:
      * `redact_finding` protects everything that LEAVES this machine as a published finding
        (tracker sinks, the delta report, the step summary). On THOSE channels `candidate_id`
        is withheld as HYGIENE rather than secrecy: the fingerprint IS published there by
        design, and for an id-bound row it is a digest of that same id, so the oracle is
        already public and withholding the rawer digest protects nothing (agents-qslz, per
        coord's channel standard). Scanner stdout is NOT one of those channels: it is written
        by `stdout_safe_report`, a separate function, NOT through `redact_finding`, and it
        publishes NO fingerprint at all - the fingerprint is computed downstream, when a
        scanner's output is ingested. So on stdout the same drop is SECRECY, not hygiene: the
        id is the only digest of the match in that payload. Do not extend this function's
        hygiene reasoning to the stdout channel - the rule is per channel.
      * this function protects the store AT REST. The store is local and gitignored, and it is the
        only place a second-order station can read a candidate's emitted identity, so the id has to
        survive here or the persistence is pointless.

    Collapsing the two was a real defect, caught in review: putting the drop in `redact_finding`
    also stripped the id on the way TO DISK, because save() calls this path - so the branch stored
    nothing and every test that asserted the in-memory return value still passed. Hence a named
    function: the two policies can now differ on purpose and each has a test, which is also what the
    comment at the top of this module has referred to since agents-4zg without ever having it.
    """
    stored = redact_finding(finding)
    if finding.get("candidate_id"):
        stored["candidate_id"] = finding["candidate_id"]
    return stored


def redact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [redact_finding(f) for f in findings]


def stdout_safe_report(report: Any) -> Any:
    """Return a copy of a scanner candidate report carrying only what the channel's readers need.

    THE POLICY IS AN ALLOWLIST (agents-h0mb, coord's ruling after the agents-iukb census),
    because the previous denylist did not do what this docstring always claimed: it said "the
    channel carries the keys its readers need and nothing else" while the code dropped a named
    list and masked everything else - and the census of the routed stations found EIGHT fields
    of repository-derived free text that no name list knew (context_snippet, source_context,
    context_window, preview_head, recent_diff_excerpt, readme_excerpt, body, comments). Naming
    those eight would have kept the same defect for the ninth field added next month. So the
    rule is now what the docstring always said: a key survives because a READER consumes it,
    and an unknown key is dropped, whatever its name, its text, or its shape. The safety claim
    holds by construction rather than by enumeration: a new station field carrying source text
    is safe by default, not by someone remembering to add it to a list.

    THE READER CENSUS BEHIND THE ALLOWLIST (enumerated, not sampled):
      * the terminal/CI reader this docstring has always named: rule, path, location, severity;
      * the tests that parse a station's stdout (tests/test_audit_a11y.py,
        tests/test_scan_surface.py, tests/test_audit_deps.py, tests/test_vuln_verify_prepass.py,
        tests/test_prepass_truth.py): they read `candidates`, `candidate_count`, and per
        candidate `rule_id`, `path`, `line_number`;
      * station-to-station consumers: none read stdout. docs-write consumes docs-drift through
        the --output file (prepare_docs_fixes.py), and every other subprocess call in a station
        script parses an EXTERNAL tool's stdout (npm, git, gh, gitleaks), never a station's.
    STDOUT_REPORT_KEYS is exactly that reader set; the small scalars (counts, flags) the
    summaries carry pass by shape because a number, bool or None cannot hold repository text.

    candidate_id is dropped like every other unnamed key, and on THIS channel that drop is
    SECRECY, not hygiene (agents-qslz, second review): this runs on raw scanner candidates
    BEFORE ingestion, so the payload carries no fingerprint and the id - sha256(rule NUL path
    NUL match NUL ordinal)[:16], a 16-hex digest no secret pattern matches - is the only digest
    of the matched text in the payload. On the sink and report channels the fingerprint is
    published by design (THREAT_MODEL.md) and the same drop is only hygiene; the rule is per
    channel and the two must not be collapsed. The raw values remain in the file written by
    `--output`.

    THE DECISION IS MADE ON THE KEY, NEVER ON THE KEY'S TEXT: the membership test below is the
    only thing that decides whether a field survives. A dict key whose TEXT contains a matched
    value is not a member of the allow set, so it is dropped with its value by construction -
    the same construction that drops a nested dict carrying the match. No station legitimately
    emits a matched value as a key name, and the tests pin both halves of that statement.

    Carried strings still pass through mask_text, the outer layer every channel shares, so a
    carried field whose text is credential-SHAPED (a path named after a key) is masked in place.
    That is the whole of what survives of the old masking on this channel: the by-name drop list
    and the matched-literal property it needed are gone, because a channel that carries no
    unnamed text has nothing left for them to catch. A tuple or other non-list container is
    dropped like any unnamed value (no station emits one; noted from review, not widened for).
    """
    if isinstance(report, list):
        # A bare string in a list is text under no name at all, so it cannot survive: the
        # allowlist decides on keys, and a list item has none. Dicts and lists recurse;
        # non-string scalars pass.
        return [item for item in (stdout_safe_report(entry) for entry in report)
                if not isinstance(item, str)]
    if not isinstance(report, dict):
        return report

    safe: Dict[str, Any] = {}
    for key, value in report.items():
        if isinstance(value, (dict, list)):
            # The one carried container is the candidate list the readers consume. Every other
            # container - source_context, ground_truth, metrics, comments - is dropped unnamed:
            # nested repository text is a consequence of the rule, not a special case.
            if key == STDOUT_CANDIDATES_KEY:
                safe[key] = stdout_safe_report(value)
        elif isinstance(value, str):
            # A string survives only as the value of a key a reader consumes, masked for the
            # credential-SHAPED text a carried field can still hold (mask_text is the shared
            # outer layer, not the boundary - the allowlist is the boundary).
            if key in STDOUT_REPORT_KEYS:
                safe[key] = mask_text(value)
        elif isinstance(value, (bool, int, float)) or value is None:
            # A small scalar the summary carries (candidate_count, unlocatable_count, flags):
            # it cannot hold repository-derived text, so it passes by shape, not by name.
            safe[key] = value
        # Anything else - a tuple, bytes, a set - is dropped with the unnamed strings.
    return safe


def emit_station_result(result: Any, output_path: Optional[str], *, summary: Optional[str] = None) -> None:
    """The ONE spelling of a station CLI's output rule (agents-qslz): the file gets the raw
    record, stdout gets the redacted one.

    Every station CLI ends here rather than spelling the branch out itself, because the class of
    defect this closes cannot be enumerated by grepping print sites - some scripts print a
    variable - so the rule has to be a shared helper plus the structural test in
    tests/test_redaction.py that asserts every `--output` script calls it.

    With `output_path`: write the RAW JSON there. It is the local, gitignored record of what
    matched - what a human needs in order to rotate a credential - so it must stay raw. Print
    `summary` if one is given.

    Without `output_path`: stdout goes to a terminal or a CI log, which cannot be un-published,
    so print `stdout_safe_report(result)` and point stderr at `--output`.
    """
    if output_path:
        # The file is the local record of what matched — it is what a human needs in order
        # to rotate a credential, and it is gitignored. Every published render of a finding
        # is masked instead, so write the raw record here only.
        Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        if summary:
            print(summary)
    else:
        # stdout goes to a terminal or a CI log, which cannot be un-published: never emit
        # match text there, whatever shape the credential turns out to be.
        print(json.dumps(stdout_safe_report(result), indent=2))
        sys.stderr.write(
            "Note: stdout redacts matched values. Use --output <file> for the raw local record.\n"
        )
