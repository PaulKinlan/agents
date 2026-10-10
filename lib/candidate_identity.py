"""Stable, deterministic identity for a scanner candidate (agents-rdyb).

WHY THIS EXISTS. A finding's identity is computed DOWNSTREAM from (rule id, path, snippet), because
no scanner emits an identity of its own - so the identity has to be RECONSTRUCTED from whatever the
model and the scanner happened to produce, and every step of that reconstruction is a place where a
re-worded model label or a re-quoted line moves it. That is agents-x9my: the reconstruction, and its
step 2 path/location fallback, are the repair. This module is the durable answer, because a station
that emits this id makes downstream identity a COPY of scanner-owned data - and a copy cannot drift
when the model's prose or its rule label changes, in principle rather than by convention.

THE SHAPE, and why every input is scanner-owned:

  rule_id     the scanner's own rule label, never the model's
  path        the scanner's own relative path
  match_text  the exact matched text: `raw_match` when the scanner has one, else its `snippet`. The
              whole line is only the fallback, because a snippet moves when unrelated code on the
              same line is edited while the matched token does not.
  ordinal     which occurrence of that identical (rule_id, path, match_text) this is, IN FILE ORDER
              and 1-based - so two identical matches in one file get distinct ids instead of
              silently sharing one.

THE LINE NUMBER IS DELIBERATELY NOT AN INPUT. Identity is meant to survive a line shift - code
moving down a file changes nothing that matters - and a line-based id would move with it. The
ordinal is what makes dropping the line safe: it separates duplicates without reintroducing a
position-dependent identity.

WHAT IS NOT AN INPUT, and why it is worth saying: nothing the model produces, and nothing that
would need a lookup the scanner cannot do from the files it is already reading (agents-v4q: a rule
registry cannot be inferred from scanner sources, so an id built on one would be a guess wearing a
deterministic label).

CHANGING ANY OF THOSE INPUTS IS A BREAKING CHANGE: it re-keys every stored row for every station
that consumes this id, exactly as a findings-store identity change does. CANDIDATE_ID_SCHEME is
recorded in the artefact envelope so that a future change is DETECTABLE rather than silent - the
scheme stamp that made agents-x9my's migration visible instead of mysterious.
"""

import hashlib
from typing import Any, Dict, Iterable, Optional, Tuple

# The shape of the id. Bump when an input to candidate_identity changes: an artefact then says which
# shape wrote it, and a consumer can tell a re-key from real movement instead of guessing.
CANDIDATE_ID_SCHEME = 1

# The field a station writes on each candidate. NOT `id`: three stations already use `id` for
# something else (issue ids in issue-triage, DOM element ids in accessibility, entry-point ids in
# threat-model), so `id` would collide with existing meanings rather than add one (agents-rdyb).
CANDIDATE_ID_FIELD = "candidate_id"

# Sibling key of `candidates` in the artefact envelope, carrying CANDIDATE_ID_SCHEME.
CANDIDATE_ID_SCHEME_FIELD = "candidate_id_scheme"

_MATCH_TEXT_FIELDS = ("raw_match", "snippet")


def candidate_match_text(candidate: Dict[str, Any]) -> str:
    """The scanner-owned text a candidate's identity is built on.

    `raw_match` wins because it is the token the rule actually matched; `snippet` (usually the whole
    line) is the fallback for the stations that do not emit one. An empty string when the candidate
    carries neither, which keeps the id deterministic rather than raising on a sparse record.
    """
    for field in _MATCH_TEXT_FIELDS:
        value = candidate.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def candidate_identity(rule_id: Any, path: Any, match_text: str, ordinal: int = 1) -> str:
    """A deterministic id for one candidate location. See the module docstring for the shape.

    NUL-separated so that a path or rule containing the separator cannot be confused with another
    candidate's fields, and truncated to 16 hex characters (64 bits): this is an identity label for
    a per-run candidate set, not a security boundary.

    AN IDENTIFIER, NOT A SECRET, and the distinction is worth stating where the construction lives
    because it is easy to reason about backwards. Every input here is published or guessable, and
    there is no secret or per-install salt in the digest, so anyone holding the id TOGETHER WITH the
    rule, path and ordinal can test a guess at the matched text - and for a short human-chosen value
    that search is trivial (measured: recovered in eight guesses with the rest held). Withholding the
    id from a published surface (lib/redaction.py) is therefore NOT a guessing defence: for a row
    bound by its candidate id, the PUBLISHED fingerprint is a digest of that same id, so that oracle
    is already public there. What withholding buys is narrower and mundane - a consumer has no use
    for the value - and it should be described that way. Treat this digest as provenance, never as
    containment (agents-7928).
    """
    payload = "\x00".join([
        str(rule_id or "").strip(),
        str(path or "").strip(),
        str(match_text or "").strip(),
        str(int(ordinal)),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def assign_candidate_ids(candidates: Iterable[Any]) -> int:
    """Set `candidate_id` on every candidate, in list order, and return how many were set.

    Call this ONCE, on the full candidate list, immediately before the artefact is written: the
    ordinal is the position among identical (rule_id, path, match_text) matches as the scanner
    walked the target, so it is only meaningful when the whole list is in that order. Entries that
    are not dicts are counted in the order but left alone, matching how the readers of these
    artefacts skip records they do not understand.

    Idempotent: recomputing a candidate that already carries an id yields the same value.
    """
    seen: Dict[Tuple[str, str, str], int] = {}
    assigned = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        key = (str(candidate.get("rule_id") or "").strip(),
               str(candidate.get("path") or "").strip(),
               candidate_match_text(candidate))
        seen[key] = seen.get(key, 0) + 1
        candidate[CANDIDATE_ID_FIELD] = candidate_identity(*key, ordinal=seen[key])
        assigned += 1
    return assigned


def artefact_scheme_fields() -> Dict[str, int]:
    """The envelope keys a station adds beside `candidates`, so the id's shape is recorded."""
    return {CANDIDATE_ID_SCHEME_FIELD: CANDIDATE_ID_SCHEME}
