#!/usr/bin/env python3
"""Findings Store and State Machine for Software Factory.

Handles finding identity (excluding line numbers), deduplication, lifecycle
state transitions (new -> accepted | wontfix -> fixed -> regressed), and
sink dispatch (file, beads). Public GitHub issues are no longer a finding sink
(agents-eyo): findings file to beads; public input is triaged separately and
`promote_issue` is the explicit, human-approved issue -> bead link.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent

# The committed suppressions register. AGENTS.md's noise-control contract requires a written
# reason in a *committed* file; the old per-target JSON was gitignored, so that contract could
# not be satisfied by any path (agents-411).
SUPPRESSIONS_FILENAME = "suppressions.yaml"


class SuppressionFileError(ValueError):
    """The suppressions register cannot be parsed. Loud, never a silent empty dict."""


class StoreFileError(ValueError):
    """The findings store cannot be read or parsed. Loud, never a silent empty store.

    Resetting a corrupt or truncated store to ``{"findings": {}}`` would re-book every prior
    finding as new and re-file duplicates, so a store that exists but cannot be decoded raises
    instead (agents-3ls).
    """


# The store lock is advisory mutual exclusion between writers (agents-3ls). The WAIT for it was
# unbounded, which cost a reviewer an entire deadline: a blocked lane produces no verdict at all, and
# the failure mode of an unbounded wait is SILENCE rather than an error (agents-4sij). The bound is a
# default rather than a policy, so a lane running a long gate can raise it per process.
STORE_LOCK_TIMEOUT_SECONDS = 10.0
STORE_LOCK_POLL_SECONDS = 0.05
STORE_LOCK_TIMEOUT_ENV = "FACTORY_STORE_LOCK_TIMEOUT"


class StoreBusyError(ValueError):
    """Another process holds the store lock and the bounded wait expired.

    Deliberately NOT a subclass of StoreFileError: contention is not a corrupt or unreadable store,
    and a caller that catches store errors broadly must not silently treat a busy store as a broken
    one. The message names the holder and since when, because a lane that can see "held by pid N
    since T" can decide to wait or work elsewhere, while one that sees a generic failure retries
    blindly and one that sees nothing at all - the behaviour this replaces - simply stops.
    """


def _lock_holder_description(lock_path: Path) -> str:
    """Who holds the lock, from the metadata the holder writes when it takes it (agents-4sij)."""
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "holder unknown (the lock file could not be read)"
    if not raw:
        return ("holder unknown (no metadata in the lock file - a build predating this field, or a "
                "process that did not write it, may hold it)")
    return raw

try:  # imported as lib.findings (root on sys.path), or run as a script (lib/ on it)
    from lib.redaction import redact_finding, redact_for_storage, redact_verification_for_storage
except ImportError:
    sys.path.insert(0, str(FACTORY_ROOT))
    from lib.redaction import redact_finding, redact_for_storage, redact_verification_for_storage

# Redaction removes the value from published text; the embargo decides whether a finding is
# routed to a tracker at all. It is a separate module so the policy has one home and one test.
from lib import sinks
from lib.embargo import (effective_severity, embargo_reason, is_false_positive,
                         reported_severity)
# Host-side trusted tools are resolved by absolute path + SHA-256 pin (agents-7bj); a
# mismatch fails closed rather than executing an unverified gh/bd.
from lib.tool_pins import ToolPinError, resolve_tool
from lib.sinks.github import promote_issue
# "Is this a line number, or is the location unknown?" is ONE rule, in lib/line_numbers.py
# (agents-ghtz). The re-key counter needs it: an unknown location is not an EXACT one (agents-yh0z),
# and the rule also normalises a digit string to its int, so a stored "12" and a scanned 12 are the
# same line instead of two spellings of it.
from lib.line_numbers import usable_line_number


# Keys of a per-run delta. `false_positive` counts findings the triage itself declared false
# positives: they are recorded, never counted as new/unchanged work (journal-35w).
DELTA_KEYS = ("new", "regressed", "fixed", "unchanged", "suppressed", "false_positive",
              # Not a table column: a one-time identity re-key count, announced as its own banner so
              # a migration wave cannot be read as discoveries (agents-x9my step 2, agents-1ukp).
              "migrated",
              # Not a table column: a subset counter beside `fixed` (which remains the total).
              # Counts disappearances of rows with no stable anchor (identity_source outside
              # IDENTITY_STABLE_SOURCES), announced as a banner under the counts table (agents-6r8y).
              "fixed_unanchored",
              # The APPEARANCE-side counterpart (agents-l606): a subset counter beside `new`,
              # counting new findings whose identity rests on model prose (see _unanchored_new_note).
              "new_unanchored",
              # Not a table column: an INFORMATION counter beside `new` (agents-l606). Counts new
              # findings that share a location with a row THIS SAME RUN booked Fixed, i.e. the pairs
              # that may be one finding that moved key. DELIBERATELY NOT A RECLASSIFICATION: three
              # reproductions (agents-wcki, agents-l3j1, agents-hci2, and one of my own that bypassed
              # a fail-closed tracker check) showed a location cannot distinguish a re-key from a
              # finding appearing where an old one retired, so the delta DISCLOSES the ambiguity and
              # changes nothing that a reader or a sink acts on.
              "possible_rekey",
              # The ANCHORED, CROSS-STATION subset of the same information counter, beside it and
              # never inside it (agents-09wf, decision agents-u2xe option (a)+(c)). `possible_rekey`
              # requires BOTH sides to be prose-bound, so a location twin with a stable anchor on
              # either side was silently dropped from it; this counter discloses those pairs instead
              # of reclassifying them. It is CROSS-STATION ONLY: a station-local anchored pair stays
              # refused, because there the anchor IS comparable and "the anchor would have matched"
              # is exactly what makes it not a re-key. No id value is ever compared across stations
              # here - `candidate-id` is assigned per station at scan time and copied rather than
              # re-derived, so at run scope there is no run-level anchor for it to match. Two
              # counters, disjoint by construction: this one counts at least-one-anchored pairs, the
              # other counts both-prose-bound pairs, and neither value can move the other.
              "possible_rekey_anchored",
              # Model echoes are not scanner selection. Count invalid/unshown identities and
              # contradictions with a fact-bound id without changing the fact binding (agents-hoxs).
              "anchor_unknown", "anchor_disagreement")

def normalize_text(text: Any) -> str:
    """Strip and collapse internal whitespace to make fingerprint resilient to reformatting.

    A malformed field (the model returned a dict or a number instead of text) is coerced rather
    than allowed to raise: identity has to stay deterministic, and a crash here would abort the
    whole run before the publish boundary can sanitise anything. Publishing is a separate gate —
    see lib/redaction.py.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return re.sub(r"\s+", " ", text.strip())

def normalize_path(path: Any) -> str:
    """The one path normalization used for fingerprints and candidate binding."""
    if not isinstance(path, str):
        return ""
    return path.replace("\\", "/").strip().lstrip("./")

def path_resolves_in_target(path: Any, target_dir: Optional[Path]) -> bool:
    """True when `path` names an existing entry inside `target_dir` (agents-0tl).

    Used by `bind_candidates` and by the verifier's location guard (lib/report_schema.py) for
    one question: is this location real? The anti-hallucination guard exists to stop a model
    inventing a location, so a path that actually exists must never be destroyed by it.

    Containment is enforced against the *resolved* target, so neither a traversal
    (`../../etc/passwd`) nor an absolute path outside the tree can masquerade as a location.
    A missing/empty path, or no target to check against, is not resolvable.
    """
    if not isinstance(path, str) or not path.strip():
        return False
    if target_dir is None:
        return False
    try:
        root = Path(target_dir).resolve()
    except OSError:
        return False
    if not root.is_dir():
        return False
    raw = path.strip()
    try:
        candidate = Path(raw).resolve() if os.path.isabs(raw) else (root / raw).resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return False
    if candidate == root:
        # The root is not a location. `relative_to` accepts it, so a bare "." / "./" (or
        # "subdir/..") would otherwise count as citing something; lib/path_security.py refuses
        # resolve-to-target-dir for the same reason.
        return False
    return candidate.exists()

def compute_fingerprint(agent: str, rule_id: str, path: str, snippet: str) -> str:
    """Compute stable fingerprint: sha256(agent:rule_id:normalized_path:normalized_snippet).
    
    Deliberately excludes line numbers to survive refactor churn.
    """
    norm_path = normalize_path(path)
    norm_snippet = normalize_text(snippet)
    key = f"{agent}:{rule_id}:{norm_path}:{norm_snippet}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()

def _hashable_line(value: Any) -> Any:
    """The line number as a dict key, or None when it cannot be one (agents-q0mt).

    The redaction contract is FAIL-CLOSED on non-scalar fields: a malformed value is coerced or
    dropped, never crashed on. A line_number that arrives as a dict or list used to reach the
    location counting below and raise `TypeError: unhashable type`, exiting the CLI 1 - the same
    treatment the landed unknown-line handling (agents-fy26) gives a line the scanner could not
    name. Returning None makes every lookup miss, which is the fail-closed outcome: the finding
    keeps the model's identity rather than being dropped or crashing the run.
    """
    try:
        hash(value)
    except TypeError:
        return None
    return value


def load_candidate_index(candidates_file: Path) -> Optional[Dict[str, Any]]:
    """The scanner's authoritative rule ids and paths, for binding model output (agents-nha).

    Returns None when the payload carries no candidate list or neither field, so an agent with
    no deterministic pre-pass — or one whose candidates are not location-shaped, like
    issue-triage's issue records — keeps the model's values.
    """
    try:
        data = json.loads(candidates_file.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Warning: could not read candidates {candidates_file}: {e}\n")
        return None

    candidates = data.get("candidates") if isinstance(data, dict) else data
    if not isinstance(candidates, list):
        return None

    rule_ids = set()
    paths = set()
    # The scanner's own snippet per location, so a finding's identity does not depend on how
    # the triage model chose to quote the line this time (fleet-oed).
    snippets_at: Dict[Tuple[str, str, Any], str] = {}
    snippets_in: Dict[Tuple[str, str], List[str]] = {}
    # The same snippet indexed by LOCATION ALONE, for findings whose rule label bound nothing - the
    # population where identity used to rest on the model's re-wording (agents-x9my step 2). Only
    # UNAMBIGUOUS locations are kept: a (path, line), or a path, with exactly one distinct snippet.
    by_path_at: Dict[Tuple[str, Any], List[str]] = {}
    by_path: Dict[str, List[str]] = {}
    # The scanner's raw match per location, so deterministic dummy detection can see the exact
    # matched value even when the triage model masks its snippet (agents-3r7).
    raw_matches_at: Dict[Tuple[str, str, Any], str] = {}
    raw_matches_in: Dict[Tuple[str, str], List[str]] = {}
    # The scanner's baseline severity per (rule, path), so a triage model's severity flip can
    # be clamped back to the deterministic pre-pass (agents-964).
    severities: Dict[Tuple[str, str], str] = {}
    # The candidate's own emitted identity (agents-rdyb), keyed exactly like the snippets above, so
    # a finding that binds to a candidate can COPY that candidate's identity rather than quote a
    # line the model re-words. This is what removes the reconstruction layer instead of making it
    # safer (agents-q0mt): identity becomes scanner-owned data, and the two-findings-one-path case
    # that the step-2 location fallback had to REFUSE is now resolvable, because each candidate
    # says which one it is.
    ids_set: set[str] = set()  # every emitted id, even if its location cannot be indexed
    ids_at: Dict[Tuple[str, str, Any], str] = {}
    ids_in: Dict[Tuple[str, str], List[str]] = {}
    ids_by_path_at: Dict[Tuple[str, Any], List[str]] = {}
    ids_by_path: Dict[str, List[str]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        # Normalised ONCE, because this value is a dict key in five places below: a malformed
        # artefact carrying a dict or list here would raise TypeError and take the whole run down,
        # which is the same failure the item side had (see _hashable_line).
        cand_line = _hashable_line(candidate.get("line_number"))
        rule_id = candidate.get("rule_id")
        if isinstance(rule_id, str) and rule_id.strip():
            rule_ids.add(rule_id.strip())
        path = normalize_path(candidate.get("path"))
        if path:
            paths.add(path)
        snippet = candidate.get("snippet")
        if isinstance(rule_id, str) and path and isinstance(snippet, str) and snippet.strip():
            key = (rule_id.strip(), path)
            snippets_at[key + (cand_line,)] = snippet
            snippets_in.setdefault(key, [])
            if snippet not in snippets_in[key]:
                snippets_in[key].append(snippet)
            by_path_at.setdefault((path, cand_line), []).append(snippet)
            by_path.setdefault(path, []).append(snippet)
        raw_match = candidate.get("raw_match")
        if isinstance(rule_id, str) and path and isinstance(raw_match, str) and raw_match.strip():
            key = (rule_id.strip(), path)
            raw_matches_at[key + (cand_line,)] = raw_match
            raw_matches_in.setdefault(key, [])
            if raw_match not in raw_matches_in[key]:
                raw_matches_in[key].append(raw_match)
        candidate_id = candidate.get("candidate_id")
        if isinstance(candidate_id, str) and candidate_id.strip():
            ids_set.add(candidate_id.strip())
        if isinstance(rule_id, str) and path and isinstance(candidate_id, str) and candidate_id.strip():
            cid = candidate_id.strip()
            key = (rule_id.strip(), path)
            ids_at[key + (cand_line,)] = cid
            ids_in.setdefault(key, [])
            if cid not in ids_in[key]:
                ids_in[key].append(cid)
            ids_by_path_at.setdefault((path, cand_line), []).append(cid)
            ids_by_path.setdefault(path, []).append(cid)
        severity = candidate.get("severity")
        if isinstance(rule_id, str) and path and isinstance(severity, str) and severity.strip():
            severities.setdefault((rule_id.strip(), path), severity.strip().lower())

    if not rule_ids and not paths:
        return None
    return {"rule_ids": rule_ids, "paths": paths,
            "snippets_at": snippets_at, "snippets_in": snippets_in,
            "snippets_by_path_at": {k: v[0] for k, v in by_path_at.items() if len(set(v)) == 1},
            "snippets_by_path": {p: v[0] for p, v in by_path.items() if len(set(v)) == 1},
            "raw_matches_at": raw_matches_at, "raw_matches_in": raw_matches_in,
            "ids_set": ids_set, "ids_at": ids_at, "ids_in": ids_in,
            "ids_by_path_at": {k: v[0] for k, v in ids_by_path_at.items() if len(set(v)) == 1},
            "ids_by_path": {p: v[0] for p, v in ids_by_path.items() if len(set(v)) == 1},
            "severities": severities}


# WHICH KEY produced a row's fingerprint, recorded on every finding (agents-x9my).
#
# The delta can say "Fixed" without saying what identified the row as the same finding, which
# makes the claim unfalsifiable - and operators, reasonably, concluded that nothing may be closed
# on a Fixed line. A fingerprint is sha256(agent:rule id:path:snippet), and the snippet half is
# either the SCANNER's own match text (stable across runs) or the MODEL's re-quoted prose (not
# stable): on findings/audit-target-5qe.json 28% of rows carry rule_id "unclassified", which is
# exactly the population where the scanner binding below cannot fire. Naming the key turns an
# unattributable line into a graded one - and note what the grade is a grade OF: `candidate-exact`
# says the row was recognised by the scanner's own text on its last observation, NOT that a finding
# was fixed. A row still gets booked fixed when a later run drifts its label or line, or omits it,
# which is why the Fixed section says so at the point of use.
#
# Classification, per the four-step field checklist above lib/redaction.py's RENDERED_TEXT_FIELDS:
# this is a CLOSED vocabulary produced here, never model input, so it is copied verbatim rather
# than masked; and it is deliberately NOT an input to compute_fingerprint, because identity must
# not depend on how a finding was recognised - if it did, improving the binder would re-book every
# row.
# Which identity binding wrote the KEYS in a findings store. Bump this when a change re-keys
# stored rows, because the run that first applies a bump re-books them: it reports a one-time
# new+fixed wave that is bookkeeping, not discovery, and the delta announces it in those words
# (agents-x9my step 2; announcement agents-1ukp). Scheme 1 = the scanner snippet bound by rule id
# (fleet-oed, agents-x9my step 1); scheme 2 = plus the location fallback (agents-x9my step 2);
# scheme 3 = plus the candidate id the station EMITS at scan time, consumed where a rule or
# location bound the candidate (agents-q0mt, announcement agents-*).
IDENTITY_SCHEME = 3

IDENTITY_SOURCES = (
    "candidate-exact",      # the scanner candidate at (rule id, path, line)
    "candidate-unique",     # the only candidate for (rule id, path)
    "candidate-similar-by-model-snippet",  # the candidate whose text the MODEL's snippet quotes
    "unmatched-rule-location-unique",  # rule label bound nothing; ONE candidate at (path, line)
    "unmatched-rule-path-unique",      # rule label bound nothing; ONE candidate at the path
    "candidate-id",         # the binder selected the emitted id from a rule/location fact
    "candidate-id-by-model",  # the model echoed an emitted id where fact binding missed
    "model-snippet",        # a candidate set existed but nothing bound: identity IS model prose
    "no-candidate-index",   # no candidate set at all, so there was nothing to bind to
)

# The two `unmatched-rule-*` sources bind on LOCATION ALONE: the model's rule label matched no
# candidate, so they say "there is exactly one scanner candidate here", NOT "the scanner agrees
# with the model's rule". They are deliberately not named `candidate-*`, for the reason above - a
# reader must not take them for the rule-keyed bindings - and they are stable for the same reason
# `candidate-exact` is: the model's snippet plays no part in choosing them. They fire only where the
# location is unambiguous AND only when this run reports a single finding at that path, so two rows
# cannot be handed the same scanner snippet and collapse into one (which would lose a finding).
#
# Sources that are EVIDENCE that two runs describe the same finding, as opposed to sources that
# merely say how a row was recognised. `candidate-similar-by-model-snippet` is scanner text SELECTED
# BY the model's wording, so re-wording can select a different candidate: it is only partly stable,
# and its NAME says so, because a label a reader can over-read is worse than no label (coord ruling,
# agents-x9my) - a reader seeing any `candidate-*` name could infer "scanner-derived, therefore
# trustworthy", which is the inference this vocabulary exists to make impossible. Neither it, nor
# `model-snippet`, nor `no-candidate-index` is sufficient to close on a Fixed line.
#
# `candidate-id` IS stable, and it is the one source whose value is not the scanner's TEXT at all:
# it is the identity the station assigned to that candidate at scan time, so it is copied rather
# than re-derived. It is used only where a rule or a location already bound the candidate - the
# prose-selected step keeps its own unstable name, because there the SELECTION is still the model's,
# and a stable-sounding label would hide that. The same distinction holds for candidate-id-by-model:
# the id VALUE came from the scanner but the model CHOSE it, so it is NOT stable until the separate
# two-run measurement in ADR agents-ltuf justifies a promotion.
IDENTITY_STABLE_SOURCES = ("candidate-exact", "candidate-unique",
                           "unmatched-rule-location-unique", "unmatched-rule-path-unique",
                           "candidate-id")


def is_unanchored_source(source: Any) -> bool:
    """Whether an identity SOURCE NAME is outside the stable set - the predicate without a record.

    Factored so the appearance side (agents-l606) and the disappearance side (agents-6r8y) cannot
    drift into two spellings of one rule: `process_run` holds the source NAME at the point where it
    decides a fresh appearance's `change`, and a record everywhere else.
    """
    return bool(not source or source not in IDENTITY_STABLE_SOURCES)


def is_unanchored_finding(finding: Dict[str, Any]) -> bool:
    """Whether a finding has NO stable scanner anchor (identity rests on model prose).

    A finding whose identity_source is outside IDENTITY_STABLE_SOURCES is unanchored.
    Neither it, nor model-snippet, nor no-candidate-index is sufficient to close on a Fixed line.
    Factored single predicate used by both the migration path and the delta path (agents-6r8y).

    NOTE ON OPTION E (agents-6r8y): Recomputing anchors at disappearance against this run's
    candidate index is DEFERRED, not rejected. As documented at lines 807-813, a looser
    agent+path match at disappearance would risk silently absorbing a genuinely new finding at a
    location an older row had left, trading a visible wave for an invisible one. The marker
    tracks the last-observed anchor stability without inventing speculative re-bindings.
    """
    return is_unanchored_source(finding.get("identity_source"))


def identity_snippet_binding(item: Dict[str, Any], rule_id: Any, path: Any,
                             candidate_index: Optional[Dict[str, Any]], *,
                             path_unambiguous: bool = True,
                             location_unambiguous: bool = True) -> Tuple[Any, str]:
    """The snippet a finding is fingerprinted on, and WHICH KEY bound it.

    The model re-quotes a candidate's line differently from run to run (masked, truncated,
    the bare match, the whole line), so fingerprinting on its text booked a new+fixed pair on
    a byte-identical file (fleet-oed). The deterministic pre-pass emits the same snippet for
    the same unchanged line every time, so it is used when the finding binds to exactly one
    candidate location; otherwise the model's snippet is kept, as before - and that fallback is
    now NAMED, because it is the difference between a Fixed line that is evidence and one that is
    an artefact of re-wording (agents-x9my).

    STEP 2, and why it is keyed on location rather than on the rule: the rule-keyed lookups above
    cannot fire when the model does not echo the scanner's rule id, which by measurement is the
    MAJORITY of rows (agents-x9my), so those rows rested on re-wording no matter how good the
    scanner binding was. A location that holds exactly one candidate is unambiguous on its own, so
    it is used there - still without the model's prose, which is what makes these sources stable.
    `path_unambiguous` is the run-level guard: when THIS RUN reports more than one finding for the
    path, the fallback is refused, because two rows sharing a path and a blanked rule label would
    be handed the same snippet, get the same fingerprint, and silently collapse into one - losing a
    finding rather than merely mislabelling it.

    STEP 3: where a rule or a location bound the candidate, identity is COPIED from the candidate's
    own emitted id rather than re-derived from its text (agents-q0mt). That is what removes the
    reconstruction instead of making it safer, and it resolves the case step 2's guard had to
    refuse: two candidates at one path are two identities, so two findings there no longer share a
    key. The id is used at exactly the four STABLE steps and NOT at the prose-selected one, because
    there the selection itself is the model's - naming it stable would hide the mechanism.

    STEP 4 (agents-hoxs): after all fact bindings but before a prose-similarity fallback, an
    explicitly echoed emitted id may supply the key. Its name MUST say the model selected it.
    Unknown echoes do not bind; process_run counts them and fact/echo disagreements separately.
    """
    model_snippet = item.get("snippet", "")
    if not candidate_index or not isinstance(rule_id, str):
        return model_snippet, "no-candidate-index"
    norm_path = normalize_path(path)
    key = (rule_id.strip(), norm_path)
    at = candidate_index.get("snippets_at", {})
    ids_at = candidate_index.get("ids_at", {})
    # Guarded: every lookup below hashes this value, and a non-scalar one must miss rather than
    # raise (see _hashable_line).
    line = _hashable_line(item.get("line_number"))
    if key + (line,) in at:
        if key + (line,) in ids_at:
            return ids_at[key + (line,)], "candidate-id"
        return at[key + (line,)], "candidate-exact"
    options = candidate_index.get("snippets_in", {}).get(key, [])
    if len(options) == 1:
        ids = candidate_index.get("ids_in", {}).get(key, [])
        if len(ids) == 1:
            return ids[0], "candidate-id"
        return options[0], "candidate-unique"
    if path_unambiguous or location_unambiguous:
        # The rule label bound nothing: the model renamed the rule, or the binder blanked a label it
        # could not verify. Identity must not fall back to the model's re-wording merely because the
        # LABEL moved, so bind on location - preferring the sharper statement, that the model's own
        # line points at exactly one candidate, over the coarser one that the path holds exactly one.
        #
        # The emitted id is consulted under EITHER guard, because it is the only thing here that can
        # tell two candidates at one path apart: two findings on different lines of one file bind to
        # different ids, which is the case the path-level guard had to refuse (agents-rdyb resolved
        # it at the station; agents-q0mt consumes it here). The SNIPPET fallbacks stay under the
        # path-level guard alone, because their refusal is landed behaviour (agents-x9my step 2).
        ids_by_path_at = candidate_index.get("ids_by_path_at", {})
        if (norm_path, line) in ids_by_path_at:
            return ids_by_path_at[(norm_path, line)], "candidate-id"
        if path_unambiguous:
            if (norm_path, line) in candidate_index.get("snippets_by_path_at", {}):
                return candidate_index["snippets_by_path_at"][(norm_path, line)], "unmatched-rule-location-unique"
            if norm_path in candidate_index.get("snippets_by_path", {}):
                return candidate_index["snippets_by_path"][norm_path], "unmatched-rule-path-unique"
    if path_unambiguous:
        # The path holds exactly one candidate, so its id is that candidate's alone.
        ids_by_path = candidate_index.get("ids_by_path", {})
        if norm_path in ids_by_path:
            return ids_by_path[norm_path], "candidate-id"
    echo = item.get("anchor_candidate_id")
    if isinstance(echo, str) and echo in candidate_index.get("ids_set", set()):
        return echo, "candidate-id-by-model"
    wanted = normalize_text(model_snippet)
    if wanted:
        matching = [o for o in options if wanted in normalize_text(o) or normalize_text(o) in wanted]
        if len(matching) == 1:
            return matching[0], "candidate-similar-by-model-snippet"
    return model_snippet, "model-snippet"


def identity_snippet(item: Dict[str, Any], rule_id: Any, path: Any,
                     candidate_index: Optional[Dict[str, Any]]) -> Any:
    """The snippet alone, for callers that do not need to know how it was bound."""
    return identity_snippet_binding(item, rule_id, path, candidate_index)[0]

def identity_raw_match(item: Dict[str, Any], rule_id: Any, path: Any,
                       candidate_index: Optional[Dict[str, Any]]) -> Any:
    """The scanner's raw match for a finding's location, for deterministic dummy detection.

    The model may mask or truncate the snippet it reports, so a dummy marker on the exact
    matched value must come from the scanner, not the model. Falls back to the model's own
    ``raw_match`` (or None) when no scanner candidate binds to this location (agents-3r7).
    """
    if not candidate_index or not isinstance(rule_id, str):
        return item.get("raw_match")
    key = (rule_id.strip(), normalize_path(path))
    at = candidate_index.get("raw_matches_at", {})
    # Guarded for the same reason as identity_snippet_binding: this value is hashed by the lookup.
    line = _hashable_line(item.get("line_number"))
    matched = at.get(key + (line,))
    if matched is not None:
        return matched
    # Line-number drift fallback (like identity_snippet): when a (rule, path) has a single
    # unambiguous candidate match, use it even if the model shifted the line number.
    options = candidate_index.get("raw_matches_in", {}).get(key, [])
    if len(options) == 1:
        return options[0]
    return item.get("raw_match")

def bind_candidates(item: Dict[str, Any], candidate_index: Optional[Dict[str, Any]],
                    target_dir: Optional[Path] = None) -> Tuple[Any, Any]:
    """Bind a finding's `rule_id` and `path` to the deterministic scanner's output.

    The triage model returns these strings, so without a contract any string it invents is
    stored, fingerprinted and rendered. A scanner rule id that is not in the candidate set is
    replaced with `unclassified`; a path that is not among the candidate paths with `unknown`.
    When no candidate set exists there is nothing to bind to, and the model's values pass
    through to the redaction backstop exactly as before (agents-nha).

    The rule-id blanking is deliberate and was re-examined in agents-v4q. Retaining a "real" id
    instead was tried and reverted, because no workable non-fabrication check exists: genuine ids
    already arrive in the candidate set (measured over 18 real run outputs, the candidate index
    kept 22 of 55 model rule_ids and an inferred scanner registry rescued 0 more), no station
    declares a machine-readable rule registry, and inferring one from scanner sources proved
    unfaithful in BOTH directions - it missed vuln-discovery's 9 rules (4-tuple tables) and
    docs-drift's 3 (`x if c else y` assignments), while admitting vuln-discovery's
    `threat-model-context` envelope constant and threat-model's 5 entry-point categories, which
    are not finding rules. Admitting fabrications is worse than blanking them. The pins live in
    TestRuleIdStaysBlankOnAContextShapedIndex; read that before reintroducing a registry.

    Binding must never destroy a REAL location (agents-0tl). A model path that resolves inside
    the target is evidence, not an invention, so it survives even when it is not a scanner
    candidate - otherwise a context-shaped candidate set (vuln-discovery's single threat-model
    entry, deps-supply-chain's package.json) blanks every genuine path to `unknown` and the
    finding becomes untriageable. The guard still fires on an invented path: an empty path, or
    a path that resolves nowhere, is bound to `unknown` exactly as before.

    Migration note (agents-0tl, expected - not a regression): a fingerprint includes the path, so
    preserving a real location also re-identifies records stored earlier with `path: "unknown"`.
    The first run after this shipped reports those as new (with their real path) and the old
    "unknown" records as fixed, and a suppression keyed to an old "unknown" fingerprint stops
    matching. Deliberately not bridged: the transition is one-off and self-correcting, and a
    legacy-identity shim kept forever to hide a single visible transition costs more than it
    saves.
    """
    rule_id = item.get("rule_id") or "generic"
    path = item.get("path") or ""
    if not candidate_index:
        return rule_id, path

    if candidate_index["rule_ids"]:
        if not (isinstance(rule_id, str) and rule_id.strip() in candidate_index["rule_ids"]):
            rule_id = "unclassified"
    if candidate_index["paths"] and normalize_path(path) not in candidate_index["paths"]:
        if not path_resolves_in_target(path, target_dir):
            path = "unknown"
    return rule_id, path

def bind_severity(item: Dict[str, Any], rule_id: Any, path: Any,
                  candidate_index: Optional[Dict[str, Any]]) -> Any:
    """Clamp a candidate-bound finding's severity to the scanner baseline (agents-964).

    The perf-review scanner emits a high/medium baseline per (rule, path); the triage model
    drifts medium<->low and high<->low across runs, and the temperature pin that damps that
    only reaches openai-completions engines (deepseek/qwen) — pi ignores samplingParams on
    anthropic-messages (zai/kimi). So the dispatcher enforces the baseline exactly like it
    binds rule_id/path: a finding bound to a candidate location takes the scanner's baseline,
    with no downgrade or upgrade (SKILL.md invariant 1). A deliberate `info` (test
    fixture/mock, SKILL.md rule 2) is the one exception, preserved as-is.
    """
    model_sev = item.get("severity")
    if not candidate_index or not isinstance(rule_id, str):
        return model_sev
    baseline = candidate_index.get("severities", {}).get((rule_id.strip(), normalize_path(path)))
    if not baseline:
        return model_sev
    if isinstance(model_sev, str) and model_sev.strip().lower() == "info":
        return model_sev
    return baseline

def _strip_yaml_comment(line: str) -> str:
    """Cut a YAML comment without touching a '#' inside a quoted scalar."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def parse_suppressions_yaml(text: str, source: str = SUPPRESSIONS_FILENAME) -> Dict[str, Any]:
    """Parse the committed register: `<fingerprint>:` plus indented scalar fields.

    Deliberately the same small subset the agent manifests use — comments, blank lines, one
    level of nesting — and no more: this file is committed and human-edited, so anything
    unexpected raises rather than being ignored. An entry without a reason is rejected because
    AGENTS.md requires one.
    """
    entries: Dict[str, Dict[str, str]] = {}
    current: Optional[Dict[str, str]] = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_yaml_comment(raw).rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if indent == 0:
            if not stripped.endswith(":"):
                raise SuppressionFileError(
                    f"{source}:{lineno}: expected a '<fingerprint>:' entry, found {stripped!r}"
                )
            fingerprint = stripped[:-1].strip().strip("'\"").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise SuppressionFileError(
                    f"{source}:{lineno}: {stripped[:-1].strip()!r} is not a sha256 fingerprint"
                )
            if fingerprint in entries:
                raise SuppressionFileError(f"{source}:{lineno}: duplicate entry {fingerprint}")
            current = {}
            entries[fingerprint] = current
            continue

        if current is None:
            raise SuppressionFileError(
                f"{source}:{lineno}: field {stripped!r} appears before any fingerprint"
            )
        if ":" not in stripped:
            raise SuppressionFileError(
                f"{source}:{lineno}: expected 'field: value', found {stripped!r}"
            )
        field, value = stripped.split(":", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        current[field.strip()] = value

    for fingerprint, entry in entries.items():
        if not str(entry.get("reason", "")).strip():
            raise SuppressionFileError(
                f"{source}: entry {fingerprint} has no reason; AGENTS.md requires one"
            )
    return entries

class FindingsStore:
    def __init__(self, target_name: str, findings_dir: Optional[Path] = None, *,
                 read_only: bool = False, lock_timeout: Optional[float] = None):
        self.target_name = target_name
        self.findings_dir = findings_dir or (FACTORY_ROOT / "findings")
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.store_file = self.findings_dir / f"{target_name}.json"
        self.suppressions_file = self.findings_dir / SUPPRESSIONS_FILENAME
        self.legacy_suppressions_file = self.findings_dir / f"{target_name}.suppressions.json"
        self.read_only = read_only
        self._lock_timeout = self._resolve_lock_timeout(lock_timeout)
        # CAUTION for whoever adds a WRITE path to the register: suppressions_file is a SINGLE file
        # shared by every target, while the lock below is PER-TARGET. Such a change must take its own
        # lock (SUPPRESSIONS_FILENAME + ".lock") around the register read-modify-write, ordering
        # STORE LOCK FIRST, REGISTER LOCK SECOND - never a store lock while holding the register lock.
        # A second lock inside this window is where a self-deadlock would come from (agents-ynjh).
        # Read-only today, so nothing here needs it yet (agents-5ttl).
        # Advisory lock held across the whole load -> mutate -> save window (agents-3ls).
        # Concurrent factory processes (scheduled timer, manual run, CI) each do a
        # read-modify-write; without a lock the last writer wins and silently drops the
        # other's findings and delivery receipts. The lock file is separate from the store
        # because save() replaces the store's inode via os.replace(), and a lock held on the
        # store file itself would be left pointing at the superseded inode.
        self._lock_path = self.store_file.with_name(self.store_file.name + ".lock")
        self._lock_fh = open(self._lock_path, "a+", encoding="utf-8")
        # Whether WE hold the lock. A read-only store that cannot take the shared lock proceeds
        # unlocked (see _acquire_lock), and it must then neither publish nor clear the holder
        # metadata: clearing it erased a LIVE writer's diagnostic line (agents-4sij review, P1), so
        # every later waiter reported "holder unknown" while a holder was in fact running.
        self._lock_acquired = False
        try:
            self._acquire_lock()
            # A store written before this field existed predates the stamp, so it was written by
            # some older scheme: treat it as 1 rather than as current, so the first run after the
            # change announces the re-key instead of passing it off as discoveries. A store that
            # does not exist yet has nothing to re-key and is simply stamped (agents-x9my step 2).
            had_store = self.store_file.exists()
            self.data: Dict[str, Any] = self._load_store()
            raw_scheme = self.data.get("identity_scheme")
            if isinstance(raw_scheme, int) and not isinstance(raw_scheme, bool):
                self.identity_scheme_from = raw_scheme
            else:
                self.identity_scheme_from = (IDENTITY_SCHEME - 1) if had_store else IDENTITY_SCHEME
            self.suppressions: Dict[str, Any] = self._load_suppressions()
        except BaseException:
            self._lock_fh.close()
            # The handle is gone, so a later __del__ must not touch a closed file (agents-b81j).
            self._lock_fh = None
            raise

    @staticmethod
    def _resolve_lock_timeout(lock_timeout: Optional[float]) -> float:
        """The bounded wait, from the argument, the environment, or the default (agents-4sij)."""
        if lock_timeout is not None:
            return max(0.0, float(lock_timeout))
        raw = os.environ.get(STORE_LOCK_TIMEOUT_ENV)
        if raw:
            try:
                return max(0.0, float(raw))
            except ValueError:
                pass  # a malformed override must not take a run down; the default is safe
        return STORE_LOCK_TIMEOUT_SECONDS

    def _acquire_lock(self) -> None:
        """Take the store lock, waiting at most self._lock_timeout seconds.

        A READ-ONLY store never waits: it takes the shared lock when it can and proceeds without it
        otherwise. A reader that blocks forever behind a writer is the same defect wearing a
        different hat (agents-4sij), and the store is replaced atomically on save, so a reader that
        cannot lock is still reading a consistent file.
        """
        mode = fcntl.LOCK_SH if self.read_only else fcntl.LOCK_EX
        deadline = time.monotonic() + self._lock_timeout
        while True:
            try:
                fcntl.flock(self._lock_fh.fileno(), mode | fcntl.LOCK_NB)
            except OSError:
                if self.read_only:
                    # Proceed unlocked - and stay NOT acquired, so close() leaves the holder
                    # metadata alone (agents-4sij review, P1).
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StoreBusyError(
                        f"findings store {self.store_file} is locked: "
                        f"{_lock_holder_description(self._lock_path)}; waited "
                        f"{self._lock_timeout:g}s. Another factory process is writing this store - "
                        f"retry later or work elsewhere (raise {STORE_LOCK_TIMEOUT_ENV} to wait "
                        f"longer)."
                    ) from None
                try:
                    time.sleep(min(STORE_LOCK_POLL_SECONDS, remaining))
                except InterruptedError:
                    # A rare interrupted sleep must not escape as an unhandled error from a path
                    # whose whole job is to fail predictably (review out-of-scope note).
                    pass
                continue
            # The lock is genuinely ours from here, so only from here may the holder metadata be
            # published or cleared.
            self._lock_acquired = True
            if not self.read_only:
                # A reader holding the SHARED lock is not writing this store, so it must not claim
                # to be: that line says "pid ... lane ... since ..." about a WRITER, and two
                # concurrent readers would clobber each other's (review out-of-scope notes).
                self._publish_lock_holder()
            return

    def _publish_lock_holder(self) -> None:
        """Record who holds the lock and since when, for the next waiter (agents-4sij).

        Best-effort: failing to write metadata must never fail an ACQUIRED lock, so every error here
        is swallowed and the waiter falls back to "holder unknown".
        """
        lane = os.environ.get("FLEET_LANE") or "unknown lane"
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._lock_fh.seek(0)
            self._lock_fh.truncate()
            self._lock_fh.write(f"pid {os.getpid()} lane {lane} since {stamp}\n")
            self._lock_fh.flush()
        except OSError:
            pass

    def _clear_lock_holder(self) -> None:
        """Drop the metadata BEFORE releasing the lock, so no waiter can read a stale owner.

        Clearing after LOCK_UN would race a process that had already taken the lock and written its
        own line; clearing first can only ever leave "holder unknown", which is honest.
        """
        try:
            self._lock_fh.seek(0)
            self._lock_fh.truncate()
            self._lock_fh.flush()
        except OSError:
            pass

    def close(self) -> None:
        """Release the advisory lock so another process can load and mutate this store."""
        fh = getattr(self, "_lock_fh", None)
        if fh is not None:
            try:
                # Only a store that actually HELD the lock may clear the holder line or release it.
                # A read-only store that proceeded unlocked owns neither, and clearing there is
                # what erased a live writer's diagnostic (agents-4sij review, P1).
                if self._lock_acquired:
                    if not self.read_only:
                        self._clear_lock_holder()
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    self._lock_acquired = False
            finally:
                fh.close()
            self._lock_fh = None

    def __enter__(self) -> "FindingsStore":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __del__(self) -> None:
        """Release the lock handle even when the caller never called close() (agents-b81j).

        `close()` is the documented path, but "a caller that forgets to close" is the ORDINARY case
        for a library, and this handle is opened in __init__ and held for the store's whole
        lifetime. Left to the file object's own finalizer it leaks an fd and holds the flock until
        CPython collects it, which it reports as `ResourceWarning: unclosed file
        <.../target.json.lock>` - five independent test files forgot and each leaked one. So the
        SUCCESS path of the acquisition is closed here, the way __init__'s except already closes the
        exception and FACTORY_STORE_LOCK_TIMEOUT contention paths, and no caller has to remember.
        """
        try:
            self.close()
        except Exception:
            # A finalizer must not raise: this also runs at interpreter shutdown, after the
            # modules close() needs may already be gone, and the process is exiting anyway.
            pass

    def _load_store(self) -> Dict[str, Any]:
        if not self.store_file.exists():
            return {"target": self.target_name, "findings": {}}
        try:
            data = json.loads(self.store_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise StoreFileError(
                f"cannot read findings store {self.store_file}: {e}. Refusing to reset to an "
                f"empty store, which would re-book every prior finding as new and re-file "
                f"duplicates. Restore the file from backup, or delete it explicitly to reset."
            ) from e
        if not isinstance(data, dict):
            raise StoreFileError(
                f"findings store {self.store_file} is not a JSON object; refusing to reset it "
                f"silently."
            )
        data.setdefault("target", self.target_name)
        if not isinstance(data.get("findings"), dict):
            raise StoreFileError(
                f"findings store {self.store_file} has no 'findings' object; refusing to reset "
                f"it silently."
            )
        # agents-4zg: scrub records written before the store was redacted at rest. Redaction is
        # idempotent, so already-redacted records are unchanged; a legacy store keeps its raw
        # material out of memory, and the next save() persists the redacted copy to disk.
        # redact_for_storage, not redact_finding: the store keeps `candidate_id` on purpose, while
        # every PUBLISHED surface drops it (agents-p8og).
        data["findings"] = {
            fp: (redact_for_storage(record) if isinstance(record, dict) else record)
            for fp, record in data["findings"].items()
        }
        if "verifications" in data:
            rows = data["verifications"]
            data["verifications"] = {
                key: clean for key, record in (rows.items() if isinstance(rows, dict) else ())
                if isinstance(key, str) and isinstance(record, dict)
                if (clean := redact_verification_for_storage(record))
            }
        return data

    def _load_suppressions(self) -> Dict[str, Any]:
        """Read the committed suppressions register (agents-411).

        A parse failure raises instead of returning {}: silently suppressing nothing would
        un-wontfix the whole register without telling anyone.
        """
        if self.legacy_suppressions_file.exists():
            sys.stderr.write(
                f"Warning: {self.legacy_suppressions_file} is ignored (and gitignored); move its "
                f"entries into {self.suppressions_file}\n"
            )
        if not self.suppressions_file.exists():
            return {}
        return parse_suppressions_yaml(
            self.suppressions_file.read_text(encoding="utf-8"), str(self.suppressions_file)
        )

    def _redacted_data(self) -> Dict[str, Any]:
        """A copy of the store with every finding's raw material redacted (agents-4zg).

        The store file is read-only-bound into the sandboxed engine, so it must never carry
        raw_match / snippet / title / description / remediation for a target other than the one
        being scanned. The in-memory record keeps the raw values (dispatch_to_sink routes on them
        and mutates the delivery receipts), so save() writes the redacted copy rather than
        redacting the live records in place — redact_finding copies the whole dict and masks
        only the rendered text, so the receipts and lifecycle fields survive intact.
        """
        findings = self.data.get("findings")
        if not isinstance(findings, dict):
            return self.data
        verifications = self.data.get("verifications")
        return {
            **self.data,
            "findings": {
                fp: (redact_for_storage(record) if isinstance(record, dict) else record)
                for fp, record in findings.items()
            },
            **({"verifications": {
                key: clean for key, record in verifications.items()
                if isinstance(key, str) and isinstance(record, dict)
                if (clean := redact_verification_for_storage(record))
            }} if isinstance(verifications, dict) else
               {"verifications": {}} if "verifications" in self.data else {}),
        }

    def record_verifications(self, agent: str, rows: List[Dict[str, Any]]) -> Dict[str, int]:
        """Stage bounded verifier dispositions for process_run's single atomic save.

        Not findings: they never enter the lifecycle, delta counts, or publication sinks.
        Last verdict wins per candidate identity, with a location fallback for legacy no-id rows.
        """
        if agent != "vuln-verify":
            return {}
        stored = self.data.setdefault("verifications", {})
        if not isinstance(stored, dict):
            stored = self.data["verifications"] = {}
        now = datetime.now(timezone.utc).isoformat()
        touched: Dict[str, str] = {}
        for raw in rows:
            row = redact_verification_for_storage(raw)
            if not row:
                continue
            identity = ("id", row["candidate_id"]) if row.get("candidate_id") else (
                "location", row.get("rule_id"), row.get("path"), row.get("line_number"))
            key = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            stored[key] = {**row, "last_seen": now}
            touched[key] = row["verdict"]
        # Count distinct identities in THIS run, not the cumulative/capped target ledger.
        counts = {verdict: sum(value == verdict for value in touched.values())
                  for verdict in ("disproved", "unverifiable", "verified")}
        # Protected target JSON is never pruned, so the verifier ledger caps its own footprint.
        if len(stored) > 500:
            self.data["verifications"] = dict(sorted(
                stored.items(), key=lambda entry: (entry[1].get("last_seen", ""), entry[0]),
                reverse=True)[:500])
        return counts if touched else {}

    def save(self):
        """Atomically persist the store: temp file + fsync + os.replace (agents-3ls).

        A direct write_text() could leave a truncated file after a crash/SIGKILL mid-write,
        which _load_store() would then have to treat as corruption. The temp file lives in the
        same directory so os.replace() is a same-filesystem rename, never a copy.
        """
        payload = json.dumps(self._redacted_data(), indent=2)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.store_file.parent), prefix=self.store_file.name + ".", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.store_file)
            # fsync the directory so the rename itself is durable across a crash. Best-effort:
            # the rename already made the write atomic; this only makes it durable, and some
            # filesystems cannot fsync a directory fd.
            try:
                dir_fd = os.open(str(self.store_file.parent), os.O_RDONLY)
            except OSError:
                dir_fd = None
            if dir_fd is not None:
                try:
                    os.fsync(dir_fd)
                except OSError:
                    pass
                finally:
                    os.close(dir_fd)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def process_run(self, agent: str, raw_findings: List[Dict[str, Any]], candidate_index: Optional[Dict[str, Any]] = None,
                    target_dir: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[Dict[str, Any]]]:
        """Ingests raw findings from an agent run, applies fingerprinting and state transitions.
        
        Returns:
            processed_findings: list of findings with fingerprints and updated states.
            delta_stats: counts of new, regressed, fixed, unchanged, and suppressed findings.
            fixed_items: findings resolved by this run.
        """
        now = datetime.now(timezone.utc).isoformat()
        current_fps = set()
        migrated_in_place = 0
        delta_stats = {key: 0 for key in DELTA_KEYS}
        processed = []

        # How many findings THIS RUN reports per path, so a location fallback cannot merge two of
        # them onto one scanner snippet (see identity_snippet_binding).
        path_counts: Dict[str, int] = {}
        # The same count per (path, line). This is the SHARPER guard the emitted candidate id needs:
        # two findings in one file at DIFFERENT lines bind to different candidates and so to
        # different ids, which is exactly the case the path-level guard had to refuse (agents-rdyb
        # resolved it at the station; agents-q0mt consumes it here). It is deliberately NOT used for
        # the snippet fallbacks, whose refusal is a landed behaviour (agents-x9my step 2).
        location_counts: Dict[Tuple[str, Any], int] = {}
        for item in raw_findings:
            if isinstance(item, dict):
                norm = normalize_path(item.get("path"))
                if norm:
                    path_counts[norm] = path_counts.get(norm, 0) + 1
                    loc = (norm, _hashable_line(item.get("line_number")))
                    location_counts[loc] = location_counts.get(loc, 0) + 1

        # 1. Process observed findings
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            model_label = item.get("rule_id")
            rule_id, path = bind_candidates(item, candidate_index, target_dir)
            # agents-ag4: when the binder refuses the model's own label (no candidate set, or a
            # context-shaped one like vuln-discovery's), the label was simply lost to triage. Keep
            # it in its own field, which is NOT scanner provenance and is never read as such: it
            # is not an input to compute_fingerprint (identity) nor to the credential/security
            # rule-hint classification (routing severity and embargo), and it is masked and
            # shape-checked like every other rendered model string (lib/redaction.py).
            #
            # ACCEPTED LIMIT, stated at the field because this is where it is created: for a
            # security-sensitive station this value does not reach published output at all -
            # redact_finding DROPS it for credential findings and for SECURITY_SENSITIVE_AGENTS,
            # and it is dropped rather than masked because those are the cases where the shape of a
            # value cannot be known, so no mask can be proven sufficient. That is why the labels
            # this bead was opened for - vuln-discovery's - are NOT surfaced: they survive in the
            # model's own output in the run artifact, for whoever is doing the local triage. The
            # feature's benefit is therefore limited to stations whose prose may be published, and
            # that limitation is deliberate rather than a gap (coord decision, agents-ag4).
            model_rule_id = (model_label.strip()
                             if isinstance(model_label, str) and model_label.strip()
                             and model_label.strip() != rule_id else "")
            item["severity"] = bind_severity(item, rule_id, path, candidate_index)
            item["raw_match"] = identity_raw_match(item, rule_id, path, candidate_index)
            item["agent"] = agent
            norm_path = normalize_path(path)
            path_unambiguous = bool(norm_path) and path_counts.get(norm_path, 0) == 1
            # The sharper guard, used only where the emitted candidate id is consulted: a finding is
            # the only one at its own (path, line), so the candidate there is unambiguously its own.
            location_unambiguous = bool(norm_path) and location_counts.get(
                (norm_path, _hashable_line(item.get("line_number"))), 0) == 1
            identity_snip, identity_source = identity_snippet_binding(
                item, rule_id, path, candidate_index, path_unambiguous=path_unambiguous,
                location_unambiguous=location_unambiguous)
            if "anchor_candidate_id" in item:
                echo = item["anchor_candidate_id"]
                ids_set = candidate_index.get("ids_set", set()) if candidate_index else set()
                if not isinstance(echo, str) or echo not in ids_set:
                    delta_stats["anchor_unknown"] += 1
                elif identity_source == "candidate-id" and echo != identity_snip:
                    # This comparison is possible only when the fact-bound candidate has an id;
                    # a snippet-only fact binding has no id to compare with the model's echo.
                    delta_stats["anchor_disagreement"] += 1
            fp = compute_fingerprint(
                agent=agent,
                rule_id=rule_id,
                path=path,
                snippet=identity_snip
            )
            # A SECOND key the register may still be written under, and it is TIGHTER than the
            # model-snippet bridge below (agents-z3v9p): before step 3 put the emitted candidate id
            # into the key, an unambiguous candidate was fingerprinted on the PRE-PASS's own snippet
            # for its location, and every row the register wrote then is keyed that way. Once the id
            # took precedence those rows went INERT - measured on this repository: 21 of the 76
            # candidates the pre-pass emits are covered by a register row ONLY under this shape, so
            # 21 REVIEWED dismissals were silently re-entering triage every night (20 of the 21
            # rows say "Prose-bound identity" in their own reason, which is the misdiagnosis this
            # measurement replaces: the row's key was the pre-pass's line, not the model's prose).
            # The lookup text is scanner-owned and exact per (rule id, path, line), so it absorbs
            # nothing a register row did not already name.
            candidate_exact_fp = None
            if candidate_index and isinstance(rule_id, str):
                scanner_snip = candidate_index.get("snippets_at", {}).get(
                    (rule_id.strip(), normalize_path(path), _hashable_line(item.get("line_number"))))
                if isinstance(scanner_snip, str) and scanner_snip.strip():
                    candidate_exact_fp = compute_fingerprint(
                        agent=agent, rule_id=rule_id, path=path, snippet=scanner_snip)
            if (candidate_exact_fp is not None and candidate_exact_fp != fp
                    and candidate_exact_fp in self.suppressions
                    and candidate_exact_fp not in self.data["findings"]
                    and fp not in self.data["findings"] and fp not in self.suppressions):
                fp = candidate_exact_fp
                # Named for what bound the row: `candidate-exact` IS "the scanner candidate at
                # (rule id, path, line)", the closed vocabulary's own definition of this key.
                identity_source = "candidate-exact"
            # A store or register written before the scanner snippet was the identity holds
            # the model-snippet fingerprint. Honour it once, instead of booking every finding
            # new and its old record fixed on the upgrade run (fleet-oed).
            #
            # WHY THE STEP-2 WAVE IS NOT FULLY BRIDGED, stated here because this is where a reader
            # will look for it: this bridge can only recompute an older key from TODAY's inputs, and
            # the population step 2 re-keys is exactly the population whose stored key came from the
            # model's WORDING - which the re-wording changes, so the old key usually cannot be
            # recomputed from this run at all. A looser match (same agent and path) was considered
            # and REJECTED: it would silently absorb a genuinely NEW finding at a location an older
            # row had left, trading a visible wave for one nobody can see. The wave is announced
            # instead, once, by the scheme stamp below.
            legacy_fp = compute_fingerprint(agent=agent, rule_id=rule_id, path=path,
                                            snippet=item.get("snippet", ""))
            if legacy_fp != fp and fp not in self.data["findings"] and fp not in self.suppressions:
                if legacy_fp in self.suppressions:
                    fp = legacy_fp
                elif legacy_fp in self.data["findings"] and legacy_fp not in current_fps:
                    migrated = self.data["findings"].pop(legacy_fp)
                    migrated["fingerprint"] = fp
                    migrated["legacy_fingerprint"] = legacy_fp
                    self.data["findings"][fp] = migrated
                    migrated_in_place += 1
            if fp in current_fps:
                continue
            current_fps.add(fp)

            existing = self.data["findings"].get(fp)
            false_positive = is_false_positive(item)
            
            # Check for committed suppression
            if fp in self.suppressions:
                state = "wontfix"
                suppression_reason = self.suppressions[fp].get("reason", "Suppressed")
                change = "suppressed"
            elif existing is None:
                state = "new"
                change = "new"
                suppression_reason = None
            elif existing.get("state") == "fixed":
                state = "regressed"
                change = "regressed"
                suppression_reason = None
            else:
                state = existing.get("state", "new")
                change = "unchanged"
                suppression_reason = existing.get("suppression_reason")

            delta_stats["false_positive" if false_positive else change] += 1
            # APPEARANCE SIDE (agents-l606): `new` stays the TOTAL number of appearances, with
            # `new_unanchored` as a subset counter beside it - the same shape as `fixed_unanchored`.
            # An appearance whose identity rests on the model's prose is indistinguishable from a row
            # that MOVED KEY: a reword or a rule_id re-derivation mints a fresh fingerprint for an
            # unchanged finding, so one run books it New while booking the row it re-keyed Fixed.
            # Measured in the 2026-10-13 nightly: 6 of the 7 New rows had a same-path:line Fixed twin.
            if (not false_positive and change == "new"
                    and is_unanchored_source(identity_source)):
                delta_stats["new_unanchored"] += 1
            finding_record = {
                "fingerprint": fp,
                # Which key produced this fingerprint (agents-x9my). Written from the binder's own
                # vocabulary, never read out of `item`, so a report cannot claim provenance it
                # does not have; see IDENTITY_SOURCES for the classification and the checklist.
                "identity_source": identity_source,
                # The emitted id that IS the key this fingerprint used, persisted for a
                # SECOND-ORDER station (agents-p8og). `identity_source` distinguishes selection by
                # rule/location (candidate-id) from selection by the model's echo
                # (candidate-id-by-model). Neither a prose-similarity key nor an unrecognised echo
                # can claim a scanner id here. The id is dropped on publication but kept at rest
                # by redact_for_storage; it is not a rendered model string.
                #
                # ASYMMETRY, and it is a trap for a reader of the PERSISTED record: here the key is
                # always PRESENT and None means "nothing bound". At rest the key is OMITTED for an
                # unbound row, because redact_finding strips it and redact_for_storage puts it back
                # only when it is truthy - so `rec["candidate_id"]` raises KeyError on a loaded
                # record, and `rec.get("candidate_id") is None` is the absent case, not a bound one
                # (agents-7928).
                "candidate_id": (identity_snip if identity_source in
                                 ("candidate-id", "candidate-id-by-model") else None),
                "agent": agent,
                "rule_id": rule_id,
                # The model's own label, kept only when the store did not accept it as the rule
                # id - so the field means "the label we refused to trust as a rule", and is empty
                # on the common path. Display/triage only; see the note at its computation.
                "model_rule_id": model_rule_id,
                "path": path,
                "line_number": item.get("line_number"),
                "snippet": item.get("snippet"),
                "raw_match": item.get("raw_match"),
                # Two severities, never conflated (journal-1kg, journal-y5m):
                # `severity` is what the triage said — the one value the report, the store
                # and the line's andon count; a missing/unknown label is `unclassified`, a
                # declared false positive is `info`. `routing_severity` is the fail-closed
                # value the publication embargo enforces: unknown labels and credential- or
                # vulnerability-class agents route as critical whatever the model said
                # (agents-94f). Displaying the routing value made every unlabelled or
                # false-positive finding read CRITICAL.
                "severity": reported_severity(item),
                "routing_severity": effective_severity({"agent": agent, "severity": item.get("severity"),
                                                         "false_positive": false_positive,
                                                         "raw_match": item.get("raw_match"),
                                                         "snippet": item.get("snippet")}),
                "false_positive": false_positive,
                "title": item.get("title", ""),
                "description": item.get("description", ""),
                "remediation": item.get("remediation", ""),
                "state": state,
                # Lifecycle and this run's delta are separate: 'new' can remain active.
                "change": change,
                # Retry failed deliveries, but only notify once per sink and recurrence.
                "dispatched_sinks": [] if (not existing or change == "regressed") else list(existing.get("dispatched_sinks", [])),
                "github_issue": existing.get("github_issue") if existing else None,
                "first_seen": existing.get("first_seen", now) if existing else now,
                "last_seen": now,
                "suppression_reason": suppression_reason,
                "post_close_sightings": existing.get("post_close_sightings") if existing else None,
                "post_close_bead_id": existing.get("post_close_bead_id") if existing else None,
            }
            # agents-4zg: the store is persisted REDACTED at save() and scrubbed at load (see
            # _redacted_data / _load_store), so the sandboxed engine never reads raw fields. The
            # in-memory record stays raw here and is the SAME object appended to `processed`, so
            # the delivery receipts dispatch_to_sink mutates flow to the persisted record; save()
            # keeps those receipts while dropping the raw text.
            self.data["findings"][fp] = finding_record
            processed.append(finding_record)

        # A LOCATION MATCH IS A CANDIDATE, NOT A VERDICT (agents-l606, revised). A row whose identity
        # rests on the model's prose is re-keyed when that prose is reworded or the rule label is
        # re-derived, so the SAME finding can appear under a fresh fingerprint while the row it moved from
        # is booked Fixed in this very run - measured in the 2026-10-13 nightly as six of seven "New" rows
        # having a same-path:line twin in that run's own Fixed list. An appearance at the exact location of
        # a row retiring now is REPORTED as a possible re-key, and NOTHING IS RECLASSIFIED.
        #
        # WHY IT DOES NOT DECIDE (agents-wcki, agents-hci2, agents-l3j1, and the withdrawn agent-3sl6
        # reproduction): matching on location alone cannot separate a re-key from a genuinely new finding,
        # because "one prose-bound row leaves this location and another arrives" is the shape of BOTH. Two
        # revisions that DEMOTED a matched appearance were reproduced as harm - a new critical finding hid
        # from Action Required where an info row retired, and the sink guard written alongside silently
        # skipped a FAIL-CLOSED tracker check (rc=3 became rc=0) because the fail-closed test happens to
        # have that shape. Narrowing did not help: requiring both sides to be prose-bound and requiring a
        # shared rule_id (which matches 0 of 4 real pairs) each left the defect reachable. So the counter
        # below is INFORMATION and the classification stays `new`: the row keeps its detail, stays in the
        # actionable list, and is still delivered. A sound classification needs evidence a location does
        # not carry - the scanner's own match text on BOTH sides, or a persisted occurrence-level identity -
        # which is a design change (agents-01s2), not a guard.
        retiring = {}
        for _fp, _existing in self.data["findings"].items():
            if _existing.get("agent") != agent or _fp in current_fps:
                continue
            if _existing.get("state") not in ("new", "accepted", "regressed"):
                continue
            _line = usable_line_number(_existing.get("line_number"))
            # A KNOWN LINE IS REQUIRED ON BOTH SIDES (agents-yh0z). Unknown locations are not exact
            # ones: `usable_line_number` returns None for the factory's own "?" marker, for null, for
            # booleans, for non-positive numbers and for anything non-numeric, so an unnamed row in a
            # file cannot be paired with another unnamed row in it. The nightly's own paired
            # package.json rows are exactly this case - one carrying null and one carrying "?" - and
            # before this the two could key together on a location neither of them had. The counter
            # says EXACT LOCATION, so it only counts one; unknown-line rows are left out entirely,
            # which makes the count a FLOOR rather than a guess.
            if _line is None:
                continue
            retiring.setdefault((normalize_path(_existing.get("path")), _line), _existing)
        for record in processed:
            if (record.get("change") != "new" or record.get("false_positive")
                    or not is_unanchored_finding(record)):
                continue
            _line = usable_line_number(record.get("line_number"))
            if _line is None:
                continue
            loc = (normalize_path(record.get("path")), _line)
            # CONSUMED ON MATCH (agents-l3j1): one retiring row explains exactly ONE appearance.
            # Without popping, N unanchored appearances at a recycled location would ALL be re-keyed
            # against a single retiring row - inflating `rekeyed` and taking N rows out of `new` on
            # the word of one. Consuming first also means a refused pairing cannot be re-offered to a
            # later appearance, so the decision can only ever be conservative.
            twin = retiring.pop(loc, None)
            if twin is None:
                continue
            # BOTH SIDES MUST BE PROSE-BOUND, and this is the soundness fix (agents-wcki, and a
            # fail-closed path my own sink guard silently disabled). An ANCHORED twin would have been
            # recognised by its stable key in THIS run - that is what a stable anchor means - so a row
            # it cannot match is EVIDENCE ITSELF. A twin sitting in the retirement set proves its
            # identity moved, so a location is only evidence for a pair when the row that left it was
            # prose-bound too. When the twin was anchored, the appearance is a DIFFERENT finding at a
            # recycled location: the reproduction was a genuinely new finding at the line an anchored row
            # had just left, which a location-only rule re-keyed and thereby skipped the tracker's
            # fail-closed listing check for. This narrows the COUNT, never the report.
            if not is_unanchored_finding(twin):
                continue
            # NOTHING HERE DEPENDS ON SEVERITY, deliberately (agents-wcki): the rows where a re-key
            # actually happens ARE critical/high-labelled ones, so a severity guard suppressed exactly
            # the population the rule exists for and neutered it.
            #
            # AND NOTHING HERE CHANGES THE CLASSIFICATION (agents-wcki/agents-hci2/agents-l3j1). The
            # first two revisions of this fix DEMOTED a matched appearance - out of `new`, out of the
            # actionable list, and out of publication. All three were reproduced as harm: a critical
            # finding appearing where an info row retired was hidden from Action Required, and my own
            # sink guard silently skipped a fail-closed tracker check (agents-3sl6, whose test asserts
            # rc=3 when the bead listing is unreadable), because the shape "one prose-bound row leaves
            # this location, another arrives" is INDISTINGUISHABLE between a re-key and a new finding.
            # The bead's own nightly is exactly that shape. So the delta REPORTS the pair and lets the
            # reader decide: the counter below is information, `change` stays `new`, the row stays
            # actionable, and it is still delivered. A sound reclassification needs evidence a location
            # does not carry (the scanner's own match text on BOTH sides, or a persisted location
            # index), which is a design change rather than this fix.
            delta_stats["possible_rekey"] += 1

        # 2. Check for findings previously detected by this agent that are now missing (fixed)
        fixed_items = []
        for fp, existing in self.data["findings"].items():
            if existing.get("agent") == agent and fp not in current_fps:
                if existing.get("state") in ("new", "accepted", "regressed"):
                    existing["state"] = "fixed"
                    existing["fixed_at"] = now
                    delta_stats["fixed"] += 1
                    # `fixed` is the TOTAL number of findings that left the active set.
                    # `fixed_unanchored` is a SUBSET counter beside it (not a subtraction) counting
                    # disappearances of rows with no stable anchor (agents-6r8y).
                    if is_unanchored_finding(existing):
                        delta_stats["fixed_unanchored"] += 1
                    fixed_items.append(existing)

        # This store was written by an older identity binding, so the rows it retires may be RE-KEYS
        # rather than resolved findings. Count only the ones whose stored identity was NOT stable:
        # a row recognised by the model's wording is a re-key, while a row recognised by the scanner
        # being genuinely fixed is an ordinary result, and calling that a migration would tell triage
        # not to look at a real fix. Stamp the store so the announcement happens once
        # (agents-x9my step 2; announcement agents-1ukp).
        delta_stats["migrated"] = migrated_in_place
        if self.identity_scheme_from < IDENTITY_SCHEME:
            delta_stats["migrated"] += sum(
                1 for row in fixed_items
                if is_unanchored_finding(row))
        self.data["identity_scheme"] = IDENTITY_SCHEME

        self.save()

        # 3. Append to target history ledger
        history_file = self.findings_dir / f"{self.target_name}-history.jsonl"
        with open(history_file, "a", encoding="utf-8") as hf:
            hf.write(json.dumps({
                "timestamp": now,
                "agent": agent,
                "delta": delta_stats
            }) + "\n")

        return processed, delta_stats, fixed_items

def _publishable_for_sink(sink: str, findings: List[Dict[str, Any]], visibility: Any = None) -> List[Dict[str, Any]]:
    """Filter a run's findings down to what `sink` may receive.

    Eligibility (state, delivery receipt) and the publication embargo are both decided
    here. Only an explicit public declaration plus a verified destination authorises
    publishing to GitHub; missing visibility never silently discloses high/critical.
    """
    return _partition_for_sink(sink, findings, visibility)[0]


def _partition_for_sink(sink: str, findings: List[Dict[str, Any]], visibility: Any = None) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """`_publishable_for_sink`, plus a count of why the rest was not published.

    The counts make missing/invalid visibility and delivery failures visible to callers.
    """
    publishable = []
    held = {"embargoed": 0, "false_positive": 0, "already_delivered": 0, "not_active": 0}
    for f in findings:
        if f.get("state") in ("accepted", "wontfix"):
            held["not_active"] += 1
            continue
        if f.get("state") not in ("new", "regressed"):
            held["not_active"] += 1
            continue
        if sink in f.get("dispatched_sinks", []):
            held["already_delivered"] += 1
            continue
        # A finding the triage declared a false positive is evidence, not work (journal-35w).
        if f.get("false_positive") or is_false_positive(f):
            held["false_positive"] += 1
            continue
        reason = embargo_reason(f, sink, visibility)
        if reason:
            # The guard line is published too, so it derives every rendered value from the
            # redacted copy; the severity is a deterministic enum member.
            guarded = redact_finding(f)
            print(f"[SECURITY GUARD] Suppressing {sink} publication of {effective_severity(f)} finding: {guarded['title']}")
            held["embargoed"] += 1
            continue
        publishable.append(f)
    return publishable, held


def dispatch_to_sink(sink: str, target_name: str, target_dir: Path, processed_findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]] = None, visibility: Any = None, agent: Optional[str] = None, station_only: bool = False, fragment: Optional[Path] = None, repo: Optional[str] = None, beads_dir: Optional[Path] = None, sink_options: Optional[Dict[str, Any]] = None, run_dir: Optional[Path] = None, verification_counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Dispatch findings, mutating their successful-delivery receipts.

    The caller must save its FindingsStore after dispatch to persist those receipts.

    `station_only` is set when the dispatch is one station of a factory line: the station
    writes `<target>-<agent>-delta.md` and the line writes the run's `<target>-delta.md` once
    every station has reported. Before, every station overwrote `<target>-delta.md`, so the
    file described only the last station and one empty station printed "Clean Delta" for the
    whole run (fleet-810). `fragment` receives this station's delta as JSON for the line.

    Delivery is delegated to the adapters in lib/sinks (fleet-km8): this function owns
    only *what* may be published (state, receipts, false positives, the embargo) and the
    accounting. `sink_options` are the target manifest's `sink_*` settings.

    Returns the per-sink delivery accounting.
    """
    print(f"\n[Findings Store] Target: {target_name} | Delta: {stats['new']} new, {stats['regressed']} regressed, {stats['fixed']} fixed, {stats['unchanged']} unchanged, {stats['suppressed']} suppressed, {stats.get('false_positive', 0)} triaged false positive")
    if verification_counts and sum(verification_counts.values()):
        print(f"[Verifications] {sum(verification_counts.values())} candidate disposition(s) in this run "
              f"({verification_counts.get('disproved', 0)} disproved, "
              f"{verification_counts.get('unverifiable', 0)} unverifiable, "
              f"{verification_counts.get('verified', 0)} verified); not findings or published work")

    names = sinks.expand(sink)
    # Public issues are reserved for human-approved public input, not automatic findings.
    if "github-issues" in names:
        raise ValueError("github-issues is no longer a findings sink: internal findings file "
                         "to beads automatically; public-input issue triage is a separate flow")

    # Reconcile closed bead sightings for ALL observed findings before dispatching sinks
    # and rendering reports (agents-3sl6). Report skip if reconciliation could not run (agents-j9mc).
    recon_note = None
    if "beads" in names:
        try:
            from lib.sinks.beads import reconcile_closed_bead_sightings
            recon_note = reconcile_closed_bead_sightings(
                processed_findings,
                beads_dir=beads_dir,
                target_dir=target_dir,
            )
        except Exception as e:
            recon_note = f"beads reconciliation failed ({e})"
            print(f"Warning: beads reconciliation skipped: {e}", file=sys.stderr)
    context = sinks.SinkContext(target_name=target_name, target_dir=target_dir,
                                visibility=visibility, agent=agent, stats=dict(stats),
                                options=dict(sink_options or {}), beads_dir=beads_dir,
                                diagnostics_dir=run_dir or (
                                    FACTORY_ROOT / "runs" / f"sink-{target_name}-"
                                    f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"))
    sink_results: Dict[str, Dict[str, Any]] = {}
    for s in names:
        adapter = sinks.get(s)
        if adapter is not None and adapter.private:
            continue
        publishable, held = _partition_for_sink(s, processed_findings, visibility)
        result = dict(held, eligible=len(publishable), **sinks.new_result())
        if adapter is None:
            result["note"] = f"unknown sink {s!r}: nothing published"
        else:
            result.update(adapter.publish(context, publishable))
        if s == "beads" and recon_note:
            prior = result.get("note", "")
            result["note"] = f"{prior}; reconciliation skipped: {recon_note}".lstrip("; ")
        sink_results[s] = result
        print(f"[Sink {s}] published {result['published']}, failed {result['failed']}, "
              f"duplicate {result['duplicate']}, "
              f"embargoed {result['embargoed']}, below band {result['skipped']}, "
              f"false positive {result['false_positive']}"
              + (f" ({result['note']})" if result.get("note") else ""))
        if result["embargoed"]:
            print(f"[Sink {s}] {result['embargoed']} finding(s) held locally: visibility must "
                  "be explicitly declared before synced-tracker publication.")

    # Always write the local factory delta report. It is the complete evidence trail, so it
    # deliberately includes findings the publication embargo withholds from a tracker sink.
    _dispatch_file(target_name, processed_findings, stats, fixed_items or [],
                   agent=agent if station_only else None, sink_results=sink_results,
                   verification_counts=verification_counts)

    if fragment is not None:
        # agents-5bn P0: the fragment lives in the run directory, which a write-granted session
        # held rw-bound — it may have planted a symlink there. Unlink first so this write never
        # follows it to an arbitrary operator-writable host file (the session has ended, so there
        # is no concurrent writer); a planted directory fails closed (unlink raises).
        fragment.unlink(missing_ok=True)
        fragment.write_text(json.dumps({
            "agent": agent,
            "stats": stats,
            "findings": processed_findings,
            "fixed": fixed_items or [],
            "sinks": sink_results,
            **({"verification_counts": verification_counts} if verification_counts is not None else {}),
        }, indent=2), encoding="utf-8")
    return sink_results

def dispatch_env_failure_report(target_name: str, agent: str, engine: str, reason: str,
                                findings_dir: Optional[Path] = None) -> Path:
    """Write an honest single-station delta report for an environment failure (agents-zrn).

    Findings are UNKNOWN (not 0), and the report clearly indicates the station did not run.
    """
    return _dispatch_file(
        target_name, [],
        {"new": 0, "regressed": 0, "fixed": 0, "unchanged": 0, "suppressed": 0, "false_positive": 0},
        [],
        agent=agent,
        findings_dir=findings_dir,
        env_failure=f"engine '{engine}': {reason}",
    )


def _dispatch_file(target_name: str, findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]], agent: Optional[str] = None, sink_results: Optional[Dict[str, Any]] = None, stations: Optional[List[Dict[str, Any]]] = None, line_name: Optional[str] = None, findings_dir: Optional[Path] = None, env_failure: Optional[str] = None, verification_counts: Optional[Dict[str, int]] = None):
    """Write the delta report trio (full, `-latest` alias, step-summary variant).

    With `agent` set, the trio is the station's own (`<target>-<agent>-delta.md` ...), never
    the run's: only the line, which has seen every station, writes `<target>-delta.md`
    (fleet-810).
    """
    stem = f"{target_name}-{agent}" if agent else target_name
    report_file = (findings_dir or FACTORY_ROOT / "findings") / f"{stem}-delta.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    # This report is the file the composite action used to append to the step summary, so the
    # rendered copy is redacted. The raw values stay in the run artifacts and the store.
    findings = [redact_finding(f) for f in findings]
    fixed_items = [redact_finding(f) for f in fixed_items]

    title = f"{target_name} / {agent}" if agent else target_name
    kwargs = dict(sink_results=sink_results, stations=stations, line_name=line_name,
                  env_failure=env_failure, verification_counts=verification_counts)
    report = _render_delta_report(title, findings, stats, fixed_items, **kwargs)
    report_file.write_text(report, encoding="utf-8")
    # Preserve the original path for existing consumers.
    report_file.with_name(f"{stem}-latest.md").write_text(report, encoding="utf-8")
    # The step-summary variant (agents-pgj): the summary is readable by ANY logged-in GitHub
    # account on a public repo (anonymous readers get a 404, verified), so high/critical
    # finding prose is withheld from it — rule and location only. The full report stays in
    # the findings store and the auth-gated run artifact.
    summary = _render_delta_report(title, findings, stats, fixed_items, step_summary=True, **kwargs)
    report_file.with_name(f"{stem}-summary.md").write_text(summary, encoding="utf-8")
    print(f"Delta report written to: {report_file}")
    return report_file


# Station statuses that carry a verdict. Anything else (ERROR, SKIPPED, a status added later)
# means the station did not tell us anything, and the run is not clean (fleet-810, fleet-ddd).
VERDICT_STATUSES = frozenset({"PASS", "ALERT"})


# How many deterministic candidates a station's prompt carries (factory:1683). ONE definition, because the
# completeness fact below is measured against the same slice the model was actually SHOWN: a station whose
# pre-pass found more candidates than the prompt carries is judged on what it could see, not on the tail it
# never received (agents-xx9t).
CANDIDATE_PROMPT_SLICE = 50

# NOT a verdict, deliberately: VERDICT_STATUSES stays {PASS, ALERT}, so a line containing this status is
# INCOMPLETE by the existing machinery instead of reading as a green (agents-xx9t).
INCOMPLETE_STATUS = "INCOMPLETE"


def station_is_incomplete(station: Any) -> bool:
    """The one completeness predicate (agents-kve2, agents-pim5).

    Every surface that decides "is this station a clean result?" comes through here. When each surface
    re-derived the answer from the status plus its own erasure list, three things went wrong at once: the
    header counted a partial station as having a verdict it did not have, the Clean Delta banner swallowed
    the incomplete state on a run with nothing new, and the console named one station in two contradictory
    banners. A fourth surface added later cannot forget a rule it does not restate.
    """
    return bool(isinstance(station, dict) and station.get("complete") is False)


def station_has_verdict(station: Any) -> bool:
    """Whether the station produced a verdict at all. Completeness is a SEPARATE fact, not folded in.

    A verdict needs BOTH a completed status AND actual counts: `None` is unknown, not zero, so a station
    whose status is PASS but whose counts are missing must not read as a clean scan (agents-ekwm). The
    isinstance guard is agents-xx9t's, so a malformed row cannot raise.

    An ALERT whose triage was partial still has a verdict - the alarm is the outcome and must not be
    softened - and it is separately flagged as incomplete via station_is_incomplete(). A station whose
    status is INCOMPLETE has no verdict by construction, because INCOMPLETE is not in VERDICT_STATUSES.

    This is the UNION of the two independently-reviewed definitions: agents-ekwm's count checks combined
    with agents-xx9t's isinstance guard. Neither side alone was sufficient.
    """
    return bool(isinstance(station, dict)
                and station.get("status") in VERDICT_STATUSES
                and station.get("findings_count") is not None
                and station.get("criticals") is not None)


# The report-side name of the pre-pass identity field. It is a LITERAL, not `from lib.candidate_identity import
# CANDIDATE_ID_FIELD`, because this module is STAGED STANDALONE into dispatch sandboxes through hand-maintained
# module lists (tests/test_factory_truth.py LIB_MODULES is one), and an import that is not in every such list
# turns a dispatch into ModuleNotFoundError - measured: adding the import made 3 dispatch tests error out with
# `No module named 'lib.candidate_identity'`. The sibling vocabulary ("candidate-id" as an identity_source) is
# already a literal in this file for the same reason; lib/candidate_identity.py remains the writer's owner.
CANDIDATE_ID_FIELD = "candidate_id"


def read_candidate_count(run_dir: Any) -> Optional[int]:
    """How many candidates the station's pre-pass produced, or None when it had no pre-pass.

    None is not zero. No candidates.json means the station had no deterministic pre-pass and completeness
    cannot be asserted from it, so it is judged exactly as it was before. Zero means a pre-pass ran and
    found nothing, which is vacuously complete.
    """
    payload = _read_candidate_payload(run_dir)
    if isinstance(payload, dict):
        candidates = payload.get("candidates")
        if isinstance(candidates, list):
            return len(candidates)
        count = payload.get("candidate_count")
        if isinstance(count, int) and not isinstance(count, bool):
            return max(0, count)
    return None


def _read_candidate_payload(run_dir: Any) -> Optional[Any]:
    """The parsed `candidates.json` payload, or None when there is no usable one.

    One reader for the two questions asked of it - how many candidates a pre-pass produced, and which of
    them the prompt carried by id - so the two can never disagree about what a run was given.
    """
    if not run_dir:
        return None
    path = Path(run_dir) / "candidates.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def read_presented_candidate_ids(run_dir: Any,
                                 slice_size: int = CANDIDATE_PROMPT_SLICE) -> Optional[List[str]]:
    """The candidate_ids the prompt actually carried, or None when the station had no pre-pass.

    THREE ANSWERS, and they are not interchangeable (agents-w9ni):

      * None   - no `candidates.json`: there was no pre-pass, so identity cannot be asked for at all and the
                 check is judged exactly as it was before;
      * a list - the ids of the candidates the prompt carried, in presentation order (factory slices the
                 first `slice_size`, factory:1692), which is the population a report must cite;
      * []     - a pre-pass ran but its candidates carry no ids (an artefact from before the identity
                 scheme, lib/candidate_identity.py), so the check must fall back to counting rows AND SAY
                 that it did - a weaker check that cannot be told from the stronger one is the defect this
                 reader exists to prevent.

    Counting and identity are two different bounds. A count can be satisfied by the right NUMBER of rows
    describing candidates the station was never shown; citing ids cannot.
    """
    # rn0ky (ported: agents-uxiks): a BATCHED run spreads its candidate list across N prompts, so "the
    # prompt carried the first slice_size" is no longer one prompt's answer and counting it as one
    # under-reads a run that presented the whole list. The dispatcher writes presented_candidates.json
    # with exactly the ids it put in front of the model - every batch, in batch order - and THIS is the
    # population a report must cite. Read it first, and fall back to the slice for every run that
    # predates batching; the fallback is not a compatibility nicety, those runs really did present only
    # the slice.
    #
    # NOT "every candidate the pre-pass found": batching is applied to the candidate list the dispatcher
    # presents, which is still bounded by CANDIDATE_PROMPT_SLICE before it is split. Lifting that bound
    # would multiply a run's model calls by the size of the backlog, which is not what this change is
    # for - the recorded population says what was actually shown, whatever bounded it.
    if run_dir:
        try:
            recorded = json.loads((Path(run_dir) / "presented_candidates.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = None
        if isinstance(recorded, dict):
            recorded_ids = recorded.get("candidate_ids")
            if isinstance(recorded_ids, list):
                ids = [cid for cid in recorded_ids if isinstance(cid, str) and cid]
                # partial ids are no ids, exactly as below: the presented population must be nameable
                return ids if len(ids) == len(recorded_ids) else []
            if recorded.get("identity") == "partial" or recorded_ids is None:
                # The dispatcher recorded that some presented candidates carry no id (agents-ju56b).
                # A partial list is not identity information: returning it - or falling through to the
                # payload slice, which holds the same partial ids - made a fully-answered run read
                # "2/5 accounted, INCOMPLETE". Count accounting is the truthful judge here, exactly as
                # it was for this bundle before batching existed.
                return None
    payload = _read_candidate_payload(run_dir)
    if payload is None:
        return None
    candidates = payload.get("candidates") if isinstance(payload, dict) else None
    if not isinstance(candidates, list):
        return []
    ids: List[str] = []
    for candidate in candidates[:max(0, int(slice_size))]:
        value = candidate.get(CANDIDATE_ID_FIELD) if isinstance(candidate, dict) else None
        if not isinstance(value, str) or not value:
            return []           # partial ids are no ids: the whole presented population must be nameable
        ids.append(value)
    return ids


def _normalise_cited_path(value: Any) -> str:
    """A path as it is compared, never as it is reported: `/`-separated, no `./` prefix, no outer space.

    A row's `path` is model-written and a candidate's `path` is pre-pass-written, so the two spellings of
    the same file can differ by a leading `./` or a stray space. Only the comparison is normalised - every
    diagnostic and every repair record keeps the original string, because that is what an operator greps.
    """
    if not isinstance(value, str):
        return ""
    path = value.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.rstrip("/")


def read_candidate_paths(run_dir: Any) -> Dict[str, str]:
    """`candidate_id -> path` for every candidate the pre-pass recorded; `{}` when there is no evidence.

    The presented population is named by `read_presented_candidate_ids` (identity), and this is the same
    population joined to the one other thing a candidate carries that a ROW also carries: the file it was
    found in. It exists for one narrow repair (agents-amgst): a citation that is exact but DUPLICATED - two
    rows naming the same presented candidate while another is named by nobody - is invisible to every
    id-text rule, and the row's own path is the only remaining evidence of which candidate it meant.

    An unreadable payload, a pre-pass with no ids, or candidates with no path yields `{}`, which disables
    that repair rather than inventing a binding.

    The path-only view of `read_candidate_locations`, kept because that repair needs nothing else.
    """
    return {cid: location["path"]
            for cid, location in read_candidate_locations(run_dir).items()
            if location.get("path")}


def read_candidate_locations(run_dir: Any) -> Dict[str, Dict[str, Any]]:
    """`candidate_id -> {"path": <normalised>, "line": <int|None>}` for every recorded candidate.

    ONE MORE JOIN THAN `read_candidate_paths` (agents-op02b). The qrcode nightly's vuln-discovery run
    emitted seven findings with NO candidate_id at all, so every row accounted for nothing and the
    station read INCOMPLETE - while the pre-pass was holding the very candidates those rows described.
    The row's own `path` (and, when several candidates live in one file, its `line_number`) is the
    remaining evidence of which candidate it meant, so the reader exposes both from the same payload
    the coverage check already reads, and the two can never disagree about the population.

    An unreadable payload, a pre-pass with no ids, or candidates with no path yields `{}`, which
    disables the location repair rather than inventing a binding.
    """
    payload = _read_candidate_payload(run_dir)
    candidates = payload.get("candidates") if isinstance(payload, dict) else None
    if not isinstance(candidates, list):
        return {}
    locations: Dict[str, Dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        cid = candidate.get(CANDIDATE_ID_FIELD)
        path = _normalise_cited_path(candidate.get("path"))
        if not (isinstance(cid, str) and cid.strip() and path):
            continue
        locations.setdefault(cid.strip(), {"path": path,
                                           "line": _usable_line_number(candidate.get("line_number"))})
    return locations


def _usable_line_number(value: Any) -> Optional[int]:
    """A line a row and a candidate can be COMPARED on, or None - never a coercion that invents one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if number > 0 else None
    return None


# ---------------------------------------------------------------------------------------------
# Candidate-id repair (agents-00sew). A model sometimes mistranscribes the 16-hex candidate_id it is
# asked to copy verbatim: chrome-agent-platform-z427f reported 4e8820782eed4e17 as 4e8820782eed17.
# Measured, that is a DELETION of the two characters at offset 12 - neither a prefix nor a contiguous
# substring - so a prefix/substring-only repair would not have fixed the case that prompted it.
#
# The repair is deliberately narrow: it rewrites a cited id ONLY when exactly one presented id can have
# produced it under a deterministic rule. An ambiguous cited id is left alone, which keeps the run's
# accounting honest (a partial triage stays visible) instead of silently binding a verdict to a
# candidate the model never meant.
# ---------------------------------------------------------------------------------------------
REPAIR_MIN_CITED_LENGTH = 8   # "4e" or "abcd" cannot identify one candidate among many
REPAIR_MAX_EDITS = 2          # the observed mistranscription dropped two hex characters
NEAREST_REPORTABLE_EDITS = 4  # a refusal names the nearest candidate only when it is plausibly the same one


def _bounded_edit_distance(left: str, right: str, limit: int) -> Optional[int]:
    """Levenshtein distance, or None as soon as it cannot be <= limit (cheap for far-apart ids)."""
    if abs(len(left) - len(right)) > limit:
        return None
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        best = i
        for j, rchar in enumerate(right, start=1):
            cost = 0 if lchar == rchar else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            best = min(best, value)
        if best > limit:
            return None
        previous = current
    distance = previous[-1]
    return distance if distance <= limit else None


_REPAIR_RULE_NAMES = {1: "prefix", 2: "substring", 3: "near"}


def _match_rank(cited: str, candidate: str) -> Tuple[Optional[int], int]:
    """`(rule rank, distance within that rule)` - lower is better - or `(None, 0)` if unexplained.

    One ordering for every candidate, local or sibling, so "which candidate does this id most likely
    mean?" is answered by the same yardstick everywhere instead of per pool.
    """
    if candidate == cited:
        return 0, 0
    if len(cited) < REPAIR_MIN_CITED_LENGTH:
        return None, 0
    if candidate.startswith(cited):
        return 1, len(candidate) - len(cited)
    if cited in candidate:
        return 2, len(candidate) - len(cited)
    distance = _bounded_edit_distance(cited, candidate, REPAIR_MAX_EDITS)
    return (3, distance) if distance is not None else (None, 0)


def repair_cited_candidate_id(cited: str,
                              presented: Iterable[str],
                              foreign: Iterable[str] = ()) -> Tuple[Optional[str], str]:
    """`(presented_id, rule)` when exactly ONE candidate - OF ANY BATCH - can explain `cited`, else
    `(None, reason)`.

    Rules, most specific first: an exact id, then a unique PREFIX (the model truncated the tail), then a
    unique SUBSTRING (the model copied a fragment), then a NEAR MATCH within REPAIR_MAX_EDITS edits - the
    deletion shape that actually occurred (agents-00sew).

    `foreign` is the ids presented to OTHER batches, and it is not just an exact-match guard (agents-fv5uk
    was the exact case; agents-00sew round 2 was the rest of it). Batch ids sit next to each other by
    construction, so a near match must be judged GLOBALLY: a one-character typo of a sibling batch's
    candidate is not an exact match to anything, and a repair that only looked at its own batch bound it to
    the local neighbour ("cand-perf-0o4" is one edit from the sibling "cand-perf-004" and two from the local
    "cand-perf-003") - the same misattribution through a typo. So a citation is repaired onto THIS batch's
    candidate only when no sibling candidate explains it at least as well; otherwise it is left exactly as
    the model wrote it and the ownership check rejects it.
    """
    cited = cited.strip() if isinstance(cited, str) else ""
    ids = [str(cid).strip() for cid in presented or () if isinstance(cid, str) and str(cid).strip()]
    elsewhere = {str(cid).strip() for cid in foreign or ()
                 if isinstance(cid, str) and str(cid).strip()}
    if not cited:
        return None, "blank"
    if cited in ids:
        return None, "exact"
    if cited in elsewhere:
        return None, "belongs to another batch"

    def scored(pool: Iterable[str]) -> List[Tuple[int, int, str]]:
        rows = []
        for candidate in pool:
            rank, distance = _match_rank(cited, candidate)
            if rank is not None:
                rows.append((rank, distance, candidate))
        return sorted(rows)

    local = scored(ids)
    siblings = scored(elsewhere)
    if not local:
        # agents-afx5o: name the nearest candidate rather than discarding what the search already found.
        # Without it a failed citation reads "no unique match" while the run holds the very ids it was
        # compared against, so an operator cannot tell a typo from a wrong-batch answer by reading the log.
        return None, _no_match_reason(cited, ids, elsewhere)
    best_rank = local[0][0]
    at_best = [(distance, candidate) for rank, distance, candidate in local if rank == best_rank]
    if best_rank == 3:
        best_distance = min(distance for distance, _ in at_best)
        at_best = [(distance, candidate) for distance, candidate in at_best
                   if distance == best_distance]
    if len(at_best) > 1:
        names = ", ".join(sorted(candidate for _, candidate in at_best)[:3])
        return None, f"ambiguous {_REPAIR_RULE_NAMES[best_rank]}: {len(at_best)} candidates ({names})"
    # A sibling candidate that explains the citation as well or better means the model was answering
    # ANOTHER batch's candidate - the row must be rejected there, not attached to a local neighbour.
    if siblings:
        sibling_rank, sibling_distance, sibling_id = siblings[0]
        if sibling_rank < best_rank or (sibling_rank == best_rank and (
                best_rank != 3 or sibling_distance <= at_best[0][0])):
            return None, (f"a sibling batch's candidate ({sibling_id}) explains it at least as well"
                          if sibling_rank == best_rank else
                          f"a sibling batch's candidate ({sibling_id}) matches more specifically")
    return at_best[0][1], _REPAIR_RULE_NAMES[best_rank]


def _no_match_reason(cited: str, ids: Iterable[str], elsewhere: Iterable[str]) -> str:
    """`no unique match`, plus the closest candidate the search saw and how far away it was."""
    nearest: Optional[Tuple[int, str]] = None
    for candidate in list(ids) + list(elsewhere):
        distance = _bounded_edit_distance(cited, candidate, len(cited) + 1)
        if distance is not None and (nearest is None or distance < nearest[0]):
            nearest = (distance, candidate)
    # Naming a candidate that is 16 edits away is noise, not a clue: report the nearest only when it is
    # close enough to be a plausible typo of the one that was cited.
    if nearest is None or nearest[0] > NEAREST_REPORTABLE_EDITS:
        return "no unique match"
    return (f"no unique match (nearest candidate: {nearest[1]} at {nearest[0]} edit"
            f"{'' if nearest[0] == 1 else 's'})")


def _rows_by_cited_id(rows: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Every row that cites each id - with MULTIPLICITY, because a duplicate is the thing being read."""
    citing: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        cited = row.get("candidate_id")
        if isinstance(cited, str) and cited.strip():
            citing.setdefault(cited.strip(), []).append(row)
    return citing


def repair_duplicate_citations_by_path(rows: Any, presented: Iterable[str],
                                       candidate_paths: Optional[Dict[str, str]],
                                       repairs: List[Dict[str, Any]],
                                       refusals: Optional[List[Dict[str, Any]]] = None
                                       ) -> List[Dict[str, Any]]:
    """Re-bind a DUPLICATED-but-valid citation onto the candidate the row's own path names.

    THE CASE THE ID-TEXT RULES CANNOT SEE (agents-amgst). Nightly 2026-10-23 failed on one modern-web
    station: six dismissal rows, one per page, but the `docs/index.html` row cited `docs/help.html`'s
    candidate_id. Two rows therefore cite `d21fff3b2fa42e68`, `b1cea3c268d41ac2` is cited by nobody, and
    the station reads "cited 5 of the 6". `repair_cited_candidate_id` answers `(None, 'exact')` for a
    citation that IS a presented id, so the row was invisible to repair AND to refusal: no
    `candidate_id_repairs*.json` was written at all and the operator got only the count.

    ALL FOUR must hold or the citation is left exactly as the model wrote it, because binding a verdict to
    the wrong candidate is worse than a visible shortfall:
      * the cited id is a PRESENTED candidate cited by MORE THAN ONE row (two rows may legitimately answer
        one candidate, and a run whose every candidate is cited is not short of anything);
      * at least one presented candidate is cited by NO row, read BEFORE any rewrite (a duplicate only
        matters when it plausibly explains the shortfall);
      * the row's own `path` matches exactly ONE presented candidate - a model-written path, so an
        ambiguous one refuses instead of guessing; and
      * that candidate is still uncited (a citation is never moved off a candidate another row names).

    Every applied rewrite is appended to `repairs` as `rule: 'path'` so it is auditable in the run
    directory rather than an invisible kindness. A duplicate that survives is appended to `refusals`, naming
    the id, the rows' paths and how many candidates stay unaccounted - the diagnostic the failure lacked.
    """
    rows_list = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    presented_ids: List[str] = []
    for value in presented or ():
        if isinstance(value, str) and value.strip() and value.strip() not in presented_ids:
            presented_ids.append(value.strip())
    paths: Dict[str, str] = {}
    for cid, path in (candidate_paths or {}).items():
        normalised = _normalise_cited_path(path)
        if isinstance(cid, str) and cid.strip() and normalised:
            paths[cid.strip()] = normalised
    if not rows_list or not presented_ids or not paths:
        return []

    citing = _rows_by_cited_id(rows_list)
    uncited = [cid for cid in presented_ids if cid not in citing]
    duplicated = [cid for cid in presented_ids if len(citing.get(cid, [])) > 1]
    if not uncited or not duplicated:
        return []

    by_path: Dict[str, List[str]] = {}
    for cid in presented_ids:
        path = paths.get(cid)
        if path:
            by_path.setdefault(path, []).append(cid)

    applied: List[Dict[str, Any]] = []
    still_uncited = set(uncited)
    for cid in duplicated:
        for row in citing.get(cid, []):
            matches = by_path.get(_normalise_cited_path(row.get("path")), [])
            if len(matches) != 1 or matches[0] not in still_uncited:
                continue
            target = matches[0]
            row["candidate_id"] = target
            still_uncited.discard(target)
            record = {"cited": cid, "repaired": target, "rule": "path", "path": row.get("path")}
            repairs.append(record)
            applied.append(record)

    if refusals is None:
        return applied
    citing = _rows_by_cited_id(rows_list)
    for cid in duplicated:
        rows_here = citing.get(cid, [])
        if len(rows_here) < 2:
            continue                                  # the duplicate was resolved, not refused
        remaining = [other for other in presented_ids if other not in citing]
        if not remaining:
            continue                                  # an intentional duplicate that costs no coverage
        re_bound = sum(1 for record in applied if record["cited"] == cid)
        row_paths = [row.get("path") for row in rows_here]
        named = ", ".join(str(path) for path in row_paths[:4])
        if len(row_paths) > 4:
            named += f", +{len(row_paths) - 4} more"
        refusals.append({
            "cited": cid,
            "path": row_paths[0] if row_paths else None,
            "paths": row_paths,
            "reason": (
                f"duplicated citation: {len(rows_here)} row(s) cite it ({named})"
                f"{f' - {re_bound} re-bound by path' if re_bound else ''}, and the left-over"
                f" row path(s) do not name exactly one still-uncited presented candidate, so"
                f" {len(remaining)} presented candidate id(s) stay unaccounted"
                f" ({', '.join(remaining[:4])}"
                f"{f', +{len(remaining) - 4} more' if len(remaining) > 4 else ''})"),
        })
    return applied


def repair_cited_candidate_ids(rows: Any,
                               presented: Iterable[str],
                               foreign: Iterable[str] = (),
                               refusals: Optional[List[Dict[str, Any]]] = None,
                               candidate_paths: Optional[Dict[str, str]] = None,
                               candidate_locations: Optional[Dict[str, Dict[str, Any]]] = None
                               ) -> List[Dict[str, Any]]:
    """Rewrite `candidate_id` in place on rows where a UNIQUE repair exists; return the repairs.

    Returns one record per rewritten row ({cited, repaired, rule, path}) so the repair is auditable in
    the run directory rather than an invisible kindness.

    `candidate_paths` (`candidate_id -> path`, `read_candidate_paths`) enables the ONE repair the id-text
    rules cannot express: a duplicated-but-valid citation, re-bound onto the candidate the row's own path
    names when that is unambiguous (agents-amgst, `repair_duplicate_citations_by_path`). Without it the
    function behaves exactly as before.

    `candidate_locations` (`candidate_id -> {path, line}`, `read_candidate_locations`) enables the repair
    for a row that carries NO id at all (agents-op02b, `repair_missing_candidate_ids_by_location`). It is
    a superset of `candidate_paths`, so a caller holding it needs to pass only this one.
    """
    if candidate_paths is None and candidate_locations:
        candidate_paths = {cid: location["path"] for cid, location in candidate_locations.items()
                           if isinstance(location, dict) and location.get("path")}
    repairs: List[Dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else ():
        if not isinstance(row, dict):
            continue
        cited = row.get("candidate_id")
        if not isinstance(cited, str) or not cited.strip():
            continue
        repaired, rule = repair_cited_candidate_id(cited, presented, foreign=foreign)
        if repaired is None:
            # agents-afx5o: keep the reason. An id that was already exact is not a refusal - there was
            # nothing to repair - so only cited ids that could not be accounted for are recorded.
            if refusals is not None and rule != "exact":
                refusals.append({"cited": cited.strip(), "reason": rule, "path": row.get("path")})
            continue
        row["candidate_id"] = repaired
        repairs.append({"cited": cited.strip(), "repaired": repaired, "rule": rule,
                        "path": row.get("path")})
    # A second pass deliberately: each later rule needs the citations the earlier ones produced - the
    # missing-id rule must not double-book a candidate an id-text row already names, and the duplicate
    # rule can only see duplicates among the citations that survived.
    if candidate_locations:
        repair_missing_candidate_ids_by_location(rows, presented, candidate_locations, repairs, refusals)
    repair_duplicate_citations_by_path(rows, presented, candidate_paths, repairs, refusals)
    return repairs


MISSING_ROW_NAMED_CANDIDATES = 2   # a refusal names the candidates its location could have meant


def repair_missing_candidate_ids_by_location(rows: Any,
                                            presented: Iterable[str],
                                            locations: Optional[Dict[str, Dict[str, Any]]],
                                            repairs: List[Dict[str, Any]],
                                            refusals: Optional[List[Dict[str, Any]]] = None
                                            ) -> List[Dict[str, Any]]:
    """Give a row that carries NO candidate_id the one presented candidate its own location names (agents-op02b).

    THE DEFECT THIS ANSWERS, MEASURED. The qrcode nightly's vuln-discovery station emitted seven findings
    whose `path`/`line_number` described real pre-pass candidates but which carried no `candidate_id` key
    at all. Every id-text rule skips such a row (`repair_cited_candidate_ids` `continue`s on a blank
    citation) and every path rule needs an id to move, so the station's coverage read "cited 0 of 7" and
    the run was INCOMPLETE - while the answer to every one of those candidates was sitting in the row. The
    omission is unwritable-to-repair for the id rules and unambiguous for a location rule, which is why it
    is a repair and not another schema requirement: `candidate_id` cannot be `required` in the shared
    station schemas (a pre-pass with no ids, and every count-only station, legitimately omit it - see
    tests/test_station_candidate_accounting.py), and a rejection would spend a whole model call to
    re-derive what is already in the report.

    STRICTER THAN THE ID RULES, ON PURPOSE. Binding a verdict to the wrong candidate is worse than a
    visible shortfall, so an id is filled in only when ALL FOUR hold:
      * the row names a `path`, and that path is one exactly ONE presented candidate carries;
      * when the row also carries a `line_number`, candidates in that file are narrowed to the one on that
        line - a unique path does not have to be a unique LOCATION, and a file with three candidates is
        the ordinary case, not the exotic one;
      * no candidate OUTSIDE the presented population (a sibling batch, or a pre-pass record the prompt
        never carried) matches the location as well or better - the same sibling rule the id-text repair
        uses (agents-fv5uk), one level over;
      * the candidate is not already cited by another row - a citation is never double-booked.
    Everything refused is appended to `refusals` with the reason, because "7 rows lost their id" and "7
    rows could not be matched" are different operator problems and the run directory has to tell them apart.
    """
    presented_ids: List[str] = []
    for value in presented or ():
        if isinstance(value, str) and value.strip() and value.strip() not in presented_ids:
            presented_ids.append(value.strip())
    if not presented_ids or not isinstance(locations, dict) or not locations:
        return []
    own = {cid: locations[cid] for cid in presented_ids
           if isinstance(locations.get(cid), dict) and locations[cid].get("path")}
    if not own:
        return []
    elsewhere = {cid: location for cid, location in locations.items()
                 if cid not in own and isinstance(location, dict) and location.get("path")}
    rows_list = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def rank(location: Dict[str, Any], path: str, line: Optional[int]) -> Optional[int]:
        """1 for the same file AND line, 2 for the same file, None for a different file."""
        if not path or location.get("path") != path:
            return None
        return 1 if line is not None and location.get("line") == line else 2

    cited = set()
    for row in rows_list:
        current = row.get("candidate_id")
        if isinstance(current, str) and current.strip():
            cited.add(current.strip())

    applied: List[Dict[str, Any]] = []
    for row in rows_list:
        current = row.get("candidate_id")
        if isinstance(current, str) and current.strip():
            continue                                  # id-text and duplicate rules own that row
        path = _normalise_cited_path(row.get("path"))
        line = _usable_line_number(row.get("line_number"))
        if not path:
            if refusals is not None:
                refusals.append({"cited": None, "path": row.get("path"), "missing": True,
                                 "reason": "row carries no candidate_id and no path to match one on"})
            continue
        scored = sorted((rank(location, path, line), cid) for cid, location in own.items()
                        if rank(location, path, line) is not None)
        if not scored:
            if refusals is not None:
                refusals.append({"cited": None, "path": row.get("path"), "missing": True,
                                 "reason": (f"row carries no candidate_id and its path {path!r} names none of "
                                            f"the {len(own)} presented candidate(s)")})
            continue
        best_rank = scored[0][0]
        at_best = [cid for rank_here, cid in scored if rank_here == best_rank]
        if len(at_best) > 1:
            named = ", ".join(sorted(at_best)[:MISSING_ROW_NAMED_CANDIDATES])
            if refusals is not None:
                refusals.append({"cited": None, "path": row.get("path"), "missing": True,
                                 "reason": (f"row carries no candidate_id and {len(at_best)} presented "
                                            f"candidate(s) share its location ({named}); "
                                            f"a row that names no line cannot choose between them")})
            continue
        target = at_best[0]
        better = [cid for cid, location in elsewhere.items()
                  if (rank(location, path, line) or 99) <= best_rank]
        if better:
            if refusals is not None:
                refusals.append({"cited": None, "path": row.get("path"), "missing": True,
                                 "reason": (f"row carries no candidate_id and a candidate it was NOT shown "
                                            f"({sorted(better)[0]}) matches its location at least as well")})
            continue
        if target in cited:
            if refusals is not None:
                refusals.append({"cited": None, "path": row.get("path"), "missing": True,
                                 "reason": (f"row carries no candidate_id and the candidate its location names "
                                            f"({target}) is already cited by another row")})
            continue
        row["candidate_id"] = target
        cited.add(target)
        record = {"cited": None, "repaired": target,
                  "rule": "path+line" if best_rank == 1 else "path", "path": row.get("path")}
        repairs.append(record)
        applied.append(record)
    return applied


COVERAGE_NAMED_UNCITED_IDS = 5   # name a shortfall's candidates, never a wall of 45 of them


def _coverage_diagnostic(accounted: int, duplicates: List[Dict[str, Any]],
                         uncited: List[str], rows_without_candidate_id: int = 0) -> str:
    """The part of a coverage reason that says WHICH candidates the shortfall is about (agents-amgst).

    "cited 5 of the 6" was the only clue a failed nightly offered, and it pointed at neither the duplicated
    citation nor the candidate nobody answered: nightly 2026-10-23's modern-web station had six dismissal
    rows where one row cited another page's candidate_id, so the count was short by a duplicate and not by
    a missing row. Naming both is what turns that into one sentence an operator can act on.

    A ROW WITH NO ID IS A THIRD CAUSE AND IT GOES FIRST (agents-op02b). The qrcode nightly read "cited 0 of
    the 7" for seven rows that each named a real candidate by path and simply carried no id, which looks
    exactly like seven rows naming the wrong candidate. It is named first because the delta table truncates
    this note at 200 characters: a clause appended after two others is the one an operator never sees.

    NOT A WALL OF IDS. An 8-of-49 report would otherwise list 41 ids the model is being told to copy back,
    and a 0-of-N report names nothing it does not already say ("cited 0" is the whole finding), so a
    nothing-cited report keeps its existing text and only duplicates are named.
    """
    parts: List[str] = []
    if rows_without_candidate_id:
        parts.append(f"{rows_without_candidate_id} row(s) carried no candidate_id")
    if duplicates:
        parts.append("duplicated citation(s): " + "; ".join(
            f"{record['candidate_id']} cited by {record['citations']} rows" for record in duplicates))
    if uncited and accounted > 0:
        named = ", ".join(uncited[:COVERAGE_NAMED_UNCITED_IDS])
        if len(uncited) > COVERAGE_NAMED_UNCITED_IDS:
            named += f", +{len(uncited) - COVERAGE_NAMED_UNCITED_IDS} more"
        parts.append(f"presented id(s) no row cited: {named}")
    return "; ".join(parts)


def candidate_coverage(candidates_in: Optional[int], reported: int,
                       slice_size: int = CANDIDATE_PROMPT_SLICE, *,
                       presented_ids: Optional[Iterable[str]] = None,
                       cited_ids: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Whether the report can show the station accounted for the candidates it was shown (agents-xx9t).

    OUTCOME AND VALIDITY ARE TWO FACTS. `status` says what the station found; this says whether its report
    can show it looked at what it was given. A repair-retry that triaged 8 of 49 candidates PASSed because
    the only question asked of it was "were there criticals" - and nothing in the report contradicted that.

    `reported` counts every finding the report carried BEFORE the false-positive filter, so a station that
    lists its dismissals with a verdict accounts for them and one that silently drops them does not. The
    bound is the slice the prompt carries, not the raw candidate count.

    IDENTITY WHEN AVAILABLE, COUNT WHEN NOT (agents-w9ni). A count is satisfiable by the right NUMBER of rows
    describing candidates the station was never shown - measured: 5 candidates presented and 5 invented rows
    with no candidate_id read as "accounted 5 of 5". So when the presented candidates carry ids
    (`presented_ids`), coverage counts the DISTINCT PRESENTED ids the report cites and a row that names no
    presented candidate accounts for nothing. When they do not, the count stands and `identity` says
    "count-only", which every surface must show: a weaker check indistinguishable from the stronger one is
    the same blind spot one level down.

    A SHORTFALL NAMES ITS OWN CAUSE (agents-amgst). "cited 5 of the 6" is true and useless: nightly
    2026-10-23's failing station had six dismissal rows where one row cited another page's candidate_id, so
    the missing sixth was a DUPLICATE, not a missing row. The reason therefore names duplicated citations
    (with their row counts) and the presented ids no row cited - and carries both as structured fields
    (`duplicate_cited_ids`, `uncited_candidate_ids`) so a line-level reader does not have to parse prose.

    A ROW THAT CARRIES NO ID AT ALL IS COUNTED HERE (agents-op02b), as `rows_without_candidate_id`. It is not
    the same defect as a WRONG id and it is not the count-only path: count-only means the pre-pass supplied
    no ids, so a blank is expected there and is never counted. This is identity mode with a report that
    named no candidate while the machine was holding `presented` of them.
    """
    duplicates: List[Dict[str, Any]] = []
    uncited: List[str] = []
    if candidates_in is None:
        return {"candidates_in": None, "candidates_presented": None,
                "candidates_accounted": int(reported), "complete": True, "reason": "",
                "identity": "not-applicable", "duplicate_cited_ids": duplicates,
                "uncited_candidate_ids": uncited, "rows_without_candidate_id": 0}
    total = max(0, int(candidates_in))
    presented = min(total, max(0, int(slice_size)))
    ids = [str(i) for i in (presented_ids or []) if i]
    rows_without_candidate_id = 0
    if ids:
        identity = "identity-matched"
        # Counted WITH multiplicity (agents-amgst): coverage intersects sets, so a citation repeated by a
        # second row is invisible in the count - and that duplication is exactly what leaves a presented
        # candidate unanswered while every row looks answered.
        citations: Dict[str, int] = {}
        for value in cited_ids or []:
            if isinstance(value, str) and value.strip():
                citations[value.strip()] = citations.get(value.strip(), 0) + 1
            else:
                rows_without_candidate_id += 1
        accounted = len(set(ids) & set(citations))
        duplicates = [{"candidate_id": cid, "citations": count}
                      for cid, count in citations.items() if count > 1 and cid in set(ids)]
        uncited = [cid for cid in ids if cid not in citations]
    else:
        identity = "count-only"
        accounted = int(reported)
    complete = presented == 0 or accounted >= presented
    if complete:
        reason = ""
    elif identity == "identity-matched":
        reason = (
            f"cited {accounted} of the {presented} candidate id(s) shown "
            f"({total} found by the pre-pass): a partial triage is not a clean result; every row - confirmed "
            f"or dismissed - must carry the candidate_id of the pre-pass candidate it answers")
        diagnostic = _coverage_diagnostic(accounted, duplicates, uncited, rows_without_candidate_id)
        if diagnostic:
            reason = f"{reason}; {diagnostic}"
    else:
        reason = (
            f"accounted for {accounted} of the {presented} candidate(s) shown "
            f"({total} found by the pre-pass): a partial triage is not a clean result; list a dismissed "
            f"candidate with its verdict to account for it, as secret-scan does "
            f"(count-only: these candidates carry no candidate_id to compare)")
    return {"candidates_in": total, "candidates_presented": presented,
            "candidates_accounted": accounted, "complete": complete, "reason": reason,
            "identity": identity, "duplicate_cited_ids": duplicates,
            "uncited_candidate_ids": uncited,
            "rows_without_candidate_id": rows_without_candidate_id}


def candidate_accounting_mode(agent_cfg: Dict[str, Any]) -> str:
    """The manifest's explicit accounting contract; unknown values never become row mode."""
    mode = agent_cfg.get("candidate_accounting", "row")
    if not isinstance(mode, str) or mode not in ("row", "aggregate-claimed"):
        raise ValueError(f"unsupported candidate_accounting declaration {mode!r}: "
                         "expected 'row' or 'aggregate-claimed'")
    return mode


def aggregate_candidate_coverage(candidates_in: Optional[int],
                                 rows: List[Dict[str, Any]], *,
                                 presented_ids: Optional[Iterable[str]],
                                 slice_size: int = CANDIDATE_PROMPT_SLICE) -> Dict[str, Any]:
    """Opt-in many-to-one accounting: model-CLAIMED dispositions, not verified grouping.

    Row mode remains in candidate_coverage unchanged. Every aggregate row explicitly
    names the distinct PRESENTED ids it disposes of; an anchor_candidate_id selects
    primary identity only and cannot count toward this coverage. Return the claimed
    ID-to-row mapping as report evidence, even when an invalid claim refuses PASS.

    THE VERDICT AND ITS REASON MUST NOT DISAGREE (agents-hwjhv). A run read "accounted for 35 of
    the 50", but its 15 anchor values looked to the operator exactly like 15 supplied ids, so the
    summary read as though the counter had thrown valid anchors away. It had not - measured: an id
    that is BOTH covered and anchored is counted once (50/50), so "35 of 50" is only reachable when
    those ids appear ONLY as anchors, i.e. were never claimed. Counting anchors instead would turn
    15 unclaimed candidates into a false 50/50 PASS and reverse agents-88cd, so the diagnostics say
    what happened instead: the anchor-only row is named as such (one problem, not a duplicate and
    false-sounding "outside its own covered_candidate_ids"), a malformed list is named as malformed
    rather than absent, and the unaccounted ids are listed so nobody has to infer them.
    """
    claims = [{"row_index": index,
               "covered_candidate_ids": row.get("covered_candidate_ids") if isinstance(row, dict) else None,
               "anchor_candidate_id": row.get("anchor_candidate_id") if isinstance(row, dict) else None}
              for index, row in enumerate(rows)]
    total = None if candidates_in is None else max(0, int(candidates_in))
    presented = None if total is None else min(total, max(0, int(slice_size)))
    raw_ids = list(presented_ids or [])
    ids = raw_ids[:presented] if presented is not None else []
    valid_ids = [value for value in ids if isinstance(value, str) and value.strip()]
    presented_set = set(valid_ids)
    problems: List[str] = []
    if presented is None:
        problems.append("aggregate mode requires a candidates pre-pass, not a count or an absent index")
    elif len(ids) != presented or len(valid_ids) != presented or len(presented_set) != presented:
        problems.append("aggregate mode requires unique presented candidate ids for every shown candidate")
    population_problems = len(problems)

    claimed = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            problems.append(f"row {index}: expected a finding object with covered_candidate_ids")
            continue
        row_ids = row.get("covered_candidate_ids")
        has_list = isinstance(row_ids, list) and bool(row_ids)
        if row_ids is not None and not isinstance(row_ids, list):
            # A model that joins the ids into one string HAS claimed coverage, badly; calling that
            # "absent" would hide the shape that actually produced the shortfall (agents-hwjhv).
            problems.append(f"row {index}: covered_candidate_ids must be a list of ids, got"
                            f" {type(row_ids).__name__}")
        elif not has_list:
            # `anchor_candidate_id` is primary identity, never coverage, so a row that carries only an
            # anchor is named as an anchor-only row: the old wording reported "absent or empty" AND
            # "anchor is outside its own covered_candidate_ids" for one cause, which reads to an
            # operator holding that anchor value like a valid claim being discarded (agents-hwjhv).
            anchor_value = row.get("anchor_candidate_id")
            anchor_named = anchor_value.strip() if isinstance(anchor_value, str) and anchor_value.strip() else ""
            if anchor_named:
                problems.append(f"row {index}: anchor only - anchor_candidate_id {anchor_named} is primary"
                                f" identity, not coverage; list it in covered_candidate_ids")
            else:
                problems.append(f"row {index}: covered_candidate_ids absent or empty")
        if not has_list:
            row_ids = []
        valid_row_ids = []
        for value in row_ids:
            if not isinstance(value, str) or not value.strip():
                problems.append(f"row {index}: covered_candidate_ids must contain nonempty string ids")
                continue
            valid_row_ids.append(value)
        if len(valid_row_ids) != len(set(valid_row_ids)):
            problems.append(f"row {index}: duplicate covered_candidate_ids within one row")
        row_set = set(valid_row_ids)
        if row_set & claimed:
            problems.append(f"row {index}: duplicate covered_candidate_ids across rows")
        claimed.update(row_set)
        if row_set - presented_set:
            problems.append(f"row {index}: unknown/unshown covered_candidate_ids")
        if "anchor_candidate_id" in row and has_list:
            # Only a row that HAS a claim can hold an anchor outside it; the anchor-only row is
            # already explained above and must not be reported twice for one cause (agents-hwjhv).
            anchor = row["anchor_candidate_id"]
            if not isinstance(anchor, str) or not anchor.strip() or anchor not in row_set:
                problems.append(f"row {index}: anchor_candidate_id is outside its own covered_candidate_ids")
    if presented_set - claimed:
        unaccounted = [cid for cid in valid_ids if cid not in claimed]
        named = ", ".join(unaccounted[:4])
        if len(unaccounted) > 4:
            named += f", +{len(unaccounted) - 4} more"
        # The population fact first: it is the one line an operator reads, and it names the ids so a
        # reader never has to guess whose absence made the count short (agents-hwjhv).
        problems.insert(population_problems,
                        f"missing {len(unaccounted)} presented candidate id(s) ({named})")
    return {"candidates_in": total, "candidates_presented": presented,
            "candidates_accounted": len(presented_set & claimed),
            "complete": not problems, "reason": "; ".join(problems),
            "identity": "identity-claimed-aggregate", "candidate_claims": claims}


def _run_level_anchored_cross_station_pairs(findings: List[Dict[str, Any]],
                                            fixed: List[Dict[str, Any]]) -> int:
    """Location twins across stations where AT LEAST ONE side is ANCHORED - counted, never paired.

    agents-09wf, the implementation of decision agents-u2xe option (a)+(c). `_run_level_possible_rekeys`
    above requires BOTH sides to be prose-bound, so a twin with a stable anchor (`candidate-id` is in
    IDENTITY_STABLE_SOURCES) is skipped there and was therefore neither counted nor disclosed. The
    nightly's own example has exactly that shape: a `new` row under vuln-triage (no-candidate-index) and
    a Fixed twin under modern-web (candidate-id) at the same location. This function DISCLOSES those
    pairs and does nothing else - the classification of both rows is untouched, nothing is paired for
    action, and no id value is compared (see the DELTA_KEYS comment).

    CROSS-STATION ONLY, and that restriction is the whole soundness point. Station-local anchored pairs
    remain refused here AND at the station: there the anchor is comparable, "the anchor would have
    matched this station's rows" is sound, and such a pair is not a re-key - the case the original
    refusal exists for. Both rows must also carry a KNOWN `agent` and those agents must DIFFER: an
    unknown agent is not evidence of a cross-station pair, so it is left out and the count stays a
    FLOOR rather than a guess (agents-yh0z's discipline).

    Shape rules are the same as the sibling pass, deliberately: an exact usable line is required on
    both sides, the pair key is `(normalize_path, line)`, and one retiring row explains exactly ONE
    appearance (agents-l3j1), consumed by popping the matched partner.
    """
    retiring: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in fixed:
        line = usable_line_number(row.get("line_number"))
        if line is None:
            continue
        retiring.setdefault((normalize_path(row.get("path")), line), []).append(row)
    pairs = 0
    for row in findings:
        if row.get("change") != "new" or row.get("false_positive"):
            continue
        line = usable_line_number(row.get("line_number"))
        if line is None:
            continue
        pool = retiring.get((normalize_path(row.get("path")), line))
        if not pool:
            continue
        appearance_agent = row.get("agent")
        for index, twin in enumerate(pool):
            # at least one side anchored = NOT (both prose-bound); the both-prose-bound pairs belong to
            # the sibling counter above, so the two counters cannot double-count the same pair
            if is_unanchored_finding(row) and is_unanchored_finding(twin):
                continue
            twin_agent = twin.get("agent")
            if not appearance_agent or not twin_agent or appearance_agent == twin_agent:
                continue
            pool.pop(index)
            pairs += 1
            break
    return pairs

def _run_level_possible_rekeys(findings: List[Dict[str, Any]],
                              fixed: List[Dict[str, Any]]) -> int:
    """The possible-re-key pairs over the WHOLE RUN, which is what the counter always claimed to count.

    agents-pxzb: the delta's own wording is run-level - a `new` row that 'shares a location with a row
    THIS SAME RUN booked Fixed' - but the implementation compared inside ONE station (the retirement set
    is built from rows whose `agent` is the station's own). A pair whose twin ANOTHER station booked was
    therefore invisible, and the nightly's own example has exactly that shape: docs/css/factory.css:192
    is a `new` row under vuln-triage (`no-candidate-index`) and the Fixed twin is modern-web's
    (`candidate-id`). The line is the first place that can see both halves, so the pairing is done here
    as well.

    THE RULE IS UNCHANGED, only its scope. Both sides must be prose-bound (`is_unanchored_finding`),
    both need an exact usable line, and one retiring row explains exactly ONE appearance (agents-l3j1) -
    so this can only count pairs the station-level pass could not see, never pairs it refused. Note what
    that leaves out, because it is the nightly example's own shape: a twin whose identity is ANCHORED
    (`candidate-id` is in IDENTITY_STABLE_SOURCES) is still refused, here as at the station, because the
    soundness argument is that a stable anchor WOULD have matched this run's rows. Across stations that
    argument is weaker than it sounds - a station only ever compares its OWN agent's rows, so an anchored
    twin booked elsewhere was never offered to the appearance - but widening the rule is a soundness
    decision, not a scope one, and it is recorded rather than taken here.
    """
    retiring: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in fixed:
        if not is_unanchored_finding(row):
            continue
        line = usable_line_number(row.get("line_number"))
        if line is None:
            continue
        retiring.setdefault((normalize_path(row.get("path")), line), []).append(row)
    pairs = 0
    for row in findings:
        if (row.get("change") != "new" or row.get("false_positive")
                or not is_unanchored_finding(row)):
            continue
        line = usable_line_number(row.get("line_number"))
        if line is None:
            continue
        pool = retiring.get((normalize_path(row.get("path")), line))
        if pool:
            pool.pop(0)
            pairs += 1
    return pairs


def write_line_report(target_name: str, line_name: str, stations: List[Dict[str, Any]],
                      findings_dir: Optional[Path] = None) -> Path:
    """Write the run's delta report from every station of one factory line (fleet-810).

    `stations` is the line's scorecard, in order; a station that produced a findings delta
    carries its fragment path under `fragment`. Findings, fixed items and stats are the union
    over stations, and the station table says which stations produced no verdict, so the
    report can never call a run clean on the strength of one station's empty slice.
    """
    findings: List[Dict[str, Any]] = []
    fixed: List[Dict[str, Any]] = []
    stats = {key: 0 for key in DELTA_KEYS}
    sinks: Dict[str, Dict[str, Any]] = {}
    verification_counts: Dict[str, int] = {}
    has_verification_counts = False
    for station in stations:
        fragment = station.get("fragment")
        if not fragment or not Path(fragment).exists():
            continue
        data = json.loads(Path(fragment).read_text(encoding="utf-8"))
        findings.extend(data.get("findings", []))
        fixed.extend(data.get("fixed", []))
        for key in DELTA_KEYS:
            stats[key] += int(data.get("stats", {}).get(key, 0) or 0)
        station_counts = data.get("verification_counts")
        if isinstance(station_counts, dict):
            has_verification_counts = True
            for verdict in ("disproved", "unverifiable", "verified"):
                count = station_counts.get(verdict)
                if type(count) is int and count >= 0:
                    verification_counts[verdict] = verification_counts.get(verdict, 0) + count
        for sink, result in (data.get("sinks") or {}).items():
            total = sinks.setdefault(sink, {})
            for key, value in result.items():
                if isinstance(value, int) and not isinstance(value, bool):
                    total[key] = total.get(key, 0) + value
                elif value and key == "note":
                    total["note"] = "; ".join(filter(None, [total.get("note"), str(value)]))
    # agents-pxzb: the summed station counters can only see pairs whose two halves were booked by the
    # SAME station. The run-level count is what the counter has always documented, and it is never the
    # smaller of the two (per location it is at least the sum of the stations' own pairs), so this can
    # only add misses - and `max` keeps the summed value when a fragment cannot supply the rows the
    # recomputation needs, so a fragment shape that lacks them cannot silently lower the count.
    stats["possible_rekey"] = max(int(stats.get("possible_rekey", 0) or 0),
                                  _run_level_possible_rekeys(findings, fixed))
    # agents-09wf: the anchored cross-station subset, DISCLOSED beside `possible_rekey` and never inside
    # it. ADDITIVE: this line cannot lower the sibling's value (a separate function and a separate key),
    # which is why the two counters are disjoint by construction rather than by agreement.
    stats["possible_rekey_anchored"] = max(int(stats.get("possible_rekey_anchored", 0) or 0),
                                           _run_level_anchored_cross_station_pairs(findings, fixed))
    report = _dispatch_file(target_name, findings, stats, fixed, sink_results=sinks,
                            stations=stations, line_name=line_name, findings_dir=findings_dir,
                            verification_counts=verification_counts if has_verification_counts else None)
    machine = report.with_name(f"{target_name}-line.json")
    machine.write_text(json.dumps({
        "target": target_name,
        "line": line_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        # complete requires every station to BOTH produce a verdict and not be flagged
        # incomplete: agents-ekwm's count checks (via station_has_verdict) plus agents-xx9t's
        # incompleteness fact, which stay two separate predicates.
        "complete": all(station_has_verdict(s) and not station_is_incomplete(s)
                        for s in stations),
        "stats": stats,
        "sinks": sinks,
        **({"verification_counts": verification_counts} if has_verification_counts else {}),
        "stations": [{k: v for k, v in s.items() if k != "fragment"} for s in stations],
    }, indent=2), encoding="utf-8")
    return report


def _badge(f: Dict[str, Any]) -> str:
    """The triaged severity, plus the routing band when the embargo treats it differently."""
    if f.get("false_positive"):
        return "[FALSE POSITIVE]"
    shown = reported_severity(f)
    routed = effective_severity(f)
    if routed != shown:
        return f"[{shown.upper()} · routed {routed}]"
    return f"[{shown.upper()}]"


def _identity_grade(f: Dict[str, Any]) -> str:
    """The grading suffix for a row's identity source, or empty when the source is stable.

    Rendered rather than only documented: a reader should not have to know this module's vocabulary
    to know how much to trust the key, so every source outside IDENTITY_STABLE_SOURCES is marked
    wherever the key is shown - the full report, the step summary and the Fixed section.

    NOTE ON MISSING IDENTITY_SOURCE (agents-l17v): A row with no `identity_source` (None or missing)
    deliberately renders no grade suffix because `_identity_grade` is a caveat modifying a displayed
    key (see `_identity_note`), and with no key there is nothing to annotate. In contrast,
    `is_unanchored_finding(f)` classifies a missing source as unanchored because it lacks a verified
    stable anchor for delta metrics and the unanchored-disappearance banner.
    """
    source = f.get("identity_source")
    if not source:
        return ""
    if is_unanchored_finding(f):
        return " (reword-unstable — not evidence on its own)"
    return ""


def _new_row_locations(findings: List[Dict[str, Any]]) -> Dict[tuple, int]:
    """Exact locations THIS RUN reports a `new` finding at, for the Fixed side's own warning (agents-x9my).

    The Fixed section's header warning is GENERAL - "a row is also booked fixed when a later run drifts its
    label or line, or omits it entirely" - and a general warning leaves the reader to cross-reference
    locations by hand, which is why the hub's report of this defect arrived as the phrase "rows both new and
    Fixed in one run" with no named rows. So this records the locations a New row occupies, and every Fixed
    row sitting on one is marked explicitly: the warning becomes an instruction that can be acted on row by
    row. A false positive is not a live row and does not count, and a row whose line the scanner could not
    name is left out rather than paired on a location it does not have (the agents-yh0z floor).

    THIS IS A COINCIDENCE OF LOCATION, NOT A RE-KEY CLAIM. It deliberately does not look at either row's
    identity source, and it does not touch the pairing `possible_rekey` counts - whose run-level scope is
    agents-pxzb's and whose rule (may an ANCHORED twin be paired at all) is agents-u2xe's open question.
    Naming the line and calling it a re-key are different statements, and only the first is a thing this
    report can observe.
    """
    located: Dict[tuple, int] = {}
    for row in findings:
        if row.get("change") != "new" or row.get("false_positive"):
            continue
        line = usable_line_number(row.get("line_number"))
        if line is None:
            continue
        loc = (normalize_path(row.get("path")), line)
        located[loc] = located.get(loc, 0) + 1
    return located


def _contradiction_note(f: Dict[str, Any], new_at: Dict[tuple, int]) -> str:
    """The marker appended to a Fixed row that a New row in this same run sits on (agents-x9my)."""
    line = usable_line_number(f.get("line_number"))
    if line is None:
        return ""
    count = new_at.get((normalize_path(f.get("path")), line))
    if not count:
        return ""
    plural = "findings" if count > 1 else "finding"
    return (f" - ⚠ **contradicted here**: this run also reports {count} NEW {plural} at this exact "
            "line, so this Fixed booking is not evidence the finding is gone - read that row before "
            "closing anything on this line (agents-x9my)")


def _identity_note(f: Dict[str, Any]) -> str:
    """` — identity: `x`` plus its grading, naming the key that produced this fingerprint.

    A Fixed line nobody can attribute is unfalsifiable, which is why the teams reading these
    reports concluded that nothing may be closed on one. `model-snippet` says the row was
    recognised by the model's re-quoted prose, and `candidate-exact` that the scanner's own match
    text recognised it.

    WHAT THIS IS NOT, corrected after review: no source makes a Fixed line proof that a finding was
    fixed. A row is also booked fixed when the next run drifts its rule label, drifts its line in a
    multi-candidate file, or omits it entirely - and the row that disappears then still carries a
    stable-looking `candidate-exact` from its LAST observation, because that is when it was written.
    The key describes how the row was recognised, never that its disappearance was verified.
    """
    source = f.get("identity_source")
    return f" — identity: `{source}`{_identity_grade(f)}" if source else ""


def _migration_note(stats: Dict[str, int]) -> List[str]:
    """The one-time identity-migration announcement, for a run that re-keyed stored rows.

    A migration re-books rows, so the run that performs it reports a new+fixed wave that is
    BOOKKEEPING rather than discovery. Without this line the wave is indistinguishable from real
    findings, and every VM's triage spends the next morning on it - the exact false-new/false-fixed
    confusion this change exists to end (agents-x9my step 2, agents-1ukp).
    """
    migrated = int(stats.get("migrated", 0) or 0)
    if migrated <= 0:
        return []
    return [
        f"> **Identity migration (one-time)**: this findings store was written by an older identity "
        f"binding, so {migrated} row(s) it held were re-keyed in this run. Identity now comes from "
        "the scanner candidate at a row's LOCATION instead of from the model's wording, so a row that "
        "disappears as Fixed and reappears as New in the same run is the SAME finding moving key - "
        "BOOKKEEPING, not findings. Do not triage that wave: it happens on this run only, because the "
        "store is now stamped with the binding that wrote it. Old keys stay on the records as "
        "`legacy_fingerprint`. (agents-x9my step 2; announcement agents-1ukp.)",
        "",
    ]


def _unanchored_fixed_note(stats: Dict[str, int]) -> List[str]:
    """The banner note for resolved findings that had no stable scanner anchor.

    `fixed` counts the total number of findings that left the active set; this note reports the
    subset whose identity rested on model prose rather than scanner candidates, so triagers know
    their disappearance is not evidence on its own. (agents-6r8y)
    """
    unanchored = int(stats.get("fixed_unanchored", 0) or 0)
    if unanchored <= 0:
        return []
    total_fixed = int(stats.get("fixed", 0) or 0)
    return [
        f"> **Unanchored disappearances**: {unanchored} of {total_fixed} finding(s) that left the "
        "active set had no stable anchor, so their disappearance is unattributed and not evidence "
        "of a fix on its own. (agents-6r8y)",
        "",
    ]


def _unanchored_new_note(stats: Dict[str, int]) -> List[str]:
    """The appearance-side counterpart of _unanchored_fixed_note (agents-l606).

    `new` counts the total number of new findings; this note reports the subset whose identity rested
    on the model's wording rather than on a scanner candidate, whose newness is therefore unattributed
    - a reworded or re-keyed row looks the same as a discovery. It also names how many of those share
    a location with a row this same run booked Fixed, which is the signature of ONE finding moving
    key; the delta reports that pair rather than reclassifying it, because a location cannot tell the
    two apart and every reclassification attempted was reproduced as a way to hide work.
    """
    unanchored = int(stats.get("new_unanchored", 0) or 0)
    if unanchored <= 0:
        return []
    total_new = int(stats.get("new", 0) or 0)
    note = [
        f"> **Unanchored appearances**: {unanchored} of {total_new} new finding(s) had no stable "
        "anchor, so their newness is unattributed: a row whose wording was reworded or whose rule "
        "label was re-derived is indistinguishable from a discovery. (agents-l606)",
    ]
    paired = int(stats.get("possible_rekey", 0) or 0)
    if paired > 0:
        note.append(
            f"> **Possibly re-keyed, not reclassified**: {paired} of them sit at an exact line a row "
            "this run booked Fixed - including rows another station of the line booked, since the "
            "run-level pairing compares every appearance with every retiring row - which is what ONE "
            "finding moving key looks like - and also what a "
            "new finding at a recycled line looks like. They are counted here and left in the "
            "actionable list, because a location cannot distinguish the two and guessing has hidden "
            "real findings. This is a floor: rows whose line the scanner could not name are not counted, "
            "so they are never paired on a location neither of them has. (agents-l606, agents-wcki, "
            "agents-yh0z)")
    note.append("")
    return note


def _possible_rekey_anchored_note(stats: Dict[str, int]) -> List[str]:
    """The banner for anchored cross-station location twins (agents-09wf, decision agents-u2xe (a)+(c)).

    DISCLOSURE, NOT A RECLASSIFICATION - the same standing rule as `possible_rekey`: the rows keep their
    classification and their detail, and nothing a reader or a sink acts on changes. This note exists so
    that such a pair is neither silently `New` nor silently counted as a prose-bound re-key.
    """
    pairs = int(stats.get("possible_rekey_anchored", 0) or 0)
    if not pairs:
        return []
    plural = "pair" if pairs == 1 else "pairs"
    return [f"**Advisory**: {pairs} {plural} of new/retired rows share an exact location across two "
            "stations with a stable anchor on at least one side. These are DISCLOSED, not reclassified: "
            "the rows keep their own states, and no anchor is compared across stations because a "
            "`candidate-id` anchor is assigned per station and is not comparable at run scope. "
            "(agents-09wf)"]


def _anchor_echo_note(stats: Dict[str, int]) -> List[str]:
    """Disclose untrusted model echoes by count, never by copying their raw values to a report."""
    unknown = int(stats.get("anchor_unknown", 0) or 0)
    disagreement = int(stats.get("anchor_disagreement", 0) or 0)
    if not unknown and not disagreement:
        return []
    return [
        f"> **Anchor echo checks**: {unknown} unknown anchor id(s) not found in the candidate "
        f"artefact; {disagreement} anchor disagreement(s) with a rule/location-bound id. "
        "Unknown echoes fell back to normal binding; fact-bound ids took precedence over "
        "disagreeing model echoes. Counts are diagnostic, not a clean verdict.",
        "",
    ]


def _render_delta_report(target_name: str, findings: List[Dict[str, Any]], stats: Dict[str, int],
                         fixed_items: List[Dict[str, Any]], *, step_summary: bool = False,
                         sink_results: Optional[Dict[str, Any]] = None,
                         stations: Optional[List[Dict[str, Any]]] = None,
                         line_name: Optional[str] = None,
                         env_failure: Optional[str] = None,
                         verification_counts: Optional[Dict[str, int]] = None) -> str:
    """Render the delta report; with step_summary=True, high/critical finding prose is reduced.

    effective_severity decides the band, matching the embargo: an understated or absent
    severity cannot leak detail onto the step summary. The badge a reader sees is the triaged
    severity (journal-1kg); when routing differs it is shown alongside, never instead.

    `stations` (a factory line's scorecard) makes the report a run report: "Clean Delta" is
    printed only when every station produced a verdict (fleet-810).
    """
    def reduced(f: Dict[str, Any]) -> bool:
        return step_summary and effective_severity(f) in ("critical", "high")

    false_positives = [f for f in findings if f.get("false_positive")]
    live = [f for f in findings if not f.get("false_positive")]
    new_or_regressed = [f for f in live if f["change"] in ("new", "regressed")]
    unchanged = [f for f in live if f["change"] == "unchanged"]
    suppressed = [f for f in live if f["state"] == "wontfix"]
    withheld = [f for f in findings if reduced(f)]
    env_failed = [s for s in (stations or []) if s.get("status") == "ENV_FAILURE"]
    # Each of these three banners names its own stations and no station appears in two: a coverage-partial
    # station did produce a report (it just cannot show it triaged what it was given), and an ENV_FAILURE has
    # its own banner. Both predicates are the shared ones, never a local re-derivation (agents-kve2, agents-pim5).
    no_verdict = [s for s in (stations or []) if not station_has_verdict(s)
                  and s.get("status") != "ENV_FAILURE" and not station_is_incomplete(s)]
    partial_triage = [s for s in (stations or []) if station_is_incomplete(s)]

    lines = [
        f"# Software Factory Delta Report: {target_name}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"",
    ]
    if stations is not None:
        # By predicate, not by subtraction: subtracting an erasure list counted a partial station as
        # having a verdict, which is the header telling the reader the opposite of the banner (agents-kve2).
        has_verdict_count = sum(1 for s in stations if station_has_verdict(s))
        lines.append(f"Line: `{line_name or '?'}` — {len(stations)} station(s), "
                     f"{has_verdict_count} with a verdict.")
        lines.append("")
    if env_failure or env_failed or no_verdict or partial_triage:
        lines += [
            f"| New | Regressed | Fixed | Unchanged | Suppressed | False positive |",
            f"|:---:|:---:|:---:|:---:|:---:|:---:|",
            f"| — | — | — | — | — | — |",
            f""
        ]
    else:
        lines += [
            f"| New | Regressed | Fixed | Unchanged | Suppressed | False positive |",
            f"|:---:|:---:|:---:|:---:|:---:|:---:|",
            f"| **{stats['new']}** | **{stats['regressed']}** | **{stats['fixed']}** | {stats['unchanged']} | {stats['suppressed']} | {stats.get('false_positive', 0)} |",
            f""
        ]

    if env_failure:
        lines.append(f"> 🚨 **ENVIRONMENT FAILURE**: Station failed due to adapter authentication/environment error:\n"
                     f"> `{env_failure}`\n>\n"
                     f"> The model triage step could not authenticate and did NOT run.\n"
                     f"> Findings count is **UNKNOWN** (not zero). This is **NOT** a clean scan.")
        lines.append("")
    if env_failed:
        names = ", ".join(f"`{s.get('station')}`" for s in env_failed)
        lines.append(f"> 🚨 **ENVIRONMENT FAILURE**: {len(env_failed)} station(s) failed due to adapter authentication/environment issues: {names}. "
                     "Findings for these stations are UNKNOWN (not zero). The stations could not run. This run is NOT clean.")
        lines.append("")
    if partial_triage:
        names = ", ".join(
            f"`{s.get('station')}` ({s.get('candidates_accounted')} of {s.get('candidates_presented')} shown, "
            f"{s.get('candidate_identity') or 'count-only'})"
            for s in partial_triage)
        lines.append(f"> **INCOMPLETE**: {len(partial_triage)} station(s) did not account for the candidates they "
                     f"were shown: {names}. A partial triage is not a clean result; their counts are not a verdict.")
        lines.append("")
    if no_verdict:
        names = ", ".join(f"`{s.get('station')}` ({s.get('status')})" for s in no_verdict)
        lines.append(f"> **INCOMPLETE**: {len(no_verdict)} station(s) produced no verdict: {names}. "
                     "Their zero is not a clean result; this run is not clean.")
        lines.append("")
    elif not env_failure and not env_failed and not partial_triage \
            and stats["new"] == 0 and stats["regressed"] == 0 and stats["fixed"] == 0:
        lines.append("> **Clean Delta**: No new, regressed, or resolved findings in this run.")
        lines.append("")

    if verification_counts and sum(verification_counts.values()):
        lines.append("> **Verifier dispositions (not findings)**: "
                     f"{sum(verification_counts.values())} candidate disposition(s) in this run — "
                     f"{verification_counts.get('disproved', 0)} disproved, "
                     f"{verification_counts.get('unverifiable', 0)} unverifiable, "
                     f"{verification_counts.get('verified', 0)} verified. "
                     "These are not false-positive findings, never published, and do not enter "
                     "the finding lifecycle or the counts above. False positive 0 does not mean "
                     "no verifier candidates were dismissed.")
        lines.append("")

    lines += _migration_note(stats)
    lines += _unanchored_fixed_note(stats)
    lines += _unanchored_new_note(stats)
    lines += _possible_rekey_anchored_note(stats)
    lines += _anchor_echo_note(stats)

    if stations is not None:
        lines.append("## Stations")
        lines.append("")
        lines.append("| Station | Status | Findings | Criticals | Note |")
        lines.append("|:---|:---:|:---:|:---:|:---|")
        for s in stations:
            has_verdict = station_has_verdict(s)
            count = s.get("findings_count") if has_verdict else "—"
            crit = s.get("criticals") if has_verdict else "—"
            if has_verdict and s.get("candidates_presented") is not None:
                # The counts sit beside the status that depends on them, not only in the banner - and HOW
                # they were met is part of what they mean: identity-matched says the rows named the
                # candidates shown, count-only says the station emitted the right NUMBER of rows and no
                # more (agents-w9ni).
                count = (f"{count} ({s.get('candidates_accounted')}/{s.get('candidates_presented')}, "
                         f"{s.get('candidate_identity') or 'count-only'})")
            note = str(s.get("error") or "") or (str(s.get("note") or "") if station_is_incomplete(s) else "")
            note = note.replace("|", "/").replace("\n", " ")[:200]
            lines.append(f"| `{s.get('station')}` | {s.get('status')} | {count} | {crit} | {note} |")
        lines.append("")

    if sink_results:
        lines.append("## Tracker Sinks")
        lines.append("")
        for sink, r in sink_results.items():
            lines.append(f"- **{sink}**: published {r.get('published', 0)}, failed {r.get('failed', 0)}, "
                         f"duplicate {r.get('duplicate', 0)}, embargoed {r.get('embargoed', 0)}, below band {r.get('skipped', 0)}, "
                         f"false positive {r.get('false_positive', 0)}"
                         + (f" — {r['note']}" if r.get("note") else ""))
        lines.append("")

    if step_summary and withheld:
        lines.append("> **Withheld**: high/critical finding details are not rendered in the step "
                     "summary — see the run artifact (the full delta report) or the findings store.")
        lines.append("")

    closed_recurrences = [f for f in findings if f.get("post_close_sightings") and f.get("closed_bead_verified_in_run")]
    if closed_recurrences:
        lines.append("## Closed Bead Re-detections (Needs Review)")
        lines.append("")
        lines.append("> ⚠️ The following finding(s) match a closed bead in the tracker. "
                     "The factory does not duplicate or auto-reopen closed beads; human review is required.")
        lines.append("")
        for f in closed_recurrences:
            count = f["post_close_sightings"]
            s_word = f"{count} sighting" if count == 1 else f"{count} sightings"
            bead_id = f.get("post_close_bead_id", "?")
            notice = f"re-detected after human close; {s_word}; needs review - not independently verified"
            loc = f"{f.get('path')}:{f.get('line_number', '?')}"
            rule = f.get('rule_id') or 'finding'
            if reduced(f):
                lines.append(f"- `{rule}` (`{loc}`) — {notice} (closed bead `{bead_id}`)")
            else:
                title = f.get('title') or rule
                lines.append(f"- **{title}** (`{rule}` at `{loc}`) — {notice} (closed bead `{bead_id}`)")
        lines.append("")

    if new_or_regressed:
        lines.append("## Action Required: New & Regressed Findings")
        lines.append("")
        for f in new_or_regressed:
            badge = _badge(f)
            if reduced(f):
                lines.append(f"### {badge} `{f['rule_id']}` (`{f['state']}`)")
                lines.append(f"- **Location**: `{f['path']}:{f.get('line_number', '?')}`{_identity_note(f)}")
                lines.append("")
                continue
            lines.append(f"### {badge} {f['title']} (`{f['state']}`)")
            lines.append(f"- **Rule**: `{f['rule_id']}`")
            if f.get("model_rule_id"):
                lines.append(f"- **Model's own label** (not scanner provenance): "
                             f"`{f['model_rule_id']}`")
            if f.get("identity_source"):
                lines.append(f"- **Identity**: `{f['identity_source']}`{_identity_grade(f)}")
            lines.append(f"- **Location**: `{f['path']}:{f.get('line_number', '?')}`")
            lines.append(f"- **Fingerprint**: `{f['fingerprint'][:16]}...`")
            lines.append(f"- **Description**: {f['description']}")
            lines.append(f"- **Snippet**: `{f['snippet']}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation**: {f['remediation']}")
            lines.append("")

    if fixed_items:
        lines.append("## Resolved in this Run (Fixed)")
        lines.append("")
        lines.append("> Identity names how each row was recognised, NOT that its disappearance was "
                     "verified: a row is also booked fixed when a later run drifts its label or line, "
                     "or omits it entirely.")
        lines.append("")
        # agents-x9my: name the SPECIFIC lines a live row sits on, so the general warning above becomes an
        # instruction a reader can act on row by row. Computed once for the whole section.
        new_at = _new_row_locations(findings)
        for f in fixed_items:
            note = _contradiction_note(f, new_at)
            if reduced(f):
                lines.append(f"- **`{f.get('rule_id')}`** (`{f.get('path')}:{f.get('line_number', '?')}`){_identity_note(f)}{note}")
                continue
            lines.append(f"- **`{f.get('rule_id')}`**: {f.get('title')} (`{f.get('path')}:{f.get('line_number', '?')}`){_identity_note(f)}{note}")
        lines.append("")

    if unchanged:
        lines.append("## Active Findings (Unchanged)")
        lines.append("")
        for f in unchanged:
            badge = _badge(f)
            if reduced(f):
                lines.append(f"- {badge} `{f['rule_id']}` (`{f['path']}:{f.get('line_number', '?')}`)")
                continue
            line = f"- {badge} **{f['title']}** (`{f['path']}:{f.get('line_number', '?')}`)"
            if f.get("model_rule_id"):
                # A finding is 'unchanged' for every run after its first, so without this the
                # label would be visible exactly once (agents-ag4, review P2).
                line += f" — model's own label (not scanner provenance): `{f['model_rule_id']}`"
            lines.append(line)
        lines.append("")

    if false_positives:
        lines.append("## Triaged False Positives (not counted, never published)")
        lines.append("")
        for f in false_positives:
            if reduced(f):
                lines.append(f"- `{f.get('rule_id')}` (`{f.get('path')}:{f.get('line_number', '?')}`)")
                continue
            lines.append(f"- **{f.get('title')}** (`{f.get('rule_id')}` at `{f.get('path')}:{f.get('line_number', '?')}`)")
        lines.append("")

    if suppressed:
        lines.append("## Suppressed Findings (Wontfix)")
        lines.append("")
        for f in suppressed:
            if reduced(f):
                lines.append(f"- `{f.get('rule_id')}` (`{f.get('path')}:{f.get('line_number', '?')}`)")
                continue
            lines.append(f"- **{f['title']}**: {f.get('suppression_reason') or 'Suppressed'}")
        lines.append("")

    return "\n".join(lines)

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Process findings into findings store")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--agent", help="Agent name (required for a findings run)")
    parser.add_argument("--input", help="JSON file with raw findings (required for a findings run)")
    parser.add_argument("--promote-issue", help="Explicitly promote this approved public issue URL")
    parser.add_argument("--beads-dir", help="Explicit initialized Beads project (beads sink and promotion)")
    parser.add_argument("--candidates", help="Scanner candidates JSON to bind rule_id/path against")
    parser.add_argument("--sink", default="file", help="Sink type (file or beads)")
    parser.add_argument("--visibility", choices=["public", "private"],
                        help="Explicit target visibility; missing withholds high/critical from a synced tracker")
    parser.add_argument("--repo", help="Explicit public github.com/OWNER/REPO issue destination")
    parser.add_argument("--run-dir", help="Private station run directory for sink diagnostics")
    parser.add_argument("--sink-option", action="append", default=[], metavar="KEY=VALUE",
                        help="A sink_* setting from the target manifest")
    parser.add_argument("--target-dir", default=".", help="Target repository directory")
    parser.add_argument("--station-only", action="store_true",
                        help="One station of a factory line: write <target>-<agent>-delta.md, "
                             "not the run's <target>-delta.md (the line writes that)")
    parser.add_argument("--fragment", help="Write this station's delta as JSON here (for the line report)")
    args = parser.parse_args(argv)
    sink_options = {}
    for option in args.sink_option:
        key, sep, value = option.partition("=")
        if not sep or not key.startswith("sink_"):
            parser.error("--sink-option requires sink_KEY=VALUE")
        if key in sink_options and key == "sink_env":
            sink_options[key] = f"{sink_options[key]},{value}"
        else:
            sink_options[key] = value

    if args.promote_issue:
        if not args.beads_dir or not args.repo or args.visibility != "public":
            parser.error("promotion needs --beads-dir, --repo and explicit --visibility public")
        try:
            with FindingsStore(target_name=args.target) as store:
                result = promote_issue(args.target, Path(args.target_dir).resolve(), args.repo,
                                       args.visibility, args.promote_issue, Path(args.beads_dir),
                                       store=store)
        except (SuppressionFileError, StoreFileError, StoreBusyError) as e:
            # The store-opening site for promotion: bounded wait failure takes the clean error path
            # rather than a traceback (agents-4sij, agents-ynjh).
            sys.stderr.write(f"Error: {e}\n")
            sys.exit(2)
        print(json.dumps(result))
        return
    if not args.agent or not args.input:
        parser.error("a findings run needs --agent and --input")
    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"Input file not found: {input_path}\n")
        sys.exit(1)

    raw_data = json.loads(input_path.read_text(encoding="utf-8"))
    findings_list = raw_data.get("findings", []) if isinstance(raw_data, dict) else raw_data

    try:
        store = FindingsStore(target_name=args.target)
    except (SuppressionFileError, StoreFileError, StoreBusyError) as e:
        # Loud and non-zero: a register or store that cannot be parsed must not silently reset, and a
        # CONTENDED store must not lose this clean path either. StoreBusyError is deliberately NOT a
        # StoreFileError subclass, so it has to be named here or contention arrives as an uncaught
        # traceback instead of the diagnostic two lines below (agents-4sij review, P2).
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)
    try:
        candidate_index = load_candidate_index(Path(args.candidates)) if args.candidates else None
        verification_counts = None
        if args.agent == "vuln-verify" and isinstance(raw_data, dict):
            rows = raw_data.get("verifications")
            if isinstance(rows, list):
                verification_counts = store.record_verifications(args.agent, rows)
        processed, stats, fixed_items = store.process_run(
            agent=args.agent, raw_findings=findings_list, candidate_index=candidate_index,
            target_dir=Path(args.target_dir).resolve(),
        )
        try:
            results = dispatch_to_sink(
                sink=args.sink,
                target_name=args.target,
                target_dir=Path(args.target_dir).resolve(),
                processed_findings=processed,
                stats=stats,
                fixed_items=fixed_items,
                visibility=args.visibility,
                repo=args.repo,
                agent=args.agent,
                station_only=args.station_only,
                fragment=Path(args.fragment) if args.fragment else None,
                beads_dir=Path(args.beads_dir) if args.beads_dir else None,
                sink_options=sink_options,
                run_dir=Path(args.run_dir) if args.run_dir else None,
                verification_counts=verification_counts,
            )
        finally:
            store.save()
    finally:
        store.close()  # even if candidate loading, processing or save() raises
    if any(result.get("failed") for result in results.values()):
        sys.stderr.write("Error: sink publication failed; findings retained for retry\n")
        sys.exit(3)


if __name__ == "__main__":
    main()
