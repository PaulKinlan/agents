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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

try:  # imported as lib.findings (root on sys.path), or run as a script (lib/ on it)
    from lib.redaction import redact_finding
except ImportError:
    sys.path.insert(0, str(FACTORY_ROOT))
    from lib.redaction import redact_finding

# Redaction removes the value from published text; the embargo decides whether a finding is
# routed to a tracker at all. It is a separate module so the policy has one home and one test.
from lib import sinks
from lib.embargo import (effective_severity, embargo_reason, is_false_positive,
                         reported_severity)
# Host-side trusted tools are resolved by absolute path + SHA-256 pin (agents-7bj); a
# mismatch fails closed rather than executing an unverified gh/bd.
from lib.tool_pins import ToolPinError, resolve_tool
from lib.sinks.github import promote_issue


# Keys of a per-run delta. `false_positive` counts findings the triage itself declared false
# positives: they are recorded, never counted as new/unchanged work (journal-35w).
DELTA_KEYS = ("new", "regressed", "fixed", "unchanged", "suppressed", "false_positive",
              # Not a table column: a one-time identity re-key count, announced as its own banner so
              # a migration wave cannot be read as discoveries (agents-x9my step 2, agents-1ukp).
              "migrated")

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
            "ids_at": ids_at, "ids_in": ids_in,
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
    "candidate-id",         # the candidate's own emitted id, used where a rule/location bound it
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
# and a stable-sounding label would hide that.
IDENTITY_STABLE_SOURCES = ("candidate-exact", "candidate-unique",
                           "unmatched-rule-location-unique", "unmatched-rule-path-unique",
                           "candidate-id")


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
    def __init__(self, target_name: str, findings_dir: Optional[Path] = None):
        self.target_name = target_name
        self.findings_dir = findings_dir or (FACTORY_ROOT / "findings")
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.store_file = self.findings_dir / f"{target_name}.json"
        self.suppressions_file = self.findings_dir / SUPPRESSIONS_FILENAME
        self.legacy_suppressions_file = self.findings_dir / f"{target_name}.suppressions.json"
        # Advisory lock held across the whole load -> mutate -> save window (agents-3ls).
        # Concurrent factory processes (scheduled timer, manual run, CI) each do a
        # read-modify-write; without a lock the last writer wins and silently drops the
        # other's findings and delivery receipts. The lock file is separate from the store
        # because save() replaces the store's inode via os.replace(), and a lock held on the
        # store file itself would be left pointing at the superseded inode.
        self._lock_path = self.store_file.with_name(self.store_file.name + ".lock")
        self._lock_fh = open(self._lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_EX)
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
            raise

    def close(self) -> None:
        """Release the advisory lock so another process can load and mutate this store."""
        fh = getattr(self, "_lock_fh", None)
        if fh is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            finally:
                fh.close()
            self._lock_fh = None

    def __enter__(self) -> "FindingsStore":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

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
        data["findings"] = {
            fp: (redact_finding(record) if isinstance(record, dict) else record)
            for fp, record in data["findings"].items()
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
        return {
            **self.data,
            "findings": {
                fp: (redact_finding(record) if isinstance(record, dict) else record)
                for fp, record in findings.items()
            },
        }

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
            fp = compute_fingerprint(
                agent=agent,
                rule_id=rule_id,
                path=path,
                snippet=identity_snip
            )
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
            finding_record = {
                "fingerprint": fp,
                # Which key produced this fingerprint (agents-x9my). Written from the binder's own
                # vocabulary, never read out of `item`, so a report cannot claim provenance it
                # does not have; see IDENTITY_SOURCES for the classification and the checklist.
                "identity_source": identity_source,
                # The station's own emitted identity, persisted so a SECOND-ORDER station that
                # rebuilds records from the store can carry it forward instead of reconstructing
                # what the scanner already knew (agents-p8og, coord ruling: PERSIST). Scanner-owned
                # and never model input, so under the checklist it is copied VERBATIM (step 1) and
                # deliberately NOT added to RENDERED_TEXT_FIELDS: nothing renders it. It is already
                # an input to compute_fingerprint because it IS the identity payload wherever it was
                # used, which is why persisting it needs no scheme bump - the fingerprint for the
                # same inputs is byte-identical before and after, and a test pins that.
                # None, not a made-up value, when nothing bound: an invented id would look like
                # provenance.
                "candidate_id": identity_snip if identity_source == "candidate-id" else None,
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
                "suppression_reason": suppression_reason
            }
            # agents-4zg: the store is persisted REDACTED at save() and scrubbed at load (see
            # _redacted_data / _load_store), so the sandboxed engine never reads raw fields. The
            # in-memory record stays raw here and is the SAME object appended to `processed`, so
            # the delivery receipts dispatch_to_sink mutates flow to the persisted record; save()
            # keeps those receipts while dropping the raw text.
            self.data["findings"][fp] = finding_record
            processed.append(finding_record)

        # 2. Check for findings previously detected by this agent that are now missing (fixed)
        fixed_items = []
        for fp, existing in self.data["findings"].items():
            if existing.get("agent") == agent and fp not in current_fps:
                if existing.get("state") in ("new", "accepted", "regressed"):
                    existing["state"] = "fixed"
                    existing["fixed_at"] = now
                    delta_stats["fixed"] += 1
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
                if row.get("identity_source") not in IDENTITY_STABLE_SOURCES)
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


def dispatch_to_sink(sink: str, target_name: str, target_dir: Path, processed_findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]] = None, visibility: Any = None, agent: Optional[str] = None, station_only: bool = False, fragment: Optional[Path] = None, repo: Optional[str] = None, beads_dir: Optional[Path] = None, sink_options: Optional[Dict[str, Any]] = None, run_dir: Optional[Path] = None) -> Dict[str, Any]:
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

    names = sinks.expand(sink)
    # Public issues are reserved for human-approved public input, not automatic findings.
    if "github-issues" in names:
        raise ValueError("github-issues is no longer a findings sink: internal findings file "
                         "to beads automatically; public-input issue triage is a separate flow")
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
                   agent=agent if station_only else None, sink_results=sink_results)

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


def _dispatch_file(target_name: str, findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]], agent: Optional[str] = None, sink_results: Optional[Dict[str, Any]] = None, stations: Optional[List[Dict[str, Any]]] = None, line_name: Optional[str] = None, findings_dir: Optional[Path] = None, env_failure: Optional[str] = None):
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
    kwargs = dict(sink_results=sink_results, stations=stations, line_name=line_name, env_failure=env_failure)
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
    for station in stations:
        fragment = station.get("fragment")
        if not fragment or not Path(fragment).exists():
            continue
        data = json.loads(Path(fragment).read_text(encoding="utf-8"))
        findings.extend(data.get("findings", []))
        fixed.extend(data.get("fixed", []))
        for key in DELTA_KEYS:
            stats[key] += int(data.get("stats", {}).get(key, 0) or 0)
        for sink, result in (data.get("sinks") or {}).items():
            total = sinks.setdefault(sink, {})
            for key, value in result.items():
                if isinstance(value, int) and not isinstance(value, bool):
                    total[key] = total.get(key, 0) + value
                elif value and key == "note":
                    total["note"] = "; ".join(filter(None, [total.get("note"), str(value)]))
    report = _dispatch_file(target_name, findings, stats, fixed, sink_results=sinks,
                            stations=stations, line_name=line_name, findings_dir=findings_dir)
    machine = report.with_name(f"{target_name}-line.json")
    machine.write_text(json.dumps({
        "target": target_name,
        "line": line_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        "complete": all(s.get("status") in VERDICT_STATUSES for s in stations),
        "stats": stats,
        "sinks": sinks,
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
    """
    source = f.get("identity_source")
    if source and source not in IDENTITY_STABLE_SOURCES:
        return " (reword-unstable — not evidence on its own)"
    return ""


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


def _render_delta_report(target_name: str, findings: List[Dict[str, Any]], stats: Dict[str, int],
                         fixed_items: List[Dict[str, Any]], *, step_summary: bool = False,
                         sink_results: Optional[Dict[str, Any]] = None,
                         stations: Optional[List[Dict[str, Any]]] = None,
                         line_name: Optional[str] = None,
                         env_failure: Optional[str] = None) -> str:
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
    no_verdict = [s for s in (stations or []) if s.get("status") not in VERDICT_STATUSES and s.get("status") != "ENV_FAILURE"]

    lines = [
        f"# Software Factory Delta Report: {target_name}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"",
    ]
    if stations is not None:
        has_verdict_count = len(stations) - len(env_failed) - len(no_verdict)
        lines.append(f"Line: `{line_name or '?'}` — {len(stations)} station(s), "
                     f"{has_verdict_count} with a verdict.")
        lines.append("")
    if env_failure or env_failed:
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
    if no_verdict:
        names = ", ".join(f"`{s.get('station')}` ({s.get('status')})" for s in no_verdict)
        lines.append(f"> **INCOMPLETE**: {len(no_verdict)} station(s) produced no verdict: {names}. "
                     "Their zero is not a clean result; this run is not clean.")
        lines.append("")
    elif not env_failure and not env_failed and stats["new"] == 0 and stats["regressed"] == 0 and stats["fixed"] == 0:
        lines.append("> **Clean Delta**: No new, regressed, or resolved findings in this run.")
        lines.append("")

    lines += _migration_note(stats)

    if stations is not None:
        lines.append("## Stations")
        lines.append("")
        lines.append("| Station | Status | Findings | Criticals | Note |")
        lines.append("|:---|:---:|:---:|:---:|:---|")
        for s in stations:
            has_verdict = s.get("status") in VERDICT_STATUSES
            count = s.get("findings_count") if has_verdict else "—"
            crit = s.get("criticals") if has_verdict else "—"
            note = str(s.get("error") or "").replace("|", "/").replace("\n", " ")[:200]
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
        for f in fixed_items:
            if reduced(f):
                lines.append(f"- **`{f.get('rule_id')}`** (`{f.get('path')}:{f.get('line_number', '?')}`){_identity_note(f)}")
                continue
            lines.append(f"- **`{f.get('rule_id')}`**: {f.get('title')} (`{f.get('path')}:{f.get('line_number', '?')}`){_identity_note(f)}")
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
        sink_options[key] = value

    if args.promote_issue:
        if not args.beads_dir or not args.repo or args.visibility != "public":
            parser.error("promotion needs --beads-dir, --repo and explicit --visibility public")
        result = promote_issue(args.target, Path(args.target_dir).resolve(), args.repo,
                               args.visibility, args.promote_issue, Path(args.beads_dir))
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
    except (SuppressionFileError, StoreFileError) as e:
        # Loud and non-zero: a register or store that cannot be parsed must not silently reset.
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)
    try:
        candidate_index = load_candidate_index(Path(args.candidates)) if args.candidates else None
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
