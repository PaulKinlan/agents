#!/usr/bin/env python3
"""Bounded batching, deterministic merging and truncation naming for station candidate lists.

Why this module exists (chrome-agent-platform-rn0ky, nightly wib2r): the factory used to hand a
station EVERY presented candidate in one prompt and ask for one row per candidate in one JSON
report. At ~45 candidates / ~50 KB the model's completion is cut mid-JSON, `extract_json_from_output`
finds no decodable object, and the station reports "no verdict" - a silent degrade that names
neither the cause (output truncation) nor the work lost. Raising the token budget is not a fix:
157 s of a 10-minute budget was used, so the binding constraint is the completion size, not time.

Three things are needed and each lives here, as pure functions so they are unit-testable without an
engine:

1. `plan_batches` - a deterministic partition of the candidate list that is bounded by BOTH a count
   and a serialized-byte budget. Order is preserved, every candidate appears exactly once, and a
   single oversized candidate goes in a batch of its own rather than being dropped or split.
2. `merge_reports` - one report from N per-batch reports: findings concatenated in pre-pass order,
   `reviewed_commits` unioned, duplicates REFUSED by name rather than silently dropped. A merge
   that loses a candidate would turn the accounting check into a lie, so it raises instead.
3. `classify_unparseable` - decides whether unparseable output was TRUNCATED (the JSON structure
   ends inside a string or with unclosed braces) or merely had no JSON in it, with the evidence
   (bytes, brace counts, candidate ids visible in the fragment). Truncation is a named station
   error, not a shrug.
"""

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# A batch of 8 candidates is ~9 KB of prompt/response - well inside the size at which the nightly
# truncated (45 ids, 50,314 B). Callers may override per station.
DEFAULT_MAX_PER_BATCH = 8

# THE PER-CALL BOUND IS POLICY, NOT A STATION'S OPT-IN (agents-tq1lt). It used to be an opt-in
# declaration read by the dispatcher, and three of the stations that present the largest candidate
# lists - vuln-triage, docs-drift, deps-supply-chain - never declared one. They therefore kept asking
# a model for up to CANDIDATE_PROMPT_SLICE (50) fully-populated rows in ONE completion, which is the
# documented truncation regime (~50 KB) and surfaced on five VMs at once as a candidate-accounting /
# JSON-parse failure on the batch-2 call rather than as a named truncation. A station that presents
# candidates is now batched whether or not it declared a bound; a declaration may only TIGHTEN this
# ceiling (vuln-verify asks for 6 from its own measured cost per case), never raise it.
MAX_CANDIDATES_PER_BATCH = DEFAULT_MAX_PER_BATCH
# Even a small count of huge candidate records (a 40 KB diff excerpt each) must not build a batch
# the model cannot answer, so a batch is also bounded by the serialized bytes of its candidates.
DEFAULT_MAX_BATCH_BYTES = 12_000

# The pre-pass identity field. Copied, never invented: the factory compares the ids a report cites
# with the ids it presented (agents-w9ni).
_CANDIDATE_ID_RE = re.compile(r"cand-[A-Za-z0-9][A-Za-z0-9_.:-]*")
_TAIL_CHARS = 180


class BatchPlanError(ValueError):
    """The candidate list or the bounds cannot produce a valid plan.

    Raised rather than returning an empty or partial plan: a station that silently processes
    three of forty candidates because a bound was misconfigured is worse than one that fails
    loudly, because its report still looks complete.
    """


class BatchMergeError(ValueError):
    """Per-batch reports cannot be merged without losing or duplicating a candidate."""


def declared_max_candidates_per_call(agent_cfg: Any) -> Optional[int]:
    """The station's `output.max_candidates_per_call`, or None when it declares no bound.

    A malformed or non-positive value is REFUSED rather than coerced or ignored: a bound nobody
    applied is how a 47-candidate completion truncated in the first place, and a station silently
    reverting to one unbounded call is the failure this module exists to remove.
    """
    if not isinstance(agent_cfg, dict):
        return None
    output = agent_cfg.get("output")
    if not isinstance(output, dict):
        return None
    raw = output.get("max_candidates_per_call")
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise BatchPlanError(
            f"agent.yaml output.max_candidates_per_call must be an integer, got {raw!r}")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise BatchPlanError(
            f"agent.yaml output.max_candidates_per_call must be an integer, got {raw!r}") from None
    if isinstance(raw, float) and raw != value:
        # 2.5 is not "2 candidates per call": refusing a fractional bound keeps a typo from becoming a
        # silently different batch size (the dispatcher used to truncate it without a word).
        raise BatchPlanError(
            f"agent.yaml output.max_candidates_per_call must be an integer, got {raw!r}")
    if value < 1:
        raise BatchPlanError(
            f"agent.yaml output.max_candidates_per_call must be >= 1, got {value}")
    return value


def resolve_max_candidates_per_call(agent_cfg: Any) -> int:
    """The per-call bound the dispatcher MUST apply: never above MAX_CANDIDATES_PER_BATCH.

    Undeclared resolves to the policy ceiling, so every station that presents a candidate list is
    batched - the station's declaration is a way to ask for a SMALLER batch, not a switch that can
    leave a station asking for one 50-candidate completion. A declaration above the ceiling is
    capped, not honoured and not refused: the batch is what keeps the completion inside the model's
    output bound, and a station declaring a larger number has no evidence that a larger completion
    completes. (The gate refuses the drift where it can be caught - tests/test_factory_truth.py - so a
    declaration above the ceiling fails review rather than 03:00.)
    """
    declared = declared_max_candidates_per_call(agent_cfg)
    if declared is None:
        return MAX_CANDIDATES_PER_BATCH
    return min(declared, MAX_CANDIDATES_PER_BATCH)


def _candidate_bytes(candidate: Any) -> int:
    """The serialized size of one candidate record, in bytes (UTF-8).

    A record that cannot be serialized still gets a size (its repr) because the planner must
    never be the thing that decides a candidate is unrepresentable - the report contract and the
    accounting check own that judgement.
    """
    try:
        return len(json.dumps(candidate, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return len(repr(candidate).encode("utf-8"))


def plan_batches(candidates: Sequence[Any],
                 max_per_batch: int = DEFAULT_MAX_PER_BATCH,
                 max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES) -> List[List[Any]]:
    """Partition `candidates` into bounded, order-preserving batches.

    Both bounds are honoured: a batch stops at `max_per_batch` records or before adding a record
    that would push its serialized bytes past `max_batch_bytes`, whichever comes first. A single
    candidate larger than `max_batch_bytes` still gets a batch of its own - it is presented, not
    dropped, and the model is asked about exactly one oversized record instead of forty.

    Determinism matters: the same input and bounds always produce the same partition, so a rerun
    (or a review) reads the same batches in the same order. An empty list yields no batches.
    """
    if max_per_batch < 1:
        raise BatchPlanError(f"max_per_batch must be >= 1, got {max_per_batch!r}")
    if max_batch_bytes < 1:
        raise BatchPlanError(f"max_batch_bytes must be >= 1, got {max_batch_bytes!r}")
    if candidates is None:
        raise BatchPlanError("candidates is None: a station with no pre-pass has nothing to batch")
    if not isinstance(candidates, (list, tuple)):
        raise BatchPlanError(
            f"candidates must be a list to be batched, got {type(candidates).__name__}")

    batches: List[List[Any]] = []
    current: List[Any] = []
    current_bytes = 0
    for candidate in candidates:
        size = _candidate_bytes(candidate)
        if current and (len(current) >= max_per_batch
                        or current_bytes + size > max_batch_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(candidate)
        current_bytes += size
    if current:
        batches.append(current)

    total = sum(len(batch) for batch in batches)
    if total != len(candidates):
        # Cannot happen with the loop above; asserted because a planner bug here would silently
        # un-account for candidates and read as a clean run.
        raise BatchPlanError(
            f"internal: planned {total} candidates from a list of {len(candidates)}")
    return batches


def batch_candidate_ids(batch: Iterable[Any]) -> List[str]:
    """The `candidate_id`s of one batch, in order, skipping candidates that carry none.

    No id is invented. A pre-pass that supplies no ids leaves this list short, which is exactly
    what the accounting check's count-only fallback keys on.
    """
    ids: List[str] = []
    for candidate in batch:
        if isinstance(candidate, dict):
            value = candidate.get("candidate_id")
            if isinstance(value, str) and value.strip():
                ids.append(value.strip())
    return ids


def _population_brief(ids: Sequence[str], total: int, idless: int, *,
                      subject: str, noun: str) -> str:
    """The population sentence: how many candidates, how many carry an id, and the ids themselves.

    `subject`/`noun` exist so the SAME facts can be stated for one batch of many (`This batch`) and for
    a list presented in a single call (`The candidate list`) without inventing a second wording that
    could drift from this one (agents-o0nv2).
    """
    if not ids:
        return (f" {subject} holds {total} candidate(s) and NONE of them carry a candidate_id: "
                f"answer every one, and omit the candidate_id field. Coverage for a {noun} without "
                f"ids is a row count, so an omitted row is indistinguishable from a missing answer.")
    if idless == 0:
        return (f" {subject} holds {total} candidate(s), each with a candidate_id: "
                f"{', '.join(ids)}.")
    return (f" {subject} holds {total} candidate(s): {len(ids)} "
            f"{'carries' if len(ids) == 1 else 'carry'} a candidate_id "
            f"({', '.join(ids)}) and the other {idless} "
            f"{'carries' if idless == 1 else 'carry'} NO candidate_id - answer those "
            f"rows too, and omit the candidate_id field on them rather than skipping them.")


def batch_brief(batch: Sequence[Any], batch_index: int, batch_count: int) -> str:
    """The header that tells the model what it is answering, and how much of it carries an id
    (agents-g42wa, agents-o0nv2).

    WHY THE COUNTS ARE SPELLED OUT. The header used to end with "The candidate ids in this batch: a,
    b." - and when a batch mixes identified and unidentified candidates (vuln-verify's pre-pass ids
    some rows and not others), that sentence described a 4-candidate batch containing one id as though
    the id list WERE the batch. A model answering "every candidate I was told about" then answered the
    one id and skipped the other three: measured on a 16-candidate plan (13 ids), the third batch held
    4 candidates and listed 1, which is exactly the reported "13/16 verified, 3 silently dropped". The
    candidates were never dropped by the code - they were never named to the model.

    So the brief states the population (how many candidates), the identified count (and their ids), and
    the UNIDENTIFIED count with the instruction to answer those rows too, without a candidate_id. A
    list with no ids at all says so, because that is the count-only case, not an empty one.

    AND IT IS NOT A BATCHING FEATURE (agents-o0nv2). Only multi-batch runs used to get this header, so a
    station whose candidate list fits ONE call was told nothing about its population or its ids. Since
    e5799b72 that is every list of 8 or fewer candidates (the policy bound is unconditional), and the
    reported night is exactly one of those: modern-web, 6 candidates, 0 cited ids. (docs-drift's 49 and
    vuln-triage's 31 are NOT single-call any more - they plan 7 and 4 batches - so this was narrower than
    "most nights"; it was still precisely the shape that failed.) The only instruction to copy a
    candidate_id in such a prompt was a schema `description` inside the JSON blob, immediately followed by
    the derived checklist that lists the fields a finding MUST carry and, correctly, does not include the
    one field that cannot be schema-required. A model reading that checklist as the contract emitted
    conforming rows with no ids, and the run was judged 0 of 6. `factory:1963` now calls this for every
    planned batch, and with ONE batch the facts are stated without the batching wording - deliberately
    not starting with `BATCH `, which is how a batched prompt is recognised downstream.

    AN EMPTY LIST GETS NO BRIEF AT ALL (agents-o0nv2 review). 15 of the 22 stations do not declare
    `short_circuit_empty`, so a clean scan really does reach the model with zero candidates: telling that
    prompt "answer for EVERY candidate below ... holds 0 candidate(s)" is self-contradictory noise, and
    returning "" keeps the pre-change prompt byte-identical for the clean-scan path.
    """
    ids = batch_candidate_ids(batch)
    total = len(list(batch))
    if total == 0:
        return ""
    idless = max(total - len(ids), 0)
    if int(batch_count) <= 1:
        return (
            "The candidate list is not split into batches: answer for EVERY candidate below - a "
            "confirmed row or a dismissal with `false_positive: true`, never an omission."
            + _population_brief(ids, total, idless, subject="The candidate list", noun="list")
            + "\n\n"
        )
    return (
        f"BATCH {batch_index + 1} of {batch_count}: the candidate list is presented in "
        f"{batch_count} batches so that no single response has to carry every row. Answer "
        f"ONLY for the candidates in THIS batch, and answer for EVERY one of them - a "
        f"confirmed row or a dismissal with `false_positive: true`, never an omission."
        + _population_brief(ids, total, idless, subject="This batch", noun="batch")
        + "\n\n"

    )


def validate_batch_attribution(rows: Any, *, batch_ids: Sequence[str],
                              batch_index: Optional[int] = None,
                              all_batch_ids: Optional[Sequence[Sequence[str]]] = None,
                              array_name: str = "findings") -> None:
    """Refuse a report row that cites a candidate THIS batch was not shown (agents-5230a).

    A batched station is told to answer only for its own batch, and aggregate candidate coverage is
    satisfied by distinct ids - so a report can reach the merge attributing candidate 001 to the call
    that was shown candidate 000 and still look complete. That is a wrong verdict attached to the
    wrong code location, which no later accounting check can see. This is checked per batch, before
    the merge, and names both the id and where it was actually presented.
    """
    own = {cid for cid in (batch_ids or ()) if isinstance(cid, str) and cid}
    elsewhere: Dict[str, int] = {}
    for index, ids in enumerate(all_batch_ids or ()):
        if index == batch_index:
            continue
        for cid in ids:
            if isinstance(cid, str) and cid and cid not in own:
                elsewhere.setdefault(cid, index + 1)
    if not batch_ids:
        # This batch's candidates carry no ids, so identity cannot be verified FOR IT - but an id KNOWN
        # to belong to another batch is still a provable misattribution, and returning early here
        # accepted one (agents-ju56b).
        for row in rows if isinstance(rows, list) else ():
            cid = row.get("candidate_id") if isinstance(row, dict) else None
            if isinstance(cid, str) and cid.strip() and cid.strip() in elsewhere:
                raise BatchMergeError(
                    f"batch {batch_index + 1 if batch_index is not None else '?'} {array_name!r} row cited candidate_id "
                    f"{cid.strip()!r}, which belongs to batch {elsewhere[cid.strip()]} - this batch's "
                    f"candidates carry no ids, so the answer cannot be its own")
        return  # nothing else is checkable here; count accounting owns a row without an id
    for row in rows if isinstance(rows, list) else ():
        if not isinstance(row, dict):
            continue
        cid = row.get("candidate_id")
        if not isinstance(cid, str) or not cid.strip() or cid.strip() in own:
            continue
        cid = cid.strip()
        where = (f"; it belongs to batch {elsewhere[cid]}" if cid in elsewhere
                 else "; it was not presented in any batch")
        raise BatchMergeError(
            f"batch {batch_index + 1 if batch_index is not None else '?'} {array_name!r} row cited candidate_id "
            f"{cid!r}, which it was not shown{where} - a row may only answer a candidate in its own batch")


# Keys the FACTORY owns after the merge: model output must never set them (a batch must not decide a
# station's status), so they are not copied or merged.
_FACTORY_OWNED_KEYS = ("verdict", "status", "scanned_files")
# Keys merged as one-per-batch metadata rather than row arrays.
_HANDLED_KEYS = ("summary", "target")


# Always row arrays, whatever their value: a non-list here is a malformed report, not a scalar to copy.
_ALWAYS_ROW_ARRAYS = ("findings",)


def row_arrays(report: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Every contract ROW ARRAY in a report, by key: findings, verifications, and any future one.

    Discovered rather than enumerated, because the alternative is what shipped broken (agents-exhhl
    review): merge copied `findings` only, so vuln-verify's `verifications` - the whole point of that
    station - vanished from every merged report while each BATCH passed its own schema check.
    """
    arrays: Dict[str, List[Dict[str, Any]]] = {}
    if not isinstance(report, dict):
        return arrays
    for key, value in report.items():
        if key in _FACTORY_OWNED_KEYS or key in _HANDLED_KEYS or key == "reviewed_commits":
            continue
        if key in _ALWAYS_ROW_ARRAYS and not isinstance(value, list):
            raise BatchMergeError(f"report has a non-list {key!r} ({type(value).__name__})")
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            arrays[key] = list(value)
    return arrays


def merge_reports(parts: Sequence[Dict[str, Any]], *,
                  summary: Optional[str] = None,
                  target: Optional[str] = None) -> Dict[str, Any]:
    """Merge per-batch reports into one report, deterministically.

    EVERY row array is merged, not just `findings` (agents-exhhl review P1): a station whose contract
    requires another array - vuln-verify's `verifications` - got a merged report with that array missing,
    because each batch validated against the schema alone and the merge silently dropped it. Rows keep the
    order the batches were planned in (the pre-pass order); `reviewed_commits` is unioned in first-seen
    order; a `candidate_id` answered twice IN THE SAME ARRAY raises, because two rows for one candidate
    means a batch answered outside its own batch and picking one would hide it.

    Non-contract keys are NOT copied: `verdict`, `status` and `scanned_files` are the factory's to set
    after this point. Other scalars are copied first-seen so a station's own metadata survives.
    """
    parts = list(parts)
    if not parts:
        raise BatchMergeError("no per-batch reports to merge")

    merged_arrays: Dict[str, List[Dict[str, Any]]] = {}
    seen_ids: Dict[str, Dict[str, int]] = {}
    scalars: Dict[str, Any] = {}
    reviewed: List[str] = []
    first_target: Optional[str] = None

    for index, part in enumerate(parts):
        if not isinstance(part, dict):
            raise BatchMergeError(
                f"batch {index} report is {type(part).__name__}, not an object")
        for key, rows in row_arrays(part).items():
            target_rows = merged_arrays.setdefault(key, [])
            seen = seen_ids.setdefault(key, {})
            for row in rows:
                candidate_id = row.get("candidate_id")
                if isinstance(candidate_id, str) and candidate_id.strip():
                    cid = candidate_id.strip()
                    if cid in seen:
                        raise BatchMergeError(
                            f"candidate_id {cid!r} appears in {key!r} in batch {seen[cid]} and batch "
                            f"{index}: a batch answered a candidate it was not given")
                    seen[cid] = index
                target_rows.append(row)
        commits = part.get("reviewed_commits")
        if isinstance(commits, list):
            for commit in commits:
                if isinstance(commit, str) and commit not in reviewed:
                    reviewed.append(commit)
        if first_target is None and isinstance(part.get("target"), str) and part["target"].strip():
            first_target = part["target"]
        for key, value in part.items():
            if key in _FACTORY_OWNED_KEYS or key in _HANDLED_KEYS or key == "reviewed_commits":
                continue
            if isinstance(value, (list, dict)):
                continue  # arrays are merged above; nested objects are not part of a batch contract
            scalars.setdefault(key, value)

    merged_arrays.setdefault("findings", [])
    findings_rows = merged_arrays.get("findings", [])
    extra_summary = "".join(
        f"; {len(rows)} {key} row(s)" for key, rows in merged_arrays.items() if key != "findings")
    merged: Dict[str, Any] = {
        "summary": summary if summary is not None else (
            f"Merged {len(parts)} bounded batch report(s): {len(findings_rows)} row(s) "
            f"across {len(seen_ids.get('findings', {}))} cited candidate id(s){extra_summary}."),
    }
    resolved_target = target if target is not None else first_target
    if resolved_target is not None:
        merged["target"] = resolved_target
    for key, value in scalars.items():
        merged.setdefault(key, value)
    merged.update(merged_arrays)
    if reviewed:
        merged["reviewed_commits"] = reviewed
    return merged


def _scan_json_structure(text: str) -> Dict[str, Any]:
    """Brace/string census of the output, ignoring string CONTENTS (so a snippet with a brace is
    not read as structure). Escapes are honoured so `\\"` does not end a string early."""
    depth = 0
    opens = 0
    closes = 0
    open_brackets = 0
    close_brackets = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
            opens += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
            closes += 1
        elif char == "[":
            # A BARE-ARRAY report is a legal JSON shape and a completion can be cut between its
            # elements without any string being left open, so brackets are structure too
            # (found in review: `[{"a": 1}, {"b"` used to be called "no JSON at all").
            open_brackets += 1
        elif char == "]":
            close_brackets += 1
    return {
        "depth": depth,
        "open_braces": opens,
        "close_braces": closes,
        "open_brackets": open_brackets,
        "close_brackets": close_brackets,
        "in_string_at_end": in_string,
        "escaped_at_end": escaped,
    }


def classify_unparseable(text: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    """Classify output that produced no report: `truncated` or `no_json`, with evidence.

    `truncated` is the signature of a completion cut by an output cap: the text ends inside a
    string, or its braces do not balance (more `{` than `}`). Both are structural facts about the
    fragment, not guesses about intent.

    Anything else is `no_json`: prose, an echoed tool call, an error transcript. That is a
    different failure - the model did not answer in the contract's shape at all - and naming it
    truncation would send an operator looking for a token limit that was never hit.
    """
    evidence: Dict[str, Any] = {"bytes": 0, "ids_seen": 0, "ids": [], "tail": ""}
    if not isinstance(text, str) or not text.strip():
        evidence["empty"] = True
        return "no_json", evidence

    scan = _scan_json_structure(text)
    ids = sorted(set(_CANDIDATE_ID_RE.findall(text)))
    evidence.update(scan)
    evidence["bytes"] = len(text.encode("utf-8"))
    evidence["ids_seen"] = len(ids)
    # ALL of them, not the last five: describe_truncation counts what the fragment still contains,
    # and a five-id window made it report EARLIER (visible) ids as "unaccounted" (found in review).
    # The list is bounded by the batch that produced it.
    evidence["ids"] = ids
    evidence["last_id"] = ids[-1] if ids else None
    evidence["tail"] = text[-_TAIL_CHARS:]

    # A TRUNCATION VERDICT NEEDS JSON TO HAVE BEEN THERE. Taking "ends inside a string" on its own
    # called ordinary prose that happened to end in a quote "truncated", which sends an operator
    # looking for a token limit that was never hit (found in review). Structure - a brace or a
    # bracket anywhere - is required before any cut can be attributed to an output bound.
    has_structure = bool(scan["open_braces"] or scan["open_brackets"])
    truncated = bool(has_structure and (scan["in_string_at_end"]
                                        or scan["depth"] > 0
                                        or scan["open_braces"] > scan["close_braces"]
                                        or scan["open_brackets"] > scan["close_brackets"]))
    return ("truncated" if truncated else "no_json"), evidence


def describe_truncation(evidence: Dict[str, Any], *,
                        batch_index: int, batch_count: int,
                        expected_ids: Sequence[str] = (),
                        produced_batches: Optional[int] = None) -> str:
    """One operator-facing line naming the truncation, its batch and the work it lost.

    Deliberately concrete: a nightly reader needs to know WHICH batch was cut, how many bytes
    arrived, and how many of the candidates it was given are not accounted for, without opening
    the run directory.
    """
    total = len(expected_ids)
    cited = {cid for cid in (evidence.get("ids") or []) if isinstance(cid, str)}
    missing = [cid for cid in expected_ids if cid not in cited]
    if total:
        accounted = f"{total - len(missing)}/{total} candidate id(s) visible in the fragment"
    else:
        accounted = "no candidate ids were supplied for this batch (count-only accounting)"
    return (
        f"batch {batch_index + 1}/{batch_count} output was TRUNCATED mid-JSON after "
        f"{evidence.get('bytes', 0)} bytes ({evidence.get('open_braces', 0)} '{{' vs "
        f"{evidence.get('close_braces', 0)} '}}', "
        f"{'ends inside a string' if evidence.get('in_string_at_end') else 'unclosed structure'}); "
        f"{accounted}"
        + (f"; first unaccounted: {', '.join(missing[:5])}" if missing else "")
        # The count above is the batches that PLANNED, so a run that stopped after batch 1 of 3 must
        # not read as "batch 1/1": say how many produced output and that the rest never ran.
        + (f"; only {produced_batches} of {batch_count} planned batch(es) produced output - "
           f"the later batches never ran"
           if produced_batches is not None and produced_batches < batch_count else "")
    )
