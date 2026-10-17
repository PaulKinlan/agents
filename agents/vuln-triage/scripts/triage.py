#!/usr/bin/env python3
"""Deterministic pre-pass for vuln-triage agent.

Clusters candidate and verified findings by file, proximity, and rule class,
and extracts target THREAT_MODEL.md context to prepare for root-cause synthesis.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_identity import artefact_scheme_fields, candidate_identity  # noqa: E402
from lib.line_numbers import usable_line_number  # noqa: E402

def load_threat_model(target_name: str, target_dir: Path, output_file: Optional[Path] = None) -> Tuple[str, str]:
    # 1. Local target THREAT_MODEL.md
    local_tm = target_dir / "THREAT_MODEL.md"
    if local_tm.exists():
        try:
            return local_tm.read_text(encoding="utf-8", errors="replace"), str(local_tm.resolve())
        except OSError:
            pass
    # 2. Docs THREAT_MODEL.md
    docs_tm = target_dir / "docs" / "THREAT_MODEL.md"
    if docs_tm.exists():
        try:
            return docs_tm.read_text(encoding="utf-8", errors="replace"), str(docs_tm.resolve())
        except OSError:
            pass
    # 3. Findings stored THREAT_MODEL.md
    store_tm = FACTORY_ROOT / "findings" / f"{target_name}-THREAT_MODEL.md"
    if store_tm.exists():
        try:
            text = store_tm.read_text(encoding="utf-8", errors="replace")
            # Inside the sandbox, findings/ is masked. Copy to run directory so the agent can read it!
            if output_file is not None:
                try:
                    copied_tm = output_file.parent / "THREAT_MODEL.md"
                    copied_tm.write_text(text, encoding="utf-8")
                    return text, str(copied_tm.resolve())
                except OSError:
                    pass
            return text, str(store_tm.resolve())
        except OSError:
            pass
    return "No THREAT_MODEL.md found. Treat all external inputs as untrusted.", ""

def gather_findings(target_name: str) -> List[Dict[str, Any]]:
    findings = []
    store_file = FACTORY_ROOT / "findings" / f"{target_name}.json"
    if store_file.exists():
        try:
            data = json.loads(store_file.read_text(encoding="utf-8"))
            for item in data.get("findings", {}).values():
                # Our prior reports are not candidates for our next pre-pass;
                # keep other agents' findings, including legacy rows without an agent.
                if item.get("agent") == "vuln-triage":
                    continue
                if item.get("state") in ("new", "regressed", "accepted"):
                    findings.append(item)
        except Exception:
            pass
    return findings


def cluster_deterministic(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups findings by file and proximity (lines within 15).

    Design choice for unknown-location findings (agents-ajt4):
    Each finding with an unknown or non-numeric line number (e.g. '?', None, or
    non-numeric string) is placed into its own distinct single-item cluster.
    Because unknown locations cannot have spatial proximity established either
    with numeric lines or with each other, they are never coerced to line 0 (which
    would falsely merge them with lines <= 15) or grouped together by proximity.
    The unknown test is `lib.line_numbers.usable_line_number` (agents-ghtz): non-positive
    values such as 0 are UNKNOWN too, not line 0.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        path = f.get("path", "unknown") or "unknown"
        by_file.setdefault(path, []).append(f)

    clusters = []
    cluster_id = 1

    for path in sorted(by_file.keys()):
        items = by_file[path]
        numeric_items: List[Tuple[int, Dict[str, Any]]] = []
        unknown_items: List[Dict[str, Any]] = []

        for item in items:
            line = usable_line_number(item.get("line_number"))
            if line is not None:
                numeric_items.append((line, item))
            else:
                unknown_items.append(item)

        sorted_numeric = sorted(
            numeric_items,
            key=lambda x: (
                x[0],
                str(x[1].get("rule_id") or ""),
                str(x[1].get("fingerprint") or ""),
                str(x[1].get("title") or ""),
            )
        )

        current_cluster: List[Dict[str, Any]] = []
        last_line: Optional[int] = None

        for line, item in sorted_numeric:
            if current_cluster and last_line is not None and abs(line - last_line) <= 15:
                current_cluster.append(item)
                last_line = line
            else:
                if current_cluster:
                    clusters.append({
                        "cluster_id": f"C{cluster_id}",
                        "file": path,
                        "count": len(current_cluster),
                        "items": current_cluster
                    })
                    cluster_id += 1
                current_cluster = [item]
                last_line = line

        if current_cluster:
            clusters.append({
                "cluster_id": f"C{cluster_id}",
                "file": path,
                "count": len(current_cluster),
                "items": current_cluster
            })
            cluster_id += 1

        # Unknown-location findings are placed in separate single-item clusters
        # sorted deterministically to prevent cluster ID churn across runs.
        sorted_unknown = sorted(
            unknown_items,
            key=lambda x: (
                str(x.get("rule_id") or ""),
                str(x.get("fingerprint") or ""),
                str(x.get("title") or ""),
                str(x.get("line_number") or ""),
            )
        )

        for item in sorted_unknown:
            clusters.append({
                "cluster_id": f"C{cluster_id}",
                "file": path,
                "count": 1,
                "items": [item]
            })
            cluster_id += 1

    return _fold_shared_candidate_clusters(clusters)


def _stored_candidate_id(item: Dict[str, Any]) -> str:
    """The scanner-owned candidate id this row carries, or "" for a legacy row (agents-np8dl)."""
    value = item.get("candidate_id")
    return value.strip() if isinstance(value, str) else ""


def _fold_shared_candidate_clusters(clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One cluster per STORED candidate_id (agents-np8dl).

    A candidate_id names a CANDIDATE, not a finding: lib/candidate_identity.py builds it from scanner-
    owned (rule id, path, match text, ordinal) and never from the agent, so two stations flagging one
    location share it by design - the same property agents-g3vnf measured for the findings ledger. The
    factory's own store shows both shapes at once: in findings/agents-factory-factory.json the ids
    50a8a7c8990e463f (THREAT_MODEL.md:1) and effe7026c6ffc948 (lib/budget.py:142) each carry a
    vuln-discovery row AND a vuln-verify row.

    Proximity clustering is line-based, so when those rows' line metadata disagrees - a stale line, or
    one of them unknown - the pair splits across clusters, both anchors present the same id, and
    cluster_candidates' duplicate-id guard (which exists for the line judge) killed the whole pre-pass.
    Measured reproduction: two rows, one candidate_id, lines 10 and 100 -> ValueError from a run that
    has nothing malformed in it.

    Folding is the honest resolution for this station, not merely the cheapest: vuln-triage declares
    `candidate_accounting: aggregate-claimed` (agents-htyb), so one candidate must be claimed once. Two
    rows of one candidate are one candidate; presenting them as two clusters asks the line judge to
    choose between two names for the same location.

    Legacy rows are NOT folded by a GUESSED identity: the ordinal counted here is the occurrence in file
    order (lib/candidate_identity.py's definition), and rows carrying a stored id occupy their ordinal
    even though their id is read off the row. That is what makes the mixed stored/derived case fold
    instead of colliding (agents-yn00b): a station's `ordinal=1` id and a legacy row that happens to be
    occurrence 1 ARE the same candidate by the scheme, so they become one cluster rather than two names
    for one location.
    """
    folded: List[Dict[str, Any]] = []
    owner: Dict[str, int] = {}
    ordinals = _occurrence_ordinals(clusters)
    for cluster in clusters:
        items = list(cluster["items"])
        anchor = min(items, key=_anchor_key) if items else None
        identity = (_anchor_identity(anchor, cluster["file"], ordinals).strip()
                    if anchor else "")
        if identity and identity in owner:
            target = folded[owner[identity]]
            target["items"] = list(target["items"]) + items
            target["count"] = len(target["items"])
            continue
        if identity:
            owner[identity] = len(folded)
        folded.append({**cluster, "items": items, "count": len(items)})

    # Dense, deterministic ids again after any fold, and a `file` that matches the anchor actually
    # presented (a fold can land a row from a differently-pathed cluster in this one).
    for index, cluster in enumerate(folded, start=1):
        cluster["cluster_id"] = f"C{index}"
        if cluster["items"]:
            anchor = min(cluster["items"], key=_anchor_key)
            cluster["file"] = anchor.get("path") or cluster["file"]
    return folded


def _first_seen(item: Dict[str, Any]) -> datetime:
    """Oldest active finding is the anchor; undated/malformed timestamps sort last."""
    raw = item.get("first_seen")
    if isinstance(raw, str) and raw.strip():
        try:
            seen = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            return seen.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    return datetime.max.replace(tzinfo=timezone.utc)


def _anchor_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
    line = usable_line_number(item.get("line_number"))
    return (_first_seen(item), line if line is not None else float("inf"),
            str(item.get("rule_id") or ""), str(item.get("fingerprint") or ""),
            str(item.get("title") or ""), str(item.get("candidate_id") or ""))


def _occurrence_ordinals(clusters: List[Dict[str, Any]]) -> Dict[int, int]:
    """Occurrence ordinal (1-based, per rule+path+fingerprint, IN FILE ORDER) for EVERY row.

    candidate_identity's `ordinal` input exists so two identical matches in one file get distinct ids
    instead of silently sharing one (lib/candidate_identity.py), and it is defined as the occurrence
    IN FILE ORDER - so a row's ordinal does not depend on which side of a cluster boundary it fell.

    Two things about this were wrong before, and both crashed the nightly pre-pass:
      * the pre-pass passed the DEFAULT ordinal 1 for legacy rows, so two rows of one
        rule+path+fingerprint computed the SAME id (agents-np8dl);
      * a STORED id and a DERIVED one can name the same ordinal - a station writing
        candidate_identity(..., ordinal=1) is indistinguishable from a legacy row that happens to be
        occurrence 1 - so counting only legacy rows left the mixed-version case colliding
        (agents-yn00b, found by rev-np8dl). Rows carrying a stored id therefore OCCUPY their ordinal
        here even though their id is read off the row rather than derived.
    """
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for cluster in clusters:
        for item in cluster["items"]:
            key = (
                str(item.get("rule_id") or "").strip(),
                str(item.get("path") or cluster["file"] or "").strip(),
                str(item.get("fingerprint") or ""),
            )
            groups.setdefault(key, []).append(item)
    return {id(item): ordinal
            for items in groups.values()
            for ordinal, item in enumerate(sorted(items, key=_file_order_key), start=1)}


def _file_order_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
    """File order for occurrence counting: line first, then a deterministic tiebreak for equal lines."""
    line = usable_line_number(item.get("line_number"))
    return (line if line is not None else float("inf"),
            str(item.get("rule_id") or ""), str(item.get("fingerprint") or ""),
            str(item.get("title") or ""), str(item.get("agent") or ""),
            str(item.get("candidate_id") or ""))


def _anchor_identity(item: Dict[str, Any], file_fallback: Any,
                    ordinals: Dict[int, int]) -> str:
    """The identity a row presents: the stored id when it has one, else the scheme's derived id.

    One resolution, used by BOTH the fold and the projector, so clustering and the guard cannot disagree
    about what a candidate is (agents-yn00b).

    The STORED value is returned EXACTLY AS STORED, whitespace included: cluster_candidates' guard is
    what reports a padded id as malformed, and stripping here would hide it from the only check that
    looks for it. Callers that need a key use .strip() on the result.
    """
    raw = item.get("candidate_id")
    if isinstance(raw, str) and raw.strip():
        return raw
    return candidate_identity(item.get("rule_id") or "", item.get("path") or file_fallback,
                              match_text=str(item.get("fingerprint") or ""),
                              ordinal=ordinals.get(id(item), 1))


def cluster_candidates(clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One identity per cluster, tied to its oldest member rather than positional C1..Cn.

    The source's persisted candidate_id wins. A legacy row without it uses its
    stored fingerprint, never its redacted snippet or scanner severity, plus its
    real occurrence rank (see _legacy_occurrence_ranks). Reject duplicate
    identities: the opt-in line judge requires every presented ID to name one
    distinct cluster and cannot repair an ambiguous pre-pass.

    Legitimate data can no longer produce that duplicate: one candidate's rows - whether they carry a
    stored id or derive one from the occurrence scheme - are folded into one cluster by
    _fold_shared_candidate_clusters (agents-np8dl, agents-yn00b). The guard below therefore only fires on
    input that really is malformed - a padded id, or clusters handed to this function directly - which
    is what the line-judge invariant needs it for.
    """
    candidates: List[Dict[str, Any]] = []
    seen_ids = set()
    ordinals = _occurrence_ordinals(clusters)
    for cluster in clusters:
        if not cluster["items"]:
            raise ValueError("vuln-triage: empty cluster has no anchor")
        anchor = min(cluster["items"], key=_anchor_key)
        rule_id = anchor.get("rule_id") or ""
        path = anchor.get("path") or cluster["file"]
        cid = _anchor_identity(anchor, cluster["file"], ordinals)
        if cid != cid.strip() or cid in seen_ids:
            raise ValueError(f"vuln-triage: duplicate candidate_id or malformed source identity: {cid!r}")
        seen_ids.add(cid)
        # The report schema accepts an integer or null, not source strings like
        # "42"/"?". Normalize both sides of the location binder to the same
        # numeric/unknown representation; do not turn an unknown line into 0.
        candidates.append({"candidate_id": cid, "rule_id": rule_id,
                           "path": path, "line_number": usable_line_number(anchor.get("line_number"))})
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Vuln Triage Pre-pass")
    parser.add_argument("--target", required=True, help="Path to target directory")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    target_name = target_path.name
    output_path = Path(args.output).resolve() if args.output else None

    threat_model_text, tm_path = load_threat_model(target_name, target_path, output_file=output_path)
    active_findings = gather_findings(target_name)
    clusters = cluster_deterministic(active_findings)

    MAX_TM_SUMMARY_BYTES = 3000
    raw_tm_bytes = threat_model_text.encode("utf-8")
    if len(raw_tm_bytes) > MAX_TM_SUMMARY_BYTES:
        truncated_text = raw_tm_bytes[:MAX_TM_SUMMARY_BYTES].decode("utf-8", errors="ignore")
        kept_bytes = len(truncated_text.encode("utf-8"))
        threat_model_summary = (
            f"[THREAT_MODEL.md summarised: showing first {kept_bytes} of {len(raw_tm_bytes)} bytes. "
            f"Full document available to read via file: {tm_path or 'THREAT_MODEL.md'}]\n"
            + truncated_text
            + f"\n\n... [TRUNCATED: remaining {len(raw_tm_bytes) - kept_bytes} bytes omitted. Read {tm_path or 'THREAT_MODEL.md'} with read tool.]"
        )
    else:
        threat_model_summary = threat_model_text

    payload = {
        "target": target_name,
        **artefact_scheme_fields(),
        "candidates": cluster_candidates(clusters),
        # Keep the existing raw pre-pass artefact contract for other readers.
        # Once candidates exist, the factory prompts with only candidates and
        # context; these top-level legacy fields alone would disappear.
        "total_active_findings": len(active_findings),
        "cluster_count": len(clusters),
        "threat_model_summary": threat_model_summary,
        "threat_model_file": tm_path or None,
        "clusters": clusters,
        # The factory shows the first 50 candidates as scanner data. The full
        # cluster bodies and threat model are separate model context, not
        # candidate identity inputs, and are not silently dropped or sliced.
        "context": {
            "total_active_findings": len(active_findings),
            "cluster_count": len(clusters),
            "threat_model_summary": threat_model_summary,
            "threat_model_file": tm_path or None,
            "clusters": clusters,
        },
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"vuln-triage: {len(active_findings)} findings grouped into {len(clusters)} deterministic clusters.")

if __name__ == "__main__":
    main()
