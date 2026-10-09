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
import shutil
import subprocess
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
from lib.embargo import (effective_severity, embargo_reason, is_false_positive,
                         reported_severity)
# Host-side trusted tools are resolved by absolute path + SHA-256 pin (agents-7bj); a
# mismatch fails closed rather than executing an unverified gh/bd.
from lib.tool_pins import ToolPinError, resolve_tool
from lib.sinks.beads import _dispatch_beads
from lib.sinks.github import promote_issue


# Keys of a per-run delta. `false_positive` counts findings the triage itself declared false
# positives: they are recorded, never counted as new/unchanged work (journal-35w).
DELTA_KEYS = ("new", "regressed", "fixed", "unchanged", "suppressed", "false_positive")

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
    return candidate.exists()

def compute_fingerprint(agent: str, rule_id: str, path: str, snippet: str) -> str:
    """Compute stable fingerprint: sha256(agent:rule_id:normalized_path:normalized_snippet).
    
    Deliberately excludes line numbers to survive refactor churn.
    """
    norm_path = normalize_path(path)
    norm_snippet = normalize_text(snippet)
    key = f"{agent}:{rule_id}:{norm_path}:{norm_snippet}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()

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
    # The scanner's raw match per location, so deterministic dummy detection can see the exact
    # matched value even when the triage model masks its snippet (agents-3r7).
    raw_matches_at: Dict[Tuple[str, str, Any], str] = {}
    raw_matches_in: Dict[Tuple[str, str], List[str]] = {}
    # The scanner's baseline severity per (rule, path), so a triage model's severity flip can
    # be clamped back to the deterministic pre-pass (agents-964).
    severities: Dict[Tuple[str, str], str] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rule_id = candidate.get("rule_id")
        if isinstance(rule_id, str) and rule_id.strip():
            rule_ids.add(rule_id.strip())
        path = normalize_path(candidate.get("path"))
        if path:
            paths.add(path)
        snippet = candidate.get("snippet")
        if isinstance(rule_id, str) and path and isinstance(snippet, str) and snippet.strip():
            key = (rule_id.strip(), path)
            snippets_at[key + (candidate.get("line_number",),)] = snippet
            snippets_in.setdefault(key, [])
            if snippet not in snippets_in[key]:
                snippets_in[key].append(snippet)
        raw_match = candidate.get("raw_match")
        if isinstance(rule_id, str) and path and isinstance(raw_match, str) and raw_match.strip():
            key = (rule_id.strip(), path)
            raw_matches_at[key + (candidate.get("line_number",),)] = raw_match
            raw_matches_in.setdefault(key, [])
            if raw_match not in raw_matches_in[key]:
                raw_matches_in[key].append(raw_match)
        severity = candidate.get("severity")
        if isinstance(rule_id, str) and path and isinstance(severity, str) and severity.strip():
            severities.setdefault((rule_id.strip(), path), severity.strip().lower())

    if not rule_ids and not paths:
        return None
    return {"rule_ids": rule_ids, "paths": paths,
            "snippets_at": snippets_at, "snippets_in": snippets_in,
            "raw_matches_at": raw_matches_at, "raw_matches_in": raw_matches_in,
            "severities": severities}


def identity_snippet(item: Dict[str, Any], rule_id: Any, path: Any,
                     candidate_index: Optional[Dict[str, Any]]) -> Any:
    """The snippet a finding is fingerprinted on: the scanner's, when it can be identified.

    The model re-quotes a candidate's line differently from run to run (masked, truncated,
    the bare match, the whole line), so fingerprinting on its text booked a new+fixed pair on
    a byte-identical file (fleet-oed). The deterministic pre-pass emits the same snippet for
    the same unchanged line every time, so it is used when the finding binds to exactly one
    candidate location; otherwise the model's snippet is kept, as before.
    """
    model_snippet = item.get("snippet", "")
    if not candidate_index or not isinstance(rule_id, str):
        return model_snippet
    key = (rule_id.strip(), normalize_path(path))
    at = candidate_index.get("snippets_at", {})
    line = item.get("line_number")
    if key + (line,) in at:
        return at[key + (line,)]
    options = candidate_index.get("snippets_in", {}).get(key, [])
    if len(options) == 1:
        return options[0]
    wanted = normalize_text(model_snippet)
    if wanted:
        matching = [o for o in options if wanted in normalize_text(o) or normalize_text(o) in wanted]
        if len(matching) == 1:
            return matching[0]
    return model_snippet

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
    line = item.get("line_number")
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

    Binding must never destroy a REAL location (agents-0tl). A model path that resolves inside
    the target is evidence, not an invention, so it survives even when it is not a scanner
    candidate - otherwise a context-shaped candidate set (vuln-discovery's single threat-model
    entry, deps-supply-chain's package.json) blanks every genuine path to `unknown` and the
    finding becomes untriageable. The guard still fires on an invented path: an empty path, or
    a path that resolves nowhere, is bound to `unknown` exactly as before.
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
            self.data: Dict[str, Any] = self._load_store()
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
        delta_stats = {key: 0 for key in DELTA_KEYS}
        processed = []

        # 1. Process observed findings
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            rule_id, path = bind_candidates(item, candidate_index, target_dir)
            item["severity"] = bind_severity(item, rule_id, path, candidate_index)
            item["raw_match"] = identity_raw_match(item, rule_id, path, candidate_index)
            item["agent"] = agent
            fp = compute_fingerprint(
                agent=agent,
                rule_id=rule_id,
                path=path,
                snippet=identity_snippet(item, rule_id, path, candidate_index)
            )
            # A store or register written before the scanner snippet was the identity holds
            # the model-snippet fingerprint. Honour it once, instead of booking every finding
            # new and its old record fixed on the upgrade run (fleet-oed).
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
                "agent": agent,
                "rule_id": rule_id,
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


def dispatch_to_sink(sink: str, target_name: str, target_dir: Path, processed_findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]] = None, visibility: Any = None, agent: Optional[str] = None, station_only: bool = False, fragment: Optional[Path] = None, repo: Optional[str] = None, beads_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Dispatch findings, mutating their successful-delivery receipts.

    The caller must save its FindingsStore after dispatch to persist those receipts.

    `station_only` is set when the dispatch is one station of a factory line: the station
    writes `<target>-<agent>-delta.md` and the line writes the run's `<target>-delta.md` once
    every station has reported. Before, every station overwrote `<target>-delta.md`, so the
    file described only the last station and one empty station printed "Clean Delta" for the
    whole run (fleet-810). `fragment` receives this station's delta as JSON for the line.

    Returns the per-sink delivery accounting.
    """
    print(f"\n[Findings Store] Target: {target_name} | Delta: {stats['new']} new, {stats['regressed']} regressed, {stats['fixed']} fixed, {stats['unchanged']} unchanged, {stats['suppressed']} suppressed, {stats.get('false_positive', 0)} triaged false positive")

    sinks = [s.strip() for s in sink.split(",") if s.strip()]
    # agents-eyo: findings file to beads automatically. `both`/`all` are legacy aliases for the
    # one tracker sink that remains. Public GitHub issues are no longer a FINDINGS sink — the
    # issue-triage station handles public INPUT issues as a separate flow (promote_issue is that
    # flow's explicit, human-approved issue -> bead link).
    if "both" in sinks or "all" in sinks:
        sinks = ["beads"]
    if "github-issues" in sinks:
        raise ValueError("github-issues is no longer a findings sink: internal findings file "
                         "to beads automatically; public-input issue triage is a separate flow")

    sink_results: Dict[str, Dict[str, Any]] = {}
    for s in sinks:
        if s == "file":
            continue
        publishable, held = _partition_for_sink(s, processed_findings, visibility)
        result = dict(held, eligible=len(publishable), published=0, failed=0, skipped=0,
                      duplicate=0, note="")
        if s == "beads":
            result.update(_dispatch_beads(beads_dir or target_dir, publishable, visibility))
        else:
            result["note"] = f"unknown sink {s!r}: nothing published"
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
                lines.append(f"- **Location**: `{f['path']}:{f.get('line_number', '?')}`")
                lines.append("")
                continue
            lines.append(f"### {badge} {f['title']} (`{f['state']}`)")
            lines.append(f"- **Rule**: `{f['rule_id']}`")
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
        for f in fixed_items:
            if reduced(f):
                lines.append(f"- **`{f.get('rule_id')}`** (`{f.get('path')}:{f.get('line_number', '?')}`)")
                continue
            lines.append(f"- **`{f.get('rule_id')}`**: {f.get('title')} (`{f.get('path')}:{f.get('line_number', '?')}`)")
        lines.append("")

    if unchanged:
        lines.append("## Active Findings (Unchanged)")
        lines.append("")
        for f in unchanged:
            badge = _badge(f)
            if reduced(f):
                lines.append(f"- {badge} `{f['rule_id']}` (`{f['path']}:{f.get('line_number', '?')}`)")
                continue
            lines.append(f"- {badge} **{f['title']}** (`{f['path']}:{f.get('line_number', '?')}`)")
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
    parser.add_argument("--target-dir", default=".", help="Target repository directory")
    parser.add_argument("--station-only", action="store_true",
                        help="One station of a factory line: write <target>-<agent>-delta.md, "
                             "not the run's <target>-delta.md (the line writes that)")
    parser.add_argument("--fragment", help="Write this station's delta as JSON here (for the line report)")
    args = parser.parse_args(argv)

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
