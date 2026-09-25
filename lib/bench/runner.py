#!/usr/bin/env python3
"""Class C Optimizer Benchmark Harness & Hill-Climb Ledger (lib/bench/runner.py)

Provides deterministic countable measurements (asset bytes, gzip bytes, static
performance hazard counts, and optional custom benchmark commands) alongside an
append-only JSONL ledger of hill-climb experiments so Class C agents never
repeat dead-end hypotheses.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent
FINDINGS_DIR = FACTORY_ROOT / "findings"

try:  # imported as lib.bench.runner, or run as a script
    from lib.child_env import child_environment
except ImportError:
    sys.path.insert(0, str(FACTORY_ROOT))
    from lib.child_env import child_environment

# A hung bench command must not hold the hill-climb station forever. Measurement is not an agent
# station, so there is no budget.max_minutes in scope here: fixed cap, and a timed-out run simply
# contributes no timing (SF-06).
BENCH_TIMEOUT_SECONDS = 300

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist-cache", ".venv", "venv",
    "__pycache__", ".next", ".nuxt", "coverage", ".beads", "runs"
}

ASSET_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".css", ".html", ".wasm"}


def measure_target(target_dir: Path, bench_cmd: Optional[str] = None) -> Dict[str, Any]:
    """Compute deterministic countable metrics and optional custom command timing."""
    total_raw_bytes = 0
    total_gzip_bytes = 0
    js_raw_bytes = 0
    js_gzip_bytes = 0
    css_raw_bytes = 0
    html_raw_bytes = 0
    asset_count = 0

    # Static performance anti-pattern counters (countable proxy when no runtime harness is set)
    render_blocking_scripts = 0
    unoptimized_images = 0
    layout_thrash_patterns = 0
    sync_loops_or_timers = 0
    hot_files: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in ASSET_EXTS:
                continue
            try:
                raw = fpath.read_bytes()
            except Exception:
                continue

            rel_path = str(fpath.relative_to(target_dir))
            raw_len = len(raw)
            gz_len = len(gzip.compress(raw, compresslevel=6))

            total_raw_bytes += raw_len
            total_gzip_bytes += gz_len
            asset_count += 1

            if ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
                js_raw_bytes += raw_len
                js_gzip_bytes += gz_len
            elif ext == ".css":
                css_raw_bytes += raw_len
            elif ext == ".html":
                html_raw_bytes += raw_len

            text = raw.decode("utf-8", errors="ignore")
            file_hazards = 0

            if ext == ".html":
                # Scripts in head without defer/async/module
                for m in re.finditer(r"<script\b([^>]*)>", text, re.IGNORECASE):
                    attrs = m.group(1).lower()
                    if "src=" in attrs and not any(k in attrs for k in ("defer", "async", 'type="module"', "type='module'")):
                        render_blocking_scripts += 1
                        file_hazards += 1
                # Images without loading/fetchpriority or width/height
                for m in re.finditer(r"<img\b([^>]*)>", text, re.IGNORECASE):
                    attrs = m.group(1).lower()
                    if "loading=" not in attrs and "fetchpriority=" not in attrs:
                        unoptimized_images += 1
                        file_hazards += 1

            if ext in {".js", ".mjs", ".ts", ".tsx", ".jsx"}:
                # Layout reads inside loops or frequent events
                if re.search(r"(offsetWidth|offsetHeight|getBoundingClientRect|getComputedStyle)", text):
                    layout_thrash_patterns += 1
                    file_hazards += 1
                if re.search(r"addEventListener\(\s*['\"](scroll|mousemove|resize)['\"]", text):
                    sync_loops_or_timers += 1
                    file_hazards += 1

            hot_files.append({
                "path": rel_path,
                "raw_bytes": raw_len,
                "gzip_bytes": gz_len,
                "hazards": file_hazards
            })

    hot_files.sort(key=lambda x: (x["hazards"], x["gzip_bytes"]), reverse=True)

    perf_hazard_score = (
        render_blocking_scripts * 15
        + unoptimized_images * 5
        + layout_thrash_patterns * 10
        + sync_loops_or_timers * 8
    )

    custom_bench_ms: Optional[float] = None
    if bench_cmd:
        timings = []
        for _ in range(3):
            t0 = time.perf_counter()
            try:
                res = subprocess.run(bench_cmd, shell=True, cwd=str(target_dir), capture_output=True,
                                     text=True, timeout=BENCH_TIMEOUT_SECONDS, env=child_environment())
            except subprocess.TimeoutExpired:
                continue
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res.returncode == 0:
                timings.append(elapsed_ms)
        if timings:
            timings.sort()
            custom_bench_ms = round(timings[len(timings) // 2], 2)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_raw_bytes": total_raw_bytes,
        "total_gzip_bytes": total_gzip_bytes,
        "js_raw_bytes": js_raw_bytes,
        "js_gzip_bytes": js_gzip_bytes,
        "css_raw_bytes": css_raw_bytes,
        "html_raw_bytes": html_raw_bytes,
        "asset_count": asset_count,
        "perf_hazard_score": perf_hazard_score,
        "hazard_breakdown": {
            "render_blocking_scripts": render_blocking_scripts,
            "unoptimized_images": unoptimized_images,
            "layout_thrash_patterns": layout_thrash_patterns,
            "unthrottled_event_listeners": sync_loops_or_timers,
        },
        "custom_bench_ms": custom_bench_ms,
        "top_hot_files": hot_files[:15]
    }


def get_ledger_path(target_name: str) -> Path:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    return FINDINGS_DIR / f"{target_name}-hillclimb-ledger.jsonl"


def read_ledger(target_name: str) -> List[Dict[str, Any]]:
    path = get_ledger_path(target_name)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries


def append_ledger(target_name: str, entry: Dict[str, Any]) -> None:
    path = get_ledger_path(target_name)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **entry
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Class C Benchmark & Ledger Utility")
    parser.add_argument("--target", required=True, help="Path to target repo")
    parser.add_argument("--target-name", help="Logical target name for ledger lookup")
    parser.add_argument("--bench-cmd", help="Optional shell command to benchmark")
    parser.add_argument("--goal-metric", default="total_gzip_bytes", help="Metric to optimize")
    parser.add_argument("--goal-value", type=float, help="Target goal value ( default: 5% reduction )")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    target_name = args.target_name or target_dir.name

    metrics = measure_target(target_dir, args.bench_cmd)
    ledger = read_ledger(target_name)

    current_val = metrics.get(args.goal_metric, metrics["total_gzip_bytes"])
    goal_val = args.goal_value if args.goal_value is not None else round(current_val * 0.95, 2)

    reverted_hypotheses = [
        {
            "hypothesis": e.get("hypothesis"),
            "files_touched": e.get("files_touched", []),
            "metric": e.get("metric"),
            "delta": e.get("delta"),
            "reason": e.get("reason", "Failed to improve metric")
        }
        for e in ledger if e.get("outcome") == "REVERTED"
    ]

    kept_optimizations = [
        {
            "hypothesis": e.get("hypothesis"),
            "files_touched": e.get("files_touched", []),
            "metric": e.get("metric"),
            "delta": e.get("delta")
        }
        for e in ledger if e.get("outcome") == "KEPT"
    ]

    payload = {
        "target": target_name,
        "goal": {
            "metric": args.goal_metric,
            "current_value": current_val,
            "goal_value": goal_val,
            "gap_to_goal": round(current_val - goal_val, 2),
            "goal_met": current_val <= goal_val
        },
        "current_metrics": metrics,
        "ledger_summary": {
            "total_attempts": len(ledger),
            "kept_count": len(kept_optimizations),
            "reverted_count": len(reverted_hypotheses),
            "dead_ends_to_avoid": reverted_hypotheses[-15:],
            "prior_wins": kept_optimizations[-10:]
        },
        "candidates": metrics["top_hot_files"]
    }

    out_text = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out_text, encoding="utf-8")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
