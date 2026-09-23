#!/usr/bin/env python3
"""Deterministic Pre-Pass for Goal-Directed Performance Hill-Climber (agents/perf-hillclimb/scripts/measure_and_context.py)

Invokes `lib/bench/runner.py` to measure current deterministic performance metrics
(gzip bytes, raw bytes, static perf hazard score, and optional custom benchmark
timing), reads the target's append-only hill-climb ledger to surface previous
KEPT wins and REVERTED dead-ends, and extracts snippets of the highest-cost files.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.bench.runner import measure_target, read_ledger  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Measure baseline & ledger for perf-hillclimb")
    parser.add_argument("--target", required=True, help="Target repository path")
    parser.add_argument("--goal-metric", default="perf_hazard_score", help="Primary metric to hill-climb (perf_hazard_score, total_gzip_bytes, custom_bench_ms)")
    parser.add_argument("--goal-value", type=float, help="Explicit numeric target value")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    target_name = target_dir.name

    metrics = measure_target(target_dir)
    ledger = read_ledger(target_name)

    # Select default goal metric: if perf_hazard_score > 0 optimize that first, else total_gzip_bytes
    goal_metric = args.goal_metric
    if goal_metric == "perf_hazard_score" and metrics.get("perf_hazard_score", 0) == 0:
        goal_metric = "total_gzip_bytes"

    current_val = float(metrics.get(goal_metric, metrics["total_gzip_bytes"]))
    if args.goal_value is not None:
        goal_val = args.goal_value
    elif goal_metric == "perf_hazard_score":
        goal_val = 0.0
    else:
        goal_val = round(current_val * 0.90, 2)  # Default: 10% reduction target

    dead_ends = [e for e in ledger if e.get("outcome") == "REVERTED"]
    kept_wins = [e for e in ledger if e.get("outcome") == "KEPT"]

    # Enrich top hot files with short snippets so the optimizer can propose exact edits
    hot_candidates = []
    for item in metrics.get("top_hot_files", [])[:10]:
        fpath = target_dir / item["path"]
        preview = ""
        if fpath.exists():
            try:
                preview = "\n".join(fpath.read_text(encoding="utf-8", errors="ignore").splitlines()[:40])
            except Exception:
                pass
        hot_candidates.append({
            **item,
            "preview_head": preview[:800]
        })

    payload: Dict[str, Any] = {
        "target": target_name,
        "goal": {
            "metric": goal_metric,
            "current_value": current_val,
            "goal_value": goal_val,
            "remaining_delta_needed": round(max(0.0, current_val - goal_val), 2),
            "goal_achieved": current_val <= goal_val
        },
        "baseline_metrics": metrics,
        "experiment_ledger": {
            "total_prior_attempts": len(ledger),
            "kept_wins_count": len(kept_wins),
            "reverted_dead_ends_count": len(dead_ends),
            "dead_ends_do_not_repeat": dead_ends[-15:],
            "prior_wins": kept_wins[-10:]
        },
        "candidates": hot_candidates
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
