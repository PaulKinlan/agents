#!/usr/bin/env python3
"""Deterministic Pre-Pass for Documentation Writer (agents/docs-write/scripts/prepare_docs_fixes.py)

Runs `docs-drift` detection and compares actual repository structure, scripts,
package.json scripts / CLI subcommands against README.md and docs/*.md so the
Proposer model has both the broken doc lines and the ground-truth source inventory
needed to author exact markdown patches.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DOCS_DRIFT_SCRIPT = FACTORY_ROOT / "agents" / "docs-drift" / "scripts" / "check_docs.py"

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next",
    "coverage", ".venv", "venv", "__pycache__", ".beads", "runs"
}


def collect_repo_ground_truth(target_dir: Path) -> Dict[str, Any]:
    top_dirs = []
    source_files = []
    doc_files = []
    npm_scripts = {}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        rel_root = Path(root).relative_to(target_dir)
        if str(rel_root) == ".":
            top_dirs = sorted(dirs)
        for fname in sorted(files):
            fpath = Path(root) / fname
            rel_path = str(fpath.relative_to(target_dir))
            if fpath.suffix.lower() == ".md":
                doc_files.append(rel_path)
            elif fpath.suffix.lower() in {".js", ".ts", ".py", ".sh", ".yaml", ".json"}:
                source_files.append(rel_path)

    pkg_json = target_dir / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
            npm_scripts = pkg.get("scripts", {})
        except Exception:
            pass

    # If target is the Software Factory itself, also list all agents in agents/
    agents_subdir = target_dir / "agents"
    discovered_agents = []
    if agents_subdir.exists() and agents_subdir.is_dir():
        discovered_agents = sorted([
            p.name for p in agents_subdir.iterdir()
            if p.is_dir() and (p / "agent.yaml").exists()
        ])

    return {
        "top_level_directories": top_dirs,
        "markdown_files": doc_files[:25],
        "source_files_sample": source_files[:50],
        "npm_scripts": npm_scripts,
        "discovered_agents": discovered_agents
    }


def main():
    parser = argparse.ArgumentParser(description="Prepare context for docs-write proposer")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    drift_candidates: List[Dict[str, Any]] = []

    if DOCS_DRIFT_SCRIPT.exists():
        try:
            res = subprocess.run(
                [sys.executable, str(DOCS_DRIFT_SCRIPT), "--target", str(target_dir)],
                capture_output=True, text=True, timeout=15
            )
            if res.returncode == 0 and res.stdout.strip():
                drift_data = json.loads(res.stdout)
                drift_candidates = drift_data.get("candidates", [])
        except Exception:
            pass

    ground_truth = collect_repo_ground_truth(target_dir)
    readme_excerpt = ""
    readme_path = target_dir / "README.md"
    if readme_path.exists():
        readme_excerpt = readme_path.read_text(encoding="utf-8", errors="ignore")[:3500]

    payload = {
        "target": target_dir.name,
        "drift_candidates_count": len(drift_candidates),
        "candidates": drift_candidates,
        "ground_truth": ground_truth,
        "readme_excerpt": readme_excerpt
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
