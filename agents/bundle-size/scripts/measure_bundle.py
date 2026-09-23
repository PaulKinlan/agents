#!/usr/bin/env python3
"""Deterministic bundle size scanner and optimizer pre-pass.

Locates build outputs, distribution bundles, extension directories, and main
JavaScript modules. Computes countable metrics (total bytes, gzipped bytes,
largest assets, module counts), and checks against any baseline file in the
target or findings store.
"""

import argparse
import gzip
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent

EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".beads", "runs", "scratch",
    "findings", "__pycache__", ".nyc_output", "coverage", "test", "tests",
    "test-artifacts", "fixtures", "cap-evidence", ".agent-state"
}

RE_IMPORT = re.compile(r"""(?:import\s+.*?from\s+['"][^'"]+['"]|require\s*\(['"][^'"]+['"]\)|import\s*\(['"][^'"]+['"]\))""")
RE_EXPORT = re.compile(r"""(?:export\s+(?:default|const|let|var|function|class|type)|module\.exports\s*=)""")

def classify_type(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
        return "javascript"
    elif ext in {".css", ".scss", ".sass", ".less"}:
        return "stylesheet"
    elif ext in {".html", ".htm"}:
        return "html"
    elif ext == ".json":
        return "json"
    elif ext == ".wasm":
        return "wasm"
    elif ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"}:
        return "image"
    return "other"

def is_minified_heuristic(content_bytes: bytes, lines_count: int, size: int) -> bool:
    if size < 500:
        return False
    if lines_count <= 3 and size > 1000:
        return True
    try:
        text = content_bytes.decode("utf-8", errors="ignore")
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return False
        avg_line_len = sum(len(line) for line in lines) / len(lines)
        if avg_line_len > 200:
            return True
        # Check ratio of whitespace
        ws_count = sum(1 for c in text if c in " \t\r\n")
        if (ws_count / max(1, len(text))) < 0.08 and size > 2000:
            return True
    except Exception:
        pass
    return False

def discover_assets(target_dir: Path) -> List[Dict[str, Any]]:
    assets = []
    
    # Check for dedicated distribution directories
    build_dir_names = ["dist", "build", ".build", "out", "bundle", "public/dist", "public/build"]
    found_build_dirs = [target_dir / d for d in build_dir_names if (target_dir / d).is_dir()]
    
    extension_dir = target_dir / "extension"
    pages_dir = target_dir / "pages"
    
    tracked_paths = set()

    def process_file(file_path: Path, category: str):
        if file_path in tracked_paths or not file_path.is_file():
            return
        # Skip symlinks pointing outside
        try:
            rel_path = file_path.relative_to(target_dir)
        except ValueError:
            return

        # Skip lock files or huge binary metadata
        if file_path.name in {"package-lock.json", "deno.lock", "yarn.lock", "pnpm-lock.yaml"}:
            return

        tracked_paths.add(file_path)
        try:
            raw_bytes = file_path.stat().st_size
            content = file_path.read_bytes()
            gzip_bytes = len(gzip.compress(content, compresslevel=9))
        except Exception:
            return

        ftype = classify_type(file_path)
        line_count = 0
        import_count = 0
        export_count = 0
        is_minified = False
        sample_snippet = ""

        if ftype in {"javascript", "html", "stylesheet", "json"}:
            try:
                text = content.decode("utf-8", errors="ignore")
                lines = text.splitlines()
                line_count = len(lines)
                sample_snippet = "\n".join(lines[:3])[:200]
                if ftype == "javascript":
                    import_count = len(RE_IMPORT.findall(text))
                    export_count = len(RE_EXPORT.findall(text))
                    is_minified = is_minified_heuristic(content, line_count, raw_bytes)
            except Exception:
                pass

        assets.append({
            "path": str(rel_path),
            "raw_bytes": raw_bytes,
            "gzip_bytes": gzip_bytes,
            "category": category,
            "type": ftype,
            "line_count": line_count,
            "import_count": import_count,
            "export_count": export_count,
            "is_minified": is_minified,
            "snippet": sample_snippet
        })

    # 1. Inspect dedicated build dirs
    for bdir in found_build_dirs:
        for root, dirs, files in os.walk(bdir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
            for f in files:
                process_file(Path(root) / f, "distribution_build")

    # 2. Inspect extension assets
    if extension_dir.is_dir():
        for root, dirs, files in os.walk(extension_dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
            for f in files:
                process_file(Path(root) / f, "extension_bundle")

    # 3. Inspect pages assets
    if pages_dir.is_dir():
        for root, dirs, files in os.walk(pages_dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
            for f in files:
                process_file(Path(root) / f, "page_asset")

    # 4. If few or no build assets were found, scan entrypoints and shipped source modules
    if not found_build_dirs:
        # Check root JS / entrypoints
        for item in target_dir.glob("*.js"):
            process_file(item, "entrypoint")
        for item in target_dir.glob("*.mjs"):
            process_file(item, "entrypoint")

        # Check core source directories
        for sub in ["lib", "cli", "server", "src"]:
            sdir = target_dir / sub
            if sdir.is_dir():
                for root, dirs, files in os.walk(sdir):
                    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
                    for f in files:
                        p = Path(root) / f
                        if p.suffix.lower() in {".js", ".mjs", ".cjs", ".ts", ".html", ".css", ".json", ".wasm"}:
                            process_file(p, "runtime_module")

    return assets

def compute_metrics(assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_raw_bytes = sum(a["raw_bytes"] for a in assets)
    total_gzip_bytes = sum(a["gzip_bytes"] for a in assets)
    asset_count = len(assets)
    js_module_count = sum(1 for a in assets if a["type"] == "javascript")

    by_type: Dict[str, Dict[str, int]] = {}
    by_category: Dict[str, Dict[str, int]] = {}

    for a in assets:
        t = a["type"]
        if t not in by_type:
            by_type[t] = {"count": 0, "raw_bytes": 0, "gzip_bytes": 0}
        by_type[t]["count"] += 1
        by_type[t]["raw_bytes"] += a["raw_bytes"]
        by_type[t]["gzip_bytes"] += a["gzip_bytes"]

        c = a["category"]
        if c not in by_category:
            by_category[c] = {"count": 0, "raw_bytes": 0, "gzip_bytes": 0}
        by_category[c]["count"] += 1
        by_category[c]["raw_bytes"] += a["raw_bytes"]
        by_category[c]["gzip_bytes"] += a["gzip_bytes"]

    # Top largest assets sorted by raw_bytes descending
    sorted_assets = sorted(assets, key=lambda x: x["raw_bytes"], reverse=True)
    largest = [
        {
            "path": a["path"],
            "raw_bytes": a["raw_bytes"],
            "gzip_bytes": a["gzip_bytes"],
            "category": a["category"],
            "type": a["type"]
        }
        for a in sorted_assets[:10]
    ]

    return {
        "total_raw_bytes": total_raw_bytes,
        "total_gzip_bytes": total_gzip_bytes,
        "asset_count": asset_count,
        "js_module_count": js_module_count,
        "by_type": by_type,
        "by_category": by_category,
        "largest_assets": largest
    }

def find_baseline(target_name: str, target_dir: Path, explicit_path: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[Path]]:
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    candidates.append(target_dir / ".bundle-baseline.json")
    candidates.append(target_dir / "bundle-baseline.json")
    candidates.append(FACTORY_ROOT / "findings" / f"{target_name}-bundle-baseline.json")

    for p in candidates:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data, p
            except Exception:
                continue
    return None, None

def evaluate_baseline_delta(current_metrics: Dict[str, Any], baseline_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not baseline_data:
        return {
            "baseline_found": False,
            "baseline_raw_bytes": 0,
            "baseline_gzip_bytes": 0,
            "delta_raw_bytes": 0,
            "delta_gzip_bytes": 0,
            "delta_percentage": 0.0,
            "regressed": False,
            "status": "No prior baseline found. Current metrics establish initial reference."
        }

    base_raw = baseline_data.get("total_raw_bytes") or baseline_data.get("metrics", {}).get("total_raw_bytes", 0)
    base_gzip = baseline_data.get("total_gzip_bytes") or baseline_data.get("metrics", {}).get("total_gzip_bytes", 0)
    
    cur_raw = current_metrics["total_raw_bytes"]
    cur_gzip = current_metrics["total_gzip_bytes"]

    delta_raw = cur_raw - base_raw
    delta_gzip = cur_gzip - base_gzip
    pct = (delta_raw / base_raw * 100.0) if base_raw > 0 else 0.0

    # Regressed if gzip grew by > 1KB and > 2%
    regressed = delta_gzip > 1024 and pct > 2.0

    return {
        "baseline_found": True,
        "baseline_raw_bytes": base_raw,
        "baseline_gzip_bytes": base_gzip,
        "delta_raw_bytes": delta_raw,
        "delta_gzip_bytes": delta_gzip,
        "delta_percentage": round(pct, 2),
        "regressed": regressed,
        "status": f"Delta vs baseline: {delta_raw:+d} bytes raw ({pct:+.2f}%), {delta_gzip:+d} bytes gzip."
    }

def identify_bloat_candidates(assets: List[Dict[str, Any]], delta_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = []

    # 1. Unminified distribution / extension scripts
    for a in assets:
        if a["category"] in {"distribution_build", "extension_bundle"} and a["type"] == "javascript":
            if not a["is_minified"] and a["raw_bytes"] > 1000:
                candidates.append({
                    "rule_id": "unminified-bundle-asset",
                    "path": a["path"],
                    "line_number": 1,
                    "snippet": a["snippet"] or f"// File: {a['path']} ({a['raw_bytes']} bytes)",
                    "severity": "medium",
                    "title": f"Unminified JavaScript Asset in {a['category']}: {a['path']}",
                    "description": f"Asset '{a['path']}' ({a['raw_bytes']} bytes raw, {a['gzip_bytes']} bytes gzip) is shipped unminified in {a['category']}.",
                    "remediation": f"Add terser or esbuild minification step for '{a['path']}' to reduce distribution size."
                })

    # 2. Oversized assets (> 40KB raw in extension or client)
    for a in assets:
        if a["raw_bytes"] > 40 * 1024:
            candidates.append({
                "rule_id": "oversized-bundle-asset",
                "path": a["path"],
                "line_number": 1,
                "snippet": f"// File: {a['path']} ({a['raw_bytes']} bytes raw, {a['gzip_bytes']} bytes gzip)",
                "severity": "medium",
                "title": f"Oversized Single Asset Exceeds 40KB: {a['path']}",
                "description": f"Asset '{a['path']}' is {a['raw_bytes']} bytes ({a['gzip_bytes']} bytes gzip), contributing heavily to initial payload.",
                "remediation": "Audit module for code splitting, dead code elimination, or dynamic import."
            })

    # 3. High import count / Tree shaking opportunity
    for a in assets:
        if a["type"] == "javascript" and a["import_count"] >= 6 and a["raw_bytes"] > 3000:
            candidates.append({
                "rule_id": "tree-shaking-opportunity",
                "path": a["path"],
                "line_number": 1,
                "snippet": a["snippet"] or f"// File: {a['path']}",
                "severity": "low",
                "title": f"Tree Shaking & Sub-path Import Candidate: {a['path']}",
                "description": f"Module '{a['path']}' has {a['import_count']} import statements and {a['raw_bytes']} bytes. May import unnecessary dependencies.",
                "remediation": "Use explicit sub-path imports and verify tree shaking removes unused exports."
            })

    # 4. Large auxiliary modules as dynamic import candidates
    for a in assets:
        if a["category"] in {"runtime_module", "entrypoint"} and any(k in a["path"].lower() for k in ["video", "image", "cost", "options", "prompt"]):
            if a["raw_bytes"] > 2500:
                candidates.append({
                    "rule_id": "dynamic-import-candidate",
                    "path": a["path"],
                    "line_number": 1,
                    "snippet": f"// File: {a['path']} ({a['raw_bytes']} bytes)",
                    "severity": "info",
                    "title": f"Dynamic Import Opportunity for Secondary Feature: {a['path']}",
                    "description": f"Non-critical feature module '{a['path']}' is loaded synchronously. Can be deferred via dynamic import().",
                    "remediation": "Load this feature on-demand using dynamic `import('./path')` when the feature is actually triggered."
                })

    # 5. Baseline regression
    if delta_info.get("regressed"):
        candidates.append({
            "rule_id": "bundle-size-regression",
            "path": "bundle",
            "line_number": 1,
            "snippet": f"delta: +{delta_info['delta_raw_bytes']} bytes (+{delta_info['delta_percentage']}%)",
            "severity": "high",
            "title": "Bundle Size Growth Regression Exceeds Threshold",
            "description": f"Total bundle size increased by {delta_info['delta_raw_bytes']} bytes ({delta_info['delta_percentage']}%), exceeding budget allowance.",
            "remediation": "Inspect recent additions to dependencies and distribution bundles to trim bloat."
        })

    return candidates

def main():
    parser = argparse.ArgumentParser(description="Deterministic bundle size analyzer")
    parser.add_argument("--target-dir", "--target", dest="target_dir", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Path to write JSON candidates output")
    parser.add_argument("--baseline", help="Optional explicit path to baseline JSON file")
    parser.add_argument("--save-baseline", action="store_true", help="Force saving current metrics as new baseline")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    target_name = target_dir.name

    assets = discover_assets(target_dir)
    metrics = compute_metrics(assets)

    baseline_data, baseline_file = find_baseline(target_name, target_dir, args.baseline)
    delta_info = evaluate_baseline_delta(metrics, baseline_data)
    bloat_candidates = identify_bloat_candidates(assets, delta_info)

    # If no baseline existed, initialize and write baseline into findings store for future runs
    findings_dir = FACTORY_ROOT / "findings"
    if findings_dir.is_dir() and (not baseline_data or args.save_baseline):
        baseline_out = findings_dir / f"{target_name}-bundle-baseline.json"
        if not baseline_out.exists() or args.save_baseline:
            baseline_payload = {
                "target": target_name,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "total_raw_bytes": metrics["total_raw_bytes"],
                "total_gzip_bytes": metrics["total_gzip_bytes"],
                "asset_count": metrics["asset_count"],
                "largest_assets": metrics["largest_assets"]
            }
            baseline_out.write_text(json.dumps(baseline_payload, indent=2), encoding="utf-8")
            delta_info["baseline_file_created"] = str(baseline_out)

    result = {
        "target": target_name,
        "scanned_assets_count": len(assets),
        "metrics": metrics,
        "baseline": delta_info,
        "bloat_candidates": bloat_candidates,
        "top_assets": metrics["largest_assets"]
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
