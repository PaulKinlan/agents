#!/usr/bin/env python3
"""Deterministic dependency supply chain auditor for deps-supply-chain agent.

Pre-pass script that inspects project manifests (package.json, package-lock.json,
requirements.txt, etc.), runs deterministic security audits (npm audit, pip-audit),
checks license risks, detects unpinned wildcards, and scans for code-level imports
to provide reachability context to the triage model.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

IGNORE_SCAN_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "dist", "build", ".beads",
    ".agent-state", "runs", "fixtures", "findings", "__pycache__", ".venv"
}

SOURCE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"}

COPYLEFT_LICENSES = {
    "GPL", "GPL-2.0", "GPL-3.0", "AGPL", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "GPL-2.0-ONLY", "GPL-3.0-ONLY", "AGPL-3.0-ONLY"
}

def scan_code_usages(target_dir: Path, package_names: Set[str]) -> Dict[str, List[str]]:
    """Scan project source files to determine which dependencies are actually imported."""
    usage_map: Dict[str, List[str]] = {pkg: [] for pkg in package_names}
    if not package_names:
        return usage_map

    # Pre-compile regex for each package name
    patterns = {}
    for pkg in package_names:
        escaped = re.escape(pkg)
        # Match import/require in JS/TS or import in Python
        js_pattern = rf"""(?:from\s+['"]{escaped}(?:/.*)?['"]|require\s*\(\s*['"]{escaped}(?:/.*)?['"]\s*\))"""
        py_pattern = rf"""(?:import\s+{escaped}|from\s+{escaped}\s+import)"""
        patterns[pkg] = re.compile(rf"{js_pattern}|{py_pattern}")

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_SCAN_DIRS and not d.startswith(".")]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue

            filepath = Path(root) / file
            rel_path = str(filepath.relative_to(target_dir))

            try:
                if filepath.stat().st_size > 1024 * 1024:
                    continue
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for pkg, pat in patterns.items():
                if pat.search(content):
                    if rel_path not in usage_map[pkg]:
                        usage_map[pkg].append(rel_path)

    return usage_map

def audit_npm(target_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Run npm audit --json and inspect package.json."""
    candidates = []
    manifests = []

    pkg_json_path = target_dir / "package.json"
    if not pkg_json_path.exists():
        return candidates, manifests

    manifests.append("package.json")
    pkg_lock_path = target_dir / "package-lock.json"
    if pkg_lock_path.exists():
        manifests.append("package-lock.json")

    # 1. Parse package.json for direct dependencies and unpinned versions
    try:
        pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Warning: could not parse package.json: {e}\n")
        pkg_data = {}

    prod_deps = pkg_data.get("dependencies", {})
    dev_deps = pkg_data.get("devDependencies", {})
    target_license = str(pkg_data.get("license", "")).strip().upper()

    # Check for wildcards / floating supply chain risks
    for dep, ver in prod_deps.items():
        if ver in ("*", "latest") or ver.startswith(">"):
            candidates.append({
                "type": "supply-chain-risk",
                "rule_id": "unpinned-wildcard-dependency",
                "package": dep,
                "severity": "medium",
                "is_direct": True,
                "dep_type": "production",
                "title": f"Unpinned wildcard dependency '{dep}': '{ver}'",
                "description": f"Dependency '{dep}' uses wildcard specifier '{ver}' in package.json, exposing the build to upstream supply chain tampering.",
                "affected_range": ver,
                "imported_in_code": [],
                "path": "package.json",
                "snippet": f'"{dep}": "{ver}"',
                "remediation": f"Pin '{dep}' to an explicit semantic version range (e.g. ^x.y.z or strict version)."
            })

    # 2. Run npm audit --json
    npm_bin = shutil.which("npm")
    raw_audit = None
    if npm_bin:
        cmd = [npm_bin, "audit", "--json"]
        try:
            res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False)
            if res.stdout.strip():
                try:
                    raw_audit = json.loads(res.stdout)
                except Exception as e:
                    sys.stderr.write(f"Warning: could not parse npm audit JSON: {e}\n")
        except Exception as e:
            sys.stderr.write(f"Warning: npm audit failed: {e}\n")

    if not raw_audit or "vulnerabilities" not in raw_audit:
        return candidates, manifests

    vulnerabilities = raw_audit.get("vulnerabilities", {})
    all_vuln_packages = set(vulnerabilities.keys())

    # Check code usage for reachability analysis
    code_usages = scan_code_usages(target_dir, all_vuln_packages)

    for pkg_name, vuln in vulnerabilities.items():
        is_direct = vuln.get("isDirect", False)
        if pkg_name in prod_deps:
            dep_type = "production"
        elif pkg_name in dev_deps:
            dep_type = "development"
        else:
            dep_type = "transitive"

        vuln_sev = str(vuln.get("severity", "medium")).lower()
        if vuln_sev == "moderate":
            vuln_sev = "medium"

        # Parse advisories in 'via'
        via_list = vuln.get("via", [])
        advisories = []
        via_packages = []
        for v in via_list:
            if isinstance(v, dict):
                advisories.append({
                    "advisory_id": v.get("url", "").split("/")[-1] if v.get("url") else str(v.get("source", "")),
                    "title": v.get("title", ""),
                    "url": v.get("url", ""),
                    "severity": str(v.get("severity", vuln_sev)).lower().replace("moderate", "medium"),
                    "cwe": v.get("cwe", []),
                    "cvss": v.get("cvss", {}),
                    "range": v.get("range", "")
                })
            elif isinstance(v, str):
                via_packages.append(v)

        primary_advisory = advisories[0] if advisories else {}
        advisory_id = primary_advisory.get("advisory_id") or f"npm-audit:{pkg_name}"
        title = primary_advisory.get("title") or f"Vulnerability in {pkg_name}"
        url = primary_advisory.get("url") or ""
        cwe = primary_advisory.get("cwe") or []
        cvss = primary_advisory.get("cvss") or {}
        imported_files = code_usages.get(pkg_name, [])

        snippet = ""
        if pkg_name in prod_deps:
            snippet = f'"{pkg_name}": "{prod_deps[pkg_name]}"'
        elif pkg_name in dev_deps:
            snippet = f'"{pkg_name}": "{dev_deps[pkg_name]}"'
        else:
            nodes = vuln.get("nodes", [])
            snippet = nodes[0] if nodes else f"node_modules/{pkg_name}"

        remediation = "Run `npm audit fix` or upgrade the package."
        if not is_direct and via_packages:
            remediation = f"Update root dependency pulling in {pkg_name} (via: {', '.join(via_packages)}) or use npm overrides."

        candidates.append({
            "type": "vulnerability",
            "rule_id": advisory_id,
            "package": pkg_name,
            "severity": vuln_sev,
            "is_direct": is_direct,
            "dep_type": dep_type,
            "title": title,
            "url": url,
            "cwe": cwe,
            "cvss": cvss,
            "affected_range": vuln.get("range", ""),
            "imported_in_code": imported_files,
            "via_packages": via_packages,
            "advisories_count": len(advisories),
            "advisories": advisories[:5],
            "fix_available": bool(vuln.get("fixAvailable")),
            "path": "package.json",
            "snippet": snippet,
            "remediation": remediation
        })

    # 3. License check for copyleft packages in node_modules
    if target_license and target_license not in ("GPL", "AGPL", "UNLICENSED"):
        node_modules_dir = target_dir / "node_modules"
        if node_modules_dir.exists():
            for dep in list(prod_deps.keys())[:30]:
                dep_pkg = node_modules_dir / dep / "package.json"
                if dep_pkg.exists():
                    try:
                        dep_data = json.loads(dep_pkg.read_text(encoding="utf-8"))
                        lic = str(dep_data.get("license", "")).upper()
                        if any(cp in lic for cp in COPYLEFT_LICENSES):
                            candidates.append({
                                "type": "license-risk",
                                "rule_id": f"license-copyleft-{dep}",
                                "package": dep,
                                "severity": "high",
                                "is_direct": True,
                                "dep_type": "production",
                                "title": f"Copyleft License ({lic}) in Production Dependency '{dep}'",
                                "description": f"Dependency '{dep}' has license '{lic}', which is incompatible or imposes copyleft obligations on project licensed as '{target_license}'.",
                                "affected_range": dep_data.get("version", ""),
                                "imported_in_code": code_usages.get(dep, []),
                                "path": "package.json",
                                "snippet": f'"{dep}": "{prod_deps.get(dep, "")}"',
                                "remediation": f"Replace '{dep}' with a permissively licensed alternative or verify licensing terms."
                            })
                    except Exception:
                        pass

    return candidates, manifests

def audit_python(target_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Inspect requirements.txt and run pip-audit if present."""
    candidates = []
    manifests = []

    req_path = target_dir / "requirements.txt"
    if not req_path.exists():
        return candidates, manifests

    manifests.append("requirements.txt")

    # Check for unpinned requirements
    try:
        content = req_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue
            if "==" not in line_clean and not line_clean.startswith("-"):
                pkg_name = re.split(r"[><=~]", line_clean)[0].strip()
                candidates.append({
                    "type": "supply-chain-risk",
                    "rule_id": "unpinned-python-dependency",
                    "package": pkg_name,
                    "severity": "low",
                    "is_direct": True,
                    "dep_type": "production",
                    "title": f"Unpinned Python dependency '{pkg_name}'",
                    "description": f"Requirement '{line_clean}' does not pin an exact version, allowing non-reproducible builds.",
                    "affected_range": line_clean,
                    "imported_in_code": [],
                    "path": "requirements.txt",
                    "snippet": line_clean,
                    "remediation": f"Pin '{pkg_name}' to an exact version using '=='."
                })
    except Exception as e:
        sys.stderr.write(f"Warning reading requirements.txt: {e}\n")

    # Run pip-audit if installed
    pip_audit_bin = shutil.which("pip-audit")
    if pip_audit_bin:
        cmd = [pip_audit_bin, "-r", str(req_path), "--format", "json"]
        try:
            res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False)
            if res.stdout.strip():
                data = json.loads(res.stdout)
                for item in data.get("dependencies", []):
                    for vuln in item.get("vulns", []):
                        candidates.append({
                            "type": "vulnerability",
                            "rule_id": vuln.get("id", f"pip-audit:{item.get('name')}"),
                            "package": item.get("name"),
                            "severity": "medium",
                            "is_direct": True,
                            "dep_type": "production",
                            "title": vuln.get("description", f"Vulnerability in {item.get('name')}"),
                            "url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                            "cwe": [],
                            "cvss": {},
                            "affected_range": str(vuln.get("fix_versions", [])),
                            "imported_in_code": [],
                            "path": "requirements.txt",
                            "snippet": f"{item.get('name')}=={item.get('version')}",
                            "remediation": f"Upgrade {item.get('name')} to {vuln.get('fix_versions')}"
                        })
        except Exception:
            pass

    return candidates, manifests

def main():
    parser = argparse.ArgumentParser(description="Deterministic dependency auditor for deps-supply-chain agent")
    parser.add_argument("--target", required=True, help="Target repository directory to audit")
    parser.add_argument("--output", help="Path to write JSON candidates to (default: stdout)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Error: Target directory does not exist: {target_dir}\n")
        sys.exit(1)

    candidates = []
    scanned_manifests = []

    # 1. Audit NPM / Node.js
    npm_candidates, npm_manifests = audit_npm(target_dir)
    candidates.extend(npm_candidates)
    scanned_manifests.extend(npm_manifests)

    # 2. Audit Python
    py_candidates, py_manifests = audit_python(target_dir)
    candidates.extend(py_candidates)
    scanned_manifests.extend(py_manifests)

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for c in candidates:
        sev = c.get("severity", "medium").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    result = {
        "target": str(target_dir),
        "scanner": "audit_deps",
        "scanned_manifests": scanned_manifests,
        "candidate_count": len(candidates),
        "summary": {
            "total_candidates": len(candidates),
            "by_severity": severity_counts
        },
        "candidates": candidates
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
