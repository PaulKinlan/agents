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
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

try:
    from lib.exclusions import DEFAULT_IGNORE_DIRS
    IGNORE_SCAN_DIRS = DEFAULT_IGNORE_DIRS | {"fixtures"}
except ImportError:
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

# A concrete version (optionally 'v'-prefixed, optionally with prerelease/build suffix).
# Ranges, tags and specifiers ("^17 || ^18", ">=16", "latest", "workspace:*") are not versions.
SEMVER_RE = re.compile(r"v?\d+(\.\d+)*([-+].*)?")

def clean_semver(ver: Any) -> str:
    """Normalize a concrete version string, returning "" for anything that is not one.

    The divergence check compares shipped versions against installed lockfile versions
    by equality, so a partial or invalid value must be rejected rather than normalized:
    stripping operators turned the peer range ">=16" into "16" and the specifier
    "^17 || ^18" into "17 || ^18", which manufactured false medium divergences against
    the real installed version (and an empty result poisoned the baseline).
    """
    if not isinstance(ver, str):
        return ""
    cleaned = ver.strip()
    if not SEMVER_RE.fullmatch(cleaned):
        return ""
    return cleaned[1:] if cleaned.startswith("v") else cleaned

def get_lockfile_versions(target_dir: Path) -> Dict[str, str]:
    """Extract resolved package versions from package-lock.json or installed node_modules."""
    versions: Dict[str, str] = {}
    lock_path = target_dir / "package-lock.json"
    if lock_path.exists():
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            packages = data.get("packages", {})
            for key, val in packages.items():
                if isinstance(val, dict) and "version" in val:
                    if key.startswith("node_modules/"):
                        pkg_name = key[len("node_modules/"):]
                        if "node_modules/" in pkg_name:
                            pkg_name = pkg_name.split("node_modules/")[-1]
                        v_clean = clean_semver(val["version"])
                        if v_clean:
                            versions[pkg_name] = v_clean
            if not versions and "dependencies" in data:
                def walk_v1(deps):
                    for name, info in deps.items():
                        if isinstance(info, dict):
                            v_clean = clean_semver(info.get("version"))
                            if v_clean:
                                versions[name] = v_clean
                            if isinstance(info.get("dependencies"), dict):
                                walk_v1(info["dependencies"])
                walk_v1(data.get("dependencies", {}))
        except Exception:
            pass

    # Fallback to inspect node_modules directly if lockfile had no resolved versions
    node_modules = target_dir / "node_modules"
    if not versions and node_modules.is_dir():
        for root, dirs, files in os.walk(node_modules):
            if "package.json" in files:
                pj = Path(root) / "package.json"
                try:
                    pdata = json.loads(pj.read_text(encoding="utf-8"))
                    name = pdata.get("name")
                    ver = pdata.get("version")
                    v_clean = clean_semver(ver)
                    if name and v_clean and name not in versions:
                        versions[name] = v_clean
                except Exception:
                    pass
    return versions

def resolve_shipped_versions_npm(target_dir: Path) -> Tuple[Dict[str, Tuple[str, str]], List[str], List[str]]:
    """Resolve (pkg -> (version, source_rel_path)) for shipped artifacts in npm projects.
    Returns: (shipped_versions_map, inspected_manifests, artifact_paths)
    """
    shipped_versions: Dict[str, Tuple[str, str]] = {}
    inspected_manifests: List[str] = []
    artifact_paths: List[str] = []

    # 1. Inspect dist/ and build/ directories
    for dname in ("dist", "build"):
        art_dir = target_dir / dname
        if art_dir.is_dir():
            has_bundle_files = False
            # Check for package.json in dist/build
            dist_pkg = art_dir / "package.json"
            if dist_pkg.is_file():
                has_bundle_files = True
                rel_pkg = str(dist_pkg.relative_to(target_dir))
                inspected_manifests.append(rel_pkg)
                try:
                    data = json.loads(dist_pkg.read_text(encoding="utf-8"))
                    # Only installed/production dependencies: a peerDependencies entry is a
                    # compatibility RANGE, not the version that ships, so comparing it as a
                    # shipped version produced false divergences (e.g. peer ">=16" vs 18.2.0).
                    deps = data.get("dependencies", {})
                    for k, v in deps.items():
                        v_clean = clean_semver(v)
                        if v_clean:
                            shipped_versions[k] = (v_clean, rel_pkg)
                except Exception:
                    pass

            # Scan bundle header banners in JS files in dist/build
            for root, _, files in os.walk(art_dir):
                for f in files:
                    if f.endswith((".js", ".mjs", ".cjs")):
                        has_bundle_files = True
                        fpath = Path(root) / f
                        try:
                            # Read first 4KB for license/version header comments
                            content = fpath.read_text(encoding="utf-8", errors="ignore")[:4096]
                            for m in re.finditer(r"/\*!?\s*([@\w\d_/-]+)\s+v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)", content):
                                pkg, ver = m.group(1), clean_semver(m.group(2))
                                if pkg not in shipped_versions:
                                    shipped_versions[pkg] = (ver, str(fpath.relative_to(target_dir)))
                        except Exception:
                            pass

            if has_bundle_files:
                rel_art = str(art_dir.relative_to(target_dir))
                artifact_paths.append(rel_art)

    # 2. Inspect manifest.json (Chrome extension / WebExtension)
    manifest_candidates = [
        target_dir / "manifest.json",
        target_dir / "dist" / "manifest.json",
        target_dir / "src" / "manifest.json",
        target_dir / "app" / "manifest.json",
    ]
    for mf in manifest_candidates:
        if not mf.is_file():
            continue
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            continue
        # manifest_version only exists on a WebExtension manifest; a generic manifest.json
        # (PWA, icons, tooling) is not a shipped artifact and only added unverified noise.
        if not isinstance(data, dict) or "manifest_version" not in data:
            continue
        rel_mf = str(mf.relative_to(target_dir))
        if rel_mf not in artifact_paths:
            artifact_paths.append(rel_mf)
        if rel_mf not in inspected_manifests:
            inspected_manifests.append(rel_mf)
        deps = data.get("dependencies", {})
        if isinstance(deps, dict):
            for k, v in deps.items():
                v_clean = clean_semver(v)
                if v_clean and k not in shipped_versions:
                    shipped_versions[k] = (v_clean, rel_mf)

    return shipped_versions, inspected_manifests, artifact_paths

def check_shipped_artifact_divergence_npm(
    target_dir: Path,
    lock_versions: Dict[str, str],
    prod_deps: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Check for divergence between lockfile and shipped artifact versions (agents-gtq)."""
    candidates = []
    shipped_versions, inspected_manifests, artifact_paths = resolve_shipped_versions_npm(target_dir)

    # Only concrete versions may become the comparison baseline; a range or invalid lockfile
    # value used to clean down to "" and flagged every real shipped version as divergent.
    baseline_versions: Dict[str, str] = {}
    for pkg, ver in {**prod_deps, **lock_versions}.items():
        v_clean = clean_semver(ver)
        if v_clean:
            baseline_versions[pkg] = v_clean

    divergent_found = False
    for pkg, (shipped_ver, source_path) in shipped_versions.items():
        if pkg in baseline_versions:
            lock_ver = baseline_versions[pkg]
            if shipped_ver != lock_ver:
                divergent_found = True
                candidates.append({
                    "type": "coverage-gap",
                    "rule_id": "lockfile-shipped-version-divergence",
                    "package": pkg,
                    "severity": "medium",
                    "is_direct": pkg in prod_deps,
                    "dep_type": "production",
                    "title": f"Shipped artifact version diverges from lockfile for '{pkg}' ({shipped_ver} vs {lock_ver})",
                    "description": (f"The version of '{pkg}' in the shipped artifact ({source_path}: {shipped_ver}) "
                                    f"diverges from the audited lockfile/manifest version ({lock_ver}). "
                                    "Security advisories evaluated against the lockfile do not match the shipped artifact."),
                    "affected_range": shipped_ver,
                    "imported_in_code": [],
                    "path": source_path,
                    "snippet": f'"{pkg}": "{shipped_ver}"',
                    "remediation": f"Align shipped artifact dependency versions with audited lockfile version ({lock_ver})."
                })

    # If shipped build artifacts or packaging exist, but no dependency version could be resolved
    if artifact_paths and not shipped_versions and not divergent_found:
        primary_artifact = artifact_paths[0]
        candidates.append({
            "type": "coverage-gap",
            "rule_id": "lockfile-shipped-version-divergence",
            "severity": "info",
            "is_direct": False,
            "dep_type": "production",
            "title": f"Shipped artifact dependency versions unverified against lockfile ({primary_artifact})",
            "description": (f"The project contains shipped build artifacts or manifests ({primary_artifact}), "
                            "but actual bundled dependency versions could not be verified against the lockfile. "
                            "Dependency audits were evaluated against the lockfile, which may diverge from what ships."),
            "path": primary_artifact,
            "snippet": primary_artifact,
            "remediation": "Export a verifiable bill of materials (SBOM) or dependency manifest for shipped artifacts."
        })

    return candidates, inspected_manifests

def get_python_requirements_versions(target_dir: Path) -> Dict[str, str]:
    """Parse pinned package versions from requirements.txt."""
    versions: Dict[str, str] = {}
    req_path = target_dir / "requirements.txt"
    if req_path.is_file():
        try:
            for line in req_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if "==" in line and not line.startswith(("#", "-")):
                    parts = line.split("==", 1)
                    pkg = parts[0].strip()
                    ver = clean_semver(parts[1].split(";")[0].strip())
                    if ver:  # agents-nna: never store an empty semver (e.g. a 'foo == 1.*' prefix)
                        versions[pkg] = ver
        except Exception:
            pass
    return versions

def check_shipped_artifact_divergence_python(
    target_dir: Path,
    req_versions: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Check for divergence between requirements.txt and Python shipped artifacts (agents-gtq)."""
    candidates = []
    inspected_manifests: List[str] = []
    artifact_paths: List[str] = []
    shipped_versions: Dict[str, Tuple[str, str]] = {}

    dist_dir = target_dir / "dist"
    if dist_dir.is_dir():
        has_wheels = False
        for f in dist_dir.iterdir():
            if f.suffix == ".whl" and f.is_file():
                has_wheels = True
                rel_f = str(f.relative_to(target_dir))
                inspected_manifests.append(rel_f)
                try:
                    with zipfile.ZipFile(f, "r") as z:
                        for zname in z.namelist():
                            if zname.endswith(".dist-info/METADATA"):
                                meta = z.read(zname).decode("utf-8", errors="ignore")
                                for mline in meta.splitlines():
                                    if mline.startswith("Requires-Dist:"):
                                        spec = mline[len("Requires-Dist:"):].strip()
                                        if "==" in spec:
                                            sparts = spec.split("==", 1)
                                            pkg = sparts[0].strip().split()[0]
                                            ver = clean_semver(sparts[1].split(";")[0].strip())
                                            if ver:  # agents-nna: never store an empty semver
                                                shipped_versions[pkg] = (ver, rel_f)
                except Exception:
                    pass
        if has_wheels:
            artifact_paths.append("dist")

    divergent_found = False
    for pkg, (shipped_ver, source_path) in shipped_versions.items():
        if pkg in req_versions:
            req_ver = req_versions[pkg]
            if shipped_ver != req_ver:
                divergent_found = True
                candidates.append({
                    "type": "coverage-gap",
                    "rule_id": "lockfile-shipped-version-divergence",
                    "package": pkg,
                    "severity": "medium",
                    "is_direct": True,
                    "dep_type": "production",
                    "title": f"Shipped artifact version diverges from requirements for '{pkg}' ({shipped_ver} vs {req_ver})",
                    "description": (f"The version of '{pkg}' in the shipped artifact ({source_path}: {shipped_ver}) "
                                    f"diverges from the audited requirements.txt version ({req_ver}). "
                                    "Security advisories evaluated against requirements.txt do not match the shipped artifact."),
                    "affected_range": shipped_ver,
                    "imported_in_code": [],
                    "path": source_path,
                    "snippet": f"{pkg}=={shipped_ver}",
                    "remediation": f"Align shipped artifact dependency versions with requirements.txt ({req_ver})."
                })

    if artifact_paths and not shipped_versions and not divergent_found:
        primary_artifact = artifact_paths[0]
        candidates.append({
            "type": "coverage-gap",
            "rule_id": "lockfile-shipped-version-divergence",
            "severity": "info",
            "is_direct": False,
            "dep_type": "production",
            "title": f"Shipped artifact dependency versions unverified against requirements ({primary_artifact})",
            "description": (f"The project contains shipped build artifacts ({primary_artifact}), "
                            "but actual bundled dependency versions could not be verified against requirements.txt. "
                            "Dependency audits were evaluated against requirements.txt, which may diverge from what ships."),
            "path": primary_artifact,
            "snippet": primary_artifact,
            "remediation": "Export a verifiable bill of materials (SBOM) or metadata for shipped artifacts."
        })

    return candidates, inspected_manifests

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

    # 2. Check for lockfile vs shipped artifact version divergence (agents-gtq)
    lock_versions = get_lockfile_versions(target_dir)
    divergence_candidates, shipped_manifests = check_shipped_artifact_divergence_npm(
        target_dir, lock_versions, prod_deps
    )
    candidates.extend(divergence_candidates)
    manifests.extend(shipped_manifests)

    # 3. Run npm audit --json
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
        # agents-2x6 review P2: npm audit was attempted (npm exists, a manifest exists) but
        # produced no usable result. Under the sandbox's egress allowlist this is exactly
        # what a custom-registry target looks like (registry outside the allowlist -> 403
        # -> npm audit exits non-zero with no JSON). Swallowing it let the station
        # short-circuit to "Clean scan" with zero vulnerability coverage. Surface the gap
        # as a candidate so the model must report the limitation instead of silence.
        if npm_bin:
            candidates.append({
                "type": "coverage-gap",
                "rule_id": "npm-audit-unavailable",
                "severity": "low",
                "title": "Dependency audit could not run; vulnerability coverage is incomplete",
                "description": ("`npm audit` produced no usable result. Its configured registry "
                                "may be unreachable from this run's egress allowlist (e.g. a "
                                "custom registry in .npmrc), or the audit itself failed. No npm "
                                "vulnerability data was collected for this target."),
                "path": "package.json",
                "remediation": ("Run `npm audit` where its configured registry is reachable, or "
                                "extend the station's egress allowlist declaration with the "
                                "registry host and re-run."),
            })
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

    # Check for requirements vs shipped artifact divergence (agents-gtq)
    req_versions = get_python_requirements_versions(target_dir)
    py_divergence_candidates, py_shipped_manifests = check_shipped_artifact_divergence_python(
        target_dir, req_versions
    )
    candidates.extend(py_divergence_candidates)
    manifests.extend(py_shipped_manifests)

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
