#!/usr/bin/env python3
"""Deterministic Attack Surface & Threat Model Scanner for vuln-discovery agent.

Reads target THREAT_MODEL.md (if available), extracts attack surfaces,
trust boundaries, entry points, and bug-shape hints, and locates matching
source code files and sensitive constructs in the target repository.
Outputs candidate vulnerability opportunities as structured JSON.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "coverage", ".beads", ".agent-state", "runs", "fixtures", "findings",
    "__pycache__", ".vscode", ".idea"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".zip", ".tar", ".gz", ".wasm", ".lock",
    ".min.js", ".map"
}

TARGET_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
    ".py", ".go", ".rb", ".php", ".java", ".rs", ".c", ".cpp", ".sh"
}

# Regex patterns for attack surfaces and security-sensitive primitives
SURFACE_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "unauthenticated-cors-wildcard",
        "network-listener",
        "Wildcard CORS header detected on HTTP server or endpoint",
        re.compile(r"""(?:setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]|cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"])""")
    ),
    (
        "request-interception-origin-binding",
        "browser-interception",
        "Puppeteer/CDP request interception URL redirection or response modification",
        re.compile(r"""(?:request\.continue\s*\(\s*\{[^}]*url:|request\.respond\s*\(|page\.setRequestInterception\s*\(true\))""")
    ),
    (
        "unhandled-url-construction",
        "url-parsing",
        "Direct instantiation of URL constructor with potentially untrusted parameter",
        re.compile(r"""(?:const|let|var)\s+\w+\s*=\s*new\s+URL\s*\([^)]+\)""")
    ),
    (
        "weak-domain-validation",
        "domain-validation",
        "Hostname suffix check without leading dot delimiter (subdomain confusion)",
        re.compile(r"""\.endsWith\s*\(\s*['"][^.][^'"]*['"]\s*\)""")
    ),
    (
        "prompt-template-interpolation",
        "prompt-injection",
        "Direct template interpolation of parameters into generative AI prompts",
        re.compile(r"""(?:generatePrompt|interpolate|promptTemplate|\.replaceAll\s*\(\s*[`'"]###\w+###[`'"])\s*""")
    ),
    (
        "sensitive-url-logging",
        "logging",
        "Logging full URLs, headers, or parameters that may contain sensitive tokens",
        re.compile(r"""console\.(?:log|error|warn|info)\s*\([^)]*(?:url|proxyUrl|requestUrl|token|auth|password|headers)""", re.IGNORECASE)
    ),
    (
        "child-process-execution",
        "process-execution",
        "Child process or shell command execution primitive",
        re.compile(r"""(?:child_process|execSync|execFile|spawn|exec)\s*\(""")
    ),
    (
        "dom-injection-sink",
        "dom-xss",
        "Raw DOM manipulation sink capable of HTML/script execution",
        re.compile(r"""\.(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*=""")
    ),
    (
        "http-listener-route",
        "network-listener",
        "Exposed HTTP route listener or server creation",
        re.compile(r"""(?:http\.createServer|app\.(?:get|post|put|delete|use)|server\.listen)\s*\(""")
    ),
]


def load_threat_model(target_dir: Path) -> Optional[Dict[str, Any]]:
    """Locate and parse THREAT_MODEL.md into structured sections."""
    candidates = [
        target_dir / "THREAT_MODEL.md",
        target_dir / "docs" / "THREAT_MODEL.md",
        FACTORY_ROOT / "findings" / f"{target_dir.name}-THREAT_MODEL.md",
    ]
    tm_path = None
    for c in candidates:
        if c.exists():
            tm_path = c
            break

    if not tm_path:
        return None

    try:
        content = tm_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        sys.stderr.write(f"Warning: Failed to read {tm_path}: {e}\n")
        return None

    sections: Dict[str, Any] = {
        "path": str(tm_path.relative_to(target_dir)) if tm_path.is_relative_to(target_dir) else tm_path.name,
        "raw_text": content,
        "trust_boundaries": [],
        "explicitly_trusted": [],
        "untrusted_attack_surfaces": [],
        "bug_shape_hints": [],
        "security_invariants": [],
        "explicit_exclusions": [],
        "components": []
    }

    # Split into sections by markdown headers (## ...)
    current_section = None
    section_lines: Dict[str, List[str]] = {}

    for line in content.splitlines():
        header_match = re.match(r"^##+\s+(?:\d+\.\s*)?([^\n#]+)", line)
        if header_match:
            title = header_match.group(1).strip().lower()
            if "trust boundar" in title or "actor" in title:
                current_section = "trust_boundaries"
            elif "explicitly trusted" in title or "non-threat" in title:
                current_section = "explicitly_trusted"
            elif "attack surface" in title or "untrusted" in title:
                current_section = "untrusted_attack_surfaces"
            elif "bug-shape" in title or "bug shape" in title or "history" in title:
                current_section = "bug_shape_hints"
            elif "invariant" in title or "auditor" in title:
                current_section = "security_invariants"
            elif "exclusion" in title or "wontfix" in title or "accepted" in title:
                current_section = "explicit_exclusions"
            elif "component" in title or "overview" in title or "architecture" in title:
                current_section = "components"
            else:
                current_section = "other"
            section_lines.setdefault(current_section, [])
        elif current_section:
            section_lines.setdefault(current_section, []).append(line)

    # Extract bullet points from each section
    for key, lines in section_lines.items():
        if key in sections and isinstance(sections[key], list):
            bullets = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("- ") or stripped.startswith("* "):
                    bullets.append(stripped[2:].strip())
                elif re.match(r"^\d+\.\s+", stripped):
                    bullets.append(re.sub(r"^\d+\.\s+", "", stripped).strip())
            sections[key] = bullets

    return sections


def check_enclosing_try_catch(lines: List[str], target_line_idx: int) -> bool:
    """Heuristic to check if a specific line is inside a local try-catch block."""
    brace_depth = 0
    in_try = False
    # Look back up to 25 lines
    start_lookback = max(0, target_line_idx - 25)
    for idx in range(start_lookback, target_line_idx):
        line = lines[idx]
        if re.search(r"\btry\s*\{", line):
            in_try = True
            brace_depth += line.count("{") - line.count("}")
        elif in_try:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                in_try = False
    return in_try and brace_depth > 0


def scan_source_files(target_dir: Path, threat_model: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Deterministically scan repository source files for attack surface patterns."""
    candidates: List[Dict[str, Any]] = []
    scanned_files_count = 0

    # Extract referenced file hints from threat model if available
    tm_text = threat_model.get("raw_text", "") if threat_model else ""
    referenced_files = set(re.findall(r"`([a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+)`", tm_text))

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORE_EXTENSIONS or ext not in TARGET_EXTENSIONS:
                continue

            filepath = Path(root) / file
            rel_path = filepath.relative_to(target_dir).as_posix()
            scanned_files_count += 1

            # Skip large files (> 1MB)
            try:
                if filepath.stat().st_size > 1024 * 1024:
                    continue
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            is_referenced_in_tm = (rel_path in referenced_files or file in referenced_files)

            for line_idx, line in enumerate(lines, start=1):
                if len(line) > 1000:
                    continue
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("*"):
                    continue

                for rule_id, category, description, pattern in SURFACE_PATTERNS:
                    if pattern.search(line):
                        snippet = clean_line[:180]
                        threat_context = description
                        severity = "medium"

                        # Contextual refinement based on threat model
                        if rule_id == "unauthenticated-cors-wildcard":
                            severity = "high"
                            threat_context = "Wildcard CORS on local proxy exposes endpoints to cross-origin web browser abuse"
                        elif rule_id == "unhandled-url-construction":
                            inside_try = check_enclosing_try_catch(lines, line_idx - 1)
                            if inside_try:
                                # Lower priority if already guarded by try/catch
                                severity = "low"
                                threat_context = "URL constructor enclosed in try-catch block"
                            else:
                                severity = "medium"
                                threat_context = "URL constructor outside try-catch can throw unhandled TypeError and crash process (DoS)"
                        elif rule_id == "request-interception-origin-binding":
                            severity = "high"
                            threat_context = "Request interception continuation retains original target origin, enabling UXSS via prompt injection"
                        elif rule_id == "prompt-template-interpolation":
                            severity = "high"
                            threat_context = "Prompt interpolation without encoding untrusted parameters crosses the generation trust boundary"
                        elif rule_id == "weak-domain-validation":
                            severity = "high"
                            threat_context = "Domain suffix check without leading dot permits domain spoofing / suffix bypass"

                        if is_referenced_in_tm and severity in ("medium", "low"):
                            severity = "high" if severity == "medium" else "medium"

                        candidates.append({
                            "rule_id": rule_id,
                            "path": rel_path,
                            "line_number": line_idx,
                            "snippet": snippet,
                            "category": category,
                            "severity_hint": severity,
                            "threat_context": threat_context,
                            "referenced_in_threat_model": is_referenced_in_tm
                        })

    return candidates, scanned_files_count


def main():
    parser = argparse.ArgumentParser(description="Deterministic Attack Surface & Threat Model Scanner")
    parser.add_argument("--target", "--target-dir", dest="target_dir", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output candidates JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    sys.stderr.write(f"Loading threat model for {target_dir.name}...\n")
    threat_model = load_threat_model(target_dir)

    sys.stderr.write(f"Scanning source files across attack surfaces in {target_dir.name}...\n")
    raw_candidates, scanned_files = scan_source_files(target_dir, threat_model)

    # Build candidate payload
    candidates_list: List[Dict[str, Any]] = []

    # Insert threat model summary as context item 0 if available
    if threat_model:
        candidates_list.append({
            "rule_id": "threat-model-context",
            "path": threat_model.get("path", "THREAT_MODEL.md"),
            "line_number": 1,
            "snippet": "[Threat Model Invariants and Trust Boundaries]",
            "category": "threat-model",
            "severity_hint": "info",
            "threat_context": "Target Threat Model Guidance",
            "threat_model": {
                "present": True,
                "trust_boundaries": threat_model.get("trust_boundaries", []),
                "explicitly_trusted": threat_model.get("explicitly_trusted", []),
                "untrusted_attack_surfaces": threat_model.get("untrusted_attack_surfaces", []),
                "bug_shape_hints": threat_model.get("bug_shape_hints", []),
                "security_invariants": threat_model.get("security_invariants", []),
                "explicit_exclusions": threat_model.get("explicit_exclusions", [])
            }
        })

    candidates_list.extend(raw_candidates)

    result = {
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "threat_model_present": threat_model is not None,
        "candidates": candidates_list
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"Deterministic scan complete: {len(raw_candidates)} candidates across {scanned_files} files written to {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
