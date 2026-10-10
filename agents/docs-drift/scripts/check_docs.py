#!/usr/bin/env python3
"""Deterministic documentation drift scanner for docs-drift agent.

Pre-pass scanner that inspects markdown documentation files (README.md,
docs/*.md, AGENTS.md, etc.) and extracts:
1. Markdown links (file targets and anchor references)
2. Referenced file and directory paths in code blocks, tree diagrams, and inline backticks
3. Code symbols (functions, classes)
4. CLI commands and flags

Checks all references against actual repository files, git status/history,
and source code to detect broken links, deleted references, and doc drift.
Outputs candidate matches as JSON.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_identity import assign_candidate_ids, artefact_scheme_fields  # noqa: E402
from lib.redaction import emit_station_result  # noqa: E402

try:
    from lib.exclusions import DEFAULT_IGNORE_DIRS
    IGNORE_DIRS = DEFAULT_IGNORE_DIRS | {"scratch"}
except ImportError:
    IGNORE_DIRS = {
        ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
        "__pycache__", ".beads", ".agent-state", "runs", "findings", "scratch"
    }

IGNORE_SYMBOLS = {
    "JSON", "YAML", "SHA256", "UUID", "HTTP", "HTTPS", "OAuth", "REST",
    "HTML", "CSS", "API", "CLI", "Git", "GitHub", "Actions", "Boolean",
    "String", "Array", "Object", "True", "False", "None", "Null", "Nil",
    "GET", "POST", "PUT", "DELETE", "HEAD", "PR", "PRs", "SDLC", "CI", "CD",
    "Markdown", "Linux", "Darwin", "macOS", "Windows", "Keychain", "Plan",
    "Factory", "Agent", "Line", "Sinks", "Engines", "Catalogue", "Triage",
    "Model", "Engine", "Sink", "Target", "Rule", "Status", "Important", "Note",
    "Warning", "Caution", "Tip", "Auto", "Local", "Both"
}

EXTERNAL_REPO_INDICATORS = {
    "chrome-agent-platform", "fauxmium", "@puppeteer", "anthropics/",
    "google-github-actions/", "actions/"
}

# The build/test/output containers a station's SKILL.md prose uses for the AUDITED project's
# artefacts (agents-6zq). A SKILL.md reference under `lib/`, `docs/`, `tools/` or
# `scripts/` is a claim about THIS repo and must stay checkable - lib/adapters/gha.sh was the
# one genuine drift found in this repository, and a wider list hid it.
#
# ACCEPTED LIMITATIONS OF THE SKILL.md FILTER (agents-a0d):
# Limitations 1–4 are unreachable in current repository data, while item 5 notes a surviving
# anatomy candidate. Each is a deliberate boundary. Do not modify filter behaviour unless
# concrete evidence of missed drift appears.
#
# 1. New station referencing scripts/ before directory exists:
#    - Bound: A commit adds agents/<new>/SKILL.md mentioning scripts/<file> before
#      agents/<new>/scripts/ exists on disk. (doc_dir / head).is_dir() is False, so it
#      falls through.
#    - Why deliberate: Avoids treating arbitrary 'scripts' claims as first-party before
#      the station's own directory structure is established on disk.
#    - Detection criterion: List stations whose SKILL.md mentions scripts/ but have no
#      scripts/ directory on disk, where that referenced script file is later created under
#      a different name or never appears while the reference persists.
#    - Fix shape if evidence appears: Treat a leading 'scripts/' in a SKILL.md as own-tree
#      (all 22 stations follow this convention), re-testing against the 04h and 6zq guard rails.
#
# 2. Non-git target:
#    - Bound: Running --target on a directory where `git -C <target> rev-parse` fails.
#    - Why deliberate: First-party repo-root resolution consults _git_paths(target_dir, 'tracked'),
#      which is empty without git, so skill_reference_is_checkable() falls through to False.
#    - Detection criterion: An audit on a non-git target where a SKILL.md reference to a
#      first-party repo path (under lib/, docs/, tools/, agents/, .github/) goes unreported.
#    - Fix shape if evidence appears: Accept any existing non-generic directory at the
#      repo root when the target is verified not to be a git repository via git rev-parse failure
#      (do not check .git directory presence, as .git in git worktrees is a file).
#
# 3. Filenames containing parentheses:
#    - Bound: Documents referencing real files whose names contain '()' (e.g. docs/setup(linux).md).
#    - Why deliberate: any(c in ref for c in "()") filters out call syntax / method invocations
#      from being parsed as paths.
#    - Detection criterion: Inspect station skill source references (e.g.
#      rg '`[^`]*\([^`]*\.[a-z]+' agents/*/SKILL.md) for real file paths containing parentheses
#      that are missing on disk, because skill_reference_is_checkable() discards them before
#      candidates can be emitted.
#    - Fix shape if evidence appears: Only treat '()' as call syntax when not preceded by an
#      alphanumeric character, or when not part of a valid file path string.
#
# 4. tests/ referenced as our own:
#    - Bound: A station SKILL.md referencing a concrete file in this repo's own tests/
#      (e.g. tests/test_x.py).
#    - Why deliberate: 'test' and 'tests' are in TARGET_LAYOUT_DIR_NAMES because station
#      prose repeatedly names test/, tests/ for audited target layouts. Removing 'tests'
#      would re-leak ~30 false-positive candidates on every run of this repository.
#    - Detection criterion: Grep agents/*/SKILL.md for references under tests/ naming a
#      concrete factory test file rather than a target directory convention ('files located
#      under test/, tests/, fixtures/').
#    - Fix shape if evidence appears: Prefer editing the documentation to use a resolvable path
#      (station-relative or an existing repo-relative prefix) rather than removing 'tests'
#      from TARGET_LAYOUT_DIR_NAMES.
#
# 5. README.md:343 scripts/ station anatomy note:
#    - Bound: README.md:343 names 'scripts/' with the snippet '- **scripts/**: Executable pre-pass script'.
#    - Why deliberate: This describes the internal anatomy of a STATION (which exists 22 times
#      under agents/*/scripts/), not of the repository root, so it is station-structure prose
#      rather than a broken root claim. The agents-946b23e comment described it as 'does not
#      exist at the repo root it describes', which may have mislabelled station-anatomy prose
#      as a root path. Kept as a single real candidate per 946b23e.
#    - Detection criterion: Scanner output reports doc-missing-file for reference 'scripts/' at
#      README.md:343 within the station anatomy subsection, where agents/*/scripts/ exists on disk.
#    - Fix shape if evidence appears: Revisit if triage rules classify station anatomy prose or if
#      README.md is edited to qualify the reference (e.g. 'agents/<station>/scripts/' or inline
#      clarification). If scanner filtering is chosen, scope suppression to identified anatomy
#      definition lists rather than globally unblocking 'scripts/'.
TARGET_LAYOUT_DIR_NAMES = {
    "dist", "build", "out", "output", "coverage", "generated", "bundle", "bundles",
    "test", "tests", "spec", "specs", "e2e", "fixtures", "fixture",
    "node_modules", "vendor", "tmp", "temp", "cache",
    "extension", "extensions", "pages", "page", "src", "source", "sources",
    "public", "static", "assets", "samples", "examples", "screenshots", "images", "img",
}

def is_ignored_doc(p: Path, target_dir: Path) -> bool:
    """Check if document file is in an ignored directory."""
    try:
        rel = p.relative_to(target_dir)
        return any(part in IGNORE_DIRS or (part.startswith(".") and part != ".") for part in rel.parts)
    except ValueError:
        return False

def slugify_heading(heading: str) -> str:
    r"""Converts a markdown heading text into a GitHub anchor slug.

    Follows GitHub's anchor slugification algorithm (agents-8xc4):
    1. Lowercase and strip leading/trailing whitespace.
    2. Strip markdown link markup [text](url) to text.
    3. Strip markdown formatting characters (`*_#).
    4. Strip punctuation ([^\w\s-]), including '&', which leaves adjacent spaces.
    5. Replace EACH whitespace character with a hyphen, preserving consecutive
       hyphens (e.g. 'A & B' -> 'a  b' -> 'a--b') as GitHub does.
    6. Strip leading and trailing hyphens.
    """
    text = heading.strip().lower()
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    text = re.sub(r"[`*_#]", "", text)
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s", "-", text)
    return text.strip("-")

def get_markdown_headings(file_path: Path) -> Set[str]:
    """Extract all heading anchor slugs from a markdown file."""
    slugs = set()
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return slugs

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            heading_text = line.lstrip("#").strip()
            slug = slugify_heading(heading_text)
            if slug:
                slugs.add(slug)
    return slugs

# The pre-pass used to spawn `git ls-files <path>` and `git log -1 --all -- <path>` for every
# missing reference (a full history walk each), and to `rglob` the whole tree — node_modules
# included — for every bare filename. On a large repository that overran the station's
# 5-minute budget, the process group was killed and the station produced no verdict
# (journal-idy). Each index below is now built once per target and queried in memory.
GIT_INDEX_TIMEOUT_SECONDS = 120
_GIT_INDEX_CACHE: Dict[Tuple[str, str], List[str]] = {}
_NAME_INDEX_CACHE: Dict[str, Set[str]] = {}


def _git_paths(target_dir: Path, kind: str) -> List[str]:
    """Sorted repo-relative paths: currently tracked (`tracked`) or ever in history (`history`)."""
    key = (str(target_dir), kind)
    if key not in _GIT_INDEX_CACHE:
        if kind == "tracked":
            cmd = ["git", "-C", str(target_dir), "ls-files", "-z"]
        else:
            cmd = ["git", "-C", str(target_dir), "log", "--all", "--name-only", "--format=", "-z"]
        paths: Set[str] = set()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                 timeout=GIT_INDEX_TIMEOUT_SECONDS)
            if res.returncode == 0:
                paths = {p.strip() for p in res.stdout.replace("\n", "\0").split("\0") if p.strip()}
        except Exception:
            pass
        _GIT_INDEX_CACHE[key] = sorted(paths)
    return _GIT_INDEX_CACHE[key]


def _indexed(paths: List[str], clean_path: str) -> bool:
    """`clean_path` is in `paths`, as a file or as a directory prefix (git pathspec semantics)."""
    import bisect
    if not clean_path:
        return False
    i = bisect.bisect_left(paths, clean_path)
    if i < len(paths) and paths[i] == clean_path:
        return True
    prefix = clean_path.rstrip("/") + "/"
    j = bisect.bisect_left(paths, prefix)
    return j < len(paths) and paths[j].startswith(prefix)


def git_tracked_or_deleted(target_dir: Path, rel_path: str) -> Tuple[bool, bool]:
    """Check if git tracks or previously tracked/deleted this file.

    Returns (currently_tracked, previously_tracked).
    """
    clean_path = rel_path.strip().lstrip("./")
    if _indexed(_git_paths(target_dir, "tracked"), clean_path):
        return True, True
    if _indexed(_git_paths(target_dir, "history"), clean_path):
        return False, True
    return False, False


def _file_names(target_dir: Path) -> Set[str]:
    """Every regular file name under the target (outside .git), walked once."""
    key = str(target_dir)
    if key not in _NAME_INDEX_CACHE:
        names: Set[str] = set()
        for _root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            names.update(files)
        _NAME_INDEX_CACHE[key] = names
    return _NAME_INDEX_CACHE[key]


def is_station_skill(rel_doc: str) -> bool:
    """True for a station's SKILL.md, which documents auditing an ARBITRARY target."""
    return rel_doc.startswith("agents/") and rel_doc.endswith("SKILL.md")


def skill_reference_is_checkable(target_dir: Path, doc_dir: Path, ref: str) -> bool:
    """Decide whether a MISSING path in a station SKILL.md is a claim about THIS repo.

    A station's SKILL.md describes how the station audits a target project, so its prose
    names the target's layout as often as this repository's own files. Measured on the
    2026-10-09 tree (agents-6zq): 31 of the 31 SKILL.md candidates were target-facing or
    not paths at all, while 49 SKILL.md references that DO resolve - every station's own
    scripts/*.py among them - would stop being checked if SKILL.md were skipped entirely.
    So the four target-facing shapes are skipped rather than the file:

      1. a generic container name (`dist/`, `tests/`, `fixtures/`, `src/`, ...);
      2. a prose token with no path shape (`try/catch`, `downloadToDir()`);
      3. a template or placeholder (`<feature-id>`, `scripts/*journey*.ts`);
      4. a code fragment (newline, quote or brace).

    Everything else is checked, and the key that keeps the station's own files reportable
    is that a surviving reference needs a directory prefix that exists relative to the
    station or the repo root - so renaming agents/docs-drift/scripts/check_docs.py still
    fails the check (`scripts` is a real directory next to the SKILL.md).

    Precedence was settled by measuring, not taste, because the first two versions of this
    filter each hid a genuine reference:

      * a head that is a directory NEXT TO the SKILL.md is the station's own tree
        (`scripts/scan.py`, `report.schema.json`) - always checkable, even though `scripts`
        is also a generic word;
      * a head that is a TRACKED directory at the repo root is first-party
        (`lib/adapters/gha.sh`, the one genuine drift in this repository) - checkable;
      * anything else names the audited target's layout and is skipped.

    The list consulted here is TARGET_LAYOUT_DIR_NAMES (agents-6zq). A wider list holding
    this repository's own source roots (`lib/`, `docs/`, `tools/`, `scripts/`) hid
    lib/adapters/gha.sh. The first attempt at shape 1 was also unreachable in effect: a bare
    `dist/` either resolves (so no candidate is produced) or its head is not a directory (so
    the fallback below rejects it anyway) - proved by sweeping 32 bare-container scenarios,
    where removing the guard changed nothing. TARGET_LAYOUT_DIR_NAMES is what station prose
    actually uses for the audited project's artefacts, and it is live: without it, a host
    repo that really contains a tracked `dist/` or `test/` directory would report
    `dist/bundle.js` and `test/interpolate.test.js` as drift.
    """
    if not ref:
        return False
    if any(c in ref for c in '\n"\'{}\\'):
        return False                                     # 4. code fragment
    if any(c in ref for c in "<>*"):
        return False                                     # 3. template / placeholder
    if any(c in ref for c in "()"):
        return False                                     # 2. call syntax, not a path
    # removeprefix, NOT lstrip: lstrip("./") is a character set and ate the dot of
    # `.github/workflows/ci.yml`, so that head became "github" and a genuine first-party
    # claim was silently skipped (review of 58f9931).
    clean = ref.removeprefix("./")
    if "/" not in clean:
        # A bare name is not a repo-relative claim, and the resolver's own name index
        # already covers the case where a sibling with that name exists.
        return False
    head = clean.split("/", 1)[0]
    if (doc_dir / head).is_dir():
        return True                                      # the station's own directory
    if head.lower() in TARGET_LAYOUT_DIR_NAMES:
        return False                                     # 1. the audited target's layout
    return ((target_dir / head).is_dir()
            and _indexed(_git_paths(target_dir, "tracked"), head))


def expand_path_braces(path_str: str) -> List[str]:
    """Expands brace expressions like lib/adapters/{antigravity,claude,pi}.sh"""
    match = re.search(r"\{([^}]+)\}", path_str)
    if not match:
        return [path_str]
    prefix = path_str[:match.start()]
    suffix = path_str[match.end():]
    options = [opt.strip() for opt in match.group(1).split(",")]
    results = []
    for opt in options:
        sub_paths = expand_path_braces(f"{prefix}{opt}{suffix}")
        results.extend(sub_paths)
    return results

def path_exists_or_matches(target_dir: Path, doc_dir: Path, path_str: str) -> Tuple[bool, bool]:
    """Checks if a path or path template exists.
    
    Returns (exists, was_wildcard).
    """
    clean_p = path_str.strip()
    # A `:line` suffix (or `:line:col`, or a `:line-line` range) is a LOCATION inside a
    # file, not part of its name: `lib/findings.py:256` names an existing file and was
    # reported missing purely because the suffix was treated as part of the path - the
    # one genuine false positive in the agents-kqd3 class (agents-pxx8). Only resolution
    # strips it: the recorded `reference` stays exactly as the document wrote it, so a
    # genuinely missing `no/such/file.py:12` is still reported, with its suffix intact.
    # The remainder must still look like a path, so a clock-like token (`12:30`) cannot
    # be reduced to a prefix and resolved against a directory that happens to be named
    # that - which would hide the reference instead of reporting it.
    _without_location = re.sub(r"(?::\d+)+(?:-\d+)?$", "", clean_p)
    _had_location = False
    if _without_location != clean_p and ("/" in _without_location or "." in _without_location):
        clean_p = _without_location
        _had_location = True
    if clean_p.endswith("/"):
        clean_p = clean_p[:-1]

    # Handle template wildcards like <name>, <project>, <target>, *
    if re.search(r"<[^>]+>|\*", clean_p):
        glob_pattern = re.sub(r"<[^>]+>", "*", clean_p)
        matches_root = list(target_dir.glob(glob_pattern))
        matches_doc = list(doc_dir.glob(glob_pattern))
        if _had_location:
            matches_root = [p for p in matches_root if p.is_file()]
            matches_doc = [p for p in matches_doc if p.is_file()]
        return (len(matches_root) > 0 or len(matches_doc) > 0), True

    # Direct path checks (doc-relative or repo-relative). A reference that carried a
    # `:line` location must resolve to a FILE: a line location cannot belong to a
    # directory, so accepting a directory would silence a genuinely missing file -
    # `lib/adapters:42` resolved against the DIRECTORY `lib/adapters` until the
    # cross-family review of agents-pxx8 caught it. Without a location the existing
    # directory-tolerant behaviour is unchanged.
    p1 = (doc_dir / clean_p).resolve()
    p2 = (target_dir / clean_p).resolve()

    try:
        if (p1.is_file() if _had_location else p1.exists()):
            return True, False
    except Exception:
        pass

    try:
        if (p2.is_file() if _had_location else p2.exists()):
            return True, False
    except Exception:
        pass

    # Bare filename searches. A document may name a file by name alone when the
    # full path is obvious in context, and this repo's own docs rely on it: `PLAN.md`,
    # `DESIGN.md` and `INTEGRATION.md` in AGENTS.md all match by filename.
    #
    # Bare directory matching (e.g. `audits/` resolving to `docs/audits/`) was retired
    # (agents-vdb) to eliminate ambiguity (the README-root collapse was caused by this
    # heuristic misfiring). Directories must be referenced with their actual path.
    # A path ending in "/" is explicitly a directory reference and must never match a file.
    if not path_str.endswith("/") and "/" not in clean_p and "." in clean_p and clean_p in _file_names(target_dir):
        return True, False

    return False, False

def parse_tree_diagrams(content: str) -> List[Tuple[int, str, str]]:
    """Parses ASCII tree diagrams in code blocks and extracts referenced paths.
    
    Returns list of (line_number, full_path, raw_line).
    """
    in_block = False
    stack: List[Tuple[int, str]] = []  # (depth, dir_name)
    tree_items: List[Tuple[int, str, str]] = []
    has_root = False

    for line_idx, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_block = not in_block
            stack = []
            has_root = False
            continue

        if not in_block:
            continue

        # A line with no tree glyphs is a top-level node. Several diagrams in this repo
        # list more than one root in a single block (`agents/`, `.github/`, `lib/`, …), so
        # this must also fire while a subtree is still open — otherwise every following
        # root is ignored, its parent prefix is lost, and the entry is checked against the
        # wrong path (which is how `.github/workflows/` was reported missing while it
        # existed, and why the rest only matched by fuzzy basename lookup).
        if not any(c in line for c in ["├──", "└──", "│"]):
            root_m = re.match(r"^([a-zA-Z0-9_.~/{}<>-]+/[*]?)(?:\s+#.*)?$", stripped)
            if root_m:
                root_name = root_m.group(1).strip()
                has_root = True
                stack = []
                # A root line is either a repo-root alias (`~/agents/`, `./`) or a real
                # directory named by the diagram. Only the aliases collapse to the repo
                # root: the README's "Repository Structure" block lists `agents/`,
                # `lines/`, `lib/` and `docs/` as SIBLING roots, so collapsing `agents/`
                # checked its 22 children against the repo root (`secret-scan/`,
                # `qa-station/`, …) and emitted 22 false doc-missing-file candidates on
                # every run (agents-04h; the old code normalised `agents/` away because
                # this repo is *named* agents, which is not what the diagram means).
                if root_name.startswith("~") or root_name in ("./", ".", "/"):
                    stack.append((0, ""))
                else:
                    stack.append((0, root_name))
                continue

        if any(c in line for c in ["├──", "└──", "│"]):
            m = re.match(r"^([├└│─\s]*?)(?:├──|└──)\s*([a-zA-Z0-9_./{},<>*@~-]+)(?:\s+#.*)?$", line)
            if not m:
                continue
            prefix = m.group(1)
            name = m.group(2).strip()

            clean_prefix = re.sub(r"[─]", " ", prefix)
            base_depth = 1 if has_root else 0
            depth = (len(clean_prefix) // 4) + base_depth

            while stack and stack[-1][0] >= depth:
                stack.pop()

            prefix_dirs = [s[1].rstrip("/") for s in stack if s[1]]
            full_path = "/".join(prefix_dirs + [name]) if prefix_dirs else name
            if name.endswith("/"):
                stack.append((depth, name))

            tree_items.append((line_idx, full_path, line.strip()))

    return tree_items

def scan_target(target_dir: Path) -> List[Dict[str, Any]]:
    candidates = []

    # 1. Discover all documentation files
    doc_files: List[Path] = []
    source_files: List[Path] = []
    
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            fp = Path(root) / file
            ext = fp.suffix.lower()
            if ext == ".md":
                doc_files.append(fp)
            elif ext in {".py", ".sh", ".ts", ".js", ".json", ".yaml", ".yml", ".go", ".rs"}:
                source_files.append(fp)

    # Pre-cache source file contents for symbol lookup
    source_cache: Dict[str, str] = {}
    for sf in source_files:
        try:
            if sf.stat().st_size < 1024 * 1024:
                source_cache[str(sf.relative_to(target_dir))] = sf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

    # Pre-cache headings in markdown files
    headings_cache: Dict[Path, Set[str]] = {}
    for df in doc_files:
        headings_cache[df] = get_markdown_headings(df)

    # 2. Inspect each documentation file
    for doc_path in doc_files:
        if is_ignored_doc(doc_path, target_dir):
            continue

        rel_doc = str(doc_path.relative_to(target_dir))
        # A station SKILL.md documents auditing an arbitrary target, so its prose is
        # filtered by skill_reference_is_checkable() below (agents-6zq).
        check_skill_paths = is_station_skill(rel_doc)
        doc_dir = doc_path.parent
        try:
            content = doc_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Check ASCII directory tree blocks
        tree_entries = parse_tree_diagrams(content)
        for line_idx, tree_path, raw_line in tree_entries:
            if tree_path.startswith("~"):
                continue
            expanded = expand_path_braces(tree_path)
            for exp_p in expanded:
                exists, _ = path_exists_or_matches(target_dir, doc_dir, exp_p)
                if not exists:
                    if check_skill_paths and not skill_reference_is_checkable(
                            target_dir, doc_dir, exp_p):
                        continue
                    _, was_deleted = git_tracked_or_deleted(target_dir, exp_p)
                    rule_id = "doc-deleted-reference" if was_deleted else "doc-missing-file"
                    candidates.append({
                        "rule_id": rule_id,
                        "path": rel_doc,
                        "line_number": line_idx,
                        "snippet": raw_line[:200],
                        "reference": exp_p,
                        "reference_type": "file_path",
                        "severity": "medium",
                        "title": f"Specification Drift: Missing '{exp_p}'",
                        "description": f"Repository layout in {rel_doc} specifies '{exp_p}', which does not exist in the codebase.",
                        "remediation": f"Implement '{exp_p}' or update specification diagram to mark as planned/future."
                    })

        # Process lines
        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # A. Check markdown links: [text](target)
            link_matches = re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", line)
            for lm in link_matches:
                link_text = lm.group(1).strip()
                raw_target = lm.group(2).strip()

                if raw_target.startswith(("http://", "https://", "mailto:", "ftp:", "javascript:")):
                    continue

                # Same-document anchor: #anchor
                if raw_target.startswith("#"):
                    anchor = raw_target.lstrip("#").lower()
                    doc_slugs = headings_cache.get(doc_path, set())
                    if anchor and anchor not in doc_slugs:
                        candidates.append({
                            "rule_id": "doc-broken-anchor",
                            "path": rel_doc,
                            "line_number": line_idx,
                            "snippet": line_str[:200],
                            "reference": raw_target,
                            "reference_type": "anchor",
                            "severity": "low",
                            "title": f"Broken Section Anchor '#{anchor}'",
                            "description": f"Anchor '#{anchor}' referenced in [{link_text}]({raw_target}) not found in {rel_doc}.",
                            "remediation": f"Update heading or fix anchor slug to match headings in {rel_doc}."
                        })
                    continue

                # File link, possibly with anchor: file.md#anchor
                target_parts = raw_target.split("#", 1)
                file_target = target_parts[0].strip()
                anchor_target = target_parts[1].strip().lower() if len(target_parts) > 1 else None

                if file_target:
                    resolved_file = None
                    p1 = (doc_dir / file_target).resolve()
                    p2 = (target_dir / file_target.lstrip("/")).resolve()

                    if p1.exists() and p1.is_file():
                        resolved_file = p1
                    elif p2.exists() and p2.is_file():
                        resolved_file = p2

                    if resolved_file is None:
                        _, previously_tracked = git_tracked_or_deleted(target_dir, file_target)
                        rule_id = "doc-deleted-reference" if previously_tracked else "doc-broken-link"
                        sev = "high" if "README" in rel_doc or "AGENTS" in rel_doc else "medium"
                        candidates.append({
                            "rule_id": rule_id,
                            "path": rel_doc,
                            "line_number": line_idx,
                            "snippet": line_str[:200],
                            "reference": file_target,
                            "reference_type": "file_link",
                            "severity": sev,
                            "title": f"Broken File Link '{file_target}'",
                            "description": f"Link target '{file_target}' in {rel_doc} does not exist on disk" +
                                           (" (previously existed in git history)." if previously_tracked else "."),
                            "remediation": f"Correct the relative path or remove reference to deleted file."
                        })
                    elif anchor_target:
                        target_slugs = headings_cache.get(resolved_file)
                        if target_slugs is None:
                            target_slugs = get_markdown_headings(resolved_file)
                            headings_cache[resolved_file] = target_slugs
                        if anchor_target not in target_slugs:
                            candidates.append({
                                "rule_id": "doc-broken-anchor",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": raw_target,
                                "reference_type": "anchor",
                                "severity": "low",
                                "title": f"Broken Section Anchor '#{anchor_target}' in '{file_target}'",
                                "description": f"File '{file_target}' exists, but section anchor '#{anchor_target}' was not found.",
                                "remediation": f"Update anchor to match actual section title in '{file_target}'."
                            })

            # B. Check inline backticks for referenced paths, files, and commands
            backticks = re.findall(r"`([^`\n]+)`", line)
            for item in backticks:
                item_clean = item.strip()
                if not item_clean or len(item_clean) < 3:
                    continue

                if item_clean.startswith(("http:", "https:", "~", "/dev", "/tmp", "/etc", "/usr", "$")):
                    continue
                # Any other URI scheme (`file://`, `chrome://extensions`, …) names a URL, not a
                # repository path; the old code only skipped http/https, so a doc saying the
                # pages render from `file://` produced a "Missing Referenced File 'file://'"
                # candidate (agents-04h).
                if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", item_clean):
                    continue
                if any(op in item_clean for op in ["->", "=>", "==", "!=", "<=", ">="]):
                    continue
                if any(ext_ind in item_clean for ext_ind in EXTERNAL_REPO_INDICATORS):
                    continue

                # Check if it looks like a path
                looks_like_path = False
                has_slash = "/" in item_clean and not item_clean.startswith("/")
                has_ext = any(item_clean.endswith(ext) for ext in [
                    ".py", ".sh", ".json", ".yaml", ".yml", ".md", ".ts", ".js", ".plist", ".toml"
                ])

                if (has_slash or has_ext) and not any(c in item_clean for c in [" ", "|", ";", '"', "'"]):
                    looks_like_path = True

                if looks_like_path:
                    expanded_paths = expand_path_braces(item_clean)
                    for exp_p in expanded_paths:
                        exists, is_wc = path_exists_or_matches(target_dir, doc_dir, exp_p)
                        if not exists:
                            if check_skill_paths and not skill_reference_is_checkable(
                                    target_dir, doc_dir, exp_p):
                                continue
                            _, was_deleted = git_tracked_or_deleted(target_dir, exp_p)
                            rule_id = "doc-deleted-reference" if was_deleted else "doc-missing-file"
                            candidates.append({
                                "rule_id": rule_id,
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": exp_p,
                                "reference_type": "file_path",
                                "severity": "medium",
                                "title": f"Missing Referenced File '{exp_p}'",
                                "description": f"Document references path '{exp_p}', which does not exist in repository.",
                                "remediation": f"Create the missing file or update documentation to reflect actual path."
                            })

                # C. Check for documented functions/classes: foo() or CamelCaseClass
                fn_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]{3,})\(\)$", item_clean)
                if fn_match:
                    fn_name = fn_match.group(1)
                    if fn_name not in IGNORE_SYMBOLS:
                        found = any(fn_name in content for content in source_cache.values())
                        if not found:
                            candidates.append({
                                "rule_id": "doc-missing-symbol",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": f"{fn_name}()",
                                "reference_type": "symbol",
                                "severity": "medium",
                                "title": f"Missing Referenced Function '{fn_name}()'",
                                "description": f"Document mentions function '{fn_name}()', but it was not found in source code.",
                                "remediation": f"Verify whether '{fn_name}' was renamed, removed, or has yet to be implemented."
                            })

                if re.match(r"^[A-Z][a-zA-Z0-9]+(?:Store|Adapter|Manager|Runner|Report|Scanner|Service|Client)$", item_clean):
                    class_name = item_clean
                    if class_name not in IGNORE_SYMBOLS:
                        found = any(class_name in content for content in source_cache.values())
                        if not found:
                            candidates.append({
                                "rule_id": "doc-missing-symbol",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": class_name,
                                "reference_type": "symbol",
                                "severity": "medium",
                                "title": f"Missing Referenced Symbol '{class_name}'",
                                "description": f"Document references symbol '{class_name}', but it was not found in codebase.",
                                "remediation": f"Check if symbol '{class_name}' was renamed or deleted."
                            })

    return candidates

def main():
    parser = argparse.ArgumentParser(description="Deterministic doc drift scanner for docs-drift agent")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Path to write the raw local JSON record to (default: stdout, which redacts matched values)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    candidates = scan_target(target_dir)

    # Every candidate gets a deterministic identity at scan time (agents-rdyb), so a consumer can
    # COPY it rather than reconstruct identity from the model's label and prose.
    assign_candidate_ids(candidates)

    result = {
        **artefact_scheme_fields(),
        "target": str(target_dir),
        "scanner": "check_docs.py",
        "candidate_count": len(candidates),
        "candidates": candidates
    }

    emit_station_result(result, args.output)

if __name__ == "__main__":
    main()
