#!/usr/bin/env python3
"""Stage exactly the public site files for the GitHub Pages artifact.

`docs/` is a working directory, not a publish root. It holds the six generated
pages and their assets *and* internal material that must never be served:
`PLAN.md`, `DESIGN.md`, `INTEGRATION.md` and `audits/` (internal review notes
that carry local paths and operator detail).

This tool stages the reachable site — the six pages, plus every local file they
reference, followed through CSS — into a separate output directory that the
Pages workflow uploads instead of `docs/`. Nothing else can leak in, because the
file set is derived from the pages themselves and every staged path must pass
`guard()`: a publishable extension, and no `audits/` component (compared
case-insensitively, since a case-insensitive filesystem would treat `Audits/` as
the same directory). References that try to leave the site root are refused
rather than followed, symlinked assets are refused, and the copy step re-checks
that each destination stays inside the output directory.

    python3 tools/stage_site.py --source docs --out _site
    python3 tools/stage_site.py --source docs --list
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parents[1]

#: The site's entry points. Every one must exist; each is followed for references.
PAGES = (
    "index.html",
    "install.html",
    "use.html",
    "stations.html",
    "lines.html",
    "help.html",
)

#: Extensions this site is allowed to publish. Anything else is refused rather
#: than filtered, so a mistake is loud instead of silently dropped.
PUBLISH_EXTENSIONS = frozenset({".html", ".css", ".png", ".svg", ".ico", ".webp", ".jpg", ".jpeg", ".gif"})

#: Staged files whose text is searched for further local references. Binary
#: assets are published as-is and never parsed.
REFERENCE_EXTENSIONS = frozenset({".html", ".css", ".svg"})

#: Directory names that are internal by definition, whatever they contain.
FORBIDDEN_PARTS = frozenset({"audits"})

_HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_CSS_URL = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""", re.IGNORECASE)
_EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//|#)", re.IGNORECASE)


class StagingError(RuntimeError):
    """A file that must not be published, or a reference that cannot be resolved."""


def guard(rel: str) -> str:
    """Refuse anything that is not a publishable site asset. Returns the path unchanged.

    Directory names are compared case-insensitively: a case-insensitive filesystem
    would make `Audits/report.html` the same directory as `audits/report.html`, so an
    exact-case check is not a boundary.
    """
    parts = Path(rel).parts
    if any(part.lower() in FORBIDDEN_PARTS for part in parts):
        raise StagingError(f"refusing to publish internal directory for '{rel}'")
    suffix = Path(rel).suffix.lower()
    if suffix not in PUBLISH_EXTENSIONS:
        raise StagingError(
            f"refusing to publish '{rel}': only {sorted(PUBLISH_EXTENSIONS)} may be staged "
            f"(internal notes, plans and audit files stay private)"
        )
    return rel


def _local_reference(page_rel: str, reference: str) -> str | None:
    """Resolve a reference found in a staged file, or None if it is external.

    Raises StagingError when a reference tries to leave the site root. The published
    artifact is a subtree of the source directory, so a path with a `..` component can
    never be a site asset - and on the copy side it would escape the output directory.
    """
    reference = reference.strip()
    if not reference or _EXTERNAL.match(reference):
        return None
    reference = reference.split("#", 1)[0].split("?", 1)[0]
    if not reference:
        return None
    target = Path(reference)
    if target.is_absolute():
        # A root-absolute reference resolves against the artifact root, which is the
        # output directory, not the source directory.
        raw = target.as_posix().lstrip("/")
    else:
        base = Path(page_rel).parent
        raw = ((base / target) if str(base) != "." else target).as_posix()
    normalized = os.path.normpath(raw).replace(os.sep, "/")
    if normalized in (".", "", "..") or normalized.startswith("../") or os.path.isabs(normalized):
        raise StagingError(
            f"refusing to resolve '{reference}' in '{page_rel}': it points outside the site root "
            f"(link published material to its GitHub URL instead)"
        )
    return normalized


def _references(source: Path, rel: str) -> List[str]:
    suffix = Path(rel).suffix.lower()
    if suffix not in REFERENCE_EXTENSIONS:
        return []
    text = (source / rel).read_text(encoding="utf-8")
    if suffix == ".html":
        raw = _HREF.findall(text)
    else:
        raw = _CSS_URL.findall(text)
    found = []
    for reference in raw:
        target = _local_reference(rel, reference)
        if target is not None:
            found.append(target)
    return found


def plan(source: Path | str = None) -> List[str]:
    """Return the sorted list of source-relative paths that make up the published site.

    Every page must exist. Every local reference from a staged file must resolve to a
    regular file inside the source tree (no symlinks, no escapes) and must pass `guard()`.
    """
    source = Path(source) if source is not None else ROOT / "docs"
    source_root = source.resolve()
    for page in PAGES:
        if not (source / page).is_file():
            raise StagingError(f"published page '{page}' is missing from {source}")
    seen: set[str] = set()
    queue: List[str] = list(PAGES)
    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        guard(rel)
        path = source / rel
        if path.is_symlink():
            raise StagingError(f"refusing to publish '{rel}': symlinks are not staged")
        if not path.is_file():
            raise StagingError(f"a published page references '{rel}', which does not exist in {source}")
        if not path.resolve().is_relative_to(source_root):
            raise StagingError(f"refusing to publish '{rel}': it resolves outside {source}")
        seen.add(rel)
        queue.extend(_references(source, rel))
    return sorted(seen)


def stage(source: Path | str = None, out: Path | str = None) -> List[str]:
    """Copy the published site into `out` (replacing it) and return the staged paths."""
    source = Path(source) if source is not None else ROOT / "docs"
    out = Path(out) if out is not None else ROOT / "_site"
    files = plan(source)
    out_root = out.resolve()
    if out.exists():
        shutil.rmtree(out)
    for rel in files:
        destination = (out / rel).resolve()
        if not destination.is_relative_to(out_root):
            raise StagingError(f"refusing to write '{rel}' outside {out}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / rel, destination)
    return files


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage only the publishable site files")
    parser.add_argument("--source", default=str(ROOT / "docs"), help="directory holding the site sources")
    parser.add_argument("--out", default=str(ROOT / "_site"), help="directory to stage the site into")
    parser.add_argument("--list", action="store_true", help="print the staged paths and exit without copying")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        files = plan(args.source)
    except StagingError as error:
        sys.stderr.write(f"Refusing to stage the site: {error}\n")
        return 1

    if args.list:
        print("\n".join(files))
        return 0

    staged = stage(args.source, args.out)
    print(f"Staged {len(staged)} site files into {Path(args.out).resolve()}")
    for rel in staged:
        print(f"  {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
