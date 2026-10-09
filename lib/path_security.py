#!/usr/bin/env python3
"""Path-confinement helpers for pre-pass scripts that read target files.

Pre-pass scripts receive candidate file paths from findings stores, run-dir reports, or other
model-authored sources. Joining such a path onto the target directory without confinement lets
``../``, an absolute path, or an in-target symlink read arbitrary files as the operator on the
unsandboxed path (agents-075, agents-t9w). ``resolve_within_target`` is the single shared guard:
resolve the joined path (following symlinks) and require it to stay strictly inside the resolved
target directory.
"""

from pathlib import Path
from typing import Optional


def resolve_within_target(target_dir: Path, rel_path: str) -> Optional[Path]:
    """Resolve a candidate location and require it to stay inside the target directory.

    ``rel_path`` is model/finding-supplied and must not be trusted. ``Path.resolve()`` follows
    symlinks, so a symlink (or symlink chain, or symlink-to-dir) inside the target that points
    outside is refused rather than followed out of scope. Returns ``None`` when the path escapes
    the target directory, resolves to the target directory itself, cannot be resolved, or is
    otherwise invalid.
    """
    if not isinstance(rel_path, str) or not rel_path:
        return None

    root = target_dir.resolve()
    try:
        resolved = (target_dir / rel_path).resolve()
    except (OSError, ValueError):
        return None

    # ``is_relative_to`` alone accepts the root itself, so refuse resolve-to-target-dir as well.
    if resolved == root or not resolved.is_relative_to(root):
        return None
    return resolved
