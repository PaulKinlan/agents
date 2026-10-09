#!/usr/bin/env python3
"""Shared directory and path exclusions for deterministic pre-pass scanners and target walkers (agents-uxt).

Deterministic scanners walking a target repository must exclude the factory's own artifact
directories (findings/, runs/) to prevent feedback loops where a scanner ingests previous
station outputs, delta reports, or execution logs as target source code.
"""

from typing import Set

# Core factory artifact directories that must NEVER be scanned as target source code.
FACTORY_ARTIFACT_DIRS: Set[str] = {
    "findings",
    "runs",
}

# Standard build, package, vcs, cache, and artifact directories ignored by scanners.
# Note: bundle-size (agents/bundle-size/scripts/measure_bundle.py) deliberately retains
# a private EXCLUDE_DIRS omitting 'dist' and 'build' because measuring built distribution
# artifacts is its primary function; do not replace bundle-size's set with DEFAULT_IGNORE_DIRS.
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".nyc_output",
    ".venv",
    "venv",
    "__pycache__",
    ".beads",
    ".agent-state",
    *FACTORY_ARTIFACT_DIRS,
}
