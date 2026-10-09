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
# Note: Consumers that measure built distribution artifacts and bundle outputs (such as
# bundle-size in agents/bundle-size/scripts/measure_bundle.py and perf-hillclimb via
# lib/bench/runner.py) must retain 'dist' and 'build' in their walked asset sets;
# runner.py subtracts {"dist", "build"} from DEFAULT_IGNORE_DIRS, while bundle-size
# retains a private EXCLUDE_DIRS without dist/build.
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
