#!/usr/bin/env bash
# agents-5vun: audit the pins file a run would USE against a fresh derivation.
#
# A DETECTOR, NOT A FIX. It reports what it inspected, what it re-derived and what it could
# not check, and it exits NON-ZERO when the re-derivation disagrees (1) or cannot run (2) -
# a detector that reports into a log and exits 0 is the shape this repo keeps removing.
# The honest limit is in the report and in lib/pins_audit.py: nothing in-process can
# authenticate a pins file, so this detects forged PATHS and drifted DIGESTS, and says so.
#
# Usage:
#   tools/audit-tool-pins.sh [--pins PATH] [--lookup-path DIRS]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# PYTHONPATH rather than cd: a relative --pins argument must keep resolving against the
# CALLER's cwd, not the repo root.
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m lib.pins_audit "$@"
