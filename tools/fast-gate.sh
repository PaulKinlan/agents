#!/usr/bin/env bash
# Fast gate for agents-factory (agents-651): run only the tests a branch touches.
#
# The full gate (`python3 -m unittest discover -s tests -v`) is the merger's one-time
# per-landing job. Implementers run `fleet-check --fast`, which invokes this script via
# CHECK_FAST_CMD. It is deterministic and bounded (never the whole suite) and fails loudly
# (non-zero) when a change maps to a test file that does not exist, so a missing test cannot
# silently pass.
#
# Resolution (first applicable):
#   1. changed test files vs the base branch (default origin/main) run as-is;
#   2. changed lib/*.py map to tests/test_<name>.py (scheduler -> test_schedules.py), and
#      the `factory` dispatcher maps to the core + truth harnesses;
#   3. anything else (docs, config, tools, …) falls back to a bounded smoke subset
#      (tests/test_factory_core.py).
#
# A changed lib module whose mapped test file is absent exits non-zero. Override the base
# branch with GIT_BASE=<ref> (used by tests).
#
# Wiring (per-VM ~/.fleet/check.conf, alongside the full-gate CHECK_CMD):
#   CHECK_FAST_CMD="bash tools/fast-gate.sh"
#   CHECK_FAST_TIMEOUT=180
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${GIT_BASE:-origin/main}"

# The branch delta. Empty when the base is absent/unknown -> smoke fallback.
changed="$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)"

run=""
mapped=""

while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    tests/test_*.py)
      run="$run $f"
      ;;
    factory)
      # The dispatcher script; covered by the core runner + the truth harness.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py"
      ;;
    lib/*.py)
      name="$(basename "$f" .py)"
      case "$name" in
        scheduler) t="tests/test_schedules.py" ;;
        *)         t="tests/test_${name}.py" ;;
      esac
      if [ -f "$t" ]; then
        mapped="$mapped $t"
      else
        echo "fast-gate: changed $f but $t does not exist — add that test file or extend the mapping" >&2
        exit 1
      fi
      ;;
  esac
done <<< "$changed"

# Union, dedupe, deterministic order.
files="$(printf '%s\n' $run $mapped | awk 'NF && !seen[$0]++' | sort || true)"

# Fall back to a bounded smoke subset when nothing maps (docs-only / config-only / new tools).
if [ -z "$files" ]; then
  files="tests/test_factory_core.py"
fi

modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"
echo "fast-gate: base=$BASE; running: python3 -m unittest $modules"
python3 -m unittest $modules
