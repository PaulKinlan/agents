#!/usr/bin/env bash
set -euo pipefail

# antigravity adapter for Software Factory
# Usage: antigravity.sh <agent_name> <target_dir> <skill_dir> <prompt> <run_dir>

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
PROMPT="${4}"
RUN_DIR="${5}"

mkdir -p "$RUN_DIR"
OUTPUT_FILE="$RUN_DIR/model_output.txt"

# agentapi is the only supported headless dispatch path. Fail loudly when it is
# missing: writing a placeholder and exiting 0 made the dispatcher parse no JSON and
# store an empty report, so a run that never happened was recorded as a clean scan.
AGENTAPI_BIN="$(command -v agentapi || true)"
if [ -z "$AGENTAPI_BIN" ]; then
  echo "[antigravity adapter] Error: 'agentapi' not found on PATH — cannot dispatch a headless antigravity run." >&2
  echo "[antigravity adapter] Install agentapi, or run the factory with --engine pi / --engine claude." >&2
  exit 1
fi

echo "[antigravity adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

"$AGENTAPI_BIN" new-conversation "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[antigravity adapter] Error executing agentapi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
