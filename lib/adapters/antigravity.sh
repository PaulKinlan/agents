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

echo "[antigravity adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

# If agentapi is available on this system, use it to dispatch headlessly
AGENTAPI_BIN="$(command -v agentapi || true)"
if [ -n "$AGENTAPI_BIN" ] && [ -x "$AGENTAPI_BIN" ]; then
  "$AGENTAPI_BIN" new-conversation "$PROMPT" > "$OUTPUT_FILE" 2>&1 || true
else
  echo "[antigravity adapter] Handled via session skill integration." > "$OUTPUT_FILE"
fi

echo "$OUTPUT_FILE"
