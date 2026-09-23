#!/usr/bin/env bash
set -euo pipefail

# claude adapter for Software Factory
# Usage: claude.sh <agent_name> <target_dir> <skill_dir> <prompt> <run_dir>

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
PROMPT="${4}"
RUN_DIR="${5}"

mkdir -p "$RUN_DIR"
OUTPUT_FILE="$RUN_DIR/model_output.txt"

echo "[claude adapter] Checking authentication..."
if claude -p "ping" 2>&1 | grep -q "OAuth access token has expired"; then
  echo "[claude adapter] Error: Claude OAuth token has expired. Run 'claude login' to refresh." >&2
  exit 1
fi

echo "[claude adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

claude --plugin-dir "$SKILL_DIR" -p "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[claude adapter] Error executing claude" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
