#!/usr/bin/env bash
set -euo pipefail

# pi adapter for Software Factory
# Usage: pi.sh <agent_name> <target_dir> <skill_dir> <prompt> <run_dir>

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
PROMPT="${4}"
RUN_DIR="${5}"

mkdir -p "$RUN_DIR"
OUTPUT_FILE="$RUN_DIR/model_output.txt"

echo "[pi adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

# Auth comes from pi's own configuration (~/.pi) — a signed-in developer session needs
# no provider API key in the environment (verified: this adapter completes with
# ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY unset, and with invalid values
# set, so nothing needs scrubbing here).
echo "[pi adapter] Auth: pi session configuration"

cd "$TARGET_DIR"

# Run pi non-interactively with the specified skill loaded
pi --no-session --skill "$SKILL_DIR" -p "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[pi adapter] Error executing pi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
