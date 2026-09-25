#!/usr/bin/env bash
set -euo pipefail

# pi adapter for Software Factory
# Usage: pi.sh <agent_name> <target_dir> <skill_dir> <run_dir>
# The prompt arrives on stdin, never in argv: it embeds raw scanner excerpts (agents-pgr).

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
RUN_DIR="${4}"
if [ -t 0 ]; then
  echo "[pi adapter] Error: prompt expected on stdin." >&2
  exit 2
fi
PROMPT="$(cat)"
if [ -z "$PROMPT" ]; then
  echo "[pi adapter] Error: empty prompt on stdin." >&2
  exit 2
fi

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
# The engine reads the prompt on stdin too, so it is not in the engine's argv either.
printf '%s' "$PROMPT" | pi --no-session --skill "$SKILL_DIR" -p > "$OUTPUT_FILE" 2>&1 || {
  echo "[pi adapter] Error executing pi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
