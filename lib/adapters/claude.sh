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

# Deterministic auth check — presence of a credential, not a model round trip.
# A `claude -p "ping"` probe cost a full inference per run and only recognised one
# failure string, so every other auth error surfaced later as a generic failure.
CREDENTIALS_FILE="${HOME}/.claude/.credentials.json"
if [ -z "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}" ] && [ ! -f "$CREDENTIALS_FILE" ]; then
  echo "[claude adapter] Error: no Claude credentials. Run 'claude login' for session auth (no API key required), or have the runner inject ANTHROPIC_API_KEY." >&2
  exit 1
fi

# Prefer the signed-in session over an ambient API key. Claude Code gives
# ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN precedence over the claude.ai login, so a
# stale key exported in the caller's shell hijacks the run (verified: it hangs rather
# than failing) even though a valid session exists. Only scrub when a session
# credential exists, so the CI plane — API key, no login — is unaffected.
if [ -f "$CREDENTIALS_FILE" ]; then
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
  echo "[claude adapter] Auth: developer session ($CREDENTIALS_FILE)"
else
  echo "[claude adapter] Auth: ANTHROPIC_API_KEY from environment"
fi

echo "[claude adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

claude --plugin-dir "$SKILL_DIR" -p "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[claude adapter] Error executing claude" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
