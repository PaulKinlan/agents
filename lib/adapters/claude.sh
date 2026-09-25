#!/usr/bin/env bash
set -euo pipefail

# claude adapter for Software Factory
# Usage: claude.sh <agent_name> <target_dir> <skill_dir> <run_dir>
# The prompt arrives on stdin, never in argv: it embeds raw scanner excerpts (agents-pgr).

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
RUN_DIR="${4}"

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

# Fail fast on auth first, then read the prompt: an unauthenticated run should report the
# credential problem even when stdin is empty.
if [ -t 0 ]; then
  echo "[claude adapter] Error: prompt expected on stdin." >&2
  exit 2
fi
PROMPT="$(cat)"
if [ -z "$PROMPT" ]; then
  echo "[claude adapter] Error: empty prompt on stdin." >&2
  exit 2
fi

# Prefer the signed-in session over any ambient override. Claude Code resolves auth and the
# endpoint from a precedence list, so a variable exported in the caller's shell decides
# whether the run uses the developer's session (verified: a stale ANTHROPIC_API_KEY makes it
# hang rather than fail). Removing only the two key variables left four more of the same
# class reaching the child — four reported by agents-e3u and three more found by reading the
# env-var names out of the installed CLI (2.1.265), not from documentation.
SESSION_OVERRIDE_VARS=(
  ANTHROPIC_API_KEY
  ANTHROPIC_AUTH_TOKEN
  ANTHROPIC_BASE_URL
  ANTHROPIC_BEDROCK_BASE_URL
  ANTHROPIC_CUSTOM_HEADERS
  CLAUDE_CODE_USE_BEDROCK
  CLAUDE_CODE_USE_VERTEX
  CLAUDE_CODE_USE_GATEWAY
  AWS_BEARER_TOKEN_BEDROCK
)

# Only scrub when a session credential exists, so the CI plane — API key or Bedrock, no login
# — is unaffected. CLAUDE_CODE_OAUTH_TOKEN is deliberately not in the list: it *is* session
# auth, just supplied through the environment.
if [ -f "$CREDENTIALS_FILE" ]; then
  scrubbed=()
  for var in "${SESSION_OVERRIDE_VARS[@]}"; do
    # printenv rather than indirect expansion: only *exported* variables reach the child,
    # and it behaves the same on bash 3.2 (macOS) as on bash 5.
    if printenv "$var" >/dev/null 2>&1; then
      scrubbed+=("$var")
      unset "$var"
    fi
  done
  echo "[claude adapter] Auth: developer session ($CREDENTIALS_FILE)"
  if [ ${#scrubbed[@]} -gt 0 ]; then
    echo "[claude adapter] Scrubbed ambient auth overrides: ${scrubbed[*]}"
  fi
else
  echo "[claude adapter] Auth: environment, no session credential at $CREDENTIALS_FILE"
fi

echo "[claude adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

# The engine reads the prompt on stdin too, so it is not in the engine's argv either.
printf '%s' "$PROMPT" | claude --plugin-dir "$SKILL_DIR" -p > "$OUTPUT_FILE" 2>&1 || {
  echo "[claude adapter] Error executing claude" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
