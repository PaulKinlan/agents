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
# HOME may be unset — under set -u a bare $HOME reference is fatal, which would
# replace this adapter's own diagnostic with a shell error (agents-u5x).
CREDENTIALS_FILE=""
if [ -n "${HOME:-}" ]; then
  CREDENTIALS_FILE="${HOME}/.claude/.credentials.json"
fi
has_key=0
if [ -n "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  has_key=1
fi
has_session=0
if [ -n "$CREDENTIALS_FILE" ] && [ -f "$CREDENTIALS_FILE" ]; then
  has_session=1
fi
# Bedrock/Vertex are opt-in backend auth (agents-d06): the runner selected the backend,
# and its SDK chain (AWS bearer/profile, Google application credentials) resolves the
# credential — the engine's domain, not this gate's.
has_backend=0
if [ "${CLAUDE_CODE_USE_BEDROCK:-}" = "1" ] || [ "${CLAUDE_CODE_USE_VERTEX:-}" = "1" ]; then
  has_backend=1
fi
if [ "$has_key" -eq 0 ] && [ "$has_session" -eq 0 ] && [ "$has_backend" -eq 0 ]; then
  echo "[claude adapter] Error: no Claude credentials. Run 'claude login' for session auth (no API key required), have the runner inject ANTHROPIC_API_KEY, or opt into Bedrock/Vertex (CLAUDE_CODE_USE_BEDROCK=1 / CLAUDE_CODE_USE_VERTEX=1 with the backend's own credentials)." >&2
  exit 1
fi

# Tool policy (agents-pnu). The dispatcher sets FACTORY_TOOL_POLICY from lib/containment.py;
# unset means read-only, so a direct invocation fails closed. These flags are the boundary —
# Claude Code's own tool registry and settings loader, not prompt text (non-negotiable #2):
#   --restricted         ignores user, project and local settings files, so a target's
#                        .claude/settings.json (hooks, permission rules) never applies. -p
#                        skips the workspace trust dialog, so nothing else would stop it. Also
#                        confines the file tools to the working directory and refuses
#                        bypassPermissions.
#   --tools              the only built-in tools the model can call
#   --strict-mcp-config  no MCP servers (none are passed with --mcp-config)
TOOL_POLICY="${FACTORY_TOOL_POLICY:-read-only}"
case "$TOOL_POLICY" in
  read-only) POLICY_FLAGS=(--restricted --tools "Read,Grep,Glob" --strict-mcp-config) ;;
  # worktree-write (agents-6ce): Edit,Write are added, but --restricted still confines the
  # file tools to the working directory — which the dispatcher sets to a disposable git
  # worktree — and the OS sandbox binds that worktree read-write while the target checkout
  # stays read-only. Bash stays off; the worktree is discarded after the session.
  worktree-write) POLICY_FLAGS=(--restricted --tools "Read,Grep,Glob,Edit,Write" --strict-mcp-config) ;;
  *)
    echo "[claude adapter] Refusing: tool policy '$TOOL_POLICY' cannot be enforced by this adapter." >&2
    exit 3
    ;;
esac

# Station cost cap (agents-js7): the dispatcher sets FACTORY_MAX_BUDGET_USD from the agent's
# declared budget.max_usd, and claude enforces it per run via --max-budget-usd. A malformed
# value is a dispatcher bug — refuse rather than run uncapped under a false belief.
BUDGET_FLAGS=()
if [ -n "${FACTORY_MAX_BUDGET_USD:-}" ]; then
  if ! printf '%s' "$FACTORY_MAX_BUDGET_USD" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
    echo "[claude adapter] Refusing: FACTORY_MAX_BUDGET_USD '$FACTORY_MAX_BUDGET_USD' is not a positive dollar amount." >&2
    exit 3
  fi
  BUDGET_FLAGS=(--max-budget-usd "$FACTORY_MAX_BUDGET_USD")
fi

# The skill travels in the system prompt, not as a plugin. A plugin skill needs the Skill tool,
# and the Skill tool can invoke any other skill. Measured on 2.1.282: `--restricted --tools
# Read,Grep,Glob` lists no skills at all, and adding Skill restores the plugin's skill together
# with every bundled one. A file, so SKILL.md stays out of the engine's argv.
SKILL_FLAGS=()
if [ -f "$SKILL_DIR/SKILL.md" ]; then
  SKILL_FLAGS=(--append-system-prompt-file "$SKILL_DIR/SKILL.md")
else
  echo "[claude adapter] Warning: no SKILL.md in $SKILL_DIR; running without skill instructions." >&2
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
if [ "$has_session" -eq 1 ]; then
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
  if [ -n "$CREDENTIALS_FILE" ]; then
    echo "[claude adapter] Auth: environment, no session credential at $CREDENTIALS_FILE"
  else
    echo "[claude adapter] Auth: environment (HOME unset — no session credential path)"
  fi
fi

echo "[claude adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

# The engine reads the prompt on stdin too, so it is not in the engine's argv either.
echo "[claude adapter] Tool policy: $TOOL_POLICY (${POLICY_FLAGS[*]})"
if [ ${#BUDGET_FLAGS[@]} -gt 0 ]; then
  echo "[claude adapter] Budget cap: \$$FACTORY_MAX_BUDGET_USD (--max-budget-usd)"
fi
# ${SKILL_FLAGS[@]+...} / ${BUDGET_FLAGS[@]+...}: an empty array under set -u is an error on bash 3.2 (macOS).
printf '%s' "$PROMPT" | claude "${POLICY_FLAGS[@]}" ${SKILL_FLAGS[@]+"${SKILL_FLAGS[@]}"} ${BUDGET_FLAGS[@]+"${BUDGET_FLAGS[@]}"} -p > "$OUTPUT_FILE" 2>&1 || {
  echo "[claude adapter] Error executing claude" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
