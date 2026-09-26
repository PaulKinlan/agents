#!/usr/bin/env bash
set -euo pipefail

# pi adapter for Software Factory
# Usage: pi.sh <agent_name> <target_dir> <skill_dir> <run_dir>
# The prompt arrives on stdin, never in argv: it embeds raw scanner excerpts (agents-pgr).

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
RUN_DIR="${4}"

# Tool policy (agents-pnu). The dispatcher sets FACTORY_TOOL_POLICY from lib/containment.py;
# unset means read-only, so a direct invocation fails closed. These flags are the boundary —
# pi's own tool registry, not prompt text (non-negotiable #2):
#   --tools          the only tools the model can call (built-in, extension and custom alike)
#   --no-extensions  no extension code loads, so nothing can register or re-enable a tool
#   --no-approve     a target's .pi/ (settings, extensions, skills, SYSTEM.md) is never trusted,
#                    whatever the operator's defaultProjectTrust says
# Consequence: model providers that ship as extensions are unavailable to factory runs; pi's
# built-in providers are not. pi's read tool is not confined to the target (see
# lib/containment.py ENGINE_READ_SCOPE).
TOOL_POLICY="${FACTORY_TOOL_POLICY:-read-only}"
case "$TOOL_POLICY" in
  read-only) POLICY_FLAGS=(--tools read,grep,find,ls --no-extensions --no-approve) ;;
  *)
    echo "[pi adapter] Refusing: tool policy '$TOOL_POLICY' cannot be enforced by this adapter." >&2
    exit 3
    ;;
esac

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
echo "[pi adapter] Tool policy: $TOOL_POLICY (${POLICY_FLAGS[*]})"
if [ -n "${FACTORY_MAX_BUDGET_USD:-}" ]; then
  # agents-js7: pi has no per-run budget flag — say so where the run log can see it.
  echo "[pi adapter] Note: budget.max_usd=\$$FACTORY_MAX_BUDGET_USD declared but NOT enforced by this adapter (no per-run budget flag; the claude engine enforces it via --max-budget-usd)."
fi
printf '%s' "$PROMPT" | pi --no-session "${POLICY_FLAGS[@]}" --skill "$SKILL_DIR" -p > "$OUTPUT_FILE" 2>&1 || {
  echo "[pi adapter] Error executing pi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
