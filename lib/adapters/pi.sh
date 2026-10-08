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
# built-in providers are not. pi's read tool is not path-confined by these flags; where the
# host has bubblewrap the dispatcher runs this adapter inside an OS sandbox that confines it
# to the target (lib/sandbox.py, agents-9n7). Inside the sandbox $HOME is an empty tmpfs, so
# pi authenticates only from env keys (ANTHROPIC_API_KEY etc., allowlisted by
# lib/child_env.py) — session auth from the operator's ~/.pi is deliberately unreachable.
# Those env keys are visible to pi's own /proc/self/environ (bun needs a real procfs), so
# nothing else secret may ever enter the adapter environment.
TOOL_POLICY="${FACTORY_TOOL_POLICY:-read-only}"
case "$TOOL_POLICY" in
  read-only) POLICY_FLAGS=(--tools read,grep,find,ls --no-extensions --no-approve) ;;
  # worktree-write (agents-6ce): the model may edit files, but the dispatcher runs this
  # adapter with cwd = a disposable git worktree and the OS sandbox binds that worktree
  # read-write while the target checkout stays read-only, so edits can only land in the
  # throwaway worktree. edit,write are pi's file-mutation tools; bash/network stay off. The
  # dispatcher grants this policy only when the run is engine_sandboxed (pi is in
  # SANDBOXED_ENGINES); on a bwrap-less host it downgrades to read-only (review P1-2), so the
  # OS sandbox this comment relies on is always present when this arm runs.
  worktree-write) POLICY_FLAGS=(--tools read,grep,find,ls,edit,write --no-extensions --no-approve) ;;
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

# Auth (review P2, agents-9n7): inside the OS sandbox the engine's own config (~/.pi) is
# NOT mounted, so the signed-in session file cannot be read and auth reaches pi only as the
# ANTHROPIC_API_KEY environment variable that lib/child_env.py admits (the residual
# /proc/self/environ exposure is documented in THREAT_MODEL.md section 7). Outside the
# sandbox — FACTORY_ALLOW_UNSANDBOXED trusted-target mode, or a host without bubblewrap —
# pi falls back to its own ~/.pi session configuration. Report whichever is actually true.
if [ -n "${FACTORY_SANDBOXED:-}" ]; then
  echo "[pi adapter] Auth: ANTHROPIC_API_KEY env (sandboxed; ~/.pi session config not mounted)"
else
  echo "[pi adapter] Auth: pi session configuration (~/.pi)"
fi

cd "$TARGET_DIR"

# agents-m2n: the pre-pass's system-channel directive (e.g. the threat-model nonce
# directive) rides pi's system prompt — `--append-system-prompt` accepts a file's contents
# and may repeat alongside --skill — never as user-channel Scanner Data. When the variable
# is set the file is REQUIRED (review P1-1): the dispatcher already removed the directive
# from the user payload, so silently running without it would drop the untrusted-content
# rule — the adapter fails closed instead.
SYSTEM_DIRECTIVE_FLAGS=()
if [ -n "${FACTORY_SYSTEM_DIRECTIVE_FILE:-}" ]; then
  if [ ! -r "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ] || [ ! -s "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ]; then
    echo "[pi adapter] Error: FACTORY_SYSTEM_DIRECTIVE_FILE is set but '${FACTORY_SYSTEM_DIRECTIVE_FILE}' is missing, unreadable, or empty; refusing to run without the system directive." >&2
    exit 2
  fi
  SYSTEM_DIRECTIVE_FLAGS=(--append-system-prompt "${FACTORY_SYSTEM_DIRECTIVE_FILE}")
fi

# agents-3y2: the model the pi engine runs (the dispatcher sets FACTORY_MODEL; default
# deepseek/deepseek-flash on the keyless managed endpoint). Without it, pi falls back to its
# Anthropic default and asks for ANTHROPIC_API_KEY, which is never the sandboxed keyless path.
MODEL_FLAGS=()
if [ -n "${FACTORY_MODEL:-}" ]; then
  MODEL_FLAGS=(--model "$FACTORY_MODEL")
  echo "[pi adapter] Model: $FACTORY_MODEL"
fi

# Run pi non-interactively with the specified skill loaded
# The engine reads the prompt on stdin too, so it is not in the engine's argv either.
echo "[pi adapter] Tool policy: $TOOL_POLICY (${POLICY_FLAGS[*]})"
if [ -n "${FACTORY_MAX_BUDGET_USD:-}" ]; then
  # agents-js7: pi has no per-run budget flag — say so where the run log can see it.
  echo "[pi adapter] Note: budget.max_usd=\$$FACTORY_MAX_BUDGET_USD declared but NOT enforced by this adapter (no per-run budget flag; the claude engine enforces it via --max-budget-usd)."
fi
# ${SYSTEM_DIRECTIVE_FLAGS[@]+...}: an empty array under set -u is an error on bash 3.2 (macOS).
printf '%s' "$PROMPT" | pi --no-session "${MODEL_FLAGS[@]}" "${POLICY_FLAGS[@]}" --skill "$SKILL_DIR" ${SYSTEM_DIRECTIVE_FLAGS[@]+"${SYSTEM_DIRECTIVE_FLAGS[@]}"} -p > "$OUTPUT_FILE" 2>&1 || {
  echo "[pi adapter] Error executing pi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
