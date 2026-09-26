#!/usr/bin/env bash
set -euo pipefail

# antigravity adapter for Software Factory
# Usage: antigravity.sh <agent_name> <target_dir> <skill_dir> <run_dir>
# The prompt arrives on stdin, never in argv: it embeds raw scanner excerpts (agents-pgr).

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
RUN_DIR="${4}"

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

# Tool policy (agents-pnu). `agentapi new-conversation` takes a prompt and nothing else: no
# tool allowlist, no settings isolation. A prompt is not a containment boundary
# (non-negotiable #2), so this adapter refuses every policy, read-only included, until agentapi
# can enforce one. lib/containment.py's ENGINE_TOOL_POLICIES lists none for it, and
# tests/test_containment.py holds the two in agreement.
TOOL_POLICY="${FACTORY_TOOL_POLICY:-read-only}"
case "$TOOL_POLICY" in
  *)
    echo "[antigravity adapter] Refusing: agentapi has no tool controls, so tool policy '$TOOL_POLICY' cannot be enforced. Use --engine pi or --engine claude." >&2
    exit 3
    ;;
esac

# Fail fast on the missing engine first, then read the prompt, so an empty stdin cannot mask
# the real problem.
if [ -t 0 ]; then
  echo "[antigravity adapter] Error: prompt expected on stdin." >&2
  exit 2
fi
PROMPT="$(cat)"
if [ -z "$PROMPT" ]; then
  echo "[antigravity adapter] Error: empty prompt on stdin." >&2
  exit 2
fi

echo "[antigravity adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

cd "$TARGET_DIR"

# agentapi has no stdin mode, so the prompt is positional here and appears in that engine
# process's argv for the duration of the run. The dispatcher no longer carries it (agents-pgr).
"$AGENTAPI_BIN" new-conversation "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[antigravity adapter] Error executing agentapi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
