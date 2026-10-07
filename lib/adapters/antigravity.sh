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

# agents-m2n (review P1-1): a set directive variable REQUIRES a readable, nonempty file
# (checked before the engine and tool-policy refusals below, so the dispatcher's
# input-contract violation is the specific thing reported).
if [ -n "${FACTORY_SYSTEM_DIRECTIVE_FILE:-}" ]; then
  if [ ! -r "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ] || [ ! -s "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ]; then
    echo "[antigravity adapter] Error: FACTORY_SYSTEM_DIRECTIVE_FILE is set but '${FACTORY_SYSTEM_DIRECTIVE_FILE}' is missing, unreadable, or empty; refusing to run without the system directive." >&2
    exit 2
  fi
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

# agents-m2n: agentapi new-conversation takes a prompt and NOTHING else (no system
# channel, no flags — see the tool-policy note above), so this engine cannot receive
# the pre-pass's system directive in a system channel. The honest fallback: prepend it
# to the TOP of the user prompt, at maximum salience and outside the Scanner Data —
# strictly better than the old form, where it was buried inside the JSON payload. Like
# the prompt itself, it rides argv for the run's duration (agents-pgr class). The
# directive guard near the top of the file already required a readable, nonempty file.
if [ -n "${FACTORY_SYSTEM_DIRECTIVE_FILE:-}" ]; then
  PROMPT="$(cat "$FACTORY_SYSTEM_DIRECTIVE_FILE")\n\n${PROMPT}"
fi

cd "$TARGET_DIR"

# agentapi has no stdin mode, so the prompt is positional here and appears in that engine
# process's argv for the duration of the run. The dispatcher no longer carries it (agents-pgr).
"$AGENTAPI_BIN" new-conversation "$PROMPT" > "$OUTPUT_FILE" 2>&1 || {
  echo "[antigravity adapter] Error executing agentapi" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}

echo "$OUTPUT_FILE"
