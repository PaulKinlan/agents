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
# agents-p2ik: the engine's stderr is kept SEPARATE from its stdout, as at the other
# three adapter sites. Both used to land in $OUTPUT_FILE, so an engine that wrote ONLY
# to stderr left a non-empty file that the read-back below accepted as the answer.
STDERR_FILE="$RUN_DIR/model_stderr.txt"

# agentapi is the only supported headless dispatch path. Fail loudly when it is
# missing: writing a placeholder and exiting 0 made the dispatcher parse no JSON and
# store an empty report, so a run that never happened was recorded as a clean scan.
#
# agents-28nn round 5 (review P0 — credential exfiltration): THE ADAPTER IS THE LAST
# GRANTER BEFORE THE KEY — this process's environment carries the run's model
# credentials, so the binary it execs decides who receives them. A by-name PATH lookup
# hands the key to whatever an attacker planted first on PATH: an unpinned engine is an
# EXFILTRATION PATH, not merely an unverified binary. The dispatcher resolves and
# pin-verifies the engine binary (lib/tool_pins.resolve_tool; agentapi is in
# TRUSTED_TOOLS) and passes the verified absolute path as FACTORY_ENGINE_BIN; this
# adapter execs ONLY that path and refuses without it.
AGENTAPI_BIN="${FACTORY_ENGINE_BIN:-}"
if [ -z "$AGENTAPI_BIN" ]; then
  echo "[antigravity adapter] Refusing: FACTORY_ENGINE_BIN is unset — the dispatcher must resolve and pin-verify the agentapi binary (lib/tool_pins.resolve_tool) before this adapter may hand it the run's credentials; a by-name PATH lookup is an exfiltration path (agents-28nn round 5)." >&2
  echo "[antigravity adapter] Install agentapi, or run the factory with --engine pi / --engine claude." >&2
  exit 3
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
# agents-2iwf PLACEMENT NOTE - HISTORY, KEPT BECAUSE IT EXPLAINS THE SHAPE BELOW. It is
# written in the past tense on purpose: it describes a defect that has since been fixed, so
# it cannot go stale the way a prescriptive note does when someone obeys it.
#
# WHAT WAS WRONG: the guard HERE tested $PROMPT AS READ FROM STDIN, while the run further
# down uses the FINAL prompt, which this adapter reassembles from the system directive file.
# The two differ whenever a directive is set. And the old guard tested EMPTINESS rather than
# CONTENT, so with no directive set a prompt of spaces passed it and the engine ran with
# nothing to act on. So the guard was testing the wrong string AND the wrong property.
#
# WHAT THE FILE NOW DOES, AND THIS IS A DESCRIPTION RATHER THAN AN INSTRUCTION:
#
#   The guard sits BELOW the reassembly and tests the CONTENT of the final prompt - the same
#   string the engine is about to receive. A final prompt that is not entirely whitespace is
#   a legitimate run; whitespace-only stdin WITH a reassembled directive is legitimate,
#   because the directive IS the instruction; whitespace-only stdin with NO directive is not,
#   because nothing is reassembled and the engine would get nothing to act on.
#
#   The guard carries a marker comment that the order test in
#   tests/test_adapter_stderr_readback.py indexes by string. That marker exists so the anchor
#   is stable BY DESIGN rather than by luck: it cannot reflow with the case arm without being
#   deliberately deleted.
#
# THE ROUTE THAT MADE THE OLD GUARD REACHABLE IS STILL TRUE AND WORTH KNOWING: NOTHING IN
# THIS ADAPTER OR IN THE DISPATCHER SETS FACTORY_SYSTEM_DIRECTIVE_FILE - it is a variable
# this file consumes and nothing sets - so the no-directive case is not excluded by
# configuration, and the content test is what makes that case correct now.
#
# AND ONE THING THE FIX DID NOT CLAIM TO SOLVE: whether the guard is even reachable depends
# on the tool-policy refusal earlier in this file, which refuses every policy and exits
# before reaching it. The lines below are UNREACHABLE TODAY for that reason. That is why the
# tests covering them use a test-local copy with the refusal removed, which discharges the
# ORDER of the guards and not the reachability of the lines.
PROMPT="$(cat)"

echo "[antigravity adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR'..."

# agents-m2n: agentapi new-conversation takes a prompt and NOTHING else (no system
# channel, no flags — see the tool-policy note above), so this engine cannot receive
# the pre-pass's system directive in a system channel. The honest fallback: prepend it
# to the TOP of the user prompt, at maximum salience and outside the Scanner Data —
# strictly better than the old form, where it was buried inside the JSON payload. Like
# the prompt itself, it rides argv for the run's duration (agents-pgr class). The
# directive guard near the top of the file already required a readable, nonempty file.
if [ -n "${FACTORY_SYSTEM_DIRECTIVE_FILE:-}" ]; then
  PROMPT="$(cat "$FACTORY_SYSTEM_DIRECTIVE_FILE")"$'\n\n'"${PROMPT}"
fi

# agents-ut3v: THE GUARD TESTS THE PROMPT THAT IS ACTUALLY RUN, AND IT TESTS CONTENT.
# It used to sit above this point, testing the value read from stdin for EMPTINESS - so a
# prompt of spaces passed, and it tested a string the reassembly above may have replaced.
# Two cases, and they differ:
#   WITH a directive, the reassembled prompt carries the directive's content, so a
#   whitespace-only stdin is a legitimate run and MUST be admitted - the directive is the
#   instruction. Measured: arm A runs.
#   WITH NO directive, nothing is reassembled, so a whitespace-only stdin leaves an engine
#   with nothing to act on - and an emptiness test admitted it. Measured before this fix:
#   arm B ran with rc=0. It must be refused.
# A content test covers both with one rule; moving the emptiness test down would not,
# because it never asks whether what REMAINS has content.
# factory: prompt-content guard (anchored by tests/test_adapter_stderr_readback.py).
# This line is a MARKER, not decoration: the test above indexes this exact string. It
# exists so the anchor is stable BY DESIGN rather than by luck - it cannot reflow with
# the case arm without being deliberately deleted, and deleting it tells you a test
# depends on the guard moving with it.
case "$PROMPT" in
  *[![:space:]]*) ;;
  *)
    echo "[antigravity adapter] Error: the prompt has no content (blank or whitespace only) after reassembly; refusing to run the engine with nothing to act on (agents-ut3v)." >&2
    exit 2
    ;;
esac

cd "$TARGET_DIR"

# agentapi has no stdin mode, so the prompt is positional here and appears in that engine
# process's argv for the duration of the run. The dispatcher no longer carries it (agents-pgr).
"$AGENTAPI_BIN" new-conversation "$PROMPT" > "$OUTPUT_FILE" 2> "$STDERR_FILE" || {
  echo "[antigravity adapter] Error executing agentapi" >&2
  cat "$OUTPUT_FILE" >&2
  cat "$STDERR_FILE" >&2
  exit 1
}

# agents-fnij/agents-p2ik: A ZERO EXIT IS NOT EVIDENCE THAT THE AGENT ANSWERED. This
# adapter had NO read-back at all - it printed the PATH and the dispatcher read that as
# the model's output - so a run that wrote nothing, or wrote only to stderr, was a
# delivered run. Measured on pi.sh, which had the same shape: rc=0 with a 0-byte file,
# and rc=0 with a 44-byte file holding nothing but "provider error: 429 rate limited".
#
# THESE LINES ARE NOT REACHABLE TODAY: the tool-policy refusal above exits 3 before
# this point, for every policy. They are fixed anyway because that refusal is a
# CONDITION, not a property - if it is ever satisfied this defect becomes live AT ONCE,
# in a file whose diff says it was reviewed (agents-2iwf; the reachability test in
# tests/test_adapter_stderr_readback.py asserts the refusal precedes this block).
if [ ! -s "$OUTPUT_FILE" ]; then
  echo "[antigravity adapter] Error: agentapi exited 0 but wrote no output to $OUTPUT_FILE; the run produced no result (agents-fnij)." >&2
  if [ -s "$STDERR_FILE" ]; then cat "$STDERR_FILE" >&2; fi
  exit 1
fi
if [ -s "$STDERR_FILE" ]; then cat "$STDERR_FILE" >&2; fi
echo "$OUTPUT_FILE"
