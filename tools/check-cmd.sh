#!/usr/bin/env bash
# Resolve the gate's command configuration: TRACKED default first, per-VM override second.
#
# agents-ia3p: the tracked file is what a fresh VM gets and what a reviewer can read in a
# PR; tools/check-cmd.sh --install writes its values into ~/.fleet/check.conf where the
# deployed gate reads them. To update or tune configuration, edit tools/check.conf and
# re-run --install.
#
# Usage:  tools/check-cmd.sh [CHECK_CMD|CHECK_FAST_CMD|CHECK_TIMEOUT|CHECK_FAST_TIMEOUT]
# With no argument it prints the whole resolved set. Values from the override win.
#
# IT FAILS LOUD. This file is sourced, so a syntax error in either config is fatal under
# `set -e`, and a missing CHECK_CMD is an error rather than an empty string. A gate that
# silently substitutes a command nobody chose reports a verdict about the wrong thing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACKED="$ROOT/tools/check.conf"
OVERRIDE="${FLEET_CHECK_CONF:-$HOME/.fleet/check.conf}"

if [ ! -r "$TRACKED" ]; then
  echo "check-cmd: the TRACKED gate config is missing: $TRACKED" >&2
  echo "  It is the default a fresh VM gets and the file a reviewer can read. Refusing." >&2
  exit 2
fi

# shellcheck source=tools/check.conf
. "$TRACKED"

: "${CHECK_CMD:?check-cmd: CHECK_CMD is unset or empty in $TRACKED - refusing to report a verdict about a command nobody chose}"

INSTALL=0
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1 ;;
    --force|-f) FORCE=1 ;;
    *) break ;;
  esac
  shift
done

# agents-ia3p (C): INSTALL this project's resolved command into the per-VM config, so the
# DEPLOYED entrypoint (~/fleet/bin/fleet-check) reads the TRACKED command through the
# mechanism it already uses. fleet-check sources ONLY $HOME/.fleet/check.conf (:149),
# auto-detects deno.json or package.json and NOTHING ELSE (:155-159), and exits 2 when it
# finds neither (:161) - so a Python project has NO PATH through the deployed gate on a
# fresh VM. The tracked file is the source of truth a PR can review; this writes the copy
# the deployed gate reads. (A) - fleet-check gaining a project-local lookup - remains the
# correct end state and would make this step redundant; it needs the fleet-bundle repo.
#
# agents-r1o7: DO NOT SOURCE THE OVERRIDE BEFORE --install. If an existing per-VM file is
# malformed, corrupted, or has syntax errors, an installer whose job is to replace it
# with clean tracked defaults must NOT fail by sourcing the broken file first.
if [ "$INSTALL" -eq 1 ]; then
  dest="${OVERRIDE}"
  mkdir -p "$(dirname "$dest")"

  # agents-2cuv: ~/.fleet/check.conf is machine-global. Refuse to overwrite a file
  # belonging to a different project unless explicit force is passed.
  if [ -f "$dest" ]; then
    is_foreign=0
    if grep -q -E '^[# ]*Project:' "$dest" 2>/dev/null; then
      if ! grep -q "Project: agents-factory" "$dest" 2>/dev/null; then
        is_foreign=1
      fi
    elif grep -q -E '^\s*CHECK_(FAST_)?CMD=' "$dest" 2>/dev/null; then
      if ! grep -q -E 'python3 .*discover .*tests' "$dest" 2>/dev/null; then
        is_foreign=1
      fi
    fi

    if [ "$is_foreign" -eq 1 ]; then
      if [ "$FORCE" -ne 1 ] && [ "${SF_FORCE_GATE_CONF:-0}" != "1" ] && [ "${FLEET_CHECK_CONF_FORCE:-0}" != "1" ]; then
        echo "check-cmd: ERROR: $dest already exists and belongs to a different project (shared-HOME collision)." >&2
        echo "  Refusing to overwrite another project's gate configuration." >&2
        echo "  To overwrite intentionally, pass --force (or set SF_FORCE_GATE_CONF=1)." >&2
        exit 1
      fi
      echo "check-cmd: WARNING: overwriting $dest which was stamped by another project (--force active)" >&2
    fi
  fi

  {
    printf '%s\n' "# Written by tools/check-cmd.sh --install from tools/check.conf (agents-ia3p, agents-f6no, agents-2cuv)."
    printf '%s\n' "# Project: agents-factory ($ROOT)"
    printf '%s\n' "# WARNING: This file is MACHINE-GLOBAL (~/.fleet/check.conf). fleet-check reads this file"
    printf '%s\n' "# for any repo invoked on this host; running --install replaces the active gate command."
    printf '%s\n' "# DO NOT HAND-EDIT FOR TUNING: a hand-edit and a stale install are indistinguishable"
    printf '%s\n' "# from the files alone, and tests/test_gate_entrypoint_config.py fails on any divergence"
    printf '%s\n' "# from the tracked command. To tune, edit tools/check.conf and re-run --install."
    grep -E '^[A-Z_]+=' "$TRACKED"
  } > "$dest"
  echo "check-cmd: installed the project's gate command into $dest"
  exit 0
fi

# The per-VM override is optional, and it is sourced second so its values win.
if [ -r "$OVERRIDE" ]; then
  # shellcheck disable=SC1090
  . "$OVERRIDE"
fi

: "${CHECK_CMD:?check-cmd: CHECK_CMD is unset or empty after reading $OVERRIDE - refusing to report a verdict about a command nobody chose}"

want="${1:-}"
case "$want" in
  "") printf 'CHECK_CMD=%s\nCHECK_FAST_CMD=%s\nCHECK_TIMEOUT=%s\nCHECK_FAST_TIMEOUT=%s\n' \
        "${CHECK_CMD}" "${CHECK_FAST_CMD:-}" "${CHECK_TIMEOUT:-}" "${CHECK_FAST_TIMEOUT:-}" ;;
  CHECK_CMD|CHECK_FAST_CMD|CHECK_TIMEOUT|CHECK_FAST_TIMEOUT)
        printf '%s\n' "${!want}" ;;
  *) echo "check-cmd: unknown field '$want'" >&2; exit 2 ;;
esac
