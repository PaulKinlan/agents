#!/usr/bin/env bash
# Resolve the gate's command configuration: TRACKED default first, per-VM override second.
#
# agents-ia3p: the tracked file is what a fresh VM gets and what a reviewer can read in a
# PR; tools/check-cmd.sh --install writes its values into ~/.fleet/check.conf (or
# $FLEET_CHECK_CONF when set) where the deployed gate reads them. To update or tune
# configuration, edit tools/check.conf and re-run --install.
#
# Usage:  tools/check-cmd.sh [CHECK_CMD|CHECK_FAST_CMD|CHECK_TIMEOUT|CHECK_FAST_TIMEOUT]
# With no argument it prints the whole resolved set. Values from the override win.
#         tools/check-cmd.sh --install   writes the tracked values into the per-VM file.
#         tools/check-cmd.sh --check     compares the per-VM file with the tracked one and names every
#                                        key that differs (agents-d081). Exits 0 in sync, 1 on drift,
#                                        3 when nothing is installed, 2 on a usage/tracked error.
#                                        --check --quiet prints one line naming the keys (the form
#                                        tools/fast-gate.sh warns from at the point of use).
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

# agents-d081: THE DRIFT DETECTOR. --install makes the deployed copy match the tracked file, but until
# this mode existed NOTHING COULD TELL YOU WHEN IT STOPPED MATCHING. That is not hypothetical: measured
# on the agents-factory VM on 2026-10-12, the deployed ~/.fleet/check.conf predated the tracked file, so
# its CHECK_CMD had no summary/tee wrapper and CHECK_FAST_TIMEOUT was 360 against the tracked 180 -
# i.e. the VM had been running a different gate command (and losing the full gate's output capture)
# while every gate on it reported PASS. A fix that lives in a machine-global config file cannot reach a
# machine whose copy predates it; this mode is how anyone can ASK, and how the answer can be made loud
# without a test reading machine state.
#
# IT DELIBERATELY DOES NOT SOURCE THE OVERRIDE. The agents-r1o7 rule stated for --install applies here
# for the same reason: a malformed or half-written per-VM file must be REPORTED as drift, not crash the
# thing that reports drift. Comparison is therefore TEXTUAL, tracked key line against deployed key line.
# WHAT IS NOT COMPARED, STATED SO A READER DOES NOT ASSUME MORE: the deployed file's header comments.
# --install regenerates them, but they cannot change what the gate runs; the KEY LINES are the contract.
#
# EXIT CODES: 0 in sync · 1 drift (every differing key named, with both values) · 3 no per-VM config
# installed (not drift - a fresh VM legitimately has none) · 2 tracked config missing or unusable.
#
# --quiet keeps the same exit codes and prints ONE line naming the differing keys instead of the full
# report. It exists for the POINT OF USE (tools/fast-gate.sh warns from it on every lane's gate run):
# a warning that is eight lines long on every gate is a warning people learn to scroll past, and the
# detail is one command away.
if [ "${1:-}" = "--check" ]; then
  quiet=0
  if [ "${2:-}" = "--quiet" ]; then quiet=1; fi
  dest="${OVERRIDE}"
  if [ ! -e "$dest" ]; then
    echo "check-cmd: no per-VM config at $dest - nothing is installed on this VM (a fresh install would create it from $TRACKED)" >&2
    exit 3
  fi
  drift=0
  drift_keys=""
  note() { drift=1; drift_keys="${drift_keys}${drift_keys:+ }$1"; }
  # A copy written by another project on a shared-HOME host is drift even if every key agrees - and
  # so is a copy written by an --install from before the stamp existed (agents-f6no): the wording
  # below names BOTH, because this detector is the thing that has to be trusted when it fires and an
  # assertion of the wrong cause is how a reader learns to ignore it. Measured 2026-10-12: the live
  # copy on the agents-factory VM was this second case.
  if ! grep -q "Project: agents-factory" "$dest" 2>/dev/null; then
    if [ "$quiet" -eq 0 ]; then
      echo "check-cmd: DRIFT: $dest carries no 'Project: agents-factory' stamp - it was written by another project on a shared-HOME host, or by an --install from before that stamp existed; re-running --install stamps it either way" >&2
    fi
    note "no-project-stamp"
  fi
  while IFS= read -r tracked_line; do
    key="${tracked_line%%=*}"
    if ! grep -q "^${key}=" "$dest" 2>/dev/null; then
      if [ "$quiet" -eq 0 ]; then
        printf 'check-cmd: DRIFT: %s is missing from %s\n' "$key" "$dest" >&2
      fi
      note "${key}(missing)"
      continue
    fi
    deployed_line="$(grep -m1 "^${key}=" "$dest")"
    if [ "$deployed_line" != "$tracked_line" ]; then
      if [ "$quiet" -eq 0 ]; then
        printf 'check-cmd: DRIFT: %s differs\n  tracked : %s\n  deployed: %s\n' \
          "$key" "$tracked_line" "$deployed_line" >&2
      fi
      note "$key"
    fi
  done < <(grep -E '^[A-Z_]+=' "$TRACKED")
  # A key the tracked file does not have is drift too: --install writes exactly the tracked keys.
  while IFS= read -r deployed_key; do
    if ! grep -q "^${deployed_key}=" "$TRACKED" 2>/dev/null; then
      if [ "$quiet" -eq 0 ]; then
        printf 'check-cmd: DRIFT: %s is in %s but not in %s\n' "$deployed_key" "$dest" "$TRACKED" >&2
      fi
      note "${deployed_key}(extra)"
    fi
  done < <(grep -E '^[A-Z_]+=' "$dest" | sed 's/=.*//')
  if [ "$drift" -ne 0 ]; then
    if [ "$quiet" -eq 1 ]; then
      printf 'check-cmd: DRIFT keys: %s\n' "$drift_keys" >&2
    else
      printf 'check-cmd: DRIFT keys: %s\n  repair with: bash tools/check-cmd.sh --install   (rewrites %s from %s)\n' \
        "$drift_keys" "$dest" "$TRACKED" >&2
    fi
    exit 1
  fi
  echo "check-cmd: in sync - $dest matches the tracked keys in $TRACKED"
  exit 0
fi

# agents-ia3p (C): INSTALL this project's resolved command into the per-VM config, so the
# DEPLOYED entrypoint (~/fleet/bin/fleet-check) reads the TRACKED command through the
# mechanism it already uses. fleet-check sources ${FLEET_CHECK_CONF:-$HOME/.fleet/check.conf},
# auto-detects deno.json or package.json and NOTHING ELSE (:155-159), and exits 2 when it
# finds neither (:161) - so a Python project has NO PATH through the deployed gate on a
# fresh VM. The tracked file is the source of truth a PR can review; this writes the copy
# the deployed gate reads. (A) - fleet-check gaining a project-local lookup - remains the
# correct end state and would make this step redundant; it needs the fleet-bundle repo.
#
# agents-r1o7: DO NOT SOURCE THE OVERRIDE BEFORE --install. If an existing per-VM file is
# malformed, corrupted, or has syntax errors, an installer whose job is to replace it
# with clean tracked defaults must NOT fail by sourcing the broken file first.
if [ "${1:-}" = "--install" ]; then
  dest="${OVERRIDE}"
  mkdir -p "$(dirname "$dest")"

  # agents-f6no: ~/.fleet/check.conf is machine-global. Warn if replacing a file
  # not stamped by agents-factory (e.g. another project on a shared-HOME host).
  if [ -f "$dest" ] && ! grep -q "Project: agents-factory" "$dest" 2>/dev/null; then
    echo "check-cmd: WARNING: overwriting $dest which was not stamped by agents-factory (shared-HOME host)" >&2
  fi

  # agents-0utp: NAME THE LIFE THIS COPY LEADS. The header used to assert MACHINE-GLOBAL whatever $dest was,
  # which is only true at the default path. When FLEET_CHECK_CONF names a per-repo override, a file that calls
  # itself machine-global tells its reader that --install maintains it - and --install WITHOUT the variable set
  # replaces the host's shared ~/.fleet/check.conf instead, which is the incident: a repair whose own
  # documentation instructs the reader to trigger the bug. Generated rather than literal because $dest is known
  # here and nowhere else.
  if [ "$dest" = "$HOME/.fleet/check.conf" ]; then
    life_lines=$(cat <<'LIFE'
# THIS COPY IS MACHINE-GLOBAL (~/.fleet/check.conf). fleet-check reads it BY DEFAULT for any repo invoked on
# this host, so --install without FLEET_CHECK_CONF set REPLACES THE ACTIVE GATE COMMAND FOR EVERY REPO HERE.
LIFE
)
    tune_lines=$(cat <<'TUNE'
# To tune, edit tools/check.conf and re-run: bash tools/check-cmd.sh --install (agents-024z).
TUNE
)
  else
    life_lines=$(cat <<LIFE
# THIS COPY IS A REPO-LOCAL OVERRIDE, at $dest.
# fleet-check reads it ONLY when FLEET_CHECK_CONF names this path, and --install writes here ONLY when that
# variable is set at install time. Running --install WITHOUT it set replaces the machine-global
# ~/.fleet/check.conf for every repo on this host instead, and leaves this file untouched.
LIFE
)
    # agents-mnvd (review finding on the first attempt at agents-0utp): the tune instruction must not be the one
    # bare command this header just warned about. A header that says "running --install WITHOUT the variable
    # replaces the host's shared config" and then says "re-run: bash tools/check-cmd.sh --install" hands the
    # reader the trap two lines after naming it. In this life the variable IS the path, so it is named.
    tune_lines=$(cat <<TUNE
# To tune, edit tools/check.conf and re-run WITH THIS FILE SELECTED, so the global config is not written:
#   FLEET_CHECK_CONF=$dest bash tools/check-cmd.sh --install   (agents-024z, agents-mnvd)
TUNE
)
  fi
  {
    printf '%s\n' "# Written by tools/check-cmd.sh --install from tools/check.conf (agents-ia3p, agents-f6no, agents-0utp)."
    printf '%s\n' "# Project: agents-factory ($ROOT)"
    printf '%s\n' "$life_lines"
    printf '%s\n' "# DO NOT HAND-EDIT FOR TUNING: a hand-edit and a stale install are indistinguishable"
    printf '%s\n' "# from the files alone, so --install overwrites the file it is pointed at. No test reads this"
    printf '%s\n' "# file (it is machine state, and fleet-check sources whatever it says): the repair is --install."
    printf '%s\n' "$tune_lines"
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
