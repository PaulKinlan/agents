#!/usr/bin/env bash
# Resolve the gate's command configuration: TRACKED default first, per-VM override second.
#
# agents-ia3p: the tracked file is what a fresh VM gets and what a reviewer can read in a
# PR. agents-0utp moved where --install writes by default: a bare `--install` now writes the
# REPO-LOCAL file ($HOME/.fleet/<repo>-check.conf), the host-wide ~/.fleet/check.conf that the
# deployed gate reads BY DEFAULT is written only with an explicit --global (install.sh asks for
# it), and FLEET_CHECK_CONF=<path> --install writes that path. To update or tune configuration,
# edit tools/check.conf and re-run the install command that writes the file you mean.
#
# Usage:  tools/check-cmd.sh [CHECK_CMD|CHECK_FAST_CMD|CHECK_TIMEOUT|CHECK_FAST_TIMEOUT]
# With no argument it prints the whole resolved set. Values from the override win.
#         tools/check-cmd.sh --install [--global]   writes the tracked values into the per-VM file.
#                                        No flag: the repo-local default. --global: the host-wide
#                                        file every repo on this machine reads by default.
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
# agents-0utp: WHERE --install WRITES IS ITS OWN DECISION, AND THE DEFAULT IS REPO-LOCAL. The header has always
# described two lives for this file; the installer used to behave as if only one existed and wrote the
# MACHINE-GLOBAL path by default - which is how installing from repo A silently gave repo B a gate command naming
# a file A has and B does not (other repos' gates then died with EXIT 127, reporting a missing tool where the
# truth was a foreign config). PRECEDENCE: an explicit FLEET_CHECK_CONF wins (the override workflow, unchanged);
# --global is the explicit opt-in for the host-wide file that every repo on this machine reads; otherwise the
# destination is a repo-local file OUTSIDE the checkout, named for this repo, so a timer that resets the checkout
# cannot take it away.
# agents-7mby: these two lines used to expand $HOME at TOP LEVEL, unconditionally, so a caller with a scrubbed
# environment - a subshell, a service unit, a CI step, `env -i` - died on "HOME: unbound variable" BEFORE it could
# use the FLEET_CHECK_CONF it had explicitly set. The old one-liner did not have that fault because ${V:-$HOME/...}
# expands its default LAZILY. So: expand lazily again (${HOME:+...} yields empty when HOME is unset, and touches
# nothing otherwise), and DECIDE what the repo-local default means without HOME rather than only avoiding the
# crash: it has no location, because the whole sentence is "the default lives under $HOME/.fleet/<repo>-check.conf"
# and that sentence has no referent. A READ with an explicit FLEET_CHECK_CONF therefore works with no HOME at all;
# an --install that would need the default refuses and NAMES the missing referent.
GLOBAL_CONF="${HOME:+$HOME/.fleet/check.conf}"
REPO_CONF="${HOME:+$HOME/.fleet/$(basename "$ROOT")-check.conf}"
OVERRIDE="${FLEET_CHECK_CONF:-$GLOBAL_CONF}"
INSTALL_GLOBAL=0

# agents-p8lh / agents-0utp: THE ONE PLACE THAT KNOWS WHICH COMMAND WRITES A GIVEN DESTINATION, so every
# message that names a repair can be built from it instead of restating the rule. The defect class this
# closes is the fleet's most repeated one, in the words the reviewer used: the instruction IS the defect.
# Before this function the generated header, --check's repair line, the no-project-stamp note and the
# usage text each carried their own copy of the rule - so when agents-0utp moved the default destination,
# some were updated and some were not, and --check went on telling its reader to run a command that writes
# a DIFFERENT file (a repair that cannot reach the file it names: agents-d081's failure mode). Callers pass
# the destination they are about to talk about; the answer is the command that writes THAT file.
# The three cases are the same three the --install decision below computes, in the same order of
# precedence: the host-wide file, the repo-local default, an explicitly named path.
install_cmd_for() {
  case "${1:-}" in
    "")            printf 'bash tools/check-cmd.sh --install' ;;   # no HOME and no FLEET_CHECK_CONF: the bare
                                                                 # form is the only one that can be meant
    "$GLOBAL_CONF") printf 'bash tools/check-cmd.sh --install --global' ;;
    "$REPO_CONF")   printf 'bash tools/check-cmd.sh --install' ;;
    *)              printf 'FLEET_CHECK_CONF=%s bash tools/check-cmd.sh --install' "$1" ;;
  esac
}

# agents-0r1c: THE READER REFUSES A COMMAND THAT CANNOT RUN WHERE IT IS BEING HANDED OUT. agents-0utp fixed
# the WRITER (a bare --install no longer rewrites the machine-global file) and agents-p8lh made the repairs
# truthful, but a config already installed by another repo keeps being READ: ~/.fleet/check.conf carries
# `bash tools/fast-gate.sh` and a suite command needing tools/ and tests/, all of which exist only in
# agents-factory. A gate in any other repo died with EXIT 127 - a message about a MISSING TOOL, when the truth
# is a FOREIGN CONFIG - and nothing in the reader refused it. THE TEST IS "CANNOT EXIST HERE", NOT "CAME FROM
# ELSEWHERE": a config whose named paths all resolve in this repo is legitimate even when its Project: stamp
# names another directory (a lane worktree of this same project is exactly that), so identity alone never
# refuses - refusing on identity would turn every worktree gate red for an innocent branch. The stamp is used
# for ATTRIBUTION in the message, not as the trigger.
#
# Repo-relative path tokens are extracted conservatively, because a FALSE REFUSAL is worse than the defect it
# prevents: only tokens containing a slash, not starting with / or $ or -, not part of a URL or a variable
# expansion, and not shell metacharacters of any kind. Flags that NAME a path (-s/-t for unittest discovery)
# are checked as paths too, since that is how the poisoned CHECK_CMD fails. An unstamped config keeps the
# existing path: it is not attributed to anyone, and the refusal says so instead of inventing a culprit.
path_tokens() {
  # stdin: a command string. stdout: each repo-relative path token, one per line.
  tr ' \t\n' '\n\n\n' \
    | sed -E 's/^[-]+//' \
    | grep -E '^[A-Za-z0-9_][A-Za-z0-9_.@-]*(/[A-Za-z0-9_.@-]+)+$' \
    | grep -vE '://' || true
}

# The flags that name a directory for unittest discovery (-s <dir>, -t <dir>) are arguments, not slashed tokens,
# so `-s tests -t .` reads as two bare words. They are the exact shape the poisoned CHECK_CMD uses.
flag_path_tokens() {
  # stdin: a command string. stdout: the value of every -s/-t flag, one per line.
  awk '{ for (i = 1; i < NF; i++) if ($i == "-s" || $i == "-t") print $(i + 1) }' \
    | sed -E 's/^["'"'"']//; s/["'"'"']$//' \
    | grep -E '^[A-Za-z0-9_][A-Za-z0-9_.@-]*(/[A-Za-z0-9_.@-]+)*$' || true
}

# Prints the repo/path this config says it was installed by, or empty when it carries no stamp.
config_provenance() {
  [ -r "$1" ] || return 0
  grep -m1 -E '^# Project: ' "$1" 2>/dev/null | sed -E 's/^# Project: //' || true
}

# Returns non-zero (and prints the refusal) when one of the command's named paths does not exist in $ROOT.
refuse_if_unrunnable() {
  local field="$1" cmd="$2" missing="" tok
  [ -n "$cmd" ] || return 0
  for tok in $(printf '%s\n' "$cmd" | path_tokens) $(printf '%s\n' "$cmd" | flag_path_tokens); do
    [ "$tok" = "." ] && continue            # `.` is the repo itself: it always exists here
    if [ ! -e "$ROOT/$tok" ]; then missing="${missing}${missing:+, }$tok"; fi
  done
  [ -n "$missing" ] || return 0
  local who=""
  if [ -n "$provenance" ]; then who="was installed by $provenance and"; else who="carries no 'Project:' stamp and"; fi
  echo "check-cmd: REFUSING to report $field: $CONFIG_SOURCE $who names [$missing], which does not exist in $ROOT." >&2
  echo "check-cmd:   That command cannot run here - it fails with EXIT 127, which reads as a missing tool when the truth is a config naming paths from another repo." >&2
  if [ -n "$REPO_CONF" ]; then
    echo "check-cmd:   repair: $(install_cmd_for "$REPO_CONF")   # writes this repo its own config, $REPO_CONF; then point the gate at it: FLEET_CHECK_CONF=$REPO_CONF" >&2
  else
    echo "check-cmd:   repair: $(install_cmd_for "$GLOBAL_CONF")   # HOME is unset, so the host-wide file is the only destination this reader can name" >&2
  fi
  return 1
}

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
    if [ -n "$dest" ]; then
      echo "check-cmd: no per-VM config at $dest - nothing is installed on this VM (a fresh install would create it from $TRACKED: $(install_cmd_for "$dest"))" >&2
    else
      # agents-p8lh, same class as the repair lines: an empty path in a message reads as a bug in the tool.
      # With neither HOME nor FLEET_CHECK_CONF there is no path to report - so name the missing input instead.
      echo "check-cmd: no per-VM config to check: neither FLEET_CHECK_CONF nor HOME is set, so there is no path to read (set one of them, or run --install --global to deploy the host-wide file)" >&2
    fi
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
      echo "check-cmd: DRIFT: $dest carries no 'Project: agents-factory' stamp - it was written by another project on a shared-HOME host, or by an --install from before that stamp existed; $(install_cmd_for "$dest") stamps it either way" >&2
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
      printf 'check-cmd: DRIFT keys: %s\n  repair with: %s   (rewrites %s from %s)\n' \
        "$drift_keys" "$(install_cmd_for "$dest")" "$dest" "$TRACKED" >&2
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
# fresh VM. The tracked file is the source of truth a PR can review. WHERE THIS WRITES IS A
# DECISION, NOT A CONSTANT: agents-0utp made the default a repo-local file, so this no longer
# writes "the copy the deployed gate reads" - the host-wide file the deployed gate reads by
# default is written only under --global, and the install_cmd_for() helper above is the single
# place that says which command writes which file. (A) - fleet-check gaining a project-local lookup -
# remains the correct end state and would make this step redundant; it needs the fleet-bundle repo.
#
# agents-r1o7: DO NOT SOURCE THE OVERRIDE BEFORE --install. If an existing per-VM file is
# malformed, corrupted, or has syntax errors, an installer whose job is to replace it
# with clean tracked defaults must NOT fail by sourcing the broken file first.
if [ "${1:-}" = "--install" ]; then
  # --global is the explicit opt-in for the host-wide file. Without it (and without FLEET_CHECK_CONF) the default
  # is the repo-local file, because writing the shared path is the claim that THIS repo's gate commands are the
  # host's - a claim that belongs to an operator, never to a default.
  case "${2:-}" in
    --global)
      if [ -n "${FLEET_CHECK_CONF:-}" ]; then
        echo "check-cmd: --global ignored: FLEET_CHECK_CONF=$FLEET_CHECK_CONF is explicit and wins" >&2
      else
        INSTALL_GLOBAL=1; OVERRIDE="$GLOBAL_CONF"
      fi;;
    "") ;;
    *) echo "check-cmd: unknown option '$2' (expected --global, or nothing)" >&2; exit 2;;
  esac
  # Decide the destination ONCE, then classify it - the class is a function of the decision, not a parallel
  # computation that can disagree with it (the first version of this edit classified before deciding).
  if [ -n "${FLEET_CHECK_CONF:-}" ]; then
    OVERRIDE="$FLEET_CHECK_CONF"
  elif [ "$INSTALL_GLOBAL" = 1 ]; then
    OVERRIDE="$GLOBAL_CONF"
  else
    OVERRIDE="$REPO_CONF"
  fi
  if [ -z "$OVERRIDE" ]; then
    echo "check-cmd: cannot --install: HOME is unset, so the repo-local default (\$HOME/.fleet/$(basename "$ROOT")-check.conf) has no location, and no FLEET_CHECK_CONF was given to name one." >&2
    echo "  Fix: export HOME, or pass a destination explicitly: FLEET_CHECK_CONF=<path> bash tools/check-cmd.sh --install" >&2
    exit 2
  fi
  # agents-0utp: THREE LIVES, NOT TWO, AND THE HEADER IS GENERATED FROM THIS SAME CLASSIFICATION. The first
  # version of this edit told the header about two lives while this case statement already knew three, so a file
  # written to the repo-local DEFAULT was described by the override text - which is how a header came to name a
  # repair command that writes a DIFFERENT file (agents-0utp follow-up: the three claims below were all written
  # before --install's default moved, and each one describes the pre-change behaviour).
  case "$OVERRIDE" in
    "$GLOBAL_CONF") DEST_CLASS="MACHINE-GLOBAL (every repo on this host reads it by default)"; DEST_LIFE="global";;
    "$REPO_CONF")   DEST_CLASS="the repo-local default (read only when FLEET_CHECK_CONF names it)"; DEST_LIFE="repo-default";;
    *)              DEST_CLASS="explicit override (FLEET_CHECK_CONF)"; DEST_LIFE="explicit";;
  esac
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
  case "$DEST_LIFE" in
    global)
      # THE ONE CLAIM THAT MATTERS HERE IS NOT "this file is machine-global" BUT "what command repairs THIS
      # file" - and after the default moved, the bare form is no longer it. A reader who follows a repair that
      # writes somewhere else keeps the stale command running while believing they repaired it, which is the
      # failure mode agents-d081 exists to detect (a fix that cannot reach the machine whose copy is stale).
      life_lines=$(cat <<'LIFE'
# THIS COPY IS MACHINE-GLOBAL (~/.fleet/check.conf). fleet-check reads it BY DEFAULT for any repo invoked on
# this host, so REPLACING IT CHANGES THE ACTIVE GATE COMMAND FOR EVERY REPO HERE. A bare --install no longer
# writes here - it writes a repo-local file that fleet-check does not read by default - so the command that
# repairs THIS file is the one named under "To tune" below (agents-0utp).
LIFE
)
      tune_lines=$(printf '# To tune, edit tools/check.conf and re-run INTO THIS FILE: %s (agents-024z, agents-0utp).\n' "$(install_cmd_for "$dest")")
      ;;
    repo-default)
      life_lines=$(cat <<LIFE
# THIS COPY IS THE REPO-LOCAL DEFAULT, at $dest - NOT machine-global.
# fleet-check reads it ONLY when FLEET_CHECK_CONF names this path, and a bare --install from this repo
# rewrites exactly this file. The host-wide file that fleet-check reads by default for every repo on this
# machine is $GLOBAL_CONF, and only --install --global writes THAT (agents-0utp).
LIFE
)
      tune_lines=$(printf '# To tune, edit tools/check.conf and re-run (this file is the bare form\x27s destination):\n#   %s   (agents-024z)\n' "$(install_cmd_for "$dest")")
      ;;
    *)
      # agents-mnvd (review finding on the first attempt at agents-0utp), restated for the life that actually
      # holds the trap now: the tune instruction must not be a command that writes a file OTHER than the one the
      # reader is looking at. A bare --install from this repo writes $REPO_CONF, so for an explicitly named
      # override the variable IS the path and it is named.
      life_lines=$(cat <<LIFE
# THIS COPY IS AN EXPLICIT OVERRIDE, at $dest - NOT machine-global, and not the repo-local default.
# fleet-check reads it ONLY when FLEET_CHECK_CONF names this path, and only that variable makes --install
# write here: a BARE --install from this repo would write $REPO_CONF instead - a different file - and would
# leave this one and $GLOBAL_CONF untouched (agents-0utp).
LIFE
)
      tune_lines=$(printf '# To tune, edit tools/check.conf and re-run WITH THIS FILE SELECTED, so a different file is not written:\n#   %s   (agents-024z, agents-mnvd, agents-0utp)\n' "$(install_cmd_for "$dest")")
      ;;
  esac
  {
    printf '%s\n' "# Written by tools/check-cmd.sh --install from tools/check.conf (agents-ia3p, agents-f6no, agents-0utp)."
    printf '%s\n' "# Project: agents-factory ($ROOT)"
    printf '%s\n' "$life_lines"
    printf '%s\n' "# DO NOT HAND-EDIT FOR TUNING: a hand-edit and a stale install are indistinguishable"
    printf '%s\n' "# from the files alone, so --install overwrites the file it is pointed at. No test reads this"
    printf '%s\n' "# file (it is machine state, and fleet-check sources whatever it says): the repair is the install"
    printf '%s\n' "# command this header names, which is the one that writes THIS file."
    printf '%s\n' "$tune_lines"
    grep -E '^[A-Z_]+=' "$TRACKED"
  } > "$dest"
  echo "check-cmd: installed the project's gate command into $dest ($DEST_CLASS)"
  case "$DEST_LIFE" in
    global)
      echo "check-cmd: NOTE - $dest is MACHINE-GLOBAL: this replaces the active gate command for every repo on this host." >&2;;
    repo-default)
      echo "check-cmd: NOTE - repo-local by default: a lane that wants it sets FLEET_CHECK_CONF=$dest; --global writes the host-wide $GLOBAL_CONF instead." >&2;;
    *)
      echo "check-cmd: NOTE - explicit override: it is read only when FLEET_CHECK_CONF names it; nothing else was written." >&2;;
  esac
  exit 0
fi

# The per-VM override is optional, and it is sourced second so its values win.
if [ -r "$OVERRIDE" ]; then
  # shellcheck disable=SC1090
  . "$OVERRIDE"
fi

: "${CHECK_CMD:?check-cmd: CHECK_CMD is unset or empty after reading $OVERRIDE - refusing to report a verdict about a command nobody chose}"

# agents-0r1c: WHERE THE VALUES CAME FROM, and who to blame when they cannot run here. The attribution comes
# from the file's own '# Project: <name> (<path>)' stamp, written by --install since agents-ia3p, so the refusal
# can name the repo that installed the config the reader is being asked to trust. An UNSTAMPED file is not
# attributed to anyone - the refusal says exactly that rather than inventing a culprit, which is the existing
# path for a file that predates the stamp.
provenance="$(config_provenance "$OVERRIDE")"
CONFIG_SOURCE="${OVERRIDE:-the tracked file ${TRACKED}}"

want="${1:-}"
case "$want" in
  "")
        # The whole set: EVERY command in it has to be runnable here, because the caller may use any of them.
        refuse_if_unrunnable CHECK_CMD "${CHECK_CMD:-}" || exit 2
        refuse_if_unrunnable CHECK_FAST_CMD "${CHECK_FAST_CMD:-}" || exit 2
        printf 'CHECK_CMD=%s\nCHECK_FAST_CMD=%s\nCHECK_TIMEOUT=%s\nCHECK_FAST_TIMEOUT=%s\n' \
        "${CHECK_CMD}" "${CHECK_FAST_CMD:-}" "${CHECK_TIMEOUT:-}" "${CHECK_FAST_TIMEOUT:-}" ;;
  CHECK_CMD|CHECK_FAST_CMD)
        # ONE FIELD ASKED FOR: refuse THAT command, not the file - the other one may be perfectly usable here,
        # and a reader that refused the file would be making a bigger claim than the evidence supports.
        refuse_if_unrunnable "$want" "${!want}" || exit 2
        printf '%s\n' "${!want}" ;;
  CHECK_TIMEOUT|CHECK_FAST_TIMEOUT)
        printf '%s\n' "${!want}" ;;
  --repair-hint)
        # agents-p8lh: ONE SOURCE OF TRUTH FOR THE REPAIR, for callers that must name it without knowing the
        # destination - tools/fast-gate.sh warns about drift at the point of use and used to carry its own
        # copy of this command. It prints the command that writes the file --check would report on for the
        # SAME environment, so a caller cannot name a repair for a file it is not complaining about.
        printf '%s\n' "$(install_cmd_for "$OVERRIDE")" ;;
  *) echo "check-cmd: unknown field '$want'" >&2; exit 2 ;;
esac
