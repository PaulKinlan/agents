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
#         tools/check-cmd.sh --explain-failure <exit-code> [FIELD]
#                                        agents-0r1c, third shape: the diagnostic a RUNNER calls after the
#                                        command has already failed by itself. It speaks only for a
#                                        command-not-found exit (127, or 126 not-executable), and then names
#                                        the config's Project: stamp, the tokens that do not resolve here,
#                                        and the repair. Silent and exit 0 otherwise, so it is safe to call
#                                        after every run and it can never change a verdict. This file cannot
#                                        refuse on a prediction: three attempts to do so at hand-out time
#                                        broke working gates (`./` miss, then an output redirection, `deno
#                                        test` and `timeout -k 30 60s` all falsely refused), because each was
#                                        a narrower parse of a shell command line.
#
# IT FAILS LOUD. This file is sourced, so a syntax error in either config is fatal under
# `set -e`, and a missing CHECK_CMD is an error rather than an empty string. A gate that
# silently substitutes a command nobody chose reports a verdict about the wrong thing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACKED="$ROOT/tools/check.conf"
# agents-bf1f: THE READER'S FIELDS ARE NAMED IN ONE PLACE. The diagnostic below accepts a FIELD argument, and a
# typed copy of the list in its error message would be a repair instruction that names the wrong thing the day a
# field is added or removed - the agents-p8lh defect, where the printed instruction stops matching the code. One
# list, used by the validation AND by the message, with a test that ties it to the dispatch (the reader's plain
# field query) so the two cannot drift apart unnoticed.
# agents-bf1f: THE READER'S FIELDS ARE NAMED IN ONE PLACE EACH FOR THE TWO THINGS THEY DO. A command field holds a
# command whose 126/127 this diagnostic can explain; a bound field holds a timeout, and a timeout cannot exit 127,
# so passing one here was answered with "CHECK_FAST_TIMEOUT exited 127 ... It names [60s (not on PATH)]" - a bound
# accused of being a missing program. Typed copies of either list would be a repair instruction that names the wrong
# thing the day a field changes (the agents-p8lh defect), so both lists live here and the tests derive their names
# back out of the printed message.
CMD_FIELDS="CHECK_CMD CHECK_FAST_CMD"
BOUND_FIELDS="CHECK_TIMEOUT CHECK_FAST_TIMEOUT"
FIELDS="$CMD_FIELDS $BOUND_FIELDS"
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

# agents-0r1c, THIRD SHAPE - DO NOT REFUSE ON A PREDICTION; DIAGNOSE AFTER AN OBSERVED FAILURE.
# (Ruling by coord, 2026-10-14T00:45Z, after three rounds of this guard failed in review: round one MISSED
# `bash ./tools/fast-gate.sh` and OVER-REFUSED an output redirection; round two replaced the rule and
# OVER-REFUSED again twice - `deno test`, where the interpreter rule read deno's SUBCOMMAND as a script path,
# and `timeout -k 30 60s`, where the wrapper rule walked into the option's own argument and named the
# duration. Every round was a narrower PARSE OF A SHELL COMMAND LINE, and every round the parser was wrong
# about a construct it had not anticipated. That is a parser guessing at a property it cannot see, and the two
# error directions are not equal: A FALSE REFUSAL BREAKS A WORKING GATE, while a MISS only fails to explain a
# 127 that was going to happen anyway.)
#
# So this file no longer refuses anything. It ships a DIAGNOSTIC that a runner may call AFTER the command has
# already failed by itself, and it speaks only when the failure is command-not-found class. What it then says
# is what is actually known: the config's own '# Project:' stamp (who installed it), the tokens the command
# names that do not resolve here, and the one-line repair. An observed fact cannot false-refuse anything.
#
# THE EXTRACTOR IS DELIBERATELY DUMB NOW, BECAUSE IT DECIDES NOTHING: the first word (after leading VAR=
# assignments) if it does not resolve on PATH, and every token containing a slash that does not exist here.
# A wrong name can only make an explanation of an already-observed failure less precise - it cannot refuse a
# gate - which is exactly the property the parser could not have. No wrappers, no interpreter rules, no flag
# semantics: those were the three sources of false refusals, and none of them is needed to explain a 127.
command_tokens() {
  # stdin: a command string. stdout: the first word, plus every word containing a slash.
  awk '
    {
      n = split($0, w, /[ \t]+/)
      first = ""
      for (i = 1; i <= n; i++) {
        t = w[i]
        gsub(/^["\047]+/, "", t); gsub(/["\047]+$/, "", t)
        if (t == "") continue
        if (first == "") first = t
        if (t ~ /\//) print t
      }
      if (first !~ /\//) print first
    }'
}

# Prints the repo/path this config says it was installed by, or empty when it carries no stamp.
config_provenance() {
  [ -r "$1" ] || return 0
  grep -m1 -E '^# Project: ' "$1" 2>/dev/null | sed -E 's/^# Project: //' || true
}

# agents-bf1f: EXACT MEMBERSHIP, NOT A SUBSTRING TEST. The first version of this fix validated the field with
# `case " $CMD_FIELDS " in *" $field "*)`, which MATCHED a multi-token argument: " CHECK_CMD CHECK_FAST_CMD " is a
# literal substring of " CHECK_CMD CHECK_FAST_CMD CHECK_TIMEOUT ...", so the argument passed validation, reached
# ${!field}, and bash died with 'line 148: CHECK_CMD CHECK_FAST_CMD: invalid variable name', exit 1 - the same
# broken contract, one door over, because the shape of the field was bounded but not its EXTENT. The field must
# EQUAL one of the declared names.
field_in() {
  local want="$1" f
  for f in $2; do [ "$f" = "$want" ] && return 0; done
  return 1
}

# THE POST-FAILURE DIAGNOSTIC. $1 = the exit code the runner OBSERVED, $2 = the field (default CHECK_CMD).
# Prints nothing at all unless the code is command-not-found class, so it is safe for a runner to call
# unconditionally after every run, and it never changes the verdict - the gate has already failed or passed.
explain_failure() {
  local rc="${1:-}" field="${2:-CHECK_CMD}" cmd tok missing="" who
  case "$rc" in 126|127) ;; *) return 0 ;; esac          # 127 command not found, 126 found but not executable
  # agents-bf1f: THE FIELD NAME IS VALIDATED BEFORE IT IS EXPANDED INDIRECTLY, because bash rejects a malformed
  # NAME before any default can apply: `--explain-failure 127 "not a field"` died with "invalid variable name" and
  # exit 1, breaking this diagnostic's own contract ("always exit 0, so a runner may call it unconditionally after
  # any run") for a CALLER-side typo, and `${!field-}` does not help - the name is the problem, not the value.
  # A tool is allowed to be loud about its OWN misuse while staying silent about gates, which is why this prints a
  # usage line rather than nothing: silence here would leave a runner believing it had asked a valid question.
  if field_in "$field" "$CMD_FIELDS"; then
    :
  elif field_in "$field" "$BOUND_FIELDS"; then
    printf 'check-cmd: --explain-failure: %s is a BOUND, not a command, so a 126/127 cannot be about it. Pass one of %s. Nothing was explained, and this is not a verdict about any gate.\n' "$field" "$CMD_FIELDS" >&2
    return 0
  else
    printf 'check-cmd: --explain-failure: unknown field %s; expected one of %s. Nothing was explained, and this is not a verdict about any gate.\n' \
      "${field:-<empty>}" "$CMD_FIELDS" >&2
    return 0
  fi
  cmd="${!field:-}"
  [ -n "$cmd" ] || return 0
  for tok in $(printf '%s\n' "$cmd" | command_tokens | sort -u); do
    tok="${tok#./}"
    case "$tok" in
      ".") continue ;;
      /*)  [ -e "$tok" ]      || missing="${missing}${missing:+, }$tok" ;;
      */*) [ -e "$ROOT/$tok" ] || missing="${missing}${missing:+, }$tok" ;;
      *)   command -v "$tok" >/dev/null 2>&1 || missing="${missing}${missing:+, }$tok (not on PATH)" ;;
    esac
  done
  if [ -n "$provenance" ]; then who="was installed by $provenance"; else who="carries no 'Project:' stamp"; fi
  echo "check-cmd: NOTE (agents-0r1c): $field exited $rc, and $CONFIG_SOURCE $who." >&2
  if [ -n "$missing" ]; then
    echo "check-cmd:   It names [$missing]; those do not resolve in $ROOT, which is what a foreign config looks like from here." >&2
  else
    echo "check-cmd:   Every token it names does resolve in $ROOT, so the $rc came from something this diagnostic cannot name - do not read this as the config being innocent." >&2
  fi
  if [ -n "$REPO_CONF" ]; then
    echo "check-cmd:   repair: $(install_cmd_for "$REPO_CONF")   # writes this repo its own config, $REPO_CONF; then point the gate at it: FLEET_CHECK_CONF=$REPO_CONF" >&2
  else
    echo "check-cmd:   repair: $(install_cmd_for "$GLOBAL_CONF")   # HOME is unset, so the host-wide file is the only destination this reader can name" >&2
  fi
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

# agents-0r1c, THIRD SHAPE: THE READER NO LONGER REFUSES ANYTHING (coord ruling, 2026-10-14T00:45Z). agents-0utp
# fixed the WRITER (a bare --install no longer rewrites the machine-global file) and agents-p8lh made the
# repairs it prints truthful, but a config already installed by another repo keeps being READ: the live
# ~/.fleet/check.conf carries `bash tools/fast-gate.sh` and a suite command needing tools/ and tests/, all of
# which exist only in agents-factory, so a gate in any other repo died with EXIT 127 - a message about a MISSING
# TOOL when the truth is a FOREIGN CONFIG. THREE attempts to refuse that READ-time, at hand-out time, on a
# prediction, failed in review (a missed ./ prefix; then an output redirection, `deno test`, and
# `timeout -k 30 60s` all falsely refused), because each was a narrower parse of a shell command line and the
# parser was always wrong about some construct it had not anticipated. A false refusal breaks a WORKING gate;
# a miss only fails to explain a 127 that was going to happen anyway. So the diagnostic moved to where the
# evidence is: explain_failure() above, called by whatever RUNNER observed the failure, and it speaks only on a
# command-not-found exit. The attribution comes from the file's own '# Project: <name> (<path>)' stamp, written
# by --install since agents-ia3p, so the note can name the repo that installed the config the reader is being
# asked to trust; an UNSTAMPED file is not attributed to anyone - the note says exactly that rather than
# inventing a culprit.
provenance="$(config_provenance "$OVERRIDE")"
CONFIG_SOURCE="${OVERRIDE:-the tracked file ${TRACKED}}"

want="${1:-}"
case "$want" in
  "")
        # The whole set. Reported, not vetted: a command that cannot run here is still REPORTED, and the
        # runner that observes its 127 is the thing that explains it (explain_failure).
        printf 'CHECK_CMD=%s\nCHECK_FAST_CMD=%s\nCHECK_TIMEOUT=%s\nCHECK_FAST_TIMEOUT=%s\n' \
        "${CHECK_CMD}" "${CHECK_FAST_CMD:-}" "${CHECK_TIMEOUT:-}" "${CHECK_FAST_TIMEOUT:-}" ;;
  CHECK_CMD|CHECK_FAST_CMD)
        printf '%s\n' "${!want}" ;;
  CHECK_TIMEOUT|CHECK_FAST_TIMEOUT)
        printf '%s\n' "${!want}" ;;
  --explain-failure)
        # The runner half of the third shape: `--explain-failure <exit-code> [FIELD]` prints the note (stamp,
        # unresolvable tokens, repair) when the code it is GIVEN is command-not-found class, and nothing
        # otherwise, so a caller can invoke it unconditionally after any run and it cannot change a verdict.
        # It is a diagnostic, not a gate: it always exits 0.
        explain_failure "${2:-}" "${3:-CHECK_CMD}" ;;
  --repair-hint)
        # agents-p8lh: ONE SOURCE OF TRUTH FOR THE REPAIR, for callers that must name it without knowing the
        # destination - tools/fast-gate.sh warns about drift at the point of use and used to carry its own
        # copy of this command. It prints the command that writes the file --check would report on for the
        # SAME environment, so a caller cannot name a repair for a file it is not complaining about.
        printf '%s\n' "$(install_cmd_for "$OVERRIDE")" ;;
  *) echo "check-cmd: unknown field '$want'" >&2; exit 2 ;;
esac
