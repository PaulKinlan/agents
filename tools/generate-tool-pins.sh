#!/usr/bin/env bash
# Generate a host-local tool pins file for the Software Factory (agents-3g6).
#
# agents-7bj made tool pinning FAIL-CLOSED: every trusted host-side tool (bwrap, gh, bd,
# git, semgrep, gitleaks, node, npm, npx) must carry a sha256 pin or a real run is refused.
# bwrap heads the list: it delivers the OS sandbox itself, so an unpinned bwrap makes the
# host read as unable to sandbox (agents-28nn). The
# repo `tools.yaml` ships the format with the pins commented out, because a binary's hash
# is host-specific and cannot live in a shared repo. This helper writes the host's actual
# pins to a host-local file that the factory reads via the FACTORY_TOOL_PINS env var (which
# is merged OVER tools.yaml by lib/tool_pins.load_tool_pins).
#
# Usage:
#   tools/generate-tool-pins.sh [OUT] [--lookup-path DIRS]
#   export FACTORY_TOOL_PINS="$HOME/.config/factory/tools.pins.yaml"
#
# THE LOOKUP NEVER TRUSTS THE INHERITED PATH (agents-28nn round 2, review P1). The hash
# this script writes IS the vouch for the binary, so locating binaries with `command -v`
# across the operator/runner PATH would let an earlier CI step plant a fake tool (one
# `$GITHUB_PATH` line) and have this script HASH AND PIN THE FAKE — the attacker then
# supplies both the binary and the hash that vouches for it. The lookup therefore runs
# under a FIXED PATH of the standard system bin dirs (below), which an earlier workflow
# step cannot redirect through PATH manipulation, and this script's OWN PATH is set to it
# before anything runs — so the hasher (sha256sum/shasum) and every other command are
# also immune to a planted namesake. A tool that exists only elsewhere (homebrew on
# macOS, nvm, ~/.local/bin) is reported NOT FOUND rather than trusted from an
# attacker-writable location; the operator passes those dirs EXPLICITLY via
# --lookup-path. The override is a command-line flag — never an inherited environment
# variable — because $GITHUB_ENV would let an earlier CI step set the variable and
# reopen the hole, while the invocation itself lives in the pinned action.yml.
#
# A tool that is not installed (e.g. the optional semgrep/gitleaks pre-pass scanners, or
# bwrap on a host that never sandboxes) is skipped with a comment: the factory only fails
# closed for a tool it actually resolves, so an absent tool stays absent rather than
# blocking the run.
#
# This is an explicit operator/runner step, never auto-run by the factory — the factory does
# not generate or relax pins on its own.
set -euo pipefail

# The known-safe lookup dirs: the standard system bin dirs, which an earlier CI step
# cannot reach through PATH manipulation ($GITHUB_PATH only PREPENDS directories; it
# cannot change what these directories contain).
SYSTEM_LOOKUP_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PIN_LOOKUP_PATH="$SYSTEM_LOOKUP_PATH"
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --lookup-path)
      [ $# -ge 2 ] || { echo "error: --lookup-path needs a colon-separated directory list" >&2; exit 2; }
      # Operator dirs are PREPENDED to the system dirs, never a replacement: the script's
      # own plumbing (mkdir/dirname/date/awk and the hasher) must keep resolving from the
      # system dirs, or the override would hand the hasher to the operator dir.
      PIN_LOOKUP_PATH="$2:$SYSTEM_LOOKUP_PATH"; shift 2 ;;
    --lookup-path=*)
      PIN_LOOKUP_PATH="${1#--lookup-path=}:$SYSTEM_LOOKUP_PATH"; shift ;;
    -*)
      echo "error: unknown flag $1" >&2; exit 2 ;;
    *)
      [ -z "$OUT" ] || { echo "error: unexpected extra argument $1" >&2; exit 2; }
      OUT="$1"; shift ;;
  esac
done
OUT="${OUT:-${HOME}/.config/factory/tools.pins.yaml}"

# From here on EVERY command this script runs — the `command -v` lookups AND the hasher
# AND date/mkdir/dirname/awk — resolves only from the lookup dirs, so a PATH-planted
# namesake can neither be pinned nor feed the pin.
PATH="$PIN_LOOKUP_PATH"

TOOLS="bwrap gh bd git semgrep gitleaks node npm npx"

mkdir -p "$(dirname "$OUT")"
{
  echo "# Host-local Software Factory tool pins (agents-3g6)."
  echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ); consumed via FACTORY_TOOL_PINS (merged over tools.yaml)."
  echo "# Regenerate after any tool upgrade: tools/generate-tool-pins.sh"
  echo "# Lookup confined to: $PIN_LOOKUP_PATH (an inherited PATH is never trusted; agents-28nn round 2)"
  for tool in $TOOLS; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    if [ -z "$path" ]; then
      echo "# $tool: not found in the pinned lookup dirs — no pin"
      continue
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      hash="$(sha256sum "$path" | awk '{print $1}')"
    else
      hash="$(shasum -a 256 "$path" | awk '{print $1}')"
    fi
    echo "$tool:"
    echo "  path: $path"
    echo "  sha256: $hash"
  done
} > "$OUT"
echo "Wrote tool pins to $OUT (lookup confined to: $PIN_LOOKUP_PATH)"
echo "Export it: export FACTORY_TOOL_PINS=\"$OUT\""
