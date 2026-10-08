#!/usr/bin/env bash
# Generate a host-local tool pins file for the Software Factory (agents-3g6).
#
# agents-7bj made tool pinning FAIL-CLOSED: every trusted host-side tool (gh, bd, git,
# semgrep, gitleaks, node, npm, npx) must carry a sha256 pin or a real run is refused. The
# repo `tools.yaml` ships the format with the pins commented out, because a binary's hash is
# host-specific and cannot live in a shared repo. This helper writes the host's actual pins
# to a host-local file that the factory reads via the FACTORY_TOOL_PINS env var (which is
# merged OVER tools.yaml by lib/tool_pins.load_tool_pins).
#
# Usage:
#   tools/generate-tool-pins.sh [OUT]     # default: $HOME/.config/factory/tools.pins.yaml
#   export FACTORY_TOOL_PINS="$HOME/.config/factory/tools.pins.yaml"
#
# A tool that is not installed (e.g. the optional semgrep/gitleaks pre-pass scanners) is
# skipped with a comment: the factory only fails closed for a tool it actually resolves, so
# an absent optional tool stays absent rather than blocking the run.
#
# This is an explicit operator/runner step, never auto-run by the factory — the factory does
# not generate or relax pins on its own.
set -euo pipefail

OUT="${1:-${HOME}/.config/factory/tools.pins.yaml}"
TOOLS="gh bd git semgrep gitleaks node npm npx"

mkdir -p "$(dirname "$OUT")"
{
  echo "# Host-local Software Factory tool pins (agents-3g6)."
  echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ); consumed via FACTORY_TOOL_PINS (merged over tools.yaml)."
  echo "# Regenerate after any tool upgrade: tools/generate-tool-pins.sh"
  for tool in $TOOLS; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    if [ -z "$path" ]; then
      echo "# $tool: not found on PATH (optional pre-pass tool) — no pin"
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
echo "Wrote tool pins to $OUT"
echo "Export it: export FACTORY_TOOL_PINS=\"$OUT\""
