#!/usr/bin/env bash
# The Software Factory — Universal Installer (install.sh)
#
# Usage:
#   One-liner remote install (all 22 skills + `factory` CLI):
#     curl -fsSL https://raw.githubusercontent.com/PaulKinlan/agents/main/install.sh | bash
#
#   Install a specific skill only:
#     curl -fsSL https://raw.githubusercontent.com/PaulKinlan/agents/main/install.sh | bash -s -- --skill modern-web
#
#   Local install from repo checkout:
#     ./install.sh [--skill <name>] [--dir <install_dir>] [--with-hooks]

set -euo pipefail

REPO_URL="${SF_REPO_URL:-https://github.com/PaulKinlan/agents.git}"
DEFAULT_INSTALL_DIR="${SF_INSTALL_DIR:-$HOME/agents}"
SKILL_FILTER=""
INSTALL_HOOKS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skill|-s)
      SKILL_FILTER="${2:-}"
      shift 2
      ;;
    --dir|-d)
      DEFAULT_INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --with-hooks)
      INSTALL_HOOKS="true"
      shift
      ;;
    --help|-h)
      cat <<EOF
The Software Factory — Universal Installer

Usage:
  ./install.sh [options]
  curl -fsSL https://raw.githubusercontent.com/PaulKinlan/agents/main/install.sh | bash [-s -- options]

Options:
  -s, --skill <name>   Install only a specific station skill (e.g. modern-web, secret-scan)
  -d, --dir <path>     Directory to clone/update the factory into (default: ~/agents)
  --with-hooks         Also install deterministic pre-commit hooks across configured targets
  -h, --help           Show this help message
EOF
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

# Determine source directory: if running from inside a checkout, use it directly
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
if [[ -f "$SCRIPT_DIR/factory" && -d "$SCRIPT_DIR/agents" ]]; then
  FACTORY_DIR="$SCRIPT_DIR"
else
  FACTORY_DIR="$DEFAULT_INSTALL_DIR"
  if [[ -d "$FACTORY_DIR/.git" ]]; then
    echo "↻ Updating existing Software Factory checkout in $FACTORY_DIR..."
    # agents-yow5: A FAILED UPDATE MUST NOT LOOK LIKE A SUCCESSFUL INSTALL. This was
    # `|| true`, so a VM whose pull failed installed skills from a checkout of unknown age,
    # printed its success lines and EXITED 0 - and the caller (remote/provision.sh:970) runs
    # this installer with ALL OUTPUT SUPPRESSED, so the exit code is the only signal that
    # survives it. The factory tracks main deliberately (no pin), which is precisely why the
    # update failing has to be visible: otherwise the nightly runs against a station set of
    # unknown age while every health check still passes.
    if ! git -C "$FACTORY_DIR" pull --ff-only --quiet; then
      stale="$(git -C "$FACTORY_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
      {
        echo "✗ install.sh: could not update the Software Factory checkout in $FACTORY_DIR"
        echo "  'git pull --ff-only' failed, so this run would install station skills from a"
        echo "  stale checkout (currently at $stale). Resolve the checkout or the network and"
        echo "  re-run; nothing was installed from it (agents-yow5)."
      } >&2
      exit 1
    fi
  else
    echo "⬇ Cloning Software Factory from $REPO_URL into $FACTORY_DIR..."
    git clone --depth 1 "$REPO_URL" "$FACTORY_DIR"
  fi
fi

AGENTS_SRC="$FACTORY_DIR/agents"

# Discover and link into all supported agent skill hubs on the machine:
# - ~/.pi/agent/skills        (pi coding agent)
# - ~/.claude/skills          (Claude Code)
# - ~/.agents/skills          (skills.sh / Codex / OpenCode / universal hub)
# - ~/.gemini/config/plugins  (Antigravity / Gemini CLI)

link_skills_into_hub() {
  local label="$1"
  local hub_dir="$2"
  mkdir -p "$hub_dir"
  local count=0

  for skill_path in "$AGENTS_SRC"/*; do
    [[ -d "$skill_path" && -f "$skill_path/SKILL.md" ]] || continue
    local skill_name
    skill_name="$(basename "$skill_path")"
    if [[ -n "$SKILL_FILTER" && "$skill_name" != "$SKILL_FILTER" ]]; then
      continue
    fi
    ln -sfn "$skill_path" "$hub_dir/$skill_name"
    count=$((count + 1))
  done
  echo "  ✓ $label: linked $count skill(s) -> $hub_dir"
}

echo "🔧 Installing Software Factory skills from $FACTORY_DIR..."
link_skills_into_hub "pi (~/.pi/agent/skills)" "$HOME/.pi/agent/skills"
link_skills_into_hub "Claude (~/.claude/skills)" "$HOME/.claude/skills"
link_skills_into_hub "Universal (~/.agents/skills)" "$HOME/.agents/skills"

# Gemini / Antigravity plugin folder
GEMINI_PLUGIN_DIR="$HOME/.gemini/config/plugins/software-factory-plugin"
mkdir -p "$GEMINI_PLUGIN_DIR"
ln -sfn "$AGENTS_SRC" "$GEMINI_PLUGIN_DIR/skills"
echo "  ✓ Gemini/Antigravity: linked plugin -> $GEMINI_PLUGIN_DIR/skills"

# Symlink `factory` binary into ~/.local/bin if writable
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
ln -sfn "$FACTORY_DIR/factory" "$LOCAL_BIN/factory"
echo "  ✓ CLI binary: linked -> $LOCAL_BIN/factory"

# Gate configuration (agents-l2xb): THIS IS THE CALLER THE TRACKED CONFIG WAS MISSING.
# The DEPLOYED gate on a fleet VM is ~/fleet/bin/fleet-check, and it reads the per-VM
# ~/.fleet/check.conf ONLY: it has no project-local lookup, and this repo has neither a
# deno.json nor a package.json, so with no per-VM file it refuses outright (rc 2) rather
# than falling back to a wrong command. The TRACKED tools/check.conf therefore reaches the
# deployed gate through this one step - the tracked file is the SOURCE, the per-VM file is
# the copy the gate reads. Without it a fresh VM, and a VM whose per-VM copy has gone
# stale, have no gate command for this project at all while every tracked file says the
# gate is configured. --install resolves the tracked file, repairs a stale or malformed
# per-VM file (agents-r1o7), and warns rather than silently clobbering another project's
# config on a shared HOME (agents-f6no).
if [[ -f "$FACTORY_DIR/tools/check-cmd.sh" ]]; then
  # agents-d081: SHOW THE DRIFT BEFORE REPAIRING IT, and check that the repair landed. Until this,
  # the replacement above was SILENT - a host that had been running a different gate command for
  # days learned nothing when provisioning finally fixed it (measured 2026-10-12 on a fleet VM: the
  # per-VM copy predated the tracked file, so its CHECK_CMD carried no summary/tee wrapper and
  # CHECK_FAST_TIMEOUT was 360 against the tracked 180, while every gate on the host reported PASS).
  # --check exits 0 in sync, 1 on drift and 3 when nothing is installed, and prints the differing
  # keys with both values. A non-zero here is NOT an error - provisioning is the repair - so it is
  # reported and the install continues.
  if ! drift_report="$(bash "$FACTORY_DIR/tools/check-cmd.sh" --check 2>&1)"; then
    echo "  ! this host's gate command config did not match the tracked one; provisioning is replacing it:"
    printf '%s\n' "$drift_report" | sed 's/^/    /'
  fi
  bash "$FACTORY_DIR/tools/check-cmd.sh" --install
  # The post-install half is stronger than the pre-install half: it catches the failure mode where
  # the installer believes it wrote the config but the host did not keep it (a read-only or
  # wrong-HOME destination), which previously would have been reported as a successful install.
  if ! post_report="$(bash "$FACTORY_DIR/tools/check-cmd.sh" --check 2>&1)"; then
    echo "  ! WARNING: after installing, the per-VM gate config STILL differs from the tracked one -"
    printf '%s\n' "$post_report" | sed 's/^/    /'
  fi
else
  echo "  ! no gate configuration: $FACTORY_DIR/tools/check-cmd.sh is absent, so the deployed gate's config is left untouched"
fi

if [[ "$INSTALL_HOOKS" == "true" ]]; then
  "$FACTORY_DIR/factory" hook install --all
fi

echo ""
echo "✨ Done! Software Factory skills are ready in pi, Claude, Antigravity, and ~/.agents/skills."
