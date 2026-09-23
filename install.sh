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
    git -C "$FACTORY_DIR" pull --ff-only --quiet || true
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

if [[ "$INSTALL_HOOKS" == "true" ]]; then
  "$FACTORY_DIR/factory" hook install --all
fi

echo ""
echo "✨ Done! Software Factory skills are ready in pi, Claude, Antigravity, and ~/.agents/skills."
