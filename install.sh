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
    # printed its success lines and EXITED 0. The factory tracks main deliberately (no pin),
    # which is precisely why the update failing has to be visible: otherwise the nightly runs
    # against a station set of unknown age while every health check still passes.
    #
    # WHERE THIS BRANCH IS ACTUALLY REACHED (corrected by agents-rn78 - the original comment here
    # claimed the caller runs the installer with all output suppressed, and that is no longer true:
    # fleet-24zj made provision.sh print, and provision.log is where that output lands). This pull
    # runs for the DOCUMENTED one-liner when the target directory already exists and the script is
    # not itself inside a checkout. IT DOES NOT RUN FOR PROVISIONING: the VM provisioning script pulls
    # ~/agents itself and :995 then invokes this installer from INSIDE the checkout, where the
    # shortcut above takes FACTORY_DIR=$SCRIPT_DIR and no pull happens at all. A reviewer measured
    # exactly that on a clone whose bare origin had been deleted: outside the checkout rc=1 with a
    # class, the way provisioning invokes it rc=0 with none. Provisioning's own pull failure is
    # classified by the provisioning script's pull-failure classifier.
    #   the provision-failed-pull change (bead agents-rn78) (agents-rn78).
    #
    # agents-a1ko: AND IT MUST NAME THE CLASS OF FAILURE, because a bare exit code forces the
    # operator to guess between a transient NETWORK outage and a DIVERGED checkout, and those want
    # OPPOSITE responses (retry later versus investigate the checkout on the host). The class is read
    # from git's own error text, which is MEASURED rather
    # than assumed - all three shapes are driven against real git in
    # tests/test_gate_entrypoint_config.py - and THE THIRD CLASS EXISTS SO AN UNRECOGNISED FAILURE
    # IS REPORTED AS UNRECOGNISED rather than guessed into one of the other two. That matters here
    # specifically: the wording of the local-state case is NOT stable - MEASURED in two runs of the
    # same shape on this VM, git said "error: cannot pull with rebase: You have unstaged changes."
    # under the host's global pull.rebase=true and "error: Your local changes to the following files
    # would be overwritten by merge" with that setting pinned false - so a two-class rule would have
    # to guess on one of them.
    if ! update_error="$(git -C "$FACTORY_DIR" pull --ff-only --quiet 2>&1)"; then
      stale="$(git -C "$FACTORY_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
      failure_class="checkout-local-state"
      failure_action="The checkout has uncommitted changes, or a git config routes the pull through a rebase, so the pull cannot fast-forward. Inspect the checkout on the host; the network is not the problem."
      case "$update_error" in
        # agents-uvzh (found reviewing agents-a1ko): AUTHENTICATION IS NOT A NETWORK OUTAGE, and git's text
        # for the two OVERLAPS - a refused key prints "Permission denied (publickey)." immediately followed by
        # "fatal: Could not read from remote repository." (MEASURED with a real pull against an ssh:// remote
        # and a refusing GIT_SSH_COMMAND stub). So this arm must come FIRST: below the unreachable arm, a
        # wrong credential was reported as transient and the operator would retry a failure that cannot fix
        # itself.
        *"Permission denied"* | *"Authentication failed"* | *"publickey"* | \
        *"could not read Username"* | *"terminal prompts disabled"* | *"Host key verification failed"*)
          failure_class="remote-auth-denied"
          failure_action="The remote was reachable and REFUSED this host - credentials or permissions - which is NOT transient, so retrying cannot fix it. Check what this checkout authenticates with (ssh key or agent, a token in the remote URL) and that the files it writes are writable, then re-run."
          ;;
        *"does not appear to be a git repository"* | *"Could not read from remote repository"* | \
        *"Could not resolve host"* | *"unable to access"* | *"Connection refused"* | \
        *"Connection timed out"* | *"No route to host"* | *"Temporary failure in name resolution"*)
          failure_class="remote-unreachable"
          failure_action="The remote could not be reached, which is usually transient: retrying the pull later is safe and no local state was changed."
          ;;
        *"Not possible to fast-forward"* | *"Diverging branches"* | *"non-fast-forward"*)
          failure_class="checkout-diverged"
          failure_action="The checkout has local commits (or a rewritten history) the remote does not have, so the pull cannot fast-forward. Investigate the checkout on the host; retrying fails the same way."
          ;;
      esac
      {
        echo "✗ install.sh: could not update the Software Factory checkout in $FACTORY_DIR"
        echo "  FAILURE CLASS: $failure_class (agents-a1ko)"
        echo "  $failure_action"
        while IFS= read -r line; do echo "  git: $line"; done <<<"$update_error"
        echo "  The checkout is still at $stale, so this run would have installed station skills"
        echo "  from a stale checkout; nothing was installed from it (agents-yow5)."
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
# The DEPLOYED gate reads the per-VM
# ~/.fleet/check.conf ONLY: it has no project-local lookup, and this repo has neither a
# deno.json nor a package.json, so with no per-VM file it refuses outright (rc 2) rather
# than falling back to a wrong command. The TRACKED tools/check.conf therefore reaches the
# deployed gate through this one step - the tracked file is the SOURCE, the per-VM file is
# the copy the gate reads. Without it a fresh VM, and a VM whose per-VM copy has gone
# stale, have no gate command for this project at all while every tracked file says the
# gate is configured. --install resolves the tracked file, repairs a stale or malformed
# per-VM file (agents-r1o7), and warns rather than silently clobbering another project's
# config on a shared HOME (agents-f6no).
# Check if this VM hosts a different project (e.g. chrome-agent-platform, audio-feed, etc.).
# On shared-HOME hosts for other projects, ~/agents must NOT overwrite the host or project's gate config.
host_proj=$(cat "$HOME/.fleet/project" 2>/dev/null || echo "")
if [[ -f "$FACTORY_DIR/tools/check-cmd.sh" ]]; then
  if [[ -n "$host_proj" && "$host_proj" != "agents" && "$host_proj" != "agents-factory" ]]; then
    # Write only repo-local gate config ($HOME/.fleet/agents-check.conf) and leave project gate untouched
    echo "  • shared-HOME host for '$host_proj': installing repo-local gate config for agents"
    FLEET_CHECK_CONF="" bash "$FACTORY_DIR/tools/check-cmd.sh" --install
  else
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
    # agents-0utp: --install now DEFAULTS TO A REPO-LOCAL destination, so provisioning - whose whole purpose here
    # is to give the MACHINE's deployed gate a command - must ask for the host-wide file EXPLICITLY rather than
    # inheriting it from a default. This line is the one place that claim belongs: an operator/installer writing the
    # shared path on purpose, not a convenience that silently makes every repo on the host read this repo's gate.
    bash "$FACTORY_DIR/tools/check-cmd.sh" --install --global
    # The post-install half is stronger than the pre-install half: it catches the failure mode where
    # the installer believes it wrote the config but the host did not keep it (a read-only or
    # wrong-HOME destination), which previously would have been reported as a successful install.
    if ! post_report="$(bash "$FACTORY_DIR/tools/check-cmd.sh" --check 2>&1)"; then
      echo "  ! WARNING: after installing, the per-VM gate config STILL differs from the tracked one -"
      printf '%s\n' "$post_report" | sed 's/^/    /'
    fi
  fi
else
  echo "  ! no gate configuration: $FACTORY_DIR/tools/check-cmd.sh is absent, so the deployed gate's config is left untouched"
fi

if [[ "$INSTALL_HOOKS" == "true" ]]; then
  "$FACTORY_DIR/factory" hook install --all
fi

echo ""
echo "✨ Done! Software Factory skills are ready in pi, Claude, Antigravity, and ~/.agents/skills."
