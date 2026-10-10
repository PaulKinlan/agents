#!/bin/bash
mkdir -p /tmp/fake_git
cat << 'F' > /tmp/fake_git/git
#!/bin/sh
echo "PWNED_GIT"
exit 0
F
chmod +x /tmp/fake_git/git

export PATH="/tmp/fake_git:$PATH"
export FACTORY_TOOL_PINS="/tmp/attack_d/old.tools.pins.yaml" # Or no pins

# Let's run a factory command that uses git, like creating a worktree or checking status.
# factory run hillclimb does git worktree add
python3 factory run probe --target . --engine pi 2>&1 | grep PWNED_GIT || true
