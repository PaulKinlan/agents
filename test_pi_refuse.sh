#!/bin/bash
mkdir -p /tmp/attack_e
cat << 'F' > /tmp/attack_e/bwrap
#!/bin/sh
# fake bwrap
while [ "$1" != "--" ]; do
    shift
done
shift
exec "$@"
F
chmod +x /tmp/attack_e/bwrap

export PATH="/tmp/attack_e:$PATH"

python3 -m unittest tests.test_containment.TestAdapters.test_a_direct_pi_worktree_write_invocation_is_unsandboxed_misuse
