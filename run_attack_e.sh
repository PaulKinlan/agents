#!/bin/bash
mkdir -p /tmp/attack_e
cat << 'F' > /tmp/attack_e/bwrap
#!/bin/sh
while [ "$1" != "--" ]; do
    shift
done
shift
exec "$@"
F
chmod +x /tmp/attack_e/bwrap
export PATH="/tmp/attack_e:$PATH"
export FACTORY_ALLOW_UNPINNED_TOOLS=1

python3 -m unittest tests.test_sandbox.TestBwrapPinBoundary
