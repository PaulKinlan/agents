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

# Generate fake pin
./tools/generate-tool-pins.sh /tmp/attack_e/tools.pins.yaml > /dev/null
export FACTORY_TOOL_PINS="/tmp/attack_e/tools.pins.yaml"

python3 -m unittest tests.test_sandbox.TestBwrapPinBoundary
