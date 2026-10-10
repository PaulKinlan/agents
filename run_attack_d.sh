#!/bin/bash
# Test what happens if the deployer doesn't regenerate host pins
# That means tools.pins.yaml is missing or has the wrong bwrap pin (e.g. before bwrap was added).
# Let's say tools.pins.yaml does NOT contain bwrap, because the deployer didn't regenerate it.
mkdir -p /tmp/attack_d
cat << 'F' > /tmp/attack_d/old.tools.pins.yaml
gh:
  path: /usr/bin/gh
  sha256: 1234
F
export FACTORY_TOOL_PINS="/tmp/attack_d/old.tools.pins.yaml"

python3 -c '
from lib.sandbox import sandbox_available
import lib.sandbox
lib.sandbox._probe_result = None
print("Sandbox available (deployer forgot to regen):", sandbox_available())
'

# Now let's see what a normal run does
python3 factory run probe --target . --engine pi 2>&1 | grep -E "Sandbox|sandboxed|Error" || true
