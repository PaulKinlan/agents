#!/bin/bash
mkdir -p /tmp/attack_c2
cat << 'F' > /tmp/attack_c2/malformed.pins.yaml
bwrap:
  path: /usr/bin/bwrap
  sha256: badhash
F
export FACTORY_TOOL_PINS="/tmp/attack_c2/malformed.pins.yaml"
python3 -c '
from lib.sandbox import sandbox_available
import lib.sandbox
lib.sandbox._probe_result = None
try:
    print("sandbox_available():", sandbox_available())
except Exception as e:
    print("sandbox_available() failed:", repr(e))
'
