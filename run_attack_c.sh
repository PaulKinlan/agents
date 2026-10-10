#!/bin/bash
# Test 1: pinned-but-missing bwrap
mkdir -p /tmp/attack_c
cat << 'F' > /tmp/attack_c/tools.pins.yaml
bwrap:
  path: /tmp/attack_c/missing-bwrap
  sha256: 0000000000000000000000000000000000000000000000000000000000000000
F
export FACTORY_TOOL_PINS="/tmp/attack_c/tools.pins.yaml"
echo "--- pinned-but-missing bwrap ---"
python3 -c '
from lib.sandbox import sandbox_available
print("sandbox_available():", sandbox_available())
'
python3 -c '
from lib.sandbox import sandbox_command
try:
    sandbox_command(["/bin/true"], target_dir=".", factory_root=".", run_dir=".")
except Exception as e:
    print("sandbox_command() failed:", repr(e))
'

# Test 2: bwrap present but mismatched
echo "test" > /tmp/attack_c/mismatched-bwrap
cat << 'F' > /tmp/attack_c/tools.pins.yaml
bwrap:
  path: /tmp/attack_c/mismatched-bwrap
  sha256: 0000000000000000000000000000000000000000000000000000000000000000
F
echo "--- present but mismatched bwrap ---"
python3 -c '
from lib.sandbox import sandbox_available
# Force probe re-run
import lib.sandbox
lib.sandbox._probe_result = None
print("sandbox_available():", sandbox_available())
'
python3 -c '
from lib.sandbox import sandbox_command
import lib.sandbox
lib.sandbox._probe_result = None
try:
    sandbox_command(["/bin/true"], target_dir=".", factory_root=".", run_dir=".")
except Exception as e:
    print("sandbox_command() failed:", repr(e))
'

# Test 3: unreadable pins file
touch /tmp/attack_c/unreadable.pins.yaml
chmod 000 /tmp/attack_c/unreadable.pins.yaml
export FACTORY_TOOL_PINS="/tmp/attack_c/unreadable.pins.yaml"
echo "--- unreadable pins file ---"
python3 -c '
from lib.sandbox import sandbox_available
import lib.sandbox
lib.sandbox._probe_result = None
try:
    print("sandbox_available():", sandbox_available())
except Exception as e:
    print("sandbox_available() failed:", repr(e))
'
python3 -c '
from lib.sandbox import sandbox_command
import lib.sandbox
lib.sandbox._probe_result = None
try:
    sandbox_command(["/bin/true"], target_dir=".", factory_root=".", run_dir=".")
except Exception as e:
    print("sandbox_command() failed:", repr(e))
'
