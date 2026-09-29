#!/usr/bin/env bash
set -euo pipefail

# DeepSeek adapter for Software Factory
# Usage: deepseek.sh <agent_name> <target_dir> <skill_dir> <run_dir>

AGENT_NAME="${1}"
TARGET_DIR="${2}"
SKILL_DIR="${3}"
RUN_DIR="${4}"

TOOL_POLICY="${FACTORY_TOOL_POLICY:-read-only}"
case "$TOOL_POLICY" in
  read-only) ;;
  *)
    echo "[deepseek adapter] Refusing: tool policy '$TOOL_POLICY' cannot be enforced by this adapter." >&2
    exit 3
    ;;
esac

if [ -t 0 ]; then
  echo "[deepseek adapter] Error: prompt expected on stdin." >&2
  exit 2
fi
PROMPT="$(cat)"
if [ -z "$PROMPT" ]; then
  echo "[deepseek adapter] Error: empty prompt on stdin." >&2
  exit 2
fi

mkdir -p "$RUN_DIR"
OUTPUT_FILE="$RUN_DIR/model_output.txt"

# If a stub 'deepseek' binary is in PATH (e.g. during containment unit tests), invoke it
if command -v deepseek >/dev/null 2>&1; then
  echo "$PROMPT" | deepseek "$@" > "$OUTPUT_FILE" 2>&1 || exit $?
  echo "$OUTPUT_FILE"
  exit 0
fi

# Execute via Python stdlib HTTP call to DeepSeek API
echo "[deepseek adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR' via DeepSeek API..."
export PYTHONUNBUFFERED=1

python3 - << 'EOF' > "$OUTPUT_FILE" 2>&1 || {
  echo "[deepseek adapter] Error executing DeepSeek API call" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
}
import json
import os
import sys
import urllib.request
import urllib.error

key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("deepseek_api_key")
if not key:
    sys.stderr.write("[deepseek adapter] Error: DEEPSEEK_API_KEY is not configured.\n")
    sys.exit(1)

base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
model = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
if model in ("deepseek-flash", "deepseek-v3"):
    model = "deepseek-chat"

# Read prompt from stdin
prompt = sys.stdin.read()

payload = {
    "model": model,
    "messages": [
        {
            "role": "system",
            "content": "You are a software analysis and triage agent. You must output strictly valid JSON matching the report schema requested."
        },
        {
            "role": "user",
            "content": prompt
        }
    ],
    "temperature": 0.1
}

url = f"{base_url}/chat/completions"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {key}",
    "User-Agent": "SoftwareFactory/1.0"
}

req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")

try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        print(res_data["choices"][0]["message"]["content"])
except urllib.error.HTTPError as e:
    err_body = e.read().decode("utf-8")
    sys.stderr.write(f"DeepSeek API HTTPError {e.code}: {err_body}\n")
    sys.exit(1)
except Exception as e:
    sys.stderr.write(f"DeepSeek API Request Error: {e}\n")
    sys.exit(1)
EOF

echo "$OUTPUT_FILE"
