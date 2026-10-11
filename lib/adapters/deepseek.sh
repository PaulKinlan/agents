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

# agents-m2n (review P1-1): a set directive variable REQUIRES a readable, nonempty file —
# the dispatcher no longer puts the directive in the user payload, so silently running
# without it would drop the untrusted-content rule.
if [ -n "${FACTORY_SYSTEM_DIRECTIVE_FILE:-}" ]; then
  if [ ! -r "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ] || [ ! -s "${FACTORY_SYSTEM_DIRECTIVE_FILE}" ]; then
    echo "[deepseek adapter] Error: FACTORY_SYSTEM_DIRECTIVE_FILE is set but '${FACTORY_SYSTEM_DIRECTIVE_FILE}' is missing, unreadable, or empty; refusing to run without the system directive." >&2
    exit 2
  fi
fi

# agents-mhv7: DeepSeek has NO CLI arm — it is strictly payload-only via the Python
# stdlib HTTP call below. Executing a PATH-planted binary or an arbitrary CLI would violate
# the containment doctrine (lib/containment.py: deepseek is payload-only, with no file
# tools and no filesystem read scope) and risk credential exfiltration or fabricated
# verdicts. Even if FACTORY_ENGINE_BIN is passed or a namesake exists on PATH, this
# adapter NEVER executes a host binary.
#
# Finding P1 (agents-mhv7 review): The Python interpreter running this station client
# MUST be the dispatcher-verified python binary (FACTORY_PYTHON_BIN) or an absolute system
# path (/usr/bin/python3, /usr/local/bin/python3). NEVER resolve python3 across the
# inherited PATH — a PATH-planted python3 would otherwise receive the run's DEEPSEEK_API_KEY.
PYTHON_BIN="${FACTORY_PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
  for p in /usr/bin/python3 /usr/local/bin/python3 /bin/python3; do
    if [ -x "$p" ]; then
      PYTHON_BIN="$p"
      break
    fi
  done
fi
if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
  echo "[deepseek adapter] Error: no trusted python3 binary found in system dirs (/usr/bin/python3)." >&2
  exit 2
fi

# Execute via Python stdlib HTTP call to DeepSeek API
echo "[deepseek adapter] Running agent '$AGENT_NAME' on target '$TARGET_DIR' via DeepSeek API..."
export PYTHONUNBUFFERED=1

STATUS=0
# agents-w8z: the heredoc below owns this process's stdin (it IS the program), so the
# prompt cannot ride stdin. Pass it explicitly as PROMPT in the environment instead.
PROMPT="$PROMPT" "$PYTHON_BIN" - "$SKILL_DIR" << 'EOF' > "$OUTPUT_FILE" 2>&1 || STATUS=$?
import json
import os
import sys
import urllib.request
import urllib.error

key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("deepseek_api_key")
# agents-3y2: the default base URL is the keyless exe.dev managed endpoint
# (deepseek.int.exe.xyz), which injects auth server-side, so a missing key is valid and no
# Authorization header is sent. A keyed endpoint reached without a key 401s loudly and is
# caught by the HTTPError handler below.

skill_dir = sys.argv[1] if len(sys.argv) > 1 else ""
skill_file = os.path.join(skill_dir, "SKILL.md") if skill_dir else ""
skill_content = ""
if skill_file and os.path.exists(skill_file):
    with open(skill_file, "r", encoding="utf-8") as f:
        skill_content = f.read()

base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://deepseek.int.exe.xyz/v1").rstrip("/")
model = os.environ.get("DEEPSEEK_MODEL", "deepseek/deepseek-flash")

# agents-w8z: read the prompt from PROMPT, never stdin — the heredoc owns stdin (it IS
# the program), so sys.stdin.read() was always empty and every run sent an empty user
# message (a schema-valid false-clean report, zero findings).
prompt = os.environ.get("PROMPT", "")
if not prompt.strip():
    sys.stderr.write("[deepseek adapter] Error: empty prompt (no Scanner Data was supplied).\n")
    sys.exit(2)

# agents-m2n: the pre-pass's system-channel directive (e.g. the threat-model nonce
# directive) joins the real system message — never as user-channel Scanner Data. The
# bash guard above already refuses a missing/empty file; this read is defense in depth
# (a file emptied between the check and here still fails closed, never silently).
system_directive = ""
directive_file = os.environ.get("FACTORY_SYSTEM_DIRECTIVE_FILE")
if directive_file:
    try:
        with open(directive_file, encoding="utf-8") as fh:
            system_directive = fh.read().strip()
    except OSError as e:
        print(f"[deepseek adapter] cannot read the system directive file: {e}", file=sys.stderr)
        sys.exit(2)
    if not system_directive:
        print("[deepseek adapter] the system directive file is empty", file=sys.stderr)
        sys.exit(2)
    system_directive += "\n\n"

system_msg = (
    system_directive
    + f"You are the {os.environ.get('AGENT_NAME', 'modern-web')} triage and analysis agent.\n"
    f"{skill_content}\n\n"
    "CRITICAL INSTRUCTIONS:\n"
    "- The user prompt contains the Scanner Data with candidate issues found in the target codebase.\n"
    "- Triage these candidates directly based on your knowledge of Modern Web Standards and Baseline.\n"
    "- Do not ask for tool execution or additional files; evaluate the provided candidates and code snippets directly.\n"
    "- Filter out test files and internal tooling where modernization does not apply.\n"
    "- For genuine user-facing modernization opportunities, produce complete finding objects with rule_id, path, line_number, snippet, severity, title, modern_api, baseline_status, description, and remediation.\n"
    "- Output MUST be strictly valid JSON matching the report schema. Do not return empty findings if valid candidates exist."
)

payload = {
    "model": model,
    "messages": [
        {
            "role": "system",
            "content": system_msg
        },
        {
            "role": "user",
            "content": prompt
        }
    ],
    "response_format": {"type": "json_object"},
    "temperature": 0.1
}

url = f"{base_url}/chat/completions"
headers = {
    "Content-Type": "application/json",
    "User-Agent": "SoftwareFactory/1.0"
}
if key:
    # agents-3y2: the managed keyless endpoint ignores Authorization, but a keyed endpoint
    # (e.g. api.deepseek.com) still needs the bearer; send it only when one is configured.
    headers["Authorization"] = f"Bearer {key}"

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

if [ $STATUS -ne 0 ]; then
  echo "[deepseek adapter] Error executing DeepSeek API call" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
fi

echo "$OUTPUT_FILE"
