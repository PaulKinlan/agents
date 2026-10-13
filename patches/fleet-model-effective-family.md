## `fleet-model-effective-family.patch` (agents-kq0r)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-model-audit` — gains `family <lane>` query (and `lane <lane> --family` alias) to establish
    what model family a lane actually ran, distinguishing observed turn records (`turns.jsonl`) and
    host fallback records (`events.log`) from mutable pointer files (`.model`), with strict exit-code
    precedence (MISMATCH [1] > UNKNOWN [3] > MATCH [0]).
  - `remote/pick-model.sh` — derives the observed-fallback set dynamically from
    `ℹ runtime model fell back: <requested> -> <effective>` lines in `~/.fleet/lanes/*.events.log`,
    and skips handing out requested models that have been observed to fall back, logging skips to stderr.
  - `tests/fleet-model-audit.test.sh` — Section 11 added, with 14 new assertions (11a–11n) covering single-turn,
    multi-turn, agreeing fallback, contradicting fallback, events-only fallback, pointer-only refusal,
    missing records, and usage error.
  - `tests/pick-model-crossfamily.test.sh` — Section 7 added, verifying that `pick-model.sh` skips models
    observed to fall back in `events.log` and logs the skip to stderr.
- **Baseline file hashes:**
  `c623019549cce2dd64b841566c904b779b0e34334d2bc924ea086530d74b1518  bin/fleet-model-audit`
  `ab8fafeff0c6d2a224110f5ac7c5f700ab71a9341e2282e5fbf0c1cd6b095ea8  remote/pick-model.sh`
  `38a235a861f06682cb3cc6f6e24cd68c9c8b7da7fa6c869af67eb540c84748c7  tests/fleet-model-audit.test.sh`
  `ad844d21150fdab530cdfc6a5b37a29af704b0fc68acf0f92ba0e52ba5c6a956  tests/pick-model-crossfamily.test.sh`
- **Patched file hashes:**
  `71674d02b9ef25ef5af10d26a6d54ef14774542e8874d639dc48ca03922c23d8  bin/fleet-model-audit`
  `31c3c195ca7ef50fd0ba513ae3d7111dbca0a4c0172621290acae85c78d70327  remote/pick-model.sh`
  `731a1266e7a73f7e1416d770966b5a228db65893981dd7d901b55d293e76c11b  tests/fleet-model-audit.test.sh`
  `3ed077718c9ad86ca6d4bfe4669cb4426d34c04070ba30a5ace2d40c5ccb3579  tests/pick-model-crossfamily.test.sh`

### Problem statement (agents-kq0r)

The review cadence requires an independent reviewer model family from the author. However, on this VM:
- **23 of 29 lanes** that logged a runtime fallback fell back as:
  `pi-claude-code-provider/sonnet -> deepseek/deepseek-flash`
  because `pi-claude-code-provider` is not registered in the local runtime.
- Two lanes could appear cross-family (one asked for Claude, one asked for DeepSeek), while **both actually ran DeepSeek**.
- `<lane>.model` under `~/.fleet/lanes/` is a mutable pointer rewritten by `run-lane.sh` on lane start with the requested
  model, and rewritten by `sdk-host/host.mjs:118` with the effective model upon fallback. It is neither durable nor an ask record.
- The durable per-turn record of what ran is `<lane>.turns.jsonl` (one JSON object per turn, containing `model`, e.g.
  `{"model":"deepseek/deepseek-flash",...}`). It survives lane retirement (`retire` cleans `.model`, `.conf`, and `.state.json` only).
- When a runtime fallback happens, `sdk-host/host.mjs:117` writes:
  `HH:MM:SS ℹ runtime model fell back: <requested> -> <effective>` to `<lane>.events.log`. Prior to this patch, no tool read this line.
- An a-priori provider check (e.g. querying `~/.pi/agent/models-store.json`) is measured **wrong** here: `models-store.json` does
  not list `antigravity`, yet antigravity models execute successfully. Learning from runtime observation is the only truthful authority.

### Established Mechanism & Rules

1. **Never use the requested model or pointer as proof of what ran.** A lane with only pointer or ask evidence reports `UNKNOWN` (exit 3), never a match.
2. **Always identify the evidence source.** Output states whether the answer came from `turns.jsonl`, `events.log`, `turns.jsonl and events.log`, or `pointer-only`.
3. **Contradictions are findings, not notes.** If `turns.jsonl`'s most recent turn disagrees with `events.log`'s fallback, that is a `MISMATCH` (exit 1).
4. **Precedence:** `MISMATCH (1) > UNKNOWN (3) > MATCH (0)`.
5. **Observation-based skipping:** `remote/pick-model.sh` inspects `~/.fleet/lanes/*.events.log` for runtime fallbacks and skips handing out models that have demonstrated fallback, avoiding silent same-family collisions at spawn time.

### Changes

- `bin/fleet-model-audit:31-36`: USAGE updated to document `fleet-model-audit family <lane-name>`.
- `bin/fleet-model-audit:509-601`: `lane_family()` implemented. Validates encoding via `trust_bytes`, extracts the last turn model from `turns.jsonl` with `turn_model` and `dup_keys`, extracts the last runtime fallback from `events.log`, and reconciles:
  - Both present and agreeing: `MATCH family <fam> (lane <lane> ran <model>, source: turns.jsonl and events.log)` (exit 0).
  - Both present and disagreeing: `note_mis` -> `MISMATCH` (exit 1).
  - Turns only: `MATCH family <fam> (lane <lane> ran <model>, source: turns.jsonl)` (exit 0).
  - Fallback events only (e.g. lane retired or 0 turns completed): `MATCH family <fam> (lane <lane> fell back to <model>, source: events.log)` (exit 0).
  - Pointer only: `note_unk` naming `source: pointer-only` (exit 3).
  - No records: `note_unk` (exit 3).
- `bin/fleet-model-audit:619-635`: Dispatches `family <lane>` and `lane <lane> --family`.
- `remote/pick-model.sh:17-48`: `observed_fallback()` scans `*.events.log` for `ℹ runtime model fell back: <req> -> <eff>` lines; `skip_observed_fallback()` logs skips to stderr once per model; `is_healthy()` skips models in the observed-fallback set.
- `remote/pick-model.sh:137-147`: `pick_subagent_model()` fail-open avoids handing out models with observed fallbacks.
- `remote/pick-model.sh:264`: Lane rotation loop skips models with observed fallbacks.
- `remote/pick-model.sh:274-284`: Lane rotation fail-open loop skips models with observed fallbacks and falls open to non-fallen-back rotation models if available.

### TESTS

The following hermetic test script demonstrates all new behaviors on temporary fixtures without touching live fleet state:

```bash
#!/usr/bin/env bash
set -u
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/lanes" "$ROOT/bin" "$ROOT/remote" "$ROOT/fleet"
cp bin/fleet-model-audit "$ROOT/bin/fleet-model-audit"
cp remote/pick-model.sh "$ROOT/remote/pick-model.sh"
cp fleet.conf "$ROOT/fleet.conf"

export FLEET_LANES_DIR="$ROOT/lanes"
export FLEET_RUNS_DIR="$ROOT/runs"
export HOME="$ROOT"
export FLEET_VM=test-vm

# 1. Hermetic fixture with two turns on different models + agreeing events.log fallback
cat > "$ROOT/lanes/lane-agree.turns.jsonl" << 'EOF'
{"at":"2026-10-13T00:01:00Z","model":"kimi/k3","host":"sdk"}
{"at":"2026-10-13T00:02:00Z","model":"deepseek/deepseek-flash","host":"sdk"}
EOF
echo "10:00:00 ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash" > "$ROOT/lanes/lane-agree.events.log"

out=$(bash "$ROOT/bin/fleet-model-audit" family lane-agree 2>&1); rc=$?
echo "1. Agreeing fallback: rc=$rc"
echo "   $out"
# Expected: rc=0, MATCH family deepseek (lane lane-agree ran deepseek/deepseek-flash, source: turns.jsonl and events.log)

# 2. Contradiction fixture: last turn deepseek vs fallback to openai-codex
cat > "$ROOT/lanes/lane-disagree.turns.jsonl" << 'EOF'
{"at":"2026-10-13T00:01:00Z","model":"kimi/k3","host":"sdk"}
{"at":"2026-10-13T00:02:00Z","model":"deepseek/deepseek-flash","host":"sdk"}
EOF
echo "10:00:00 ℹ runtime model fell back: pi-claude-code-provider/sonnet -> openai-codex/gpt-6-sol" > "$ROOT/lanes/lane-disagree.events.log"

out=$(bash "$ROOT/bin/fleet-model-audit" family lane-disagree 2>&1); rc=$?
echo "2. Contradicting fallback: rc=$rc"
echo "   $out"
# Expected: rc=1, MISMATCH ... but events.log recorded fallback to openai-codex/gpt-6-sol

# 3. Turns only (two turns on different models, reports last turn):
cat > "$ROOT/lanes/lane-turns.turns.jsonl" << 'EOF'
{"at":"2026-10-13T00:01:00Z","model":"kimi/k3","host":"sdk"}
{"at":"2026-10-13T00:02:00Z","model":"openai-codex/gpt-6-sol","host":"sdk"}
EOF

out=$(bash "$ROOT/bin/fleet-model-audit" family lane-turns 2>&1); rc=$?
echo "3. Turns only: rc=$rc"
echo "   $out"
# Expected: rc=0, MATCH family openai-codex (lane lane-turns ran openai-codex/gpt-6-sol, source: turns.jsonl)

# 4. Pointer-only evidence (refused: requested model is not evidence of what ran)
echo "pi-claude-code-provider/sonnet" > "$ROOT/lanes/lane-ptr.model"

out=$(bash "$ROOT/bin/fleet-model-audit" family lane-ptr 2>&1); rc=$?
echo "4. Pointer only: rc=$rc"
echo "   $out"
# Expected: rc=3, UNKNOWN lane 'lane-ptr' has only pointer evidence (..., source: pointer-only)

# 5. Picker skips models observed to fall back in events.log
cat > "$ROOT/fleet.conf" << 'EOF'
FLEET_MODEL_IMPL="deepseek/deepseek-flash"
FLEET_ROTATION_IMPL="pi-claude-code-provider/sonnet deepseek/deepseek-flash"
FLEET_ROTATION_REVIEWER="pi-claude-code-provider/sonnet deepseek/deepseek-flash"
EOF
echo "10:00:00 ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash" > "$ROOT/lanes/fallback.events.log"
m=$(bash "$ROOT/remote/pick-model.sh" reviewer r2 2>"$ROOT/err_pick")
echo "5. Picker selection: $m"
echo "   Picker stderr: $(cat "$ROOT/err_pick")"
# Expected: $m = deepseek/deepseek-flash, stderr mentions skipping pi-claude-code-provider/sonnet
```

### Verification Against Live Files

Tested in isolated throwaway copies without modifying live files:
1. `tests/fleet-model-audit.test.sh`: **122 passed, 0 failed** (108 baseline tests preserved + 14 new tests 11a–11n).
2. `tests/pick-model-crossfamily.test.sh`: **26 passed, 0 failed** (24 baseline tests preserved + 2 new tests 7a–7b).
3. `tests/quota-horizon.test.sh`: **19 passed, 0 failed**.
4. `tests/subagent-cooldown.test.sh`: **27 passed, 0 failed**.
5. Live lane spot-checks on read-only live lane store (`~/.fleet/lanes/`):
   - `family impl-tdot` -> `MATCH family deepseek (lane impl-tdot ran deepseek/deepseek-flash, source: turns.jsonl and events.log)` (rc=0)
   - `family impl-f6du` -> `MATCH family openai-codex (lane impl-f6du ran openai-codex/gpt-6-sol, source: turns.jsonl)` (rc=0)
   - `family 5qe-opus` (retired lane) -> `MATCH family deepseek (lane 5qe-opus ran deepseek/deepseek-flash, source: turns.jsonl and events.log)` (rc=0)

### Hub Application

```bash
cd ~/fleet
git apply -p1 --check /path/to/patches/fleet-model-effective-family.patch
git apply -p1 /path/to/patches/fleet-model-effective-family.patch
bash tests/fleet-model-audit.test.sh
bash tests/pick-model-crossfamily.test.sh
```
