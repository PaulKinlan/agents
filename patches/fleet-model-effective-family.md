## `fleet-model-effective-family.patch` (agents-kq0r)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-model-audit` — gains `family <lane>` query (and `lane <lane> --family` alias) to establish
    what model family a lane actually ran, distinguishing observed turn records (`turns.jsonl`) and
    host fallback records (`events.log`) from mutable pointer files (`.model`), with strict exit-code
    precedence (MISMATCH [1] > UNKNOWN [3] > MATCH [0]). Resolves temporal correlation between fallback
    lines and turns so historical fallbacks from prior runs do not falsely contradict newer turns (agents-1to3).
  - `remote/pick-model.sh` — derives the observed-fallback set dynamically from
    `ℹ runtime model fell back: <requested> -> <effective>` lines in `~/.fleet/lanes/*.events.log`,
    and skips handing out requested models that have been observed to fall back, logging skips to stderr.
  - `tests/fleet-model-audit.test.sh` — Section 11 added, with 18 assertions (11a–11r) covering single-turn,
    multi-turn, same-run agreeing fallback, same-run contradicting fallback, historical fallback followed by
    newer turn on different model (reviewer reproducer), stale fallback outside run window, fallback logged
    after last completed turn, events-only fallback, pointer-only refusal, missing records, and usage error.
    All assertion blocks guard with `[ -n "$out" ]` so an empty output fails explicitly rather than passing vacuously.
  - `tests/pick-model-crossfamily.test.sh` — Section 7 added, verifying that `pick-model.sh` skips models
    observed to fall back in `events.log` and logs the skip to stderr.

### APPLIES TO (Live File Content Identity)

**Target chain status:** This patch rides no prerequisite chain; the live files in `/home/exedev/fleet` are pristine and ARE the target, so one hash covers both the pristine baseline and the post-chain target.

Measured directly against live tooling in `/home/exedev/fleet` at **2026-10-13T19:56:52Z**:

```text
c623019549cce2dd64b841566c904b779b0e34334d2bc924ea086530d74b1518  bin/fleet-model-audit
ab8fafeff0c6d2a224110f5ac7c5f700ab71a9341e2282e5fbf0c1cd6b095ea8  remote/pick-model.sh
38a235a861f06682cb3cc6f6e24cd68c9c8b7da7fa6c869af67eb540c84748c7  tests/fleet-model-audit.test.sh
ad844d21150fdab530cdfc6a5b37a29af704b0fc68acf0f92ba0e52ba5c6a956  tests/pick-model-crossfamily.test.sh
```

To verify your tree matches the baseline before applying:
```bash
sha256sum bin/fleet-model-audit remote/pick-model.sh tests/fleet-model-audit.test.sh tests/pick-model-crossfamily.test.sh
```

- **Baseline file hashes (measured at 2026-10-13T19:56:52Z):**
  `c623019549cce2dd64b841566c904b779b0e34334d2bc924ea086530d74b1518  bin/fleet-model-audit`
  `ab8fafeff0c6d2a224110f5ac7c5f700ab71a9341e2282e5fbf0c1cd6b095ea8  remote/pick-model.sh`
  `38a235a861f06682cb3cc6f6e24cd68c9c8b7da7fa6c869af67eb540c84748c7  tests/fleet-model-audit.test.sh`
  `ad844d21150fdab530cdfc6a5b37a29af704b0fc68acf0f92ba0e52ba5c6a956  tests/pick-model-crossfamily.test.sh`
- **Patched file hashes:**
  `39ea56535bd11313185b3b6772c6d25ef347c3798e18c1973afa12cf14e2366c  bin/fleet-model-audit`
  `31c3c195ca7ef50fd0ba513ae3d7111dbca0a4c0172621290acae85c78d70327  remote/pick-model.sh`
  `626ef0f55278b8f7d1c6dd76cc574fe096392cf3344413523fc0d4aba8bb42ae  tests/fleet-model-audit.test.sh`
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

### Finding & Temporal Association (agents-1to3 / agents-31qk)

Verbatim finding from reviewer rev-9lew (VERDICT: FAIL against increment 1, delta cff4d509..ec937c98):
> "bin/fleet-model-audit:541,553 compares last fallback log entry with last turn globally, with no temporal
> association. This defeats reliable effective-family auditing across lane restarts/model changes. Existing tests only
> cover same-run agreement/disagreement.
> REPRODUCED: an old 10:00 deepseek fallback followed by a successful openai-codex turn at 10:05 returns MISMATCH rc=1,
> falsely treating distinct runs as contradictory."

#### Timestamps Used and Run Window Derivation

1. **Timestamps Read:**
   - In `<lane>.events.log`: the line-leading timestamp `HH:MM:SS` on `ℹ runtime model fell back: <req> -> <eff>` lines, written by `sdk-host/host.mjs:88` using `ts()` (`new Date().toISOString().slice(11, 19)`).
   - In `<lane>.turns.jsonl`: the `.at` field on each turn JSON record, written by `sdk-host/host.mjs:148` (`new Date().toISOString()`, e.g. `YYYY-MM-DDTHH:MM:SS.sssZ`), alongside `.wall_s` (turn duration in seconds).

2. **Derivation of the Association:**
   - Fallback and turn completion times are converted to UTC epochs (anchored to the turn record's date, handling midnight boundary wrap-around).
   - If the fallback occurred *after* the last turn completed ($t_{fb} > t_{turn}$), it belongs to a subsequent run that has not completed a turn; it does not govern the completed turn.
   - If an intervening turn completed between $t_{fb}$ and $t_{turn}$ that matched the fallback model while the last turn ran a different model, the fallback was consumed by the earlier turn and the lane subsequently switched models. The fallback is history.
   - Run window slack: $\text{slack} = (t_{turn} - \text{wall\_s}) - t_{fb}$. When a fallback occurs, it is logged at session boot, immediately before turn start. If $\text{slack} > 120\text{s}$ (fallback occurred more than 2 minutes before turn start), the fallback is stale history from an earlier session that did not complete a turn.
   - When models agree, both sources confirm what ran (`MATCH`, exit 0, source: `turns.jsonl and events.log`).
   - When models disagree:
     - If within the same run window ($-5\text{s} \le \text{slack} \le 120\text{s}$ with no intervening turn), that is a genuine same-run contradiction (`MISMATCH`, exit 1).
     - If outside the run window or intervening turn matched, the old fallback is history and the last turn is the effective truth (`MATCH`, exit 0, source: `turns.jsonl`).

### Sibling Tool & Authority Hierarchy (agents-q7v2 vs agents-kq0r)

Two tools answer "which family actually ran" by different routes:
- `agents-q7v2` reads the live child environment (`PI_PROVIDER` and `PI_MODEL` from `/proc/<pid>/environ`) to give real-time warnings for active sessions.
- This tool (`fleet-model-audit family`, agents-kq0r) reads durable records (`<lane>.turns.jsonl` and `<lane>.events.log`) to audit lanes after the fact and across lane retirement.

**Authority rule:**
- **LIVE WINS for a RUNNING lane** (the environment is the ground truth for a lane that is executing now).
- **DURABLE WINS for a RETIRED lane** (the records are the only truth left once the process is gone).
- **Disagreement between the two is EXPECTED** when one tool reports a retired lane's last known record while the other reports a live fallback that happened after that record was written.

### Principle: Absence is Never Evidence

A recurring defect family across this bead was treating missing, unestablished, or unparseable data as if it were a finding:
1. `agents-c` first cut converted a missing guard helper (`ENOENT`) into a refusal that aborted lane startup.
2. An audit script treated an unresolved pair (`UNKNOWN` vs `UNKNOWN`) as a match in a same-family filter.
3. Treating an unestablished record as proof of contradiction.

In `fleet-model-audit family`, absence is strictly non-evidentiary: absence of durable records is `UNKNOWN` (exit 3) — never `MATCH` and never `MISMATCH`.

### Established Mechanism & Rules

1. **Never use the requested model or pointer as proof of what ran.** A lane with only pointer or ask evidence reports `UNKNOWN` (exit 3), never a match.
2. **Always identify the evidence source.** Output states whether the answer came from `turns.jsonl`, `events.log`, `turns.jsonl and events.log`, or `pointer-only`.
3. **Contradictions are findings, not notes.** If `turns.jsonl`'s turn disagrees with an associated same-run `events.log` fallback, that is a `MISMATCH` (exit 1).
4. **Precedence:** `MISMATCH (1) > UNKNOWN (3) > MATCH (0)`.
5. **Observation-based skipping:** `remote/pick-model.sh` inspects `~/.fleet/lanes/*.events.log` for runtime fallbacks and skips handing out models that have demonstrated fallback, avoiding silent same-family collisions at spawn time.

### Changes

- `bin/fleet-model-audit:31-36`: USAGE updated to document `fleet-model-audit family <lane-name>`.
- `bin/fleet-model-audit:506-597`: `fb_governs_turn()` implemented. Evaluates temporal association between `events.log` fallback lines and `turns.jsonl` records using timestamps and run window bounds.
- `bin/fleet-model-audit:599-710`: `lane_family()` implemented. Validates encoding via `trust_bytes`, extracts the last turn model from `turns.jsonl` with `turn_model` and `dup_keys`, extracts the last runtime fallback from `events.log`, and reconciles:
  - Both present and agreeing: `MATCH family <fam> (lane <lane> ran <model>, source: turns.jsonl and events.log)` (exit 0).
  - Both present, disagreeing, and same run window: `note_mis` -> `MISMATCH` (exit 1).
  - Both present, disagreeing, but fallback is historical (outside window or intervening turn): `MATCH family <fam> (lane <lane> ran <model>, source: turns.jsonl)` (exit 0).
  - Turns only: `MATCH family <fam> (lane <lane> ran <model>, source: turns.jsonl)` (exit 0).
  - Fallback events only (e.g. lane retired or 0 turns completed): `MATCH family <fam> (lane <lane> fell back to <model>, source: events.log)` (exit 0).
  - Pointer only: `note_unk` naming `source: pointer-only` (exit 3).
  - No records: `note_unk` (exit 3).
- `bin/fleet-model-audit:728-745`: Dispatches `family <lane>` and `lane <lane> --family`.
- `remote/pick-model.sh:17-48`: `observed_fallback()` scans `*.events.log` for `ℹ runtime model fell back: <req> -> <eff>` lines; `skip_observed_fallback()` logs skips to stderr once per model; `is_healthy()` skips models in the observed-fallback set.
- `remote/pick-model.sh:137-147`: `pick_subagent_model()` fail-open avoids handing out models with observed fallbacks.
- `remote/pick-model.sh:264`: Lane rotation loop skips models with observed fallbacks.
- `remote/pick-model.sh:274-284`: Lane rotation fail-open loop skips models with observed fallbacks and falls open to non-fallen-back rotation models if available.
- `tests/fleet-model-audit.test.sh:550-642`: Section 11 extended with tests 11a–11r, including same-run agreement/disagreement and across-run historical fallback handling, with non-empty output assertions.

### Red-First Verification (Reviewer Reproducer)

Fixture (`recovered`):
- `recovered.events.log`: `10:00:00 ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash`
- `recovered.turns.jsonl`:
  `{"at":"2026-10-13T10:00:02Z","model":"deepseek/deepseek-flash"}`
  `{"at":"2026-10-13T10:05:00Z","model":"openai-codex/gpt-6-sol"}`

**RED (Unfixed tool, increment 1):**
```text
$ FLEET_LANES_DIR=/tmp/lanes fleet-model-audit family recovered
MISMATCH lane 'recovered' last turn ran openai-codex/gpt-6-sol (source: turns.jsonl) but events.log recorded fallback to deepseek/deepseek-flash (source: events.log)
         a result produced by a different model is NOT attributable to the one requested - if this was
         a cross-family review, the review rule is not satisfied. Re-dispatch, or record the substitute.
$ echo $?
1
```

**GREEN (Fixed tool with temporal association):**
```text
$ FLEET_LANES_DIR=/tmp/lanes fleet-model-audit family recovered
MATCH    family openai-codex (lane recovered ran openai-codex/gpt-6-sol, source: turns.jsonl)
$ echo $?
0
```

### Verification Against Live Files

Tested in isolated throwaway copies without modifying live files:
1. `tests/fleet-model-audit.test.sh`: **126 passed, 0 failed** (108 baseline tests preserved + 18 Section 11 tests 11a–11r).
2. `tests/pick-model-crossfamily.test.sh`: **26 passed, 0 failed** (24 baseline tests preserved + 2 tests 7a–7b).
3. `tests/quota-horizon.test.sh`: **19 passed, 0 failed**.
4. `tests/subagent-cooldown.test.sh`: **27 passed, 0 failed**.
5. Live lane spot-checks on read-only live lane store (`~/.fleet/lanes/`):
   - `family impl-tdot` -> `MATCH family deepseek (lane impl-tdot ran deepseek/deepseek-flash, source: turns.jsonl and events.log)` (rc=0)
   - `family impl-f6du` -> `MATCH family openai-codex (lane impl-f6du ran openai-codex/gpt-6-sol, source: turns.jsonl)` (rc=0)
   - `family 5qe-opus` (retired lane) -> `MATCH family deepseek (lane 5qe-opus ran deepseek/deepseek-flash, source: turns.jsonl and events.log)` (rc=0)
   - `family rev-9lew` -> `MATCH family openai-codex (lane rev-9lew ran openai-codex/gpt-6-sol, source: turns.jsonl)` (rc=0)

### Hub Application

```bash
cd ~/fleet
git apply -p1 --check /path/to/patches/fleet-model-effective-family.patch
git apply -p1 /path/to/patches/fleet-model-effective-family.patch
bash tests/fleet-model-audit.test.sh
bash tests/pick-model-crossfamily.test.sh
```

## Disclosure of a superseded fallback (coord's clause, agents-kq0r)

When a fallback is SUPERSEDED by a later successful turn, the MATCH line names the turn's family and ALSO names the fallback it
superseded - "source: turns.jsonl; an earlier fallback to <model> is superseded by this turn, which is the effective family" -
so a reader can tell "never fell back" from "fell back once and recovered". Without it the two states print the same line, and
that distinction is the whole point of this tool.

Pinned by case 11s in tests/fleet-model-audit.test.sh. RED-FIRST, measured: against the previous tip the case is
`127 passed, 1 failed` - the disclosure assertion fails and prints the line that lacks it - and with this change it is
`128 passed, 0 failed`. The other half of 11s (that the turn's family is reported) passes on both, so it is a GUARD, not a
discriminator, and it is named as such rather than counted as coverage.
