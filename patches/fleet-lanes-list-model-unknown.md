## `fleet-lanes-list-model-unknown.patch` — `lanes.sh list` reports `UNKNOWN` rather than `(default)` when effective model is unrecorded (agents-oi00)

`remote/lanes.sh` `lanes list` prints the model per lane by reading `$LD/$l.model`, falling back to `MODEL` from the lane's `.conf`, and then falling back to the literal string `(default)`.

When a lane has no recorded model pointer (`$LD/$l.model` missing or empty) and has an empty `MODEL` in its configuration (e.g. `coord` or an unbooted rotation lane), falling back to `(default)` asserts a default rather than admitting an unknown. In a column read by cross-family review verification, asserting knowledge that the system does not possess can mislead tooling and operators into treating an unestablished model as a known default.

This change updates the fallback in the reporting path of `lanes.sh list` from `(default)` to `UNKNOWN`, ensuring that an unrecorded model is explicitly reported as unknown and remains distinguishable from an explicitly configured default model.

## The four hub-delivery fields

| Field | Value |
| --- | --- |
| **Artifact sha** | `patches/fleet-lanes-list-model-unknown.patch` — 3865 bytes, sha256 `90bb37a498f73684671430a91da35f3c307bb33a4e863bc168ae41f7d54ee46c`, 2 hunks, 2 file-sections |
| **Exact base it expects** | `remote/lanes.sh` = 40537 bytes, sha256 `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`; `tests/lanes.test.sh` = 64678 bytes, sha256 `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5` (both measured on deployed `~/fleet` copies on this VM) |
| **Does the destination have that shape?** | Verified against deployed copies: `patch -p1 --dry-run` is clean for 2/2 sections, and `tests/lanes.test.sh` passes 203/203 tests. |
| **Prerequisites** | None. |

## Investigation: Creator of `coord`'s configuration

1. **Which creator writes `coord`'s conf:**
   - Code path: `remote/lanes.sh:234` in `start_lane()`:
     ```bash
     [ -f "$LD/$lane.conf" ] || default_conf "$lane"
     ```
   - Invokes `default_conf()` defined at `remote/lanes.sh:64-74`:
     ```bash
     default_conf() {
       local lane=$1 dflt; dflt=$(cat "$HOME/.fleet/default-branch" 2>/dev/null || echo main)
       case $lane in
         coord) if is_hub; then write_conf coord hub "" "$HOME/journal"
                else write_conf coord coord "" "$HOME/$P"; fi ;;
         merger)
           local wt="$HOME/worktrees/$P-merger"; local R; R=$(repo_dir)
           [ -d "$wt" ] || git -C "$R" worktree add -q --detach "$wt" "refs/remotes/origin/$dflt" 2>/dev/null || true
           write_conf merger merger "" "$wt" ;;
       esac
     }
     ```
   - `write_conf()` at `remote/lanes.sh:46-51` sets `ROLE=coord`, `MODEL=""`, `WORKDIR="..."`, `BEAD=""`.
   - `coord` cannot be spawned via `remote/lanes.sh spawn` because line 262 explicitly reserves `coord` and `merger`:
     ```bash
     [[ $name == coord || $name == merger ]] && { echo "reserved lane name" >&2; exit 1; }
     ```
   - Thus, `default_conf()` at `remote/lanes.sh:64-74` (called from `start_lane()` at line 234) is the sole creator of `coord`'s configuration.

2. **Does `coord` have an effective model recorded anywhere?**
   - **At creation time (`default_conf`):** No model is passed (`MODEL=""`), and `default_conf` does not write a `.model` file (just as `lanes.sh spawn` does not write a `.model` file when model is empty). The model is chosen later at boot time by role rotation in `run-lane.sh`.
   - **In configuration (`~/.fleet/lanes/coord.conf`):** `MODEL=''` is intentionally empty per the rotation design (cooldown, failover, and rotation semantics reside in `run-lane.sh`).
   - **In process environment (`/proc/<pid>/environ`):** No per-lane model environment variable exists (SDK host runs all lanes within one process).
   - **In disk pointer (`~/.fleet/lanes/coord.model`):** The pointer file was missing on the live VM (unlinked by external test cleanups).
   - **In runtime records (`coord.state.json`, `coord.turns.jsonl`, session transcript):** The live runtime state records `"model":"deepseek/deepseek-flash"`. However, `lanes.sh list` does not parse session logs or state JSON; it consults only `$LD/<lane>.model` and conf `MODEL`.
   - **Finding:** When `$LD/<lane>.model` is absent and conf `MODEL` is empty, `lanes.sh list` had nothing recorded to read, but asserted `(default)`. This was a false assertion of knowledge. The list arm must print `UNKNOWN` rather than `(default)`.

## What changed

1. `remote/lanes.sh:545`:
   ```bash
   -        [ -z "$m" ] && m="${MODEL:-(default)}"
   +        [ -z "$m" ] && m="${MODEL:-UNKNOWN}"
   ```
   Kept narrow to the reporting path only. Does not alter spawn, does not change other roles, and preserves rendering of real models from `.model` or conf.

2. `tests/lanes.test.sh`:
   Added section 30 with 5 assertions covering:
   - `30a`: Lane with no `.model` file and empty `MODEL` in conf reports `UNKNOWN` in `lanes list`.
   - `30b`: Lane with unrecorded model does NOT report `(default)`.
   - `30c`: Lane with explicit default model (`MODEL='(default)'`) reports `(default)`, demonstrating that an unrecorded model is distinguishable from a configured default.
   - `30d`: Lane whose requested model in conf and effective model in session record / `.model` differ reports the effective model matching the session record.
   - `30e`: `lanes list` does not report the requested model when effective model differs.

## Evidence

| Run | Result |
| --- | --- |
| Baseline `tests/lanes.test.sh` on deployed `~/fleet` | **198 passed, 0 failed** |
| Patched pair (`remote/lanes.sh` + `tests/lanes.test.sh`) | **203 passed, 0 failed** (+5) |
| Pre-fix / mutant test (reverting line 545 back to `(default)`) | **201 passed, 2 failed** — assertions 30a and 30b fail loudly, naming `coord-unk` with `expected to find: UNKNOWN` and `expected NOT to find: (default)` |
| `patch -p1` on clean copies of base files | Clean application for 2/2 sections, byte-identical to tested files |

## Applying it

```bash
cd ~/fleet
sha256sum remote/lanes.sh tests/lanes.test.sh
# Expected:
# 7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa  remote/lanes.sh
# bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5  tests/lanes.test.sh

patch -p1 --dry-run < patches/fleet-lanes-list-model-unknown.patch
patch -p1 < patches/fleet-lanes-list-model-unknown.patch
bash tests/lanes.test.sh
```
