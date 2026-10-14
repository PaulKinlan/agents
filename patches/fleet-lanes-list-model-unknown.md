## patches/fleet-lanes-list-model-unknown.patch — `lanes.sh list` reports `state.json` model before conf `MODEL` and `UNKNOWN` (agents-oi00, agents-az5m, agents-dpzu)

`remote/lanes.sh` `lanes list` prints the model per lane by reading `$LD/$l.model`, falling back to `MODEL` from the lane's `.conf`, and then falling back to the literal string `(default)`.

When a lane has no recorded model pointer (`$LD/$l.model` missing or empty) and has an empty `MODEL` in its configuration (e.g. `coord` or an unbooted rotation lane), falling back to `(default)` asserts a default rather than admitting an unknown. In a column read by cross-family review verification, asserting knowledge that the system does not possess can mislead tooling and operators into treating an unestablished model as a known default (agents-oi00).

Furthermore, falling back directly to `UNKNOWN` when both `.model` and conf `MODEL` are empty hides the known runtime model when runtime state (`$LD/<lane>.state.json`) does record the effective model (agents-az5m). On this VM, `coord.state.json` accurately records `"model":"deepseek/deepseek-flash"` while `coord.model` is missing and `coord.conf` has empty `MODEL`.

Finally, checking `MODEL` from conf ahead of `state.json` allowed an explicitly configured model in conf (e.g. `MODEL=zai/glm-5.3`) to mask a different effective model in runtime state (e.g. `"model":"deepseek/deepseek-flash"` after a silent rate-limit fallback, agents-dpzu). An explicitly requested model in conf is an ask / intent, not runtime authority (Rule 247: the effective model is the last model_change).

The updated reporting path establishes a 4-tier model resolution:
1. `$LD/<lane>.model` (authoritative disk pointer written at spawn / boot / failover);
2. `.model` from `$LD/<lane>.state.json` (runtime state recorded by lane-host / SDK host);
3. `MODEL` from `$LD/<lane>.conf` (configured model / explicit default);
4. `UNKNOWN` when all three sources are empty or absent.

This guarantees that:
- A running lane whose pointer is missing or unlinked reports its actual effective model from runtime state (`state.json`), resolving agents-az5m.
- An explicit conf request does NOT mask a different effective model when the lane fell back at runtime, resolving agents-dpzu.
- An unrecorded model without runtime state reports `UNKNOWN` rather than falsely asserting `(default)`.
- An explicitly configured default (`MODEL='(default)'`) remains distinguishable from `UNKNOWN`.

## The four hub-delivery fields

| Field | Value |
| --- | --- |
| **Artifact sha** | `patches/fleet-lanes-list-model-unknown.patch` — 6237 bytes, sha256 `a96bff5c7cd72dc4ad27a5d35931dc1346b1a4bec844a44d1758e37c4cd0ceef`, 2 hunks, 2 file-sections |
| **Exact base it expects** | `remote/lanes.sh` = 40537 bytes, sha256 `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`; `tests/lanes.test.sh` = 64678 bytes, sha256 `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5` (both measured on deployed `~/fleet` copies on this VM) |
| **Does the destination have that shape?** | Verified against deployed copies: `patch -p1 --fuzz=0 --dry-run` is clean with rc 0 and zero rejects for 2/2 sections, and `tests/lanes.test.sh` passes 208/208 tests. |
| **Prerequisites** | None. |

## Investigation: Creator of `coord`'s configuration & effective model resolution

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

2. **Effective model determination:**
   - **At creation time (`default_conf`):** No model is passed (`MODEL=""`), and `default_conf` does not write a `.model` file (just as `lanes.sh spawn` does not write a `.model` file when model is empty). The model is chosen later at boot time by role rotation in `run-lane.sh`.
   - **In configuration (`~/.fleet/lanes/coord.conf`):** `MODEL=''` is intentionally empty per the rotation design (cooldown, failover, and rotation semantics reside in `run-lane.sh`).
   - **In disk pointer (`~/.fleet/lanes/coord.model`):** The pointer file was missing on the live VM at the time of observation. **The cause was NOT established, and the cleanup hypothesis is now excluded** (agents-lkml): no shipped test removes files under `~/.fleet/lanes` **and** a repository-wide search finds no code path that unlinks a `*.model` pointer at all. The pointer is written by lane start-up (spawn / boot / failover, per item 1), and it is **present again on this VM - 24 bytes, mtime 2026-10-14 14:27:03** - so the supported reading is "absent at the moment of observation, since recreated by normal operation" rather than "unlinked". What WOULD establish a removal is a path that unlinks the pointer, or an audit record of one; until then a missing pointer should not be reported with a cause.
   - **In runtime state (`coord.state.json`):** The live runtime state records `"model":"deepseek/deepseek-flash"`.
   - **Resolution:** By reading `.model` from `state.json` before conf `MODEL`, `lanes list` accurately reflects the live effective model for `coord` and running rotation/fallback lanes. If `state.json` is absent or contains no model either, the reporting arm falls back to `MODEL` from conf (e.g. `(default)`) and then to `UNKNOWN`.

## What changed

1. `remote/lanes.sh:545`:
   ```bash
   -        [ -z "$m" ] && m="${MODEL:-(default)}"
   +        [ -z "$m" ] && m=$(jq -r '.model // empty' "$LD/$l.state.json" 2>/dev/null)
   +        [ -z "$m" ] && m="${MODEL:-}"
   +        [ -z "$m" ] && m="UNKNOWN"
   ```
   Kept narrow to the reporting path only. Does not alter spawn, does not change other roles, and preserves rendering of real models from `.model` or conf.

2. `tests/lanes.test.sh`:
   Added section 30 with 10 assertions covering:
   - `30a`: Lane with no `.model` file, empty MODEL in conf, and no runtime state reports `UNKNOWN` in `lanes list`.
   - `30b`: Lane with unrecorded model does NOT report `(default)`.
   - `30c`: Lane with explicit default model (`MODEL='(default)'`) reports `(default)`, demonstrating that an unrecorded model is distinguishable from a configured default.
   - `30d`: Lane with empty conf and missing `.model`, but with runtime `state.json` naming a model, reports that model from `state.json` (agents-az5m).
   - `30e`: Lane with runtime state model does NOT report `UNKNOWN`.
   - `30f`: Lane with runtime state model does NOT report `(default)`.
   - `30g`: Lane whose requested model in conf and effective model in session record / `.model` differ reports the effective model matching the session record.
   - `30h`: `lanes list` does not report the requested model when effective model differs.
   - `30i`: Lane `rev-repro` with explicit requested `MODEL` in conf and missing `.model` reports the effective model from `state.json` rather than the requested model from conf (agents-dpzu).
   - `30j`: Lane `rev-repro` with runtime state model does NOT report the requested model `zai/glm-5.3` from conf.

## Evidence

| Run | Result |
| --- | --- |
| Baseline `tests/lanes.test.sh` on deployed `~/fleet` | **198 passed, 0 failed** |
| Patched pair (`remote/lanes.sh` + `tests/lanes.test.sh`) | **208 passed, 0 failed** (+10) |
| Pre-fix test (deployed code with `(default)`) | **202 passed, 6 failed** — assertions 30a, 30b, 30d, 30f, 30i, 30j fail |
| Mutant test (previous fix 63e1f844 with conf `MODEL` ahead of `state.json`) | **206 passed, 2 failed** — assertions 30i and 30j fail naming `rev-repro` (`expected to find: deepseek/deepseek-flash`, `expected NOT to find: zai/glm-5.3`) |
| `patch -p1 --fuzz=0` on clean copies of base files | Clean application for 2/2 sections with zero rejects and zero fuzz |

## Applying it

```bash
cd ~/fleet
sha256sum remote/lanes.sh tests/lanes.test.sh
# Expected:
# 7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa  remote/lanes.sh
# bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5  tests/lanes.test.sh

patch -p1 --fuzz=0 --dry-run < patches/fleet-lanes-list-model-unknown.patch
patch -p1 --fuzz=0 < patches/fleet-lanes-list-model-unknown.patch
bash tests/lanes.test.sh
```
