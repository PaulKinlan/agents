## patches/fleet-lanes-list-model-unknown.patch — `lanes.sh list` reports `state.json` model before `UNKNOWN` when `.model` unrecorded (agents-oi00, agents-az5m)

`remote/lanes.sh` `lanes list` prints the model per lane by reading `$LD/$l.model`, falling back to `MODEL` from the lane's `.conf`, and then falling back to the literal string `(default)`.

When a lane has no recorded model pointer (`$LD/$l.model` missing or empty) and has an empty `MODEL` in its configuration (e.g. `coord` or an unbooted rotation lane), falling back to `(default)` asserts a default rather than admitting an unknown. In a column read by cross-family review verification, asserting knowledge that the system does not possess can mislead tooling and operators into treating an unestablished model as a known default (agents-oi00).

However, falling back directly to `UNKNOWN` when both `.model` and conf `MODEL` are empty hides the known runtime model when runtime state (`$LD/<lane>.state.json`) does record the effective model (agents-az5m). On this VM, `coord.state.json` accurately records `"model":"deepseek/deepseek-flash"` while `coord.model` is missing and `coord.conf` has empty `MODEL`.

The updated reporting path establishes a 4-tier model resolution:
1. `$LD/<lane>.model` (pointer written at spawn / boot / failover);
2. `MODEL` from `$LD/<lane>.conf` (explicit requested model or explicit default);
3. `.model` from `$LD/<lane>.state.json` (runtime state recorded by lane-host/SDK host);
4. `UNKNOWN` when all three sources are empty or absent.

This guarantees that:
- A running lane whose pointer was unlinked or never written reports its actual effective model from runtime state (`state.json`), resolving agents-az5m.
- An unrecorded model without runtime state reports `UNKNOWN` rather than falsely asserting `(default)`.
- An explicitly configured default (`MODEL='(default)'`) remains distinguishable from `UNKNOWN`.

## The four hub-delivery fields

| Field | Value |
| --- | --- |
| **Artifact sha** | `patches/fleet-lanes-list-model-unknown.patch` — 5191 bytes, sha256 `d1789381f8d24e164fe0263550d2707bda8d3c5dc305bfe0f8bf23b9c43681f5`, 2 hunks, 2 file-sections |
| **Exact base it expects** | `remote/lanes.sh` = 40537 bytes, sha256 `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`; `tests/lanes.test.sh` = 64678 bytes, sha256 `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5` (both measured on deployed `~/fleet` copies on this VM) |
| **Does the destination have that shape?** | Verified against deployed copies: `patch -p1 --fuzz=0 --dry-run` is clean with rc 0 and zero rejects for 2/2 sections, and `tests/lanes.test.sh` passes 206/206 tests. |
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
   - **In disk pointer (`~/.fleet/lanes/coord.model`):** The pointer file was missing on the live VM (unlinked by external test cleanups).
   - **In runtime state (`coord.state.json`):** The live runtime state records `"model":"deepseek/deepseek-flash"`.
   - **Resolution:** By reading `.model` from `state.json` when `.model` and conf `MODEL` are empty, `lanes list` accurately reflects the live effective model for `coord` and other running rotation lanes. If `state.json` is absent or contains no model either, the reporting arm falls back to `UNKNOWN`.

## What changed

1. `remote/lanes.sh:545`:
   ```bash
   -        [ -z "$m" ] && m="${MODEL:-(default)}"
   +        [ -z "$m" ] && m="${MODEL:-}"
   +        [ -z "$m" ] && m=$(jq -r '.model // empty' "$LD/$l.state.json" 2>/dev/null)
   +        [ -z "$m" ] && m="UNKNOWN"
   ```
   Kept narrow to the reporting path only. Does not alter spawn, does not change other roles, and preserves rendering of real models from `.model` or conf.

2. `tests/lanes.test.sh`:
   Added section 30 with 8 assertions covering:
   - `30a`: Lane with no `.model` file, empty MODEL in conf, and no runtime state reports `UNKNOWN` in `lanes list`.
   - `30b`: Lane with unrecorded model does NOT report `(default)`.
   - `30c`: Lane with explicit default model (`MODEL='(default)'`) reports `(default)`, demonstrating that an unrecorded model is distinguishable from a configured default.
   - `30d`: Lane with empty conf and missing `.model`, but with runtime `state.json` naming a model, reports that model from `state.json` (agents-az5m).
   - `30e`: Lane with runtime state model does NOT report `UNKNOWN`.
   - `30f`: Lane with runtime state model does NOT report `(default)`.
   - `30g`: Lane whose requested model in conf and effective model in session record / `.model` differ reports the effective model matching the session record.
   - `30h`: `lanes list` does not report the requested model when effective model differs.

## Evidence

| Run | Result |
| --- | --- |
| Baseline `tests/lanes.test.sh` on deployed `~/fleet` | **198 passed, 0 failed** |
| Patched pair (`remote/lanes.sh` + `tests/lanes.test.sh`) | **206 passed, 0 failed** (+8) |
| Pre-fix test (deployed code with `(default)`) | **202 passed, 4 failed** — assertions 30a, 30b, 30d, 30f fail |
| Mutant test (previous fix without `state.json` read) | **204 passed, 2 failed** — assertions 30d and 30e fail naming `coord-live` (`expected to find: deepseek/deepseek-flash`, `expected NOT to find: UNKNOWN`) |
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
