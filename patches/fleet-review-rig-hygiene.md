## `fleet-review-rig-hygiene.patch` (agents-675i, agents-xcp9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `roles/reviewer.md` (lines 36-45)
- **Problem Statement (agents-675i, agents-xcp9):**
  Reviewer lanes reproducing behaviours or testing patches in scratch directories frequently ran `cp -a /home/exedev/fleet /tmp/<rig>`.
  The `/home/exedev/fleet` directory is ~434MB, of which 430MB is `sdk-host/node_modules` — a tree that reviewer test rigs never execute or use.
  Because review scripts commonly lacked exit cleanup traps, dead rigs accumulated across review sessions (accumulating 124 leaked directories and over 5.7GB in `/tmp`, driving VM disk utilization to 96%).
  Furthermore, unsandboxed executions of `install.sh` from temporary review checkouts clobbered the host's `~/.local/bin/factory` with temporary symlinks that went dangling upon directory deletion, breaking the nightly factory audit with exit 127.
- **Changes in `roles/reviewer.md`:**
  Under Step 2 ("The behaviour under review, reproduced"), added explicit **Review rig hygiene** instructions:
  1. **Never `cp -a ~/fleet`:** State explicitly that `sdk-host/node_modules` is 430MB of the 434MB checkout and unused by review rigs; instruct using `rsync -a --exclude=sdk-host ~/fleet/ /tmp/<rig>/` (~4MB, 100x smaller) or copying only the specific files or directories under review.
  2. **Always trap cleanup:** Scratch directories must be created with `mktemp -d` and removed via `trap 'rm -rf "$wd"' EXIT` (or language cleanup context).
  3. **Never run `install.sh` without an isolated `$HOME`:** When testing `install.sh`, require `HOME=$(mktemp -d)` or `SF_LOCAL_BIN=$(mktemp -d)` to prevent host `~/.local/bin/factory` symlink clobbering.
- **Companion Change in `PaulKinlan/agents` (agents-xcp9):**
  - Updated `install.sh` to allow overriding the binary link directory via `LOCAL_BIN="${SF_LOCAL_BIN:-$HOME/.local/bin}"`.
  - Added unit test `test_install_sh_respects_sf_local_bin_override` in `tests/test_gate_entrypoint_config.py`.
- **Verification:**
  - `patches/fleet-review-rig-hygiene.patch` applies cleanly against pristine `~/fleet` via `git apply --check`.
  - Focused test in `agents`: `python3 -m unittest tests.test_gate_entrypoint_config.TestProvisioningInstallsTheGateCommand.test_install_sh_respects_sf_local_bin_override` passes (0.62s).
  - Full suite `tests.test_gate_entrypoint_config` passes (18 tests, 0 failures).
  - Fast gate: `bash tools/fast-gate.sh` passes cleanly.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-review-rig-hygiene.patch
  ```
