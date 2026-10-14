## `fleet-check-refuse-foreign-config.patch` (agents-0r1c)

- **Target repository:** `PaulKinlan/fleet`
- **Target file:** `bin/fleet-check` (one insertion, immediately after the per-VM config is sourced and
  the command is resolved; the guard runs before the merger-only check and before any heavy-slot work)
- **Baseline file hash (the live bytes this patch was generated against and applies to):**
  `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498  bin/fleet-check`
  (767 lines; patched result `5850d4fbd7ee6133afe1fa97067efd0718dc1ca9955d12e1d61789167890d781`)
- **Revision:** second revision. The first was reviewed and FAILED with two P2 findings (agents-wisk,
  agents-jqc4) that broke its candidate rule in BOTH directions; the rule itself was replaced, see
  "Changes" below. Any dry-run evidence predating this revision is void - the patched bytes changed.
- **Disposition:** DELIVERY ONLY. This patch is the shared-reader half of agents-0r1c and it is
  load-bearing, but it must NOT be applied until the ordering warning below is satisfied.

### ORDERING WARNING — apply this LAST, not first

On any host whose `~/.fleet/check.conf` was written by an `--install` from ONE repo, that file names
paths that exist only in that repo (`bash tools/fast-gate.sh`, `unittest discover -s tests -t .`). The
guard refuses exactly such a command, so **applied before the host config is repaired it turns every
gate on that host into a refusal**. That is the guard working, not failing — but it is a stop-the-fleet
event and it must be sequenced:

1. Give each repo its own config (`bash tools/check-cmd.sh --install` in that repo, which since
   agents-0utp writes `$HOME/.fleet/<repo>-check.conf`) and point that repo's gate at it with
   `FLEET_CHECK_CONF`.
2. Or re-install the host-wide file from the repo that is genuinely meant to own the host's gate:
   `bash tools/check-cmd.sh --install --global`.
3. Then apply this patch. The refusal it adds is what makes the NEXT silent install loud instead of
   silent; by the time it lands, the wrong file must not already be in service.

### Problem Statement (agents-0r1c, the reader half of agents-0utp)

agents-0utp fixed the WRITER (a bare `--install` no longer rewrites the machine-global file) and
agents-p8lh made the repairs the tools print truthful. Neither touched the READER: a config already
installed by another repo keeps being read, and `bin/fleet-check` is that reader — it sources
`${FLEET_CHECK_CONF:-$HOME/.fleet/check.conf}` directly and never goes through
`tools/check-cmd.sh`, so an in-repo guard cannot close this. A gate run from any other repo then died
with **EXIT 127**, a message about a *missing tool* when the truth was a *foreign config*, and the
failure surfaced at the next repo's gate rather than at install time. Nothing refused it.

### Changes

One block inserted in `bin/fleet-check`, after `CHECK_CMD` is resolved (including the `--fast` path,
where `CHECK_CMD` is set from `CHECK_FAST_CMD`, so it is the command that will actually run) and
before the merger-only full-gate check:

1. **Refuse the offending command.** If something the command must read or execute is not here, the
   reader refuses (`exit 2`) **before** the heavy slot is touched, and writes **no verdict record**, so
   the refusal cannot be mistaken for a result.
2. **`"Cannot exist here", never "came from elsewhere".** Identity alone does not refuse. A config
   whose named paths all resolve is read normally even when its `# Project:` stamp names another
   directory — a worktree of the same project is exactly that, and refusing on identity would turn
   every worktree gate red for an innocent branch.
3. **Attribution from the existing stamp.** The message names the repo that installed the config,
   taken from the `# Project: <name> (<path>)` line `--install` has written since agents-ia3p; an
   unstamped config is refused without inventing a culprit.
4. **A one-line repair, always.** The message names how to give this repo its own config and how to
   make the host-wide file correct instead, because a refusal without a way out is a trap.
5. **THE CANDIDATE RULE IS THE PROPERTY, NOT A REGEX** (second revision). “A path the command must
   READ or EXECUTE cannot exist here” — which is what EXIT 127 means — so exactly four things are
   candidates: the **command word** (a path if it has a slash, otherwise a PATH lookup, since a
   missing `bash` is as unrunnable as a missing script); the **script argument of an interpreter**
   (skipping flags, stopping at `-c`/`--command`, where the argument is code, and at `-m`, a module);
   the values of **`-s`/`-t`** but only on a command line that mentions unittest/discover (`sort -t ,`
   is not a path); and the target of a **read redirection** (`<`). Everything else is ignored by
   construction — output redirections, plain arguments, flags — and `./` is stripped before every
   existence check.

   *Why the rule was replaced rather than repaired.* The first revision extracted “path-shaped
   tokens” and checked them all. Review broke it both ways the same day: it **missed**
   `bash ./tools/fast-gate.sh` (agents-wisk — the old regex did not match a `.` after the slash, so a
   `/`-prefix-bypass existed) and it **refused** `bash tools/fast-gate.sh > logs/result.log`
   (agents-jqc4 — a redirection target is a file the command CREATES, not one it must read). A rule
   with one missing case and one blocking case has not decided what it protects; naming the property
   is what decides it, and both findings’ repros are now pinned as controls in the in-repo suite.

### Verification

- **Applies cleanly to the live bytes:** `git apply --check` against a pristine copy of
  `~/fleet/bin/fleet-check` at the baseline hash above — no fuzz, no conflict; the applied result
  byte-matches the copy the behaviour below was measured on (`bash -n` clean).
- **Driven for real, patched copy, scratch git repo + scratch HOME + `FLEET_CHECKS_DIR` redirected**
  (the live `~/fleet` was never written to):
  - a config stamped `agents-factory (/home/exedev/agents-factory)` naming `tools/fast-gate.sh` in a
    repo that has no `tools/` → `exit 2`, message names the repo and the path, no cached record;
  - the same command with `python3 -m unittest discover -s tests -t .` → refuses and names `tests`;
  - **agents-wisk, fixed:** `bash ./tools/fast-gate.sh` (the bypass) → refuses, naming
    `tools/fast-gate.sh`; the control without the `./` refuses identically, and so does the bare
    `./tools/fast-gate.sh` form;
  - **agents-jqc4, fixed:** `bash tools/fast-gate.sh > logs/result.log` with the script present and
    `logs/` absent → **no refusal** (exit 0; the reader creates nothing). With the script REMOVED the
    same command refuses, naming the script — the output path stays ignored either way;
  - **CONTROL (no false refusal):** a fully runnable config → no refusal, the gate starts (exit 0);
  - an UNSTAMPED config naming a missing path → refuses and says `carries no 'Project:' stamp`
    rather than attributing it to a repo.
- **The in-repo half has its own tests** in agents-factory (`tests/test_gate_entrypoint_config.py`,
  class `TestTheReaderRefusesACommandThatCannotRunHere`), which pin the same four properties plus the
  field-scoped refusal and that `--install` still repairs a broken config. This patch carries the
  same logic to the reader that a deployed VM actually uses.

### Hub Application

```bash
cd ~/fleet
git apply --check /path/to/fleet-check-refuse-foreign-config.patch   # expect clean
# ONLY AFTER the ordering warning above is satisfied:
git apply /path/to/fleet-check-refuse-foreign-config.patch
bash -n bin/fleet-check
```
