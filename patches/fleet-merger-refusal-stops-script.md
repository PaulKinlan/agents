# `fleet-merger-refusal-stops-script.patch` (agents-qngy)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `roles/merger.md` (the amend-with-the-gate-record step)
  - `bin/fleet-land-message` (the two guidance lines it PRINTS for the same step)
- **Baseline file hashes:**
  - `56ef087d06fabcda86c88a2a1a8eb20f7edc4ecacb0fbf4f10f905cdf1c607f6  roles/merger.md`
  - `980899b73c2cbd87774d45d96c326364cfc322d11e190f197fec6d06c1838716  bin/fleet-land-message`
- **Problem Statement (agents-qngy, split out of agents-wwss):**
  The documented way to add the gate record is
  `git commit --amend -F <(bash ~/fleet/bin/fleet-land-message --gate <merged-sha> <bead> fleet/<x>)` "then push".
  Two defects, and the second is the harmful one:

  1. **Process substitution hides the refusal from the amend.** When the helper refuses it writes nothing
     to stdout, so `-F <(...)` hands the amend an EMPTY message.
  2. **Nothing chains the push to the amend.** The procedure puts the push in a separate step, so even
     though the amend aborts with rc=1 on an empty message, the push is not gated by that rc and proceeds
     with a commit body that carries NO gate record. That is precisely how merge `2b23cbb` landed: the
     `--gate` refusal had to be recorded in bead comments afterwards, because the pushed body could not
     carry the gate record.

  A refusal from the amend step must STOP THE SCRIPT. The helper already exits non-zero on every refusal
  path, so the signal exists and is being discarded by the caller.

- **Changes:**
  1. `roles/merger.md`: the prescription becomes a chained block that captures the message to a FILE and
     only amends and pushes if the helper succeeded:
     `msg=$(mktemp)` / `fleet-land-message ... > "$msg"` / `&& git commit --amend -F "$msg"` / `&& git push`.
     It also states why `-F <(...)` must not be used here.
  2. `bin/fleet-land-message`: both places where the helper PRINTS the "amend with this" guidance now print
     the chained form, so an operator copying the command from its own output gets the safe sequence rather
     than the unsafe one.

- **Why a file and not process substitution:** a refused substitution yields an empty message, and
  `git commit --amend -F` either aborts with "empty commit message" or is bypassed entirely by a caller
  that does not check the rc. Capturing to a file makes the helper's exit status the decision point.

- **Verification:**
  - Patch applies cleanly to pristine copies of both live files (`patch -p1`, both `checking file` lines pass).
  - Behavioural proof against a simulated helper, run in a scratch repository: with a helper that exits 1,
    the old form leaves the amend aborted (rc=1) with the push NOT gated by it, while the new form stops
    before the amend; with a helper that exits 0, the new form amends and pushes.
  - The change is a documentary fix plus the helper's printed guidance; no executable logic in the helper
    changes, so no fleet behaviour moves except the command an operator is told to run.
