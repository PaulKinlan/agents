## `--all` printed an unbound-variable error while reporting PASS - `fleet-fast-gate-all-unmapped.patch` (agents-u1hd)

A review-finding against my own `agents-i4u9` delta, confirmed by measurement rather than taken on trust.

### The defect

`unmapped=()` was declared inside the branch that resolves a CHANGED SET, and `ALL=1` steps over that branch
entirely - so `if [ ${#unmapped[@]} -gt 0 ]` at the tail read an undeclared array under `set -uo pipefail`.

Measured in BOTH modes the review named, on the post-i4u9 content:

- a plain (non-git) checkout: stderr carried `remote/fast-gate.sh: line 152: unmapped: unbound variable`
  while stdout ended `fast-gate: PASS (2 suite(s) for 0 changed path(s))`, exit **0**;
- a git tree with `--all`: the same line, same exit.

The exit code is 0 in both cases, which is worth stating plainly: this is not a crash, it is a scary line on
stderr sitting next to a PASS. That is worse than either alone, because a lane either learns to distrust a good
gate or learns to ignore the message - and the whole point of this script is that its output is believed.

### The fix, and why the fixture did not catch it

- The declaration moves to the top beside `suites=()`, so it precedes every reader in every mode. One
  declaration, not a second copy inside the branch.
- `tests/fast-gate-nongit.test.sh` gains assertion **1e**: an `ALL=1` run must not print an unbound-variable
  error. The fixture had captured stderr with `2>&1` all along and simply never looked at it, which is exactly
  why the defect shipped - the same shape as the gap it was written to close.

### Evidence

- Discriminator, sequenced: the extended fixture is **RED** before the fix (`not ok 5 - 1e ...`, `FAILED 1`,
  rc=1) with 1a-1d still passing, so the new assertion is the only thing catching it; after the fix it is
  **GREEN**, 5 of 5, and `--all` on a git tree emits zero unbound lines.
- `patch -p1 --fuzz=0` CLEAN at every step of the real install order, byte-identical after apply, and the
  stacked files drive the fixture green (5 ok / 0 failed).

### Install order is mechanical, not cautious

This patch MUST be installed AFTER `patches/fleet-fast-gate-non-git-mode.patch` (agents-i4u9). Both of its
preimages are the POST-i4u9 state, because it edits the fixture that i4u9 creates. Applied alone to the live
hub it fails rather than applying partially, and it must never be installed without i4u9.

Preimages (derived from the post-i4u9 content, and proven post-i4u9 by the presence of i4u9's own banner):

- `remote/fast-gate.sh` SHA256 `5e5c5ad1bc43dbee`
- `tests/fast-gate-nongit.test.sh` SHA256 `3054c35b308c5b99`
