## `fleet-check-branch-provenance.patch` (agents-npyn)

- **Target repository:** `PaulKinlan/fleet` (on this VM `~/fleet` is a synced, read-only copy and **not** a git
  repository, so this is delivered as an artifact under `patches/` and is **NOT applied here**).
- **Target files:**
  - `bin/fleet-check` — records the branch the suite ran on, and discloses it in `--status` beside the caller's.
  - `tests/fleet-gate-check.test.sh` — six assertions (`23-npyn-a`..`f`) beside the existing `fleet-8pqa` test.
- **Prerequisite base hashes** (sha256 of the two files modified; verify before applying):
  - `bin/fleet-check` = `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498`
  - `tests/fleet-gate-check.test.sh` = `f3919068e04d91279cae093471ba7bf870146a8530bb8b304e0a2dedc31a56a0`
- **Apply:** from `~/fleet`, `git apply patches/fleet-check-branch-provenance.patch` (git format; no exec-bit
  change here, so `patch -p1 --fuzz=0` also works).
- **After applying**, `bin/fleet-check` is `ee23a7826aa04b21e1baa9a85545b2492f3c527240fa0bad636b0cf6e9982b28`
  and `tests/fleet-gate-check.test.sh` is `53563682333f50a07abe5f0126d5925ad35916faf66c6914bb8f7db878bb5074`
  — byte-identical to the tree the red/green was measured on.
- **Prompt budget:** none. This patch changes `bin/fleet-check` and its test only, not `roles/`.

### The defect, reproduced from a second worktree

The record carries `repo` = the checkout that ran the suite. `--status` deliberately stamps the **caller's**
checkout into `repo` and discloses the producer as `produced_in` (`fleet-8pqa`, `bin/fleet-check:40-56`,
covered by `tests/fleet-gate-check.test.sh:2584`). That mechanism is right and is left alone. The hole is that
`branch` was **never given the same treatment**: it is stamped from the caller unconditionally
(`bin/fleet-check:116` → `:174`'s bare `{branch:$b}`), and there was nothing to disclose in its place, because
the producing branch **was not in the record at all**.

Measured with one record planted for a fixed tree (`repo=/tmp/produced-elsewhere`, `branch=fleet/produced-here`)
and read with `--status --fast <tree>` from two checkouts:

| reader's checkout (branch) | pristine `branch` / `produced_branch` | patched `branch` / `produced_branch` |
|---|---|---|
| `repo` (`main`) | `main` / **absent** | `main` / `fleet/produced-here` |
| `second-wt` (`fleet/reviewed-tip`) | `fleet/reviewed-tip` / **absent** | `fleet/reviewed-tip` / `fleet/produced-here` |

So on the pristine script the branch the suite actually ran on is **nowhere in the output**, and the only
`branch` a reader ever sees is their own. That matters where a clearance gets bound to a branch (`cleared:<tip>`
is recorded by a reviewer, and landings are named by branch): a reviewer quoting a cached verdict from its own
worktree reads its own branch and concludes the receipt is its own.

**Live instance on a real receipt** (not a fixture): the `agents-uq0q` fast gate for tree `3fea4be8`
(`bin/fleet-check`'s own file, run from `/tmp/uq0q-wt` on `fleet/imp-dflt-uq0q`) reported
`"branch":"main"` when read from the canonical checkout, and the raw cached record
(`~/.fleet/checks/3fea4be8….fast.json`) contains `repo=/tmp/uq0q-wt` with **no `branch` key at all**.
This is the same class as the wrong merge-base sha and the wrong base sha in the `ivp7` write-up.

### What it does

1. **Writer** (`:354-364`): `prod_branch` is read from the producing checkout and stored in the start record as
   `branch`, exactly as `repo:$top` already is. The finish-record update preserves it (it merges into the
   existing record), so the cached record carries it.
2. **`--status` overlay** (`:174`, now `:177`): the branch clause becomes the mirror image of the repo clause —
   `{branch:$b}` when the record's branch is absent or equal to the caller's, and
   `{branch:$b, produced_branch:.branch}` when they differ. `branch` therefore keeps its documented meaning (the
   asking checkout) and the producing branch is disclosed always-or-not-at-all, never silently.
3. **Backwards compatible by construction:** every record written before this patch has no `branch` key, so
   `(.branch // "") != ""` is false and the output is exactly as before — the caller's branch and **no invented
   `produced_branch`**. The fleet's existing cache keeps working.

**What it deliberately does not touch:** the `.tree`/`.kind` refusals, the `repo`/`produced_in` semantics, and
anything about how a verdict is keyed (a record's identity is still the tree and the kind — `record_identity()`
reads those three fields only, so growing the record with a provenance field cannot change which verdict is
served). `agents-6sgf`'s witness line is a **different mechanism in the same file** (a fixed local at `:586`
assigned into the record at `:589-591`), not this overlay, so the two are not folded.

### Verification

- **Red/green, in `/tmp` copies only, nothing under `~/fleet` edited or installed** — the table above is the
  measured output of both scripts side by side; pristine shows `produced_branch` absent in both reader positions.
- **`git apply` to a pristine tree reproduces the tested bytes exactly** (sha256 matches for both files above).
- **Nothing consumes `.branch` from the record**, measured: `grep -rn '\.branch\b' bin/ remote/ tools/` matches
  only `fleet-check`'s own writer/overlay, so no consumer can break on the new key or on the disclosure.
- The six new assertions run inside the fleet's own harness as `23-npyn-a`..`f`, directly beside the `fleet-8pqa`
  test they extend, and include three controls: caller == producer (no `produced_branch`), a pre-fix record with
  no branch (caller's branch, no invented field), and the negative that the producing branch never appears as
  `branch`.

### Left for the hub (deliberately not taken here)

1. **The alternative fix:** if the hub would rather not grow the record, dropping the caller's `branch` from
   `--status` entirely achieves the same honesty with less information. This patch picks disclosure because the
   repo half of the same pair already works that way.
2. **The `NONE`/refusal paths** (`:167`, `:178`) still report only the caller's branch. There is no record to
   disclose from in those paths, so nothing is wrong there today; they are left untouched for a one-file change.
3. **Human-readable status output**, if any printer of this JSON exists elsewhere, would show the new key as-is;
   no change was made to it.
