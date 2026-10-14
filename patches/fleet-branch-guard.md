## The branch must match the worktree, or the commit is refused - `fleet-branch-guard.patch` (agents-zwbk)

Hub-side artifact: a new `remote/fleet-branch-guard.sh`, an install block inside `provision.sh`'s
`install_git_hooks()`, and a driven fixture `tests/fleet-branch-guard.test.sh`.

### The hazard, measured three times in one session

The worktree you are standing in is not necessarily the branch the bead belongs to, and `git commit` accepts
whatever `HEAD` is. It cost a manual split each time, and one instance briefly voided a clearance that was
already recorded, because **clearance is per-sha**:

1. `agents-3gk3` was committed onto the **cleared** `fleet/impl-guard-8b05`, inside a gating union.
2. `agents-shua` was committed onto `fleet/impl-guard-lyrw` **after** it landed, so the artifact was not in
   main and the branch tip no longer matched its clearance.
3. `agents-rirf` was committed in the shua worktree and pushed to a differently-named branch, putting two
   beads' patches on one tip - one verdict would have cleared two beads, and either fix would have voided the
   other's clearance.

### The rule is NARROW on purpose, because a guard that cries wolf gets disabled

It fires only when **both** sides name a bead id: the worktree's last path component and the branch's last
token must each look like a 4-character id, and they must differ. That is the exact signature of all three
instances (`8b05` on `3gk3`, `lyrw` on `shua`, `shua` on `rirf`) while staying silent on legitimate shapes:
a lane worktree with no bead suffix, a branch with words after the id
(`fleet/impl-l2-0utp2-5q0w-rerun-ruling`), or a worktree outside `~/worktrees`. The refusal is overridable
deliberately with `FLEET_ALLOW_BRANCH_MISMATCH=1`, so the escape hatch is a decision rather than a workaround.

### Two implementation defects, both found by measuring rather than by reading

- **A branch name is not a path.** The first version computed the branch's last token with `${BR##*/}`, which
  on `fleet/impl-guard-3gk3` yields `impl-guard-3gk3` - so the guard silently allowed every mismatch it exists
  to catch. The fixture said so first; `bash -x` found the line in one run.
- **`provision.sh` has no `$HERE`.** The first version wired the install block to `$HERE` and would have
  written a hook pointing at `/fleet-branch-guard.sh`. The file's own post-mortem, six lines above the
  function, records that identical mistake: *"I introduced that by wiring the check to a variable this script
  never defines."* It now derives the directory from `$0`, the idiom used elsewhere in the file.

### The refusal leads with one line naming both

Coord's requirement when approving this: a machine check beats a discipline that has already failed three
times, and it should name BOTH the branch and the worktree in one line rather than make a human read a block.
So the first line is now `fleet-branch-guard: REFUSING this commit - worktree '<dir>' on branch '<branch>' -
those name different beads.`, with the full paths and the one-line repair beneath it for when they are needed.

### Evidence

- Fixture: **9 of 9** - the three real mismatches refused, six legitimate shapes silent, the override allowed.
- Commit-level discriminator: UNGUARDED **rc=0** (the old state simply lands the commit) versus GUARDED
  **rc=1** with an actionable message naming the worktree, the branch, and the `git switch -c` repair; with the
  override, **rc=0**.
- The install block DRIVEN, not described: it creates the `pre-commit`, the installed hook then refuses a real
  commit, and a second install adds no duplicate block.
- `patch -p1 --fuzz=0` CLEAN against the live hub files, byte-identical after apply. Preimages:
  `remote/provision.sh` SHA256 `a98afcd129b0aa5b`, md5 `1f36acf716a0`, git blob `5ff6660045a0` - three digests of the same
  bytes, so an md5 or a blob SHA1 does not "fail to match" a SHA256: compare like with like. (Reconciled against the
  deployed hub file, 2026-10-14: all three agree, and the operative check remains the clean `--fuzz=0` apply above, which
  a digest cannot substitute for.) The guard and the fixture are new.

### What it does NOT do

It cannot see a commit made outside `~/worktrees`, and it stays silent whenever the names carry no bead ids -
both deliberate, because a check that fires on legitimate work is one that gets switched off. It also cannot
carry the executable bit through a patch, so both the install block and the fixture invoke the guard with
`bash`; the hook need not be executable for this to work, only the `pre-commit` does.
