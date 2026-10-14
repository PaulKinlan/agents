## The branch and the commit MESSAGE must name the same bead, or the commit is refused - `fleet-stale-checkout-guard.patch` (agents-6rfp)

Hub-side artifact: a new `remote/fleet-stale-checkout-guard.sh`, an install block inside `provision.sh`'s
`install_git_hooks()` that wires it as a **`commit-msg`** hook, and a driven fixture
`tests/fleet-stale-checkout-guard.test.sh`.

### The hazard, from the lane that hit it

A worktree left on the **previous bead's** branch sends the next bead's commit to that branch: the commit landed
on the cleared/under-review `...-ufl3` branch locally and the push failed with `src refspec ... does not match
any`. Origin was verified untouched, so the cost was a repair - but had the push succeeded it would have **moved a
branch under a live review**, and clearance is **per-sha**, so a reviewed tip can be invalidated from under its
reviewer. That is the same failure family as the branch guard, with a different trigger.

### Why the branch guard cannot cover it - measured, not reasoned

`fleet-branch-guard.sh` (agents-zwbk) compares the **worktree's** last dash token with the **branch's**, and fires
only when **both** look like 4-character bead ids. In the lane layout the worktree's last token is the **lane**:
`agents-factory-impl-l2-0utp2` ends in `0utp2`, which is **five** characters. Traced with `bash -x` on the real
instance: `+ is_bead_id 0utp2` / `+ case "$1" in` / `+ return 1` / `+ exit 0`. So it exits **silently, by design**
- correctly, because a lane worktree legitimately holds many beads in turn.

The name that actually went wrong is not in the worktree path at all: the commit was **about** bead `af3e` and was
heading for the branch for bead `ufl3`. Only the commit **message** carries the bead being worked, so the
comparison must be **branch-vs-message** - which is why this runs at **`commit-msg`** time, where the message
exists, and not at `pre-commit`, where it does not.

### The rule is NARROW on purpose, because a guard that cries wolf gets disabled

It fires only when the branch is a fleet branch, the worktree is under the fleet root, the **branch** names a
4-character bead id, the **message** names at least one bead, and it names **none** that matches the branch.
Silent for: a lane branch that names no bead (`fleet/impl-l2-0utp2`), a message that names no bead at all (a
merge, housekeeping, a revert), a message naming this branch's bead, a branch with extra words after the id, and
any worktree outside the fleet root. Overridable deliberately with `FLEET_ALLOW_STALE_CHECKOUT=1`, and the
override is **reported** rather than silent, so it is a decision that gets recorded.

### A defect found by driving, not by reading

The first version took the worktree from `git rev-parse --show-toplevel`, which made the guard **silently silent
whenever it was invoked from outside the repository** - including from its own fixture, where every case passed
for the wrong reason. The worktree is now an **explicit argument** with a git fallback, which is also what makes
it drivable. This is the third instance of that family in this pair of guards (agents-zwbk recorded a branch
parsed as a path, and a directory from an undefined variable): a guard that cannot be driven cannot be shown to
fire at all.

### SEQUENCING

Applies **after** `patches/fleet-branch-guard.patch`: the recorded preimage is `remote/provision.sh` **with that
patch applied**, SHA256 `7fe2b733d258d001`, so this block is inserted directly after the branch guard's block and
the two do not collide. Unlike a change to an **artifact judge**, this one has no queue-of-judgments constraint:
it refuses **new commits** rather than re-judging applies already validated, so installing it does not
retroactively change any verdict.

### Evidence

- Fixture: **10 of 10**. It refuses the **real** instance (an `af3e` commit on the `ufl3` branch) and names both
  in one line; it offers the override; five legitimate shapes stay silent (matching branch, lane branch, no bead
  in the message, non-fleet namespace); and the override passes the real instance while reporting itself.
- Delivery contract, driven: `patch -p1 --fuzz=0` applies cleanly onto the recorded preimage and creates all three
  files; the **delivered** fixture, run from the applied tree, is 10 of 10.
- Limitation, stated rather than hidden: the install block appends a marked block to `${hdir}/commit-msg`. If an
  existing `commit-msg` hook exits early, our block will not run; the marker guard means a re-install adds no
  duplicate, and nothing is clobbered.
