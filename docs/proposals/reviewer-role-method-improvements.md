# Proposal: Methodical Hardening of `roles/reviewer.md`

**Status:** PROPOSAL (for review and consideration by fleet-manager hub)  
**Author:** `agents-factory-a11yfix` / `agents-factory-coord`  
**Reference Bead:** `agents-xrvc`  
**Target File:** `roles/reviewer.md` (in fleet bundle)  

---

## 1. The Core Principle: Constructing vs. Reading

> **"Constructing a case is a different activity from reading, and *review-the-diff* and *try-to-break-this* should not be two names for the same ticket, because only the second one produced anything today."**

Across a full day of multi-lane execution on `agents-factory` (2026-10-10), the empirical evidence for this distinction was demonstrated by a clear contrast:
- Dedicated adversarial construction instructions uncovered critical boundary defects:
  - `agents-28nn` (P1 security: unpinned `bwrap` executable path in PATH allowed sandbox skip on runtime-assembled commands in `lib/sinks/github_issues.py:139`).
  - `agents-q1a` (P1 correctness: field name mismatch `id` vs `rule_id` causing 10 pipeline stations to be skipped).
  - `agents-dm8n` (P3 data retention: `Path.rmdir()` escaping directory deletion protection).
  - `agents-gttt` / `agents-adhc` (P3 fast-gate reporting and abort trap gaps).
- In contrast, passive diff-reading repeatedly confirmed author intent without testing whether runtime compositions, alternative APIs, or shell execution paths bypassed the remedy.

Therefore, the central recommendation of this proposal is not simply to "review more carefully." It is that **a review ticket must explicitly state which activity it is**:
1. **Verification Review**: *"Review the diff for correctness, contract conformance, and style."* This is verification; it finds verification-shaped defects (syntax, contract mismatches, convention drift).
2. **Adversarial Closure Review**: *"Here is the closure this change claims — try to break it, and construct the case the fix cannot see."* This is adversarial construction; it finds escapes, unhandled variants, and bypass mechanisms.

When these two distinct activities share a single generic name, adversarial construction is crowded out by passive reading.

---

## 2. Concrete Role Proposals

Below are the concrete additions proposed for `roles/reviewer.md`. For each item, we provide the verbatim text for the role file, the failure mode it prevents, and concrete evidence from today's work.

---

### Proposal 1: Explicit Review Archetypes (Verification vs. Adversarial)

#### Proposed Role Instruction (for insertion under `### What you are given`):
> **Review Archetypes:** A review assignment must specify its mandate:
> - **Type A: Verification Review** (`review:verify`): Read the diff against specifications and tests for contract compliance, safety, and project standards.
> - **Type B: Adversarial Closure Review** (`review:adversarial`): Attack the boundary. Given the closure claimed by the author, construct the adversarial input, runtime assembly, or alternative API call that bypasses the guard. If a ticket does not state the archetype, assume Type B for any change touching security, containment, or authorization boundaries.

#### Failure it Prevents:
- Reviewers defaulting to passive code inspection on changes that require active failure-case synthesis.

#### Concrete Evidence:
- Across multiple review turns today, adversarial construction consistently uncovered boundary bypasses (such as `agents-28nn` and `agents-dm8n`) that were missed during initial implementation passes.

---

### Proposal 2: Attack the Closure, Not the Claim

#### Proposed Role Instruction (for insertion under `### What you check, in this order`):
> **4. Attack the closure, not the claim.** Do not read only to verify the specific scenario or call site the author intended to fix. Ask: *what can this remedy NOT see?* What variant, caller, indirect path, config assembly, or alternative API bypasses this guard? Adversarially construct the case the author overlooked rather than merely re-running the author's positive assertion.

#### Failure it Prevents:
- Confirmatory bias: checking off the happy path while leaving runtime compositions or alternative entrypoints unguarded.

#### Concrete Evidence:
- **`agents-28nn` (P1 Security)**: A static census of literal subprocess call sites appeared complete to authors, but missed command strings dynamically assembled from configuration values at runtime (`lib/sinks/github_issues.py:139`), leaving unpinned execution uncontained.
- **`agents-dm8n` (P3 Data Retention)**: An inventory guard prevented file deletion via `shutil.rmtree()` and filesystem unlinks, but was silently escaped by direct invocations of `Path("some_dir").rmdir()`.

---

### Proposal 3: Name the Merge-Base and Diff Only `$mb..$tip`

#### Proposed Role Instruction (refining `### On boot, Step 3`):
> **3. Always pin the exact merge-base and diff `$mb..$tip`.** Never diff against `origin/${FLEET_DEFAULT_BRANCH}` directly. A branch whose base has moved will show other landed commits as deletions on the feature branch. Always run:
> ```bash
> tip=$(git rev-parse --short origin/fleet/<x>)
> mb=$(git merge-base origin/${FLEET_DEFAULT_BRANCH} origin/fleet/<x>)
> git log --oneline $mb..$tip ; git diff --stat $mb..$tip
> ```
> Review `$mb..$tip` and nothing else. Pre-extract the diff artifact whenever handing off context.

#### Failure it Prevents:
- Spurious "deleted code" findings and false P0 alarms caused by attributing concurrent landings on `main` to the feature branch under review.

#### Concrete Evidence:
- **`gendn` (2026-10-06)**: A reviewer diffed against `origin/main` rather than `$mb..$tip`, observing 56 lines of tests missing (which had been added on main by a concurrent merge). The reviewer raised a false P0 accusing the author of deleting critical test coverage, blocking a valid branch.

---

### Proposal 4: Construct Reproductions in `/tmp` or a Copy, Never in the Branch Worktree

#### Proposed Role Instruction (for insertion under `### What you do NOT do`):
> - **Never leave exploratory mutations or reproducer scripts in the branch worktree.** Construct reproductions under `/tmp` or inside an isolated scratch clone. If an in-place mutation of the working tree is strictly necessary to test a property, you MUST revert it immediately before writing the verdict, run `git status --porcelain` to confirm the tree is completely clean of both tracked and untracked changes, and explicitly state in the verdict: *"All test mutations reverted; tree verified clean at tip <sha>"*.

#### Failure it Prevents:
- Worktree poisoning: leaving diagnostic bypasses, temporary mocks, or broken mutants installed in a shared worktree.

#### Concrete Evidence:
- **Worktree Contamination (`agents-dm8n`)**: An adversarial reviewer testing directory-pruning escapes injected `Path("some_dir").rmdir()` directly into `factory` and left temporary probe files in the worktree. The incoming implementer had to identify and clean up the reviewer's leftover edits before running their own tests; had they not checked, the suite would have executed against contaminated code.

---

### Proposal 5: Working Tree Hygiene: Tracked and Untracked Separation

#### Proposed Role Instruction (for insertion under `### On boot`):
> **2a. Verify working tree hygiene against the fetched tip ref AND check for untracked files.** An uncommitted tracked modification looks like ordinary dirty state, but an uncommitted *untracked* file (such as a leftover reproduction script) is completely ignored by `git diff <ref>`. Furthermore, `git fetch origin <branch>` updates `FETCH_HEAD` rather than `refs/remotes/origin/<branch>`. Therefore, verify both tracked tree identity and untracked cleanliness:
> ```bash
> git fetch origin fleet/<x>
> # 1. Verify tracked tree exactly matches the fetched remote tip:
> git diff FETCH_HEAD
> # 2. Verify no untracked files exist:
> git status --porcelain
> ```
> Both checks must be completely clean before beginning review.

#### Failure it Prevents:
- Evaluating a local tree contaminated with committed diagnostic hooks, stale local checkouts, or untracked attack scripts that survive `git diff` unnoticed.

#### Concrete Evidence:
- Reviewers operating in persistent worktrees have occasionally evaluated branches with leftover untracked test scripts or local diagnostic commits, producing verdicts that diverged from the author's pushed ref.

---

### Proposal 6: Verdicts Must Anchor Commit SHA and Delta

#### Proposed Role Instruction (refining `### Your verdict comment`):
> **Anchor the verdict to the exact commit SHA and delta.** A verdict that omits the commit SHA can mistakenly clear subsequent, unreviewed commits. Format:
> ```
> VERDICT: PASS | PASS-with-notes | FAIL
> Delta: <bead> <mb-short>..<tip-short> (@<tip-sha>)   branch fleet/<x>
> ```
> The merger (`bin/fleet-land-message`) enforces this by rejecting unpinned verdicts and accepting a changed commit SHA only when the patch delta is byte-identical. Reviewers must explicitly pin the reviewed commit SHA to provide an unambiguous audit trail.

#### Failure it Prevents:
- Floating clearances: an approved verdict comment being attributed to a diverging commit pushed after the review was completed.

#### Concrete Evidence:
- **`fleet-nick`**: Historically, an unpinned verdict comment naming no commit was ingested and attributed to whatever tip currently sat on the branch. Current fleet landing tooling (`bin/fleet-land-message`) was subsequently updated to require commit SHA pinning and enforce delta-identity fallback; this proposal reinforces that contract at the reviewer level.

---

### Proposal 7: Mutation Hygiene: Ensure Mutants are Non-Equivalent

#### Proposed Role Instruction (for insertion under `### Silent-failure instruments`):
> - **Verify that test mutations are genuinely non-equivalent.** When testing whether a suite catches a defect by mutating the implementation, the mutant must pass two gates:
>   1. *Does it execute?* (syntactically valid, parses without crashing).
>   2. *Does it actually change runtime behavior?* (must be non-equivalent).
>   An equivalent mutation leaves runtime behavior identical, producing a confident "green" that falsely suggests the test suite is blind.

#### Failure it Prevents:
- Filing false review findings based on equivalent mutants, or assuming a test suite is ineffective when it correctly passes an equivalent mutation.

#### Concrete Evidence:
- **`agents-gttt`**: A finding was initially drafted claiming that `tools/fast-gate.sh:374`'s one-line collapse was unpinned because replacing `passed_files="$(echo $files | tr '\n' ' ' | sed 's/ *$//')"` with `passed_files="$(echo $files)"` passed all tests. In reality, unquoted `$files` in bash word-splits on newlines and `echo` rejoins them with spaces, making the mutant equivalent to the fixed code. A real non-equivalent mutant (`passed_files="$files"`) immediately failed the test as expected.

---

## 3. Operational Dispatch Rule: Task Sizing & Bounded Runs

In addition to review method, today's multi-lane execution surfaced an essential rule for dispatching and scoping work:

> **"Three deadline deaths on one bead is a pattern about the run, not about the workers."**

When three workers die at the 30-minute deadline bound on the same task (twice leaving uncommitted work to be rescued), the root cause is run sizing rather than model capability. 

### Operational Guidelines:
1. **Scope to Single Deliverables**: Break complex items into bounded sub-tasks that can complete and verify within 10–15 minutes.
2. **Commit and Push Early**: Commit incremental progress and push to the remote branch after each step; a pushed branch is the only copy that survives a reset or deadline timeout.
3. **Explicit Partial Reporting**: A worker that reaches a boundary or deadline must stop and report a structured partial result with reproduction artifacts. Stopping to report a clean partial result is a **successful round**, not a failure.
