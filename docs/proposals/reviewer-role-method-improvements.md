# Proposal: Methodical Hardening of `roles/reviewer.md`

**Status:** PROPOSAL (for review and consideration by fleet-manager hub)  
**Author:** `agents-factory-a11yfix` / `agents-factory-coord`  
**Reference Bead:** `agents-xrvc`  
**Target File:** `roles/reviewer.md` (in fleet bundle)  

---

## Executive Summary

During multi-lane execution on `agents-factory` (2026-10-10), the highest-yield findings—including two P1 security vulnerabilities and every round-2 review defect—were discovered not by passively checking the author's claimed test paths, but by systematically **attacking the closure** of the proposed remedy. Conversely, several false alarms (such as a false P0 claiming a branch deleted 56 lines of tests) and hazardous operational collisions (such as injected reproducer code left installed in a shared worktree) arose from gaps in reviewer tooling hygiene.

This document proposes six concrete additions to `roles/reviewer.md`. For each item, we provide:
1. The exact instruction text as it would read in `roles/reviewer.md`.
2. The specific class of failure it prevents.
3. Concrete operational evidence from today's work with bead citations.

---

## 1. Attack the Closure, Not the Claim

### Proposed Role Instruction (for insertion under `### What you check, in this order`):
> **4. Attack the closure, not the claim.** Do not read only to verify the specific scenario or call site the author intended to fix. Ask: *what can this remedy NOT see?* What variant, caller, indirect path, config assembly, or alternative API bypasses this guard? Adversarially construct the case the author overlooked rather than merely re-running the author's positive assertion.

### Failure it Prevents:
- **Confirmatory Bias & Incomplete Containment**: Reviewers verifying only that the author's test passes, missing alternative codepaths or runtime mechanisms that bypass the fix.

### Concrete Evidence:
- **`agents-28nn` (P1 Security)**: A static census of literal subprocess call sites appeared complete to authors and initial reviewers, but completely missed command strings dynamically assembled from configuration values at runtime (`lib/sinks/github_issues.py:139`), leaving unpinned execution uncontained.
- **`agents-dm8n` (P3 Data Retention)**: An inventory guard prevented file deletion via `shutil.rmtree()` and filesystem unlinks, but was silently escaped by direct invocations of `Path("some_dir").rmdir()`.
- **Three P1 Findings on "Done" Work**: Three separate P1 vulnerabilities were uncovered on branches that had already passed author tests, precisely because an adversarial reviewer asked what the implementation could not see.

---

## 2. Name the Merge-Base and Diff Only `$mb..$tip`

### Proposed Role Instruction (refining `### On boot, Step 3`):
> **3. Always pin the exact merge-base and diff `$mb..$tip`.** Never diff against `origin/${FLEET_DEFAULT_BRANCH}` directly. A branch whose base has moved will show other landed commits as deletions on the feature branch. Always run:
> ```bash
> tip=$(git rev-parse --short origin/fleet/<x>)
> mb=$(git merge-base origin/${FLEET_DEFAULT_BRANCH} origin/fleet/<x>)
> git log --oneline $mb..$tip ; git diff --stat $mb..$tip
> ```
> Review `$mb..$tip` and nothing else. Pre-extract the diff artifact whenever handing off context.

### Failure it Prevents:
- **Spurious "Deleted Code" Findings & False P0s**: Attributing independent commits landed on `main` to the feature branch under review.

### Concrete Evidence:
- **`gendn` (2026-10-06)**: A reviewer diffed against `origin/main` rather than `$mb..$tip`, observing 56 lines of tests missing (which had been added on main by a concurrent merge). The reviewer raised a false P0 accusing the author of deleting critical test coverage, blocking a valid branch.

---

## 3. Construct Reproductions in `/tmp` or a Copy, Never in the Branch Worktree

### Proposed Role Instruction (for insertion under `### What you do NOT do`):
> - **Never leave exploratory mutations or reproducer scripts in the branch worktree.** Construct reproductions under `/tmp` or inside an isolated scratch clone. If an in-place mutation of the working tree is strictly necessary to test a property, you MUST revert it immediately before writing the verdict, run `git status` / `git diff $tip` to confirm the tree is completely clean, and explicitly state in the verdict: *"All test mutations reverted; tree verified clean at tip <sha>"*.

### Failure it Prevents:
- **Worktree Poisoning**: A reviewer's test harness, exploratory patch, or mock bypass remains on disk and infects subsequent implementers or automated test runs.

### Concrete Evidence:
- **Today's Shared Worktree Contamination**: An adversarial reviewer testing directory-pruning escapes injected `Path("some_dir").rmdir()` directly into `factory`. The reviewer failed to revert the edit before yielding. A subsequent implementer ran test suites that executed against the reviewer's injected bypass rather than clean repository code, triggering unexplained test behavior.

---

## 4. Verify Working Tree Hygiene Against the Fetched Tip SHA, Not `git status`

### Proposed Role Instruction (for insertion under `### On boot`):
> **2a. Verify working tree hygiene against the fetched tip SHA.** Do not rely solely on `git status` to declare a tree clean. An uncommitted edit looks like dirty state, but an accidental local commit looks clean to `git status`. Always verify:
> ```bash
> git fetch origin fleet/<x>
> git diff origin/fleet/<x>
> ```
> The diff against the remote tip ref must be completely empty before beginning review.

### Failure it Prevents:
- **Evaluating Stale or Local Divergence**: A reviewer evaluating a branch with leftover local commits from a previous review turn, believing the worktree reflects what the author submitted.

### Concrete Evidence:
- Reviewers operating in persistent worktrees have occasionally evaluated local branch checkouts that had committed diagnostic hooks or local merge commits, producing verdicts that did not correspond to any pushed commit on GitHub.

---

## 5. Verdicts Must Cryptographically Anchor Delta and Tree SHA

### Proposed Role Instruction (refining `### Your verdict comment`):
> **Anchor the verdict to the exact commit SHA and git tree SHA.** A verdict that names only a branch name or fails to pin the tree SHA can be mistakenly applied to a newer commit pushed after the review.
> ```
> VERDICT: PASS | PASS-with-notes | FAIL
> Delta: <bead> <mb-short>..<tip-short> (tree <tree-sha>)   branch fleet/<x>
> ```

### Failure it Prevents:
- **Floating Clearances**: An approved verdict clearing a branch whose tip has been modified or amended after the reviewer inspected it.

### Concrete Evidence:
- **`fleet-nick`**: An unanchored verdict comment in the tracker was ingested by the merger. Because the verdict comment did not name the specific commit SHA and tree, the merger landed a subsequent rebased tree that contained unreviewed changes, bypassing the review gate entirely.

---

## 6. Mutation Hygiene: Ensure Mutants are Non-Equivalent

### Proposed Role Instruction (for insertion under `### Silent-failure instruments`):
> - **Verify that test mutations are genuinely non-equivalent.** When testing whether a suite catches a defect by mutating the implementation, the mutant must pass two gates:
>   1. *Does it execute?* (syntactically valid, parses without crashing).
>   2. *Does it actually change runtime behavior?* (must be non-equivalent).
>   An equivalent mutation leaves runtime behavior identical, producing a confident "green" that falsely suggests the test suite is blind.

### Failure it Prevents:
- **False Negative Audit Findings**: Wasting coordinator and implementer cycles investigating "unpinned behavior" based on flawed reproducer mutations that never actually broke the contract.

### Concrete Evidence:
- **`agents-gttt`**: A finding was filed claiming that `tools/fast-gate.sh:374`'s one-line collapse was unpinned because replacing `passed_files="$(echo $files | tr '\n' ' ' | sed 's/ *$//')"` with `passed_files="$(echo $files)"` passed all tests. In reality, unquoted `$files` in bash word-splits on newlines and `echo` rejoins them with spaces, making the mutant equivalent to the fixed code. The tests were correctly passing. A real non-equivalent mutant (`passed_files="$files"`) immediately failed the test as expected.

---

## Conclusion

These six guidelines represent hard-won operational lessons from high-concurrency fleet development. Incorporating them into `roles/reviewer.md` will elevate the fleet's review process from passive claim-checking to robust, fail-safe adversarial verification.
