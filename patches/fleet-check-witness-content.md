## `fleet-check-witness-content.patch` (agents-bp6m)

- **Target repository:** `PaulKinlan/fleet`
- **Target files (two, and the second is not optional):**
  - `bin/fleet-check` — the fingerprint (`worktree_digest`), the new `worktree_content_digest`, the
    comment above `digest_start`, and the published `.witnessed` scope.
  - `tests/fleet-check-tree-stability.test.sh` — the arms whose expectation the change moves, the new
    red-first arm for the defect, and a **pre-existing flaw in that file's premise check** (below).
- **Baseline hashes (the live bytes this patch was generated against and applies to):**

  | file | baseline sha256 | patched result |
  |---|---|---|
  | `bin/fleet-check` | `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498` | `04acfaae1a9c3cf0d1625e2f68003b585a6ba6bf066da07ff527d79656d1a14f` |
  | `tests/fleet-check-tree-stability.test.sh` | `8cc667daef33635fddcb648415df99defa329cc64f84dc4f860fdc4710b57067` | `01963652b07bb4e8aa42cccbf7513bc2847e9168b8cfbf5f59b691cb3e8152af` |

- **Revision:** SECOND revision. The first FAILED cross-family review on **agents-vl8c**: its premise
  fix read the gate's log (correct) but kept the launcher's output as a **fallback**, so a log that was
  readable and did *not* carry the marker fell through to text that contains the command — absence of
  evidence read as evidence found elsewhere, the same defect class one branch over. The fallback is gone
  and the two states are now explicit; **all evidence produced before this revision is void** (the test
  file's bytes changed, and this time the change is in the acceptance instrument itself).
- **Baseline hashes are unchanged** (`bin/fleet-check` still `455e3b05…`): this revision touches only the
  test file, so the gate half of the patch is byte-identical to the revision reviewed against the same
  baseline. Nothing has been applied anywhere — the live `~/fleet` was never written to.
- **Disposition:** DELIVERY ONLY, and unlike the agents-0r1c patch there is **no ordering hazard**: this
  changes how the gate *witnesses* a tree, not whether it refuses anything, so it can be applied in any
  order. It does change behaviour a reader may rely on, so the bound it introduces is stated in the
  record itself (see below) rather than only in this file.

### Problem Statement

`worktree_digest()` fingerprinted five things: `HEAD^{tree}`, `git status --porcelain
--untracked-files=no`, `git diff HEAD`, and two `stat` lines over the tracked file list
(`'%n %s %z'` — **size and nsec ctime**, the second with `-L`). Everything except the `stat` lines is
content-addressed.

The `stat` lines are not. `ctime` advances on **every write**, so a suite that rewrites a tracked file
and produces **byte-identical** content moves the fingerprint, the end reading differs from the start
reading, and `finish()` records **STALE** — *"the worktree's CONTENT changed during the run"* — for a
tree whose bytes never changed and which the suites read correctly. A STALE is not a verdict: the
record is not cached, and a lane gets *"NOT a verdict … re-run against a settled worktree"* with no way
to settle a tree that nothing is wrong with.

**This is intermittent, by nature, and the acceptance is written for that (coord's own correction to
its earlier claim):** it fires when a suite selected for the changed files touches a tracked file inside
the run window — a regenerated fixture, a re-serialised snapshot, a formatter, a test that writes its
input back. It is not "every gate on such a repo is broken"; it is "the gate reports that it cannot tell
when it can".

### Why CONTENT, and why the per-file pass is not redundant with `git diff HEAD`

The obvious objection is that `git diff HEAD` already covers working-tree content, so a per-file content
pass adds cost for nothing. It does not, and this was measured rather than argued: **`git diff HEAD`
consults the index**, so a tracked file marked `assume-unchanged` (or `skip-worktree`) can be rewritten
with completely different bytes and `git diff HEAD --name-only` prints **nothing** — while
`git hash-object` on that path sees the new content. Measured in a scratch repo: after
`git update-index --assume-unchanged other` and `printf tampered > other`, `git diff HEAD --name-only`
was empty and the content digest had moved. A witness that reads the bytes on disk is not a second
opinion about the same thing; it is the only reading that no index state can hide from.

### Changes

1. **`worktree_content_digest()`: the bytes of every tracked path in the working tree, as one hash.**
   No mtime, no ctime, no size. `git hash-object` **follows a symlink** (measured: it hashes the
   target's content, not the link's stored path string), so a tracked link whose target lives outside
   the repository contributes its target's bytes and a target rewrite is witnessed through the link —
   fleet-sohq's protection survives without a second pass over the file list.
2. **The two `stat` lines are replaced by that digest**, and the reasoning in the comments is rewritten
   rather than left describing a form that is gone.
3. **The happy path is the fast path, and its failure mode is handled.** `git hash-object` **aborts its
   entire batch** on a path it cannot read: measured, one broken symlink in a six-path repo produced
   **two** hashes and exit 123 with nothing in the output saying four paths were skipped — a silently
   truncated witness is worse than a slow one. So the exit status is checked, and on failure every path
   is hashed individually with a `unreadable-as-content <path>` marker for the ones that have no content
   (broken link, link to a directory, submodule). Verified stable across repeated readings.
4. **The published `.witnessed` scope now names the bound**, because a PASS whose scope is silent about a
   known floor is the false-green shape this file guards elsewhere. The test asserts the bound is present
   in `.witnessed` for **every** arm.

### The bound this buys, stated plainly

Witnessing **content** at the two ends of the run means a write that is **fully reverted before the run
stops** leaves both readings identical and is **not witnessed**. The old `ctime` form did see it, so this
is a real narrowing of the guarantee, and it is the whole reason this patch touches the hub test:
arms that asserted STALE only because `ctime` had moved (a round trip, and a round trip inside one
interval) would otherwise have gone on passing while the defence they stand for was gone.

The guarantee after this patch is: **"the tree whose content is recorded is the tree the suites read,
compared at the two ends of the run"** — not *"no byte was ever written mid-run"*. Closing the gap needs
continuous observation of writes (an inotify-style watcher: a new long-lived process beside the gate),
not a digest, and that is out of scope here. The trade is accepted deliberately: the old form produced a
false STALE (no verdict at all) on healthy runs, while this bound only hides a flip that is fully
reverted inside the run — and that is now stated in every record's `.witnessed`.

### Cost (measured, because the fast gate is a contract)

`worktree_digest` on a clean tree, three runs each, wall clock per run:

| tracked files | old (metadata) | new (content) |
|---|---|---|
| 381 (this repo's worktree) | 0.020s | 0.030s |
| 2280 (a larger checkout) | 0.023s | 0.027s |

Both readings are inside a gate that is bounded at minutes, so the content pass is not a measurable
fraction of a run. The fallback path (only reached in repos with unreadable-as-content paths) is slower
by construction — one `git` process per path — and is not on any normal path.

### Verification

- **Applies cleanly** with `git apply --check` against a pristine copy of both hub files, and from
  `~/fleet` itself in check mode; the applied result byte-matches the two files every drive below was run
  against; `bash -n` is clean for the gate and for the test.
- **The hub test is the instrument, and it has a `CHECK_OVERRIDE` hook, so the SAME suite was run
  against both gates** (`CHECK_OVERRIDE=<fleet-check>`), each in its own heavy queue (2 private slots, so
  it can never queue behind the merger):
  - **patched test + patched gate → 27 passed, 0 failed** (8 arms × 3 assertions + the 3 premise-rule
    cases), **no SKIPs**, including `same-bytes-rewrite: verdict recorded PASS` — the acceptance — and
    `symlink-target-rewrite: verdict recorded STALE` still being met by content.
  - **patched test + UNPATCHED gate → 16 passed, 11 failed**, and the failures are exactly this change:
    `same-bytes-rewrite: expected PASS, state=STALE` (the defect, reproduced red-first),
    `round-trip`/`short-round-trip: expected PASS, state=STALE` (the old `ctime` detection), and the
    bound assertion failing because the old scope does not state it.
  - **unpatched test + UNPATCHED gate → 14 passed, 0 failed**: nothing that the hub has today regresses.
- **Six behaviours of the new digest, driven directly** (not read): a same-bytes rewrite leaves it
  unchanged; a real byte change moves it; a tracked symlink to a file **outside** the repo moves it when
  that target changes; a batch containing a broken and a directory symlink exercises the fallback and is
  stable across two readings; adding/removing such a path moves it; and an `assume-unchanged` rewrite
  moves it while `git diff HEAD` reports nothing.
- **Two flaws in the test file's premise check are fixed here** (the second one found by REVIEW, after
  the first fix — which is why this revision exists). Both are the same class: a check that fails to find
  something being reinterpreted as finding it somewhere else.
  1. The premise (`"the worktree never changed"`) grepped the **launcher's** output, which is the
     `started the FAST gate for <sha> (`<command>` …)` line — it contains the **command text** — so any
     arm whose marker appears literally in its own command satisfied its premise without the command
     having produced that output. Measured: an arm whose marker came from `$(cat input)` had to SKIP,
     while arms with literal markers verified nothing at all.
  2. **agents-vl8c (review finding, fixed here):** the fix for (1) kept `$T/out` as a *fallback*, so when
     the log **was** readable and simply did **not** carry the marker, the expression fell through to the
     launcher text and reported the premise as met. The reviewer drove it: log = `fast-gate: passed`,
     launcher = `started gate (exit 0; echo rewrote-identical-bytes)`, marker = `rewrote-identical-bytes`
     → the premise expression answered "found" with no marker in the log at all, so the same-bytes arm
     could certify a premise its command never met.
     The rule is now a function with **three distinct answers** — the log is readable and carries the
     marker (0), the log is readable and does **not** (1, premise not met, **no fallback**), the log cannot
     be read at all (2, its own answer, also with no fallback, because the only other text available is
     the command) — and the arm loop SKIPs loudly in both 1 and 2 with different reasons. Three unit cases
     assert the rule itself before any arm uses it, including the reviewer's exact scenario.

### Hub Application

```bash
cd ~/fleet
git apply --check /path/to/fleet-check-witness-content.patch   # expect clean
git apply /path/to/fleet-check-witness-content.patch
bash -n bin/fleet-check && bash -n tests/fleet-check-tree-stability.test.sh
bash tests/fleet-check-tree-stability.test.sh     # the suite is the acceptance; ~40s, its own slots
```

No sequencing and no host repair step: this patch refuses nothing. What a reader should expect to
change is narrow and recorded in the log: a run whose suites rewrote a tracked file with identical bytes
now reads a genuine verdict instead of STALE, and every record's `.witnessed` says which writes the
witness cannot see.
