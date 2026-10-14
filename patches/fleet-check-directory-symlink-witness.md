## `fleet-check-directory-symlink-witness.patch` (agents-eea2)

- **Target repository:** `PaulKinlan/fleet`
- **Target files (two):** `bin/fleet-check` — the fast path of the content digest `worktree_content_digest`, and
  `tests/fleet-check-tree-stability.test.sh` — its arm 9 plus the one fixture knob that arm needs.
- **THIS PATCH IS CUT AGAINST agents-bp6m's INSTALLED RESULT, not against the deployed files.** It is a member
  of bp6m's stack, not a competitor to it: the deployed `bin/fleet-check` has no `worktree_content_digest` at
  all, so the hunk below has nothing to attach to until bp6m is applied. The base claim, in bytes:

  | file | bytes | sha256 |
  |---|---|---|
  | `bin/fleet-check` (deployed, for the lineage) | 51,977 | `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498` |
  | `bin/fleet-check` (THE BASE: bp6m applied) | 54,818 | `04acfaae1a9c3cf0d1625e2f68003b585a6ba6bf066da07ff527d79656d1a14f` |
  | `bin/fleet-check` (this patch applied) | 56,262 | `65a32220caed322e9aeaa1ed815def2eb522d0e3cdf74115e28588c43bcc32e5` |
  | `tests/fleet-check-tree-stability.test.sh` (deployed, for the lineage) | 12,295 | `8cc667daef33635fddcb648415df99defa329cc64f84dc4f860fdc4710b57067` |
  | `tests/fleet-check-tree-stability.test.sh` (THE BASE: bp6m applied) | 19,510 | `01963652b07bb4e8aa42cccbf7513bc2847e9168b8cfbf5f59b691cb3e8152af` |
  | `tests/fleet-check-tree-stability.test.sh` (this patch applied) | 22,113 | `82d43486bdaa90b44a0006f93f9ebcde1cc7fa511012fff5b7ec9ba12701e7d2` |

  The two base hashes were reproduced here by applying `patches/fleet-check-witness-content.patch` to the
  deployed files with `git apply` and hashing the result; they match the values that patch and the
  `state-names-outcome` re-cut both record, so the base this is a claim about is the same base those two are.
- **Revision:** FIRST. Nothing has been applied anywhere; the live `~/fleet` is read-only to a lane and was not
  written to.
- **Disposition:** DELIVERY ONLY. It refuses nothing and is safe to apply in any order *relative to artifacts
  that do not touch these two files*. It is NOT order-free relative to
  `patches/fleet-check-state-names-outcome-recut-onto-witness-content.patch`, which is cut against the same two
  base hashes and rewrites the same test file (see SEQUENCING below).
- **Patch artifact hash:** `f11f13baa58e474e9680168afd383a4d456d5fdb331317cc282db8c93832130c` (119 lines).

### Problem Statement

`fleet-check` witnesses what the suites could read by fingerprinting four things around the run: `HEAD^{tree}`,
the porcelain, `git diff HEAD`, and — since agents-bp6m — the **content of every tracked path**. `worktree_digest`
is called at **both ends** of every run, so its cost is paid twice.

bp6m's content pass has a fast path and a slow path. The fast path is one `git hash-object` for the whole file
list; the slow path is one `git` process per path, taken when the batch fails. bp6m records the fast path at
0.030s for 381 tracked files and describes the slow one as "slower by construction" and "not on any normal
path".

**Both statements are false for the repo that prompted agents-eea2.** This repo tracks a symlink to a
DIRECTORY: `skills -> agents`, mode `120000`, the only one in the tree. `git hash-object` cannot read a
directory, so it aborts the **entire batch**:

    $ git ls-files -z | xargs -0 -r git hash-object --no-filters -- >/tmp/out 2>/tmp/err
    $ echo $?; wc -l </tmp/out; head -1 /tmp/err
    123
    326
    fatal: Unable to hash (null)

493 tracked paths in, 326 hashes out, 167 paths dropped by the abort. **The slow path is not an edge case in
this repo — it is the only path that ever runs.** Measured on the worktree, three runs each, with
`worktree_digest` extracted from the artifact bytes themselves (see MEASUREMENT METHOD):

| form of `worktree_digest` | per digest | per gate run (called twice) |
|---|---|---|
| deployed (metadata: `size + nsec ctime`) | 21–24 ms | ~45 ms |
| bp6m (content, unfiltered batch) | 904–910 ms | ~1.8 s |
| **this patch** (content, filtered batch) | 61–66 ms | ~0.13 s |

So bp6m's content witness costs about **45×** the metadata form it replaces on this repo, not the ~1.5× its
write-up records, and the recorded 0.030s describes a repo with no directory link. That is the cost of the
directory-target face that agents-eea2 is about, and it was not measured when the face was decided.

### The question the hub left open, answered

The `state-names-outcome` re-cut records the hub as having "not decided whether to close bp6m's
directory-target-replacement gap", on the prior that "a missed alarm is worse than a noisy one". agents-eea2
asked the hub to confirm bp6m against the directory case. The measurement says **no witness change is needed**:

- `git hash-object` fails on a directory symlink, so bp6m's fallback records `unreadable-as-content <path>` —
  a stable identity marker. The marker is identical at both readings, so **the followed directory's inode ctime
  no longer moves the digest**, and the false STALE is gone. That is exactly the ask ("witnessed by its
  tracked-content contribution, not by the directory inode ctime").
- The alarm that the metadata form raised here was **not about content**: it fired when
  `tests/test_report_schema.py` created and removed an UNTRACKED scratch file inside the followed `agents/`,
  and untracked debris is outside this witness by design (fleet-arx8 — counting a gate's own byproducts as a
  tree mutation is what turned four of five union-gate failures into STALE). The tracked bytes under that
  directory are witnessed path by path either way. So this is not a missed alarm; it is a false one.
- A content LISTING of the directory would be worse than the marker: it would add back exactly the untracked
  entries the witness deliberately ignores.

What was missing was not a witness fix — it was the **pin** and the **cost**, and this patch is those two.

### What it changes

1. **`bin/fleet-check`: the batch is filtered, so the fast path is reachable again.** Paths whose content cannot
   be read AS content — a link to a directory, a broken link, a submodule — are filtered out *before* the
   batch and recorded by the **same** `unreadable-as-content` marker the fallback recorded for them; the
   remaining paths go into one `git hash-object`. The fallback is kept, and now covers what it is actually for:
   a path that IS a file but unreadable (a permission, a race), where `-f` is true and the batch can still
   abort. Cost after the filter: **61–66 ms**, i.e. ~1.7s saved per gate run on this repo.
2. **`tests/fleet-check-tree-stability.test.sh`: arm 9 — `directory-symlink-churn` — plus the fixture knob it
   needs.** `run_arm` gains a 7th optional argument, `TARGET_KIND` (`file` default, `directory`), so an arm can
   point the tracked symlink at a directory containing a file. Arm 9 creates AND removes an entry inside that
   followed directory during the run and expects **PASS** under the content witness: a directory's inode ctime
   is not content. It is **RED on the deployed gate** (see VERIFICATION), which is the point — this is the
   acceptance for the face agents-eea2 measured, and there was none.
3. **No witness semantics change**, and that is measured rather than asserted (next section).

### The witness is unchanged — measured, not argued

A fixture repo carrying every path kind the filter has an opinion about — a regular file, a symlink to a file,
a symlink to a directory, a broken symlink, a symlink to a directory outside the repo — was digested with both
the bp6m form and this form, each extracted from its own artifact bytes:

| digest lines (sorted) | bp6m form | this form |
|---|---|---|
| `<hash of f>` (once for `f`, once for `flink` through the link) | 2 | 2 |
| `<hash of d/inner>` | 1 | 1 |
| `<hash of notfirst>` | 1 | 1 |
| `unreadable-as-content broken` | 1 | 1 |
| `unreadable-as-content dlink` | 1 | 1 |
| `unreadable-as-content extlink` | 1 | 1 |

The sorted line sets are **identical** (`sha256` of the sorted set `8592e440533eff410ba30ea541faccf48eb0f9bc2892e7c35bcec8e55ac80677`
for both forms). Same coverage, same markers, same follow-through-the-link for a symlink to a file (fleet-sohq
survives). The only difference is line ORDER within the digest stream — markers are emitted while scanning,
hashes after — so the digest VALUE for such a repo changes once. That value is compared only against the other
reading of the same run: it is never published in the record and never cached (`digest_start` / `digest_end`
are the only two consumers, and the record's cache key is `HEAD^{tree}`), so nothing depends on it.

### Verification

The hub's own suite is the instrument and it takes `CHECK_OVERRIDE`, so all four drives below are runs of that
suite; each got its own directory, its own gate binary and its own private heavy queue (2 slots), so none
queued behind the merger or behind another. Gate and suite hashes are named per run because a verdict is a
claim about a tree.

| run | gate | suite | result |
|---|---|---|---|
| 1 | this patch (`65a32220`) | this patch (`82d43486`) | **30 passed, 0 failed** |
| 2 | bp6m only (`04acfaae`) | this patch (`82d43486`) | **30 passed, 0 failed** |
| 3 | deployed (`455e3b05`) | this patch (`82d43486`) | 17 passed, 13 failed — **RED, as designed** |
| 4 | deployed (`455e3b05`) | deployed (`8cc667da`) | 14 passed, 0 failed (control) |

- **Arm 9 is green with the content witness (run 1):** `ok directory-symlink-churn: verdict recorded PASS
  (tree=88cba735 status=[])`.
- **Arm 9 is RED on the deployed gate (run 3):** `FAIL directory-symlink-churn: expected PASS: state=STALE
  tree=189c57d1 actual=189c57d1 status=[] reason=the worktree's CONTENT changed during the run without a commit
  (HEAD^{tree} is still 189c57d1fb862c7e65b6abc364291f1dbbb73a63), so the suites read bytes that tree does not
  describe`. That sentence — a tree whose `HEAD^{tree}` never moved, recorded as a content change — is the
  defect agents-eea2 measured, reproduced deliberately against a settled tree.
- **The `bin` half is cost-only, and run 2 is how that is known rather than claimed:** the same suite against
  bp6m's own gate is 30 passed / 0 failed, with `ok directory-symlink-churn: verdict recorded PASS
  (tree=f5fbadba)`. A change that altered the verdict for any arm would show up as an arm disagreeing between
  run 1 and run 2, and none does.
- **The control (run 4) is 14 passed / 0 failed**, which is the number bp6m recorded for the deployed pair — the
  instrument has not moved under either artifact.
- The 13 failures in run 3 are all of bp6m's arms 3/5/8 plus arm 9 expecting the content witness's states, and
  the bound assertion failing in every arm because the deployed `.witnessed` does not state the round-trip
  bound. That is the shape bp6m recorded for its own red-first run (16 passed / 11 failed) plus arm 9 and its
  bound assertion — i.e. the same change, one arm larger.

**MEASUREMENT METHOD (so a reader can dispute the instrument rather than the number).** Every timing and every
digest above was produced by `awk`-extracting the named function *from the artifact bytes* and running that, so
the function under measurement is the one in the file and not a hand-written equivalent; three runs each, wall
clock, on the worktree at 493 tracked paths. The batch-abort control is the literal
`git ls-files -z | xargs -0 -r git hash-object` command with its exit status and line count captured.

**What is NOT verified here:** nothing runs the gate twice against the same tree to compare a cached digest,
because no such comparison exists in the tool; and the 1.7s saving is a property of THIS repo's path count and
ONE directory link, not a general claim about other repos.

### SEQUENCING — stated plainly, because this is the w43q collision family

`patches/fleet-check-state-names-outcome-recut-onto-witness-content.patch` is cut against **the same two base
hashes** as this patch and rewrites the **same** test file (its hunks are in `run_arm`'s call sites and the
`.witnessed` string). Therefore:

- **This patch and that re-cut collide in both orders**, exactly as bp6m and lgdv did. Both touch
  `tests/fleet-check-tree-stability.test.sh` in the same regions, and this one additionally rewrites the digest
  function the re-cut leaves alone.
- **The cheap resolution is a re-cut of whichever lands second, and it is mechanical:** apply bp6m, do not apply
  the other change, and hash. If `bin/fleet-check` is `65a32220` / the test file is `82d43486`, this patch is in
  and the re-cut must be re-expressed on top of it; if they are `04acfaae` / `01963652`, bp6m alone is in.
- **This patch is the smaller of the two conflicts to resolve by hand**: it touches one function and one arm,
  while the re-cut is already an intent-merge of test-file assertions.
- **The hub's decision this patch exists to unblock** is the one the re-cut's own md records as open
  ("BP6M MAY STILL MOVE … the hub has not decided whether to close bp6m's directory-target-replacement gap").
  If the hub accepts the measurement above, bp6m does **not** need to move, and the re-cut keeps its base
  except for this stack member.

### Hub Application

    cd ~/fleet
    git apply --check /path/to/fleet-check-witness-content.patch   # bp6m first: this patch is cut against its result
    git apply /path/to/fleet-check-witness-content.patch
    git apply --check /path/to/fleet-check-directory-symlink-witness.patch   # expect clean, no fuzz
    git apply /path/to/fleet-check-directory-symlink-witness.patch
    bash -n bin/fleet-check && bash -n tests/fleet-check-tree-stability.test.sh
    bash tests/fleet-check-tree-stability.test.sh   # the suite is the acceptance; its own slots, ~1 min

### What a reader should expect to change

A gate run on a repo that tracks a symlink to a directory gets its content witness back in **~0.13s instead of
~1.8s** (this repo), with byte-identical coverage. A gate run on a repo whose suites write an untracked scratch
file inside a followed directory reads a genuine verdict instead of STALE — which is bp6m's fix, now pinned by
an arm that fails when it is undone. No record, verdict or refusal changes.
