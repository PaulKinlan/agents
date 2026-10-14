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
  | `tests/fleet-check-tree-stability.test.sh` (this patch applied) | 23,032 | `2afee4019dec28f061f0f9d5cd5be78ea2c11043b84bcd9e9d844b616a379d32` |

  The two base hashes were reproduced here by applying `patches/fleet-check-witness-content.patch` to the
  deployed files with `git apply` and hashing the result; they match the values that patch and the
  `state-names-outcome` re-cut both record, so the base this is a claim about is the same base those two are.
- **Revision:** FIRST. Nothing has been applied anywhere; the live `~/fleet` is read-only to a lane and was not
  written to.
- **Disposition:** DELIVERY ONLY. It refuses nothing and is safe to apply in any order *relative to artifacts
  that do not touch these two files*. It is NOT order-free relative to
  `patches/fleet-check-state-names-outcome-recut-onto-witness-content.patch`, which is cut against the same two
  base hashes and rewrites the same test file (see SEQUENCING below).
- **Patch artifact hash:** `d47708b1db8231b6e69dcd4160f2aa979d3abe6de2cc5fc97ceac2b4664bae55` (142 lines).

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
   needs.** `run_arm` gains a 7th optional argument, `FIXTURE_KIND` (`file` default; `inrepo-directory` for arm 9),
   so an arm can build the repo's actual topology: `link -> d` with `d/inner` tracked **beside** the link, exactly
   as `skills` and `agents/...` are both in this repo's `git ls-files`. Arm 9 creates AND removes an entry inside
   that followed directory during the run and expects **PASS** under the content witness: a directory's inode
   ctime is not content. It is **RED on the deployed gate** (see VERIFICATION), which is the point — this is the
   acceptance for the face agents-eea2 measured, and there was none.
   *Revision note, recorded rather than tidied away:* the first version of this arm aimed the link at a directory
   **outside** the fixture repo. Cross-family review (P3, below) found that this pins a different topology — no
   tracked entries beside the link — so the arm did not pin the real case. The fixture is now in-repo, and the
   external-directory form was not kept: an unused knob is dead code, and the in-repo form is the stronger arm.
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

**The topology under test is the repo's own, and it is red-first on its own.** Before the suite drives, the
IN-REPO shape (`link -> d`, both tracked, one tracked entry `d/inner` beside the link) was digested with each
form, extracted from its own artifact bytes, around a create-and-remove of `link/probe`:

| form | before | after | reading |
|---|---|---|---|
| deployed (metadata) | `f51cca7e509ad137` | `1d645b3502aa9a38` | **moves** → STALE |
| bp6m (content) | `1a6eca9348499be7` | `1a6eca9348499be7` | stable → PASS |
| this patch | `79635f7fcae34324` | `79635f7fcae34324` | stable → PASS |

(The first drive of this case by the author was **vacuous** — it wrote to the wrong working directory, so nothing
was created and "no movement" proved nothing. It was caught by the review round below and re-run; the numbers in
the table are from the corrected drive. Recorded because a probe that silently does nothing is the same defect
class this bead is about.)

The hub's own suite is the instrument and it takes `CHECK_OVERRIDE`, so all four drives below are runs of that
suite; each got its own directory, its own gate binary and its own private heavy queue (2 slots), so none
queued behind the merger or behind another. Gate and suite hashes are named per run because a verdict is a
claim about a tree.

| run | gate | suite | result |
|---|---|---|---|
| 1 | this patch (`65a32220`) | this patch (`2afee401`) | **30 passed, 0 failed** |
| 2 | bp6m only (`04acfaae`) | this patch (`2afee401`) | **30 passed, 0 failed** |
| 3 | deployed (`455e3b05`) | this patch (`2afee401`) | 17 passed, 13 failed — **RED, as designed** |
| 4 | deployed (`455e3b05`) | deployed (`8cc667da`) | 14 passed, 0 failed (control) |

- **Arm 9 is green with the content witness (run 1):** `ok directory-symlink-churn: verdict recorded PASS
  (tree=43cdd128 status=[])`.
- **Arm 9 is RED on the deployed gate (run 3):** `FAIL directory-symlink-churn: expected PASS: state=STALE
  tree=43cdd128 actual=43cdd128 status=[] reason=the worktree's CONTENT changed during the run without a commit
  (HEAD^{tree} is still 43cdd128e59c6aaade010c9baea04229affd2b22), so the suites read bytes that tree does not
  describe`. That sentence — a tree whose `HEAD^{tree}` never moved, recorded as a content change — is the
  defect agents-eea2 measured, reproduced deliberately against a settled tree.
- **The arm's fixture tree is IDENTICAL in runs 1, 2 and 3 (`43cdd128`), so the gate is the only variable.**
  The same fixture, the same suite, three gates: PASS, PASS, STALE. That is a sharper discrimination than a
  differing fixture would give, and it is why the fixture is built inside the repo rather than pointed at a
  directory outside it.
- **The `bin` half is cost-only, and run 2 is how that is known rather than claimed:** the same suite against
  bp6m's own gate is 30 passed / 0 failed, with the same `directory-symlink-churn: verdict recorded PASS
  (tree=43cdd128)`. A change that altered the verdict for any arm would show up as an arm disagreeing between
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

### Review history (who formed each verdict, and what it covered)

- **Cross-family READ-ONLY assessment** (`openai-codex/gpt-6-sol` subagent; it cannot comment on a bead, so the
author lane is transcribing and naming itself as the transcriber; the review covered the artifact at suite hash
`82d43486`, BEFORE the arm-9 fixture fix below): `VERDICT: PASS`, explicitly *"not executable clearance"*,
because that agent's own policy forbids shell commands. It confirmed the marker-path claim from the source and
the four-run log by inspection, found **no inconsistency between the write-up's table and the log**, and marked
the cost and line-set-equality claims UNVERIFIABLE **for lack of execution, not as disagreements**. Its one
finding was P3: arm 9's fixture aimed the link at a directory OUTSIDE the fixture repo, which pins a different
topology from the repo's own `skills -> agents` (inside, with tracked entries beside it), so the arm did not pin
the real case.
- **That P3 is FIXED in this revision, not noted away.** Arm 9 now builds the in-repo topology with
`FIXTURE_KIND=inrepo-directory`, the runs above were repeated on it, and fixing it also caught a defect in the
author's own probe for the case (a write to the wrong working directory made the first in-repo drive vacuous —
recorded in VERIFICATION rather than quietly re-run). Because the fixture changed, the suite hash moved from
`82d43486` to `2afee401`, and the assessment above is a claim about the earlier hash only.
- **The executable reproduction is with a reviewer lane** (`rev-eea2`, spawned for a cross-family model):
base-hash reproduction, fuzz-free `git apply --check`, the batch-abort control, the edge-case repos (unreadable
file, broken link, space/newline paths), the in-repo vs external directory link, and the digest-consumer audit are
its job, and its verdict is posted as its own comment on the bead. **This artifact is not queued as cleared on the
read-only assessment alone.**

### SEQUENCING — stated plainly, because this is the w43q collision family

`patches/fleet-check-state-names-outcome-recut-onto-witness-content.patch` is cut against **the same two base
hashes** as this patch and rewrites the **same** test file (its hunks are in `run_arm`'s call sites and the
`.witnessed` string). Therefore:

- **This patch and that re-cut collide in both orders**, exactly as bp6m and lgdv did. Both touch
  `tests/fleet-check-tree-stability.test.sh` in the same regions, and this one additionally rewrites the digest
  function the re-cut leaves alone.
- **The cheap resolution is a re-cut of whichever lands second, and it is mechanical:** apply bp6m, do not apply
  the other change, and hash. If `bin/fleet-check` is `65a32220` / the test file is `2afee401`, this patch is in
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
