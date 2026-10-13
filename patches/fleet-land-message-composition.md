# The composed land-message delivery: input, ordering and provenance are ONE change

- **Bead:** `agents-ymh2` (coord ruling, 2026-10-13: compose `agents-2tov` + `agents-9lew` + `agents-m6fr` into one
  delivery, because all three patch the same 61KB file in the SAME PIPELINE - choose a verdict, then decide whether
  it clears this tip).
- **Status: GREEN - 358 passed / 0 failed** on the delivered series, with the ten fixtures the ruling decided now pinning
  the OUTCOME. This document is the composition's diagnosis, the ordering, and the ruling it implements.
- **The delivery is ONE FOLDED artifact** (coord's final ruling, 2026-10-13): `patches/fleet-land-message-composition.patch`
  (1147 lines, sha256 `c23794033d5bb956…`) - the stack (scanner + families + 9lew + 2tov) with m6fr's one conflicting
  hunk resolved, the ruling's ten fixtures applied, AND agents-wwss's change (its `--landed-tip`, the agents-orjl tie
  check, and agents-jlfq's two diagnosis fixes) folded in. It applies to pristine copies at fuzz 0, is byte-identical to
  the assembled tree, and reproduces 358 passed / 0 failed.
  - **Why one artifact and not two:** the wwss change and the stack share hunks in BOTH directions, so two artifacts
    cannot both be applied to the same live file without one being re-cut; the fold is verified (358/0, wwss's 14 cases
    added with no new failures); nothing is smuggled, because the SINGLE reviewer reads the whole series including
    wwss's part - the same reason one reviewer was ruled in the first place; and wwss's own standalone artifact still
    exists at `90de2dff` **with its own PASS**, so there is no unreviewed half anywhere.
  - **Superseded form, recorded so it is not reintroduced:** an interim two-artifact shape (stack, then a post-stack
    wwss re-cut) was pushed at `fd97bbcc` before this ruling. Those source patches still exist in that branch's history
    and the re-cut file is removed here: nothing was discarded, and producing both now would be exactly the churn the
    fold avoided.
- **NOT on the merge queue, by the rule:** nothing sets `merge-queue` until a NON-AUTHOR verdict exists on the bead, and
  a clearance is per-tip. The one reviewer is what puts this in front of the merger.

## The stack, and the order that matters

| step | artifact | author | applies |
|---|---|---|---|
| 1 | `patches/fleet-verdict-transcription-scanner.patch` | (shelf, already in main) | clean |
| 2 | `patches/fleet-verdict-model-families-filter.patch` | (shelf, already in main) | clean |
| 3 | `patches/fleet-verdict-pool-sha-relevance.patch` | agents-9lew | clean |
| 4 | `patches/fleet-land-message-author-identity.patch` | agents-2tov | clean |
| 5 | `patches/fleet-verdict-transcribed-run.patch` | agents-m6fr | **one hunk conflicts** |

Verified, not assumed: the base is the live bundle by content (`bin/fleet-land-message` sha256
`980899b73c2cbd87…`, suite `647694f31286dce3…`), steps 1-4 apply with **zero failed hunks** and the suite then
reports **341 passed / 0 failed** - 2tov's own claimed figure, reproduced. All five patch files were re-extracted
from their current remote tips and their sha256s are unchanged, so these measurements are current.

### The five source objects, so the stack can be re-checked against the SAME objects

| artifact | sha256 |
|---|---|
| `fleet-verdict-transcription-scanner.patch` | `8bc661311874838afe80f096d0455b1573bdc5ed46713f27a2ee22d234a8bbc2` |
| `fleet-verdict-model-families-filter.patch` | `10087eef55ef51b809860a4d8cb42286f7e40251ea6509cb0870ce5474bcc590` |
| `fleet-verdict-pool-sha-relevance.patch` (agents-9lew) | `86d3a682942a8781d095dba21b6fd25de94a2163dcc2da1d76e81a5089aca21d` |
| `fleet-land-message-author-identity.patch` (agents-2tov) | `6be81c76ed665ec6fb5485f611ca3562cc88cac7ad0cb025338242a6415ea2a7` |
| `fleet-verdict-transcribed-run.patch` (agents-m6fr) | `25c603aa1e12d5a08069f4eddfa5672133974aef817557718dde4c1f4772aa4c` |

These are what made the measurements durable rather than stale: the zero-failed-hunk applies, the 341/0 suite and
the m6fr conflict at line 588 all still hold because the objects are the same objects.

### WHAT "IT IS IN MAIN" DOES NOT MEAN

**Three of these five artifacts are already in `origin/main`'s `patches/` directory, and that does NOT mean they are
APPLIED.** The live `bin/fleet-land-message` still hashes `980899b73c2cbd87…` - 2tov's declared PRE-STACK base. The
shelf holds delivered artifacts; the hub still has to apply them. **COMMITTED ARTIFACT, APPLIED STATE AND INSTALLED
STATE ARE THREE DIFFERENT THINGS**, and "it is in main" is not "it is running". This is the same shape as the
agents-kxbv delivery: its repo half MERGED while its upstream half stayed parked and its install remained a third
step - three layers, and any sentence that collapses them is wrong about which one it is describing.

### The label that was true about the artifact and wrong about the tip (agents-9lew)

agents-9lew's `cleared:` label was **true about the artifact** - byte-identical to what the reviewer read - and its
`merge-queue` label was **wrong**, because landing it alone is the knowingly-wrong intermediate this composition
exists to prevent: the pool reordering running against the independence value 2tov has not yet fixed. Coord removed
the queue label and the ruling wins; 9lew lands ONLY inside this stack. This is the same distinction drawn for
agents-elu6, applied to a LABEL rather than to a tip: an artifact-level truth is not a tip-level claim.

**THE TREE ORDER IS THE REVERSE OF THE SEMANTIC ORDER, AND BOTH ARE TRUE.** 9lew's reordering consults the
independence value 2tov corrects, so 2tov must be understood FIRST - but 2tov's patch is cut ON TOP OF 9lew, and
applying it before step 3 fails 2 of 9 hunks. The delivery lands as one change, so there is no landing hazard; the
application order must still be stated, or the first reader to apply the patches hits a failure this text did not
predict.

## The conflict that is mechanical (resolved here)

m6fr's hunk #1 in `bin/fleet-land-message` fails at line 588 because 2tov rewrote the same declaration line. The
resolution is additive and semantic, not textual: 2tov's extra field and m6fr's `rev_run_reason` are **separate
columns on purpose**.

**CONSTRAINT, NOT A NOTE: `author_source` (which lane or model AUTHORED) and m6fr's run-reason (whether the POSTED
VERDICT has an artifact behind it) must not share a name or a parser.** A transcribed verdict that reads as
author-sourced is precisely the confusion m6fr exists to close.

## The constraints the delivery must carry (coord's ruling)

1. **APPLICATION ORDER** is stated above, because the tree order and the semantic order are opposite.
2. **FIELD SEPARATION IS A CONSTRAINT, NOT A NOTE:** `author_source` (which lane or model AUTHORED) and m6fr's
   run-reason / the poster of the verdict must not share a name or a parser - a transcribed verdict that reads as
   author-sourced is precisely the confusion m6fr exists to close.
3. **`agents-6943` STAYS EXPLICITLY AFTER THIS:** its evidence (32 changed lines, per-file digests) must be
   RE-DERIVED rather than reused if a selection fix moves the delta - a digest is a claim about an object, and the
   object moves.
4. **`--landed-tip` IS NOT AN OVERRIDE:** it records the gate for the tip that was ACTUALLY MERGED while the gate
   commit must still CONTAIN the tip being recorded, and (after agents-orjl) while the tip must ALSO be tied to the
   named branch. It moves the OPERAND, never the decision.

THE FOLD MADE CONSTRAINT 2 CONCRETE RATHER THAN THEORETICAL: attempting the fold produced exactly ONE conflict, on
the shared declaration line - the stack's `AUTHOR_MODEL_ARG` against wwss's `LANDED_TIP`. Two independent columns on
one line, so both were kept, which is the same resolution m6fr's hunk needed. Three deliveries met on a single line
and no value was overwritten. That one-conflict measurement is also what produced the re-cut artifact shipped above
with confidence: the fold was NOT thrown away as a dead end - it IS the delivery, and it is also the measurement that
proves the interaction is one line wide
and understood rather than a rewrite - and wwss's 14 cases came back green on the folded tree with no new failures.

### What agents-wwss's change adds, now folded in here

The original wwss artifact could not certify which BRANCH it was clearing. Two review findings fixed here, both on the
same parameter, which is why they belong in one pass:

- **agents-orjl (P2):** a tip from an UNRELATED branch falsely certified the named branch, because the check was
  containment of the tip while nothing tied it to the branch. The tip must now be an ANCESTOR of the named branch, or
  share its tree (a rebase that changed no files); anything else refuses. Discriminator both ways: 292/2 against the
  revision the finding describes (both failures being the finding's cases), 294/0 with the fix.
- **agents-jlfq (P3):** a bad `--landed-tip` was diagnosed as BRANCH ADVANCEMENT rather than as the tip not being
  contained, sending the operator to the wrong object; and the gate identity named only one tip. Now: a containment
  failure with an explicit tip says `--landed-tip <t> is NOT CONTAINED by the gate commit` and does NOT print the
  advancement advice, while a valid explicit tip prints `explicit landed tip <t> for <branch> (at <current-tip>)` -
  so one landing message carries BOTH the tip that was gated and where the branch now is. 41e/41f/41g pin all three
  behaviours.

Together they say what the parameter always meant: it must name BOTH the branch it certifies and the tip it records,
and a mismatch must be diagnosed as a mismatch.

## THE RULING AND WHAT IT CHANGED (m6fr governs - it AMENDS fleet-15b5, it does not replace its outcome)

The ten fixtures above were NOT a deadlock. The ruling on them:

- **The objects differ, and that is why m6fr wins.** fleet-15b5 was written when the author was derived from the COMMENT
  APPENDER, so "the author's lane posted a cross-family verdict" could be true while the AUTHORED branch was someone
  else's. 2tov corrects the derivation to the BRANCH - the right object - so a same-lane clearance now means what it
  says, and `transcribed-verified` is the honest label for it. **m6fr is right because the INPUT it classifies is right.**
- **But BOTH paths still clear, and that keeps 15b5's outcome.** A same-lane transcription of a different family is
  stronger evidence than nothing; the rule has never been "only a different-lane reviewer may clear" - it is that a
  same-family-author pair is not independent ENOUGH TO BE CALLED cross-family. **The clearance stands; the label changes.**
- **So the fixtures pin the OUTCOME, not the vocabulary:** that the verdict CLEARS, and that the independence field
  reads `transcribed-verified`. A fixture that fails because a field was renamed from a weaker claim to a stronger one
  is testing vocabulary rather than behaviour - the cousin of a green that could never have been red.

What that took: the ten fixtures were `transcribed-unverified`, not merely mislabelled - a same-lane verdict with no run
id cannot resolve the reviewer it names, so it is the author's word about itself and is refused. They are now given
what a real transcription carries (a retained reviewer run whose family matches the named model), which is the same
faithfulness fix as the eight mechanical ones earlier: **a fabricated id still fails.**

**Discriminator, driven in both directions:** with m6fr's rename reverted in the assembled tree the suite is
**353 passed / 5 failed**, and the five failures are exactly the five assertions rewritten here (26b, 26e, 31a, 33b,
34b) with no collateral - so the assertions are load-bearing on the rename rather than decorating it. 358/0 as
shipped.

Coord's words for why this composition had to exist before it could be reviewed: **"m6fr was right in isolation and
wrong in place, and THREE SEPARATE REVIEWS COULD NEVER HAVE SEEN IT BECAUSE EACH IS CLEAN ON ITS OWN BASE."**

## The conflict that is NOT mechanical - THE FINDING

**2tov's author-derivation change widens the set of cases m6fr's transcription check fires on, and 10 existing
fixtures encode the PRE-2tov expectation.**

The mechanism, measured: 2tov derives the author from the BRANCH instead of from the actor who appended the
operative LAND-SUMMARY comment. That makes `rev_who == src_who` true in fixtures where a lane posts a verdict about
its own branch - which is exactly the condition m6fr added. m6fr's check then fires and reclassifies the case as
`transcribed-verified` / `transcribed-unverified`. On m6fr's own base the condition did not fire, so m6fr's delivery
was correct in isolation and wrong in place. **This is the failure mode coord's single-reviewer ruling predicted.**

Two classes of remaining work, and they need different owners:

1. **MECHANICAL (8 of 18 already fixed here):** the fixtures' transcribed verdicts named a reviewer model but no run
   id, and m6fr's rule is that a same-lane transcription must resolve to a RETAINED reviewer run. The fixtures
   INTEND genuine cross-family transcriptions, so they were given what a real one would have - a
   `recovery-descriptor.json` under a run root the helper scans (`${TMPDIR}/pi-subagents-*/async-subagent-runs/<id>`,
   the technique m6fr's own suite uses). This makes the fixtures MORE faithful, not weaker: the check is not
   disabled and a fabricated id still fails. 8 tests came back green from this alone.
2. **CLASSIFICATION (the remaining 10) - needs a ruling:** where the author's own lane posted a cross-family
   verdict, m6fr renames the independence to `transcribed-verified`, so assertions that pin the literal value
   `cross-family` now fail EVEN WITH a resolvable run (e.g. 26b "independence is cross-family"). Those assertions
   encode `fleet-15b5` ("a transcribed cross-family verdict clears"). m6fr is the newer rule and its rationale is
   the stronger one - a same-lane clearance is the author's word about itself - but which assertion wins is a
   fleet-wide policy decision, not an integration detail. Affected sites in `tests/fleet-land-message.test.sh`:
   lines ~795 (12p/12q, the `tip:` form), ~1109 and ~1193 (26a/b/e), ~1177 (31a), ~1201 (33b/33c), ~1217 (34b),
   ~1474 (37a).

## What the reviewer must check (one reviewer, all of it at once)

The series is presented together because its parts are clean alone and interact here. The reviewer should confirm, on
the FINAL tree: the application order (steps 1-4 apply with zero failed hunks on the stated base; the re-cut applies
on top of the result); that no field name or parser is shared between which lane AUTHORED and which lane POSTED a
verdict; that `--landed-tip` still cannot override the decision, and that the tip it records must be tied to the
branch it certifies (agents-orjl) and diagnosed as an uncontained tip rather than as branch advancement
(agents-jlfq); and that the 10 failures are the classification clash below rather than anything mechanical.

1. the application order, and that steps 1-4 apply with zero failed hunks on the stated base;
   (the folded patch applies to pristine copies at fuzz 0 and reproduces 345 passed / 10 failed exactly)
2. the field separation above - two columns, two names, no shared parser;
3. whether the m6fr reclassification is the intended outcome for a same-lane-posted cross-family verdict, or
   whether `fleet-15b5` still governs those shapes;
4. that the fixture run-root setup makes the fixtures more faithful rather than disabling the check.
