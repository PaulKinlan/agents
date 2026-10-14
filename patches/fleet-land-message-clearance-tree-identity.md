# fleet-land-message: key the landing clearance on the TREE, not the tip sha (agents-ivp7)

`fleet-land-message` compared TIPS. A commit that moves without changing the tree — a tree-preserving rebase, an
amend of the message, or a re-commit onto the same base — therefore read as STALE, the landing refused, and the
merge queue stripped a clearance whose content was byte-identical to what the reviewer and the gate had already
approved. Because every lane is told to rebase onto landed main before handing over, this is the common path: each
occurrence either costs a review round or a full gate for content that was already gated, and the full gate is the
scarcest resource on the VM.

The fix keys the CLEARANCE on the tree — what the gate measured — while the verdict keeps NAMING the commit it was
formed on, which is the distinction the defect existed because of: **the sha identifies the reviewed commit; the
tree identifies the gated content.** The stale message now prints both trees, so a reader can tell a real content
move from a rebase without running git by hand.

## The four hub-delivery fields

| Field | Value |
| --- | --- |
| **Artifact sha** | `patches/fleet-land-message-clearance-tree-identity.patch` — 17969 bytes, sha256 `1e1c6e163a0db95a3bc658f824037be563ad0231ae553d8b584424a158c14ac5`, 14 hunks, 2 file-sections |
| **Exact base it expects** | `bin/fleet-land-message` = 64670 bytes, sha256 `f6de093900f6b059db1a9797bfe2e5a0b3cecebe6fd9f07c58df34a0d4b86a30`; `tests/fleet-land-message.test.sh` = 91463 bytes, sha256 `91dfa5c97995244bfe2e8ce3f0bd7e5d3a5f8bb5be5ed67d4ef99a5b2c1ebc0f` (both = the **deployed** copies on this VM, `~/fleet/...`) |
| **Does the destination have that shape?** | Verified here against those deployed copies: `patch -p1 --dry-run` is clean for **2/2** sections, and the applied files are **byte-identical** to the files that were tested (`bin/…` → sha256 `15ed5b856d0eed90…`, `tests/…` → `f383bb3e46803773…`). The hub must re-measure on its own copy (`sha256sum ~/fleet/bin/fleet-land-message`); the deployed file is the only base this patch was cut against. If that hash differs, rebase the 14 small hunks by context — the behavioural contract to preserve is at the bottom of this file. |
| **Prerequisites** | **None.** Nothing else in `patches/` must land first; no sibling tool changes; no new dependency (bash + git + jq, all already required). |

Derived mechanically against the deployed tree by the `agents-69wa` audit tooling (`/tmp/patch_audit2.py`), which
reports this patch as **APPLIES 2/2**, base = deployed `f6de093900f6` / `91dfa5c97995`, prerequisites `nothing`.

## Relationship to `fleet-land-message-tree-identity.patch` (agents-19jh) in this directory

Same file, **different mechanism and different code path**, and the two are sequential rather than competing:

* `agents-19jh` (already in this directory) is the **`--gate` side**: when a `--gate <sha>` is supplied and the
  branch was rebased without changing the tree, it accepts the tree identity and reports `gate_identity`
  (`gate.identity` in JSON, tests 10w–10z).
* `agents-ivp7` (this patch) is the **review-clearance side**: when a *review verdict* names an older commit, the
  clearance is decided by the reviewed tree versus the tip tree (`review.tree_identical`, `cleared:` label, the
  STALE/DIVERGED refusal text).

Their patch is **already applied** in the deployed base this one is cut against — measured, not assumed: applying
it to a fresh copy of the deployed files gives *"Reversed (or previously applied) patch detected"*, and the
deployed tool carries `gate_identity` (9 occurrences) while the deployed test file carries the `10w4` no-op-rebase
test. So the hub applies **only this** patch; nothing is double-applied, and the JSON additions here (review
object) sit beside theirs (gate object) without touching the same keys.

**Naming note:** the first attempt at this delivery used the same filename as theirs
(`fleet-land-message-tree-identity.{patch,md}`) and would have overwritten a sibling's durable artifact; it was
reverted before any commit and this patch re-cut under a distinct name. Nothing of theirs was modified.

## What it changes

1. **Tree identity decides the clearance** (`bin/fleet-land-message`, review-resolution block). Between the
   exact-commit case and the ancestor/STALE case, a new branch accepts a positive verdict when the reviewed
   commit's tree equals the tip's tree:

   ```
   elif [ -n "$rev_tree" ] && [ "$rev_tree" = "$tip_tree_full" ]; then
     rev_state="CURRENT"; rev_tree_identical=true
   ```

   This catches the shape the old code could not: a *sibling* commit (same tree, same parent, new object) is not
   an ancestor of anything, so the old code called it **DIVERGED** — and the delta-identity fallback below it only
   helps when the base and file set also agree, which a rebase onto a moved base does not guarantee. Tree equality
   is the direct test for "the content the suites read has not changed".
2. **The stale refusals name both trees** — the stderr refusal and the bead comment that records the invalidation:
   `branch tip <tip> (tree <T1>) moved after review for <rev_sha> (tree <T2>)`. Both the `STALE` and `DIVERGED`
   report lines do the same. A reader told "stale" with no tree cannot tell a real move from a rebase.
3. **The message and JSON say which rule carried the clearance**, so it is never silent which of the three
   mechanisms (exact commit / tree identity / delta identity) accepted it: the review line reads
   `PASS (verdict: …) for commit <rev_sha> (tree identical to tip <tip>: <T>)`, and the review JSON object gains
   `tree_identical`, `reviewed_tree`, `tip_tree` alongside the existing `delta_identical`.

The verdict-still-names-its-commit rule is untouched: `reviewed_sha` remains the commit the reviewer reviewed, and
`cleared:<sha>` label matching is unchanged. Only the *clearance* travels with the tree.

## Evidence (measured, both directions)

Fixture (new section 36 of the test file, deterministic — its own branch, no dependence on earlier sections): a
branch whose reviewed commit is re-committed as a sibling with the **identical tree** (same tree, same parent, new
commit object), with a `VERDICT: PASS` naming the reviewed commit and the label `cleared:abcd123`.

| Run | Result |
| --- | --- |
| Deployed tool, same test file | **292 passed, 16 failed** — includes `36a tree-identical rebase is CLEARED (rc 0)` failing (the defect: refused, and the merge-queue label stripped) |
| Patched tool, same test file | **308 passed, 0 failed** |
| `patch -p1` applied to fresh copies of the two bases | clean dry-run, byte-identical result, and the applied tool passes **308/0** |

The new pins are two-sided, which is what makes them evidence rather than assertions:

* **36a–36i** (tree-identical move is CLEARED, the message says *tree identity*, the commit is still named, JSON
  exposes the trees, and **no** queue state is touched) — all red on the deployed tool, green on the patch.
* **36j–36m** (the control: a *real* content change on the same branch is still REFUSED, and the refusal and the
  bead comment both name the tip's tree and the reviewed tree) — green on both, so the change does not widen into
  "anything with a shared ancestor is fine".
* Six existing assertions pinned the old refusal wording; they are updated **in the same patch** (11f, 11k, 11l,
  11z, 12g, 12k) because the bead requires the trees in that message. They fail against the deployed tool by
  construction, which is how the wording change is visible in the suite rather than only in the diff.

## Limits and non-goals

* **It does not weaken the review gate.** Tree equality is content equality for the branch tip; a real edit
  changes the tree and still refuses (pinned by 36j–36m). The `--gate <sha>` path, the `--allow-stale` path, the
  verdict vocabulary and the independence rules are untouched.
* **It does not replace the delta-identity fallback** (`fleet-15b5`, `fleet-7347`), which still covers a rebase
  whose tree also differs from the reviewed commit but whose delta bytes are identical. Tree identity answers the
  case that needs no heuristics.
* **It does not fix the stale witness on the fleet-check side** (`agents-bp6m`, `agents-fxg2`): the `agents/`
  directory-ctime false STALE is a different witness with its own cause (`agents-eea2` at the hub). This patch is
  only about the sha-vs-tree split in the landing tool.
* **A shared tree is not a borrowed clearance.** The `OTHER-BRANCH` check (a verdict naming a different branch)
  and the within-branch ancestry rules are unchanged, so a verdict about a sibling branch cannot clear this one.
* Harness note, not a tool defect: the suite must be driven against a **fleet-shaped layout** (a copy of `~/fleet`
  with the tool's sibling files), not against a lone copy of the script — a bare copy fails ~250 tests because the
  tool reads its siblings.

## Applying it

```bash
cd ~/fleet            # the deployed fleet tree (hub: this is origin/main's checked-out content)
sha256sum bin/fleet-land-message tests/fleet-land-message.test.sh   # must equal the two bases above
patch -p1 --dry-run < patches/fleet-land-message-clearance-tree-identity.patch
patch -p1 < patches/fleet-land-message-clearance-tree-identity.patch
bash tests/fleet-land-message.test.sh    # expect: 308 passed, 0 failed
```

If either base hash differs, the hunks are 14 small edits with their context lines carried in the patch; the
behavioural contract to preserve is: **a positive verdict whose tree equals the tip's tree is CURRENT and cleared;
a genuinely different tree is still refused, and both refusals name both trees.**
