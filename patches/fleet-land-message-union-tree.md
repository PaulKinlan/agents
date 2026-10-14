## fleet-land-message-union-tree.patch — the lander can check a cleared delta's PRESENCE in a declared union tree (agents-kjpu)

**A PROPOSAL, HANDED OVER WITH ITS INTERFACE NAMED**, because it touches the hub's landing tool: the flag below is
an interface change to `bin/fleet-land-message`, and coord asked for it to be presented rather than decided here.

THE GAP IT CLOSES. `fleet-land-message` already has a DELTA-IDENTITY fallback (fleet-15b5/fleet-7347): when the
cleared sha no longer equals the tip it compares the reviewed delta against the tip's own delta, and a
byte-identical delta keeps the clearance. That covers a pure rebase. It does not cover a branch that **GREW** after
clearance — the instance that prompted agents-p3k1, where `fleet/impl-guard` carried the cleared commit PLUS
kve2/pim5/f8dj, so the delta was no longer identical and the fallback correctly declined. The merger's union DID
carry the cleared content, but the union is built **after** this tool runs, so the lander could not see it. A tool
cannot verify what it was never shown; it has to be told.

THE INTERFACE. One new flag, `--union-tree <tree-sha>` (also accepted as `--union-tree=<sha>`), defaulting to empty.
- It **asserts nothing**. It enables one check: on **every path the reviewed delta touched**, the declared tree
  must hold the **cleared commit's content**. Concretely `git diff --quiet <cleared-commit> <union-tree> -- <the
  reviewed delta's paths>`. Other paths are unconstrained — that is what "carries the cleared delta plus these
  others" means.
- On success the verdict is informational, not invalidating: `PASS (verdict: …) for commit <cleared> (union tree
  <sha> carries the cleared delta; the branch has moved past it, and the clearance is for the CONTENT it
  reviewed)`. No label is stripped, because it is a clearance rather than a refusal.
- New JSON fields, additive: `review.union_verified` (bool) and `review.union_tree` (the declared sha). The
  existing `review.delta_identical` stays **false** in this case, deliberately: this is a different fact and a
  field must carry the fact it is named for.
- Refusals go to **stderr**, naming the reason, and the machine-parsed stdout is untouched: `--union-tree` naming
  something that is not a tree object; a reviewed delta that names no paths (the pathspec would be vacuous); and a
  declared tree that does not carry the cleared delta, which names the paths it failed on.

CONSTRAINT 1 — THE FLAG MUST NOT BECOME A WAY TO ASSERT A CLEARANCE WITHOUT EVIDENCE. There is no boolean
anywhere: the whole verdict is `git diff --quiet` on those paths, so a caller cannot assert a clearance it has not
got, and the positive-verdict gate is unchanged, so a `FAIL` verdict with the content present is still refused.
The suite pins both: **13f** (a union tree missing the cleared content is REFUSED and the refusal names the path)
and **13i** (a FAIL verdict with the content present is still refused).

CONSTRAINT 2 — WITH THE FLAG ABSENT, CURRENT BEHAVIOUR IS UNCHANGED. The new block is dead unless `--union-tree`
is passed, so it is additive only and the default stays refuse. Pinned twice: the suite's **292 pre-existing tests
stay green** unchanged, and **13j/13k** assert that the same grown branch still refuses without the flag and that
`union_verified` defaults to false.

EVIDENCE. `tests/fleet-land-message.test.sh`: **303 passed, 0 failed** with the patch (292 pre-existing + 11 new),
and — **RED FIRST** — **294 passed, 9 failed** with the new tests run against the UNPATCHED tool, i.e. nine of the
eleven new drives fail without the change and all pass with it. 13a–13e cover the carried case (cleared, no label
stripped, `union_verified` true, `delta_identical` false); 13f–13h cover the refusals; 13i–13k cover the two
constraints.

BASE, cut against the DEPLOYED tree as coord directed. Both files are EDITED, so both bases are recorded exactly:
- `bin/fleet-land-message` — 64670 bytes, sha256 f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee
- `tests/fleet-land-message.test.sh` — 91463 bytes, sha256 91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77

APPLIES: `patch -p1 --fuzz=0` -> **rc 0, no rejects, no `.orig`, no fuzz or offset messages**, and the patched
result is **byte-identical** to the development tree, which then runs 303/0. NO COLLISION EXPECTED with the other
two hub artifacts in flight — `agents-kq0r` creates `bin/fleet-fallback-guard` and hooks `sdk-host/host.mjs`, and
`agents-ayqi` adds `bin/fleet-clear` and edits `roles/reviewer.md`; neither touches either file here — but the hub
re-verifies against its own tree, as it does for every hub-delivery artifact.
