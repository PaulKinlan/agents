## patches/fleet-land-message-spent-ancestry-on-p1c2-base.patch

RE-CUT of `agents-urh9` onto the already-landed `agents-p1c2`, resolving `agents-zop7` (the hunk collision) and folding
in two review findings about this lane's own new code (`agents-p2t1`, `agents-zlz4`). **APPLY ORDER: AFTER `p1c2`.**

## The collision, and why the order is a property rather than a courtesy

`agents-p1c2`'s artifact (`patches/fleet-land-message-clearance-consumed.patch`) and the previous revision of this work
both modify the **same hunk** of `bin/fleet-land-message` - p1c2's is `@@ -748,12 +748,25 @@`, and the guard region it
shifts. `agents-zop7` proved it in both orders, with rejects in each. p1c2 is on `origin/main`; this lane's previous
revision was not. **p1c2 survives as the base and this is a re-cut on top of it**, which is also the only engineering
answer: the two artifacts are **two halves of one change**, and there is no world in which both apply as they stood.

**Demonstrated, not asserted:** applying this patch to the **unpatched** canon fails (`patch -p1 --fuzz=0` -> rc 1,
nothing applied); applying p1c2 and then this one succeeds (rc 0, byte-identical to the intended result, `bash -n`
clean). That is the `etvw` shape: the later artifact's hunks are anchored on a tree that only exists once the earlier
one is applied.

## What this half actually contributes, now that p1c2 is the base

**p1c2 already owns the property**: `:757-760` sets `already_landed=1` when the bead carries the `merged` **label**, and
`:762-768` takes the spent path (a comment, no strip) when it is set, stripping only in the `else`. That structure and
its wording are **kept unchanged**. What p1c2 does not have - and what the reviewer identified as the missing fact - is
the **MEASURED** half: **ancestry against the default branch**. A label can be absent while the work is landed, so the
label alone under-reports; and the tip-move rule exists to protect "reviewed X, landing Y", which is impossible once Y
is the history of the default branch. So `already_landed` becomes 1 (label) or **2 (measured ancestry)**, and only the
measured case prints the SPENT wording, because only it can say *why*.

## THE CONTRACT WHEN ANCESTRY CANNOT BE ESTABLISHED (`agents-zlz4`) - stated, not left to the code

The ancestor test compares against the **caller's remote-tracking ref**, so its answer is only as fresh as the last
fetch, and a stale ref would otherwise turn a **spent** clearance back into an **invalidated** one. The three outcomes,
which are in the code as a comment at the guard so a reader cannot miss them:

| outcome | behaviour |
|---|---|
| **YES** - `rev_sha` is an ancestor of `refs/remotes/origin/<default>` | **spent**: keep `merge-queue` and every `cleared:` label, report SPENT, refuse the unreviewed delta |
| **NO** - the ref exists and does not contain it | **not** proof that it did not land: the p1c2 path proceeds as before, **but a NOTE on stderr names the assumption** that the ref is fresh |
| **REF ABSENT** - no `refs/remotes/origin/<default>` at all | **REFUSE**, on stderr, naming the missing ref: an unfresh ref must never license a strip |

## The two findings about this lane's own code

**`agents-p2t1` - wrong stream.** The new diagnostics go to **stderr** (`>&2`), not stdout, because a caller that
captures stderr would otherwise never see the refusal. The pre-existing REFUSING echoes in this file are unchanged:
this fix is about the code this lane added, and widening it into a stream audit of the whole tool is a different
contract.

**`agents-zlz4` - fails open on a stale ref.** Answered by the contract above and by the REF ABSENT arm, which is the
one that turns "cannot establish" into a refusal rather than an implicit "not landed".

## Hashes, by algorithm and value

| file | stage | sha256 (first 40) | bytes |
|---|---|---|---|
| `bin/fleet-land-message` | deployed canon (p1c2's declared preimage, byte-identical) | `f6de093900f6b059af938c2bfc9613d9b66cdcba` | 64670 |
| `bin/fleet-land-message` | **after p1c2** - the base this patch is cut against | `9266c3340ff6172c5629a508698ce2695d1ebb7d` | 65883 |
| `bin/fleet-land-message` | **after this patch** | `cec22d8f4f10eebe63d3e57b151541b1f6776062` | - |

**ADVISORY:** the preimages were read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`); verify by the chain you observe.

## THE TEST IS NOT IN THIS ARTIFACT, AND THE REASON IS STRUCTURAL

The acceptance criterion is a test that fails before and passes after. **This repo cannot host it**: the tool's suite
is `tests/fleet-land-message.test.sh`, which `p1c2`'s own patch modifies - and that file is **not in this repository**
(`git ls-tree -r --name-only origin/main` matches nothing) and **not in the canonical checkout either**. It lives on
the hub with the tool it tests. `p1c2` ships cases **16a-16f** for its half; this half needs the matching case, and the
honest thing is to name it rather than imply coverage:

> **the case this half requires:** with the reviewed commit an ancestor of the remote-tracking default ref and the bead
> **not** carrying `merged`, a STALE tip move must (1) keep `merge-queue` and every `cleared:` label, (2) print the
> SPENT wording, and (3) still exit 1 for the unreviewed delta. Its negative: with the ref **absent**, it must refuse
> and say which ref is missing. Against the previous revision both would fail; against this one both must pass.

If the hub wants it in `tests/fleet-land-message.test.sh`, that file is the hub's to extend and this write-up is the
specification for the case. If this repository is ever given that suite, the case goes next to 16a-16f.
