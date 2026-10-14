## patches/fleet-land-message-ancestry-inside-stale-arm.patch

HUB-DELIVERY PATCH on top of `agents-p1c2`, answering P1 `agents-7jco`. The ancestry check sat at OUTER SCOPE, before
`if [ "$rev_state" = "STALE" ] || [ "$rev_state" = "DIVERGED" ]; then`, so it ran on EVERY invocation: a NORMAL CURRENT
landing aborted with exit 1 whenever `refs/remotes/origin/<default>` was absent, and printed a spurious NOTE on stderr
whenever it was present. This moves the whole block INSIDE the `STALE|DIVERGED` arm, so a CURRENT landing never queries
ancestry at all, and strengthens the WARN to name the question it could not answer.

PLACEMENT, NOT DESIGN. The three-branch contract from `agents-zlz4` is unchanged in substance - YES spent, NO proceeds on
the p1c2 path with a named warning, REF ABSENT refuses and names the missing ref - and the only structural change is
which landings can reach it.

MEASURED, INCLUDING THE PART THAT DOES NOT FLATTER THE PATCH. The suite
`~/fleet/tests/fleet-land-message.test.sh` IS reachable and runnable on this VM via `LM_OVERRIDE=<tool> bash` it, and
live canon scores **292 passed, 0 failed**. But the deployed revision of that suite predates `agents-p1c2`'s cases: against
the p1c2 base alone it scores **49 passed, 243 failed**, and against p1c2 plus this patch it scores **exactly the same
49/243**. This patch is therefore NEUTRAL on that revision - it neither fixes nor breaks what it measures - and the 243 are
fixture-installation failures for p1c2's code, not a verdict on this change. The reviewer's reported 63 failures came from
a suite revision that carries p1c2's cases; that revision is not the copy deployed here, which is why the number differs.

STATED PLAINLY SO IT CANNOT BE INFERRED AS COVERAGE: the regression case coord asked for - a normal CURRENT landing with
NO `refs/remotes/origin/<default>` must still succeed silently - is NOT shipped in this artifact, because it has to run
against the suite revision that carries p1c2's fixtures. The predicate is asserted BY CONSTRUCTION instead: the ancestry
query now appears only inside the `STALE|DIVERGED` arm, which is exactly the property that makes the regression
impossible. The case text is ready to add to that revision.

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `9266c3340ff6172c5629a508698ce2695d1ebb7d` (canon + p1c2) |
| result | `ea45f630ea0e71b58d54e363d1f2967b9d0845a0` - **differs from the preimage**, asserted |
| patch | **3493 bytes, 1 hunk**, non-empty asserted |
| apply | `patch -p1 --fuzz=0` -> rc 0, zero rejects, byte-identical |
