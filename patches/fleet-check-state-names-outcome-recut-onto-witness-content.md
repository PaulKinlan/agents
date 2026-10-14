## fleet-check-state-names-outcome-recut-onto-witness-content.patch - agents-lgdv's change, re-cut onto agents-bp6m's installed result (agents-w43q)

## Why this is a re-cut and not a sequence

`patches/fleet-check-witness-content.patch` (agents-bp6m) and `patches/fleet-check-state-names-outcome.patch`
(agents-lgdv) collide in BOTH application orders, at `bin/fleet-check`'s terminal-state write and in the
tree-stability suite: both patches rewrite the same `witnessed=` string and the same `run_arm` call sites, so
there is no order in which one applies cleanly after the other. Two patches that collide in both orders are
rebased, not sequenced. The hub chose to re-express lgdv, on the grounds that it is the narrower of the two (a
naming/output change) while bp6m carries the witness semantics themselves, the unmeasured hashing cost and the
directory-target gap. This artifact is that re-expression. **bp6m is untouched by it.**

## THE BASE THIS IS A CLAIM ABOUT (a delivery is a claim about a moment)

This patch is cut against **bp6m's installed result**, not against the pristine deployed files:

| file | bytes | sha256 |
|---|---|---|
| `bin/fleet-check` (the cut's base = bp6m applied) | 54,818 | `04acfaae1a9c3cf0d1625e2f68003b585a6ba6bf066da07ff527d79656d1a14f` |
| `tests/fleet-check-tree-stability.test.sh` (the cut's base) | 19,510 | `01963652b07bb4e8aa42cccbf7513bc2847e9168b8cfbf5f59b691cb3e8152af` |
| `bin/fleet-check` (pristine, for the lineage) | 51,977 | `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498` |
| `tests/fleet-check-tree-stability.test.sh` (pristine) | 12,295 | `8cc667daef33635fddcb648415df99defa329cc64f84dc4f860fdc4710b57067` |

The two pristine hashes were measured independently here and match the values agents-eea2 recorded.

## RISK, STATED RATHER THAN LEFT TO BE DISCOVERED: BP6M MAY STILL MOVE

The hub has not decided whether to close bp6m's directory-target-replacement gap, and its prior is that a missed
alarm is worse than a noisy one. **If bp6m changes, this cut is against something that moved and must be re-cut
against the new installed result.** The check is cheap and mechanical: apply bp6m to the pristine files, hash
`bin/fleet-check`, and compare with `04acfaae…` above; if it differs, this artifact's base no longer exists.

## What it changes

Four files, 342 diff lines, no change to bp6m's semantics:

- `bin/fleet-check` - bp6m's content-witness text is kept verbatim; lgdv's `settled_json` is published beside it
  and added to both terminal-state `jq` writes (`.state=$st | .settled=$settled | .witnessed=…`).
- `tests/fleet-check-tree-stability.test.sh` - merged by INTENT, not by patch: lgdv's `EXPECT_SETTLED` third
  argument, the wake-capture stub, and the outcome/settled/wake assertions, together with bp6m's `marker_state()`,
  its premise-rule block, its round-trip bound assertion and its same-bytes arm.
- `bin/fleet-land-message`, `tests/fleet-gate-check.test.sh` - lgdv's hunks unchanged; bp6m never touches them.

## The merge decision that needed a human, recorded because a tool gets it wrong

A 3-way merge (`git merge-file`, ancestor = pristine, mine = lgdv, theirs = bp6m) was built as an **independent
reference**. It agrees with this artifact everywhere EXCEPT the one line that must differ: it keeps lgdv's OLD
`witnessed="…INCLUDING SYMLINK TARGETS (size + nsec ctime)…"` text, which would silently revert bp6m's content
witness. That is the collision the re-cut exists to resolve, and it is why the cut was made by intent rather than
by a merge tool.

Both reviews changed the same arms, so the rule is: **bp6m owns the witness semantics on this base, and its
judgement is translated into lgdv's two-field vocabulary.** bp6m's `STALE` meant "the witness moved", which is
lgdv's `settled=false`, so those arms become `<outcome> false`; bp6m's arms that moved to `PASS` because the
content witness cannot see a byte-identical rewrite become `PASS true`. Both "Arm 8"s are kept because they are
different defects (lgdv's is a FAILED and unsettled run, bp6m's is a rewrite to identical bytes), giving nine
arms including the control.

## Acceptance, driven rather than asserted

- Applies to a fresh copy of the DEPLOYED files with `patch -p1 --fuzz=0`: **rc 0, no rejects, no `.orig`, zero
  fuzz or offset mentions**, relative `a/<path>` -> `b/<path>` headers, four files.
- The patched result is **byte-identical** to the cut for all four files.
- **The two artifacts now stack**: pristine -> bp6m (rc 0) -> this cut (rc 0), result byte-identical to the cut.
- Structural anchors asserted on the patched tree: `run_arm` takes `expect_settled` as `$3`; 9 arm call sites;
  `.settled` published in BOTH `jq` writes; bp6m's `marker_state`, premise rule, bound check and same-bytes arm
  all present; lgdv's stale `witnessed` text absent; `bash -n` clean on both shell files.
- Independent reference: the 3-way construction above, plus the pristine-base application of lgdv (rc 0, four
  files) used as the source of lgdv's intent rather than a reproduced hash.
- Behavioural run of the merged suite against the patched `bin/fleet-check` is recorded on `agents-w43q`.
