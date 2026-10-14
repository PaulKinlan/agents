## Make a clearance consumed by landing - `fleet-land-message-clearance-consumed.patch` (agents-p1c2)

A clearance is spent when the work lands. `fleet-land-message` used to treat any later tip move as
an invalidation, so a branch that moved *after* its bead had already landed stripped `merge-queue`
and the `cleared:` labels off the bead and commented "merge-queue clearance invalidated" - reporting
as lost a clearance that had already done its job. The refusal itself was correct and stays: the
delta really is stale. What changes is the record.

**What the patch does.** Before the STALE/DIVERGED refusal, the tool reads the bead's own labels
(`.[0].labels`, the same JSON it already uses) and sets `already_landed` when the bead carries
`merged` - the fleet's marker that this bead's work has landed. On a landed bead the refusal still
exits 1, but:

- neither `merge-queue` nor any `cleared:<sha>` label is removed;
- the bead comment says the clearance was **already spent by landing** and that the spent clearance is
  **NOT invalidated**, naming the tip move and the unreviewed commit count;
- the refusal message says the labels were left in place instead of claiming a removal it did not
  perform.

A clearance that moves before it is spent keeps the old behaviour exactly: the labels are stripped and
the comment says "invalidated". The tests pin both sides, so neither can regress silently.

**Measured.** `tests/fleet-land-message.test.sh`, run on the real suite with its stubbed `bd`:

| run | result |
|---|---|
| new cases against the UNPATCHED tool | 16a passes (the refusal is right), **16b/16c/16d/16e/16f FAIL** - the strip, the "invalidated" wording, and the false removal claim |
| new cases against the PATCHED tool | **298 passed, 0 failed** (292 before, +6), and the pre-existing 11e/11f/11g/11g2/11h/11h2 - the non-landed strip path - stay green |

**Files.** `bin/fleet-land-message` - the `already_landed` read plus a conditional refusal that removes
no label and does not claim a removal - and `tests/fleet-land-message.test.sh`, the new 16a-16f cases.
Nothing else changes, and the gate/ancestry refusal logic is untouched, so a deployment that has not
applied this artifact behaves exactly as before.

**Preimages and results, by algorithm.** Preimages are the deployed copies on this VM, and they are
ADVISORY: `~/fleet` has no `.git` and canon is not reachable from this VM (agents-x8ud), so these
values describe the file this artifact was cut against rather than a canonical revision.

| file | preimage sha256 | preimage size | result sha256 | result size |
|---|---|---|---|---|
| `bin/fleet-land-message` | f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee | f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3eeSZ | 9266c3340ff6172c5629a508698ce2695d1ebb7d821e6fc2e2a1343984e17aab | 9266c3340ff6172c5629a508698ce2695d1ebb7d821e6fc2e2a1343984e17aabSZ |
| `tests/fleet-land-message.test.sh` | 91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77 | 91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77SZ | 4f0f7499866d3f22e5f080b101ecef3f2aba6bd5251516210d3906fddd4e67f5 | 4f0f7499866d3f22e5f080b101ecef3f2aba6bd5251516210d3906fddd4e67f5SZ |

**Bound.** The suite is the fleet repo's own test file, driven here against patched copies; the
end-to-end install on the hub is the hub's measurement, not this artifact's.
