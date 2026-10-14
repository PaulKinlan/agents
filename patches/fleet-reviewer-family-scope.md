## `fleet-reviewer-family-scope.patch` — the cross-family spawn guard is reviewer-specific *by choice* (agents-dyxk)

`remote/lanes.sh` refuses to spawn a **reviewer** in the implementer's own model family, and that guard is
**reviewer-specific by construction**: the enforcement is a single literal role test, `if [ "$role" = reviewer ]`.
An `architect`, `designer` or `founder` lane therefore skips the whole block and **can** be picked in the
implementer's family. That is defensible, and it is deliberate — but nothing in the tooling says so, so every
later reader has to decide for themselves whether it is a decision or an oversight. This patch is a **record,
not a change**: it extends the guard's own comment with the reason, and nothing else.

### The two facts that make the scope statement true rather than reassuring

**1. The behaviour is pinned on purpose, not left to drift.** `tests/pick-model-crossfamily.test.sh:65` prints
`5. the guard is reviewer-specific: implementer/coordinator picks are untouched`, and `:68-69` picks an
`architect` with `FLEET_IMPL_MODEL` set to the implementer's family and asserts `ok 5b architect unaffected
(<model>)`. The exemption is asserted out loud by a passing test, which is what makes it a choice rather than
an accident of code shape.

**2. There is exactly ONE enforcement point, and this is it** (line numbers as they stand *before* this patch;
the patch inserts nine comment lines above them, which is itself the reason no forward line numbers are cited
in the code comment). At `remote/lanes.sh:383`:

- `:385-388` — an explicit same-family reviewer model is **REFUSED** (`exit 1`);
- `:389-396` — an empty model is dry-run through `pick-model` with the implementer's provider excluded, so a
  rotation that cannot avoid the family **fails here, before any worktree is cut**;
- `:397-399` — when the implementer's model cannot be determined, the spawn proceeds **UNGUARDED and says so**,
  with the verdict-time provenance check as the backstop.

Everything that enforces the family rule lives inside that one role test, which is what makes "the guard is
reviewer-specific" a statement about the code rather than about the comment.

### What the patch does, and what it deliberately does not

It inserts nine comment lines at the end of the existing `REVIEWER INDEPENDENCE AT CREATION` block, saying that
the scope is a choice, giving the reason — a reviewer's model family is what the **clearance** depends on,
because its verdict gates landing, whereas an architect produces a design decision rather than a verdict on a
diff, so its independence is not what the clearance rests on — and naming the test that pins the scope.

It does **not** change the asymmetry, and it does not touch behaviour. Whether a specialist lane *should* also
be family-checked is a different decision and a different bead; this one exists so that a reader is not left
guessing which it was.

### Verification

Driven against the deployed file on this VM, not asserted: `patch -p1 --fuzz=0` succeeds with **rc 0, one hunk,
zero rejects, zero offsets**, and the result is byte-identical to the intended file. The diff versus canon is
**nine changed lines, of which zero are non-comment** — the comment-only claim is measured, not asserted — and
`bash -n` returns the same status before and after, so the script still parses.

Hashes, by algorithm and value. The base is **ADVISORY**: this VM's `~/fleet` is a deployed directory rather
than a git checkout, so nothing here reconciles it against the hub's own copy (`agents-aieo`, the same
staleness that parked seventeen blockers).

```
remote/lanes.sh   base   40537 bytes  sha256 7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa
remote/lanes.sh   result 41480 bytes  sha256 140876f638ad9525ff30c4d263cd977bdbedbf78
```

**This is a hub-delivery item.** The artifact lands in `origin/main` like any other, and the **hub** applies the
comment to canon; a `MERGED` state here means the artifact was accepted, not that the deployed tool changed.
