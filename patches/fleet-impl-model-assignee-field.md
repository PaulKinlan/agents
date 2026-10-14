## The impl-model resolver must read the assignee FIELD, not rendered text - `fleet-impl-model-assignee-field.patch` (agents-shua)

Found by the sweep coord asked for: *any tool that reads bead state from rendered `bd show` text has the same
blindness as the label grep, and the same one-line fix.* This is the one that ACTS on what it reads.

### The defect

`remote/impl-model.sh` resolves the model for a lane from **the bead's assignee**, by grepping rendered text:

```
who=$(timeout 10 bd show "$bead" 2>/dev/null | grep -oE 'Assignee: [a-z0-9][a-z0-9-]*' | head -1 | sed 's/^Assignee: //')
```

Two things make that read wrong rather than merely fragile:

1. **An unassigned bead has no Assignee line at all** - measured on this VM: `bd show agents-ttxh` prints
   none, and its field is `None`. So the grep matches the first `Assignee: ...` **anywhere in the bead's
   prose**. A description saying "hand it back to Assignee: some-lane" becomes this bead's assignee. The hub
   creates beads unassigned on purpose, so this is the common case, not a curiosity.
2. **The candidate loop breaks on the first non-empty match**, so that false positive also stops the search
   before the checkout that actually owns the bead.

The consequence is not cosmetic: `lanes.sh` calls this resolver when spawning a lane without an explicit
model, so a misread assignee silently routes the **wrong model** - and the rotation policy (implementer,
cross-family reviewer) is what it feeds.

### The change

The assignee comes from the field: `bd [-C dir] show "$bead" --json | jq -r '.[0].assignee // empty'`.

The test file's fake `bd` is made **faithful** - rendered text for a plain `show`, the field for
`--json` - because modelling only the rendered form is what let the old read look correct in this suite. That
alone fixes **four cases that are red in the deployed file on this VM** (6a, 6a2, 6b, 6c): they shim on `$1`
while the resolver calls `bd -C <dir> show`, which never matches when the `$HOME/` candidate directory
exists. A before/after seam (`IMPL_OVERRIDE`, mirroring the file's own `PICK_OVERRIDE`) makes that
comparable rather than a claim.

### Evidence

- **Discriminator, the same test, both revisions:** DEPLOYED resolver **24 passed, 1 failed** - new case 7a
  FAIL, because the prose mention resolves to `zai/glm-5.3` instead of the spawner's
  `deepseek/deepseek-flash`. PATCHED **25 passed, 0 failed**.
- Case 7 restores `imp-x.model` and `coord-lane.model` first, because 6b and 6d delete them - without that,
  the case measured the fixture's leftover state and read as an empty model on BOTH revisions. That wrong
  result is why the fix is measured rather than asserted.
- `patch -p1 --fuzz=0` applies CLEAN to the deployed files, byte-identical afterwards.
- Strict preimages: `remote/impl-model.sh` SHA256 `213904ad87d4f75d`; `tests/pick-model-crossfamily.test.sh` SHA256 `ad844d21150fdab5`.
