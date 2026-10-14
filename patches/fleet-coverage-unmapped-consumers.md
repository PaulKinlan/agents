## The two HUB consumers of the coverage entry shape - `fleet-coverage-unmapped-consumers.patch` (agents-zxdg)

Hub-side artifact: a follow-up to `agents-tpw5`, which moves the provenance of a coverage warning INSIDE each
published `.unmapped` entry and so changes that field's element type from string to object. Apply at the
fleet repo root with `patch -p1 --fuzz=0`.

### Why a follow-up rather than a re-cut

`agents-tpw5` re-pinned the two READERS and the three test files its author knew about. A complete sweep for
every access form of the field - `.unmapped`, `["unmapped"]`, `get("unmapped"`, and `index()`/`join()`/
`sorted()` over the list - found two more consumers IN THE SAME REPO, by PATH:

| consumer | why the new shape breaks it |
|---|---|
| `tests/project-template.test.sh:258` | `jq -e '.unmapped \| index("src/orphan.ts")'` - `index()` of a path in a list of objects returns null, so `D17`, the fail-loud assertion this fixture exists for, no longer holds. |
| `tests/fleet-gate-check.test.sh:731` | `has "$st_blind" '"unmapped":["lib/extra.py"]'` - an EXACT string of the serialized array: with objects the text is byte-different, so `14m` fails while the field is perfectly correct. |

Neither was exercised while `agents-tpw5` was cut: the reader-suite runs were a wrong-tree run and a run
blocked on the heavy slot, so these assertions never ran against the patched shape. This is the general form
of the lesson: **when a field's TYPE changes, name the consumers by PATH, in every repo** - do not rely on
the author to enumerate them from memory.

### The change

Both now ask the record for the PATH either way:

```sh
jq -e '[.unmapped[] | if type == "object" then .path else . end] | index("src/orphan.ts")'
```

and `14m` asserts what the status must CONVEY - that the path is surfaced - rather than the byte layout of the
array. Each is correct against a pre-fix record (strings), a post-fix one (entries), or a mixture.

### Ordering (tolerance first, so it does not matter)

Verified clean with `--fuzz=0` over BOTH the pre-`tpw5` files and the post-`tpw5` files: the lines it touches
are untouched by that artifact. So this can land before it, after it, or in the same batch.

### Evidence

Measured with the exact expressions from both lines:

| case | old form | new form |
|---|---|---|
| `index()` against an entry-shaped record | returns null (RED) | true |
| `index()` against a pre-fix string record | true | true |
| `14m` exact-array substring against an entry-shaped status | absent (RED) | - |
| `14m` path substring, entry-shaped and pre-fix | - | present in both |

Strict preimages of the deployed files, hashed on this VM before the patch was cut:
`tests/project-template.test.sh` SHA256 `0c82517f50aaa7fc` (29804 bytes);
`tests/fleet-gate-check.test.sh` SHA256 `f3919068e04d9127` (181092 bytes).
