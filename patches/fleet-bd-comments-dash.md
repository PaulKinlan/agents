## `fleet-bd-comments-dash.patch` — Beads dash text must not silently drop a verdict (agents-gb2w)

**Hub-only artifact, not an installation.** `patches/fleet-bd-comments-dash.patch` changes
`PaulKinlan/fleet` `bin/bd` and adds `tests/bd-comments-dash.test.sh`. This project lane
has not modified `~/fleet`, a live Beads DB, or any installed Git hook. The exact deployed
`bin/bd` preimage measured on 2026-10-14 is SHA-256
`f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478`;
the strict-patch output is
`3e4083deb1bb93cae8465f99a9801e5f1a500d577d9e68cb4647475ff8e7b11f`.
The new test file's output SHA-256 is
`d980429e66b54698d782a0d99c07ba229b71505b64063ce74ad2e9de8afd0242`.
The existing, unchanged `tests/bd-shim.test.sh` preimage is
`0612e2a811436e5d4af88f02f7ba176a2dedfedae039ef292434c8625d352520`.
The patch artifact itself is SHA-256
`6069fa106654ed3f8ac129940b50339249d70f9c0242b57411fdee12f36a3522`.

## Actual failure and controlled remedy

On a disposable repository and **the deployed shim with the real bd 1.3.1 binary**,
`printf 'VERDICT: PASS\nDelta: control..tip\n' | bd comments add gb2w-nxx -`
returned 0, reported `Comment added`, then a *new* `bd comments gb2w-nxx --json`
read returned one persisted text exactly `"-"` and no parseable `VERDICT: PASS`.
Root: the earlier fleet-w9ot shim guard only recognises singular `bd comment`.
Plural `bd comments add` does **not** support `--stdin`, and positional `-`
is a literal body. This loses the verdict that `fleet-land-message` reads.

The new shim clause rewrites only a **positional text dash** under plural `comments add`
to its real, measured `--file -` stdin route. It skips flag values such as `-f -`
and `--author`, preserves the piped bytes including trailing newlines, and refuses a
terminal before running bd. The real CLI returns nonzero for empty and whitespace-only
stdin without storing a row; no shim-side buffering, temp file, or secret-in-argv is
needed. The pre-existing singular `comment` guard remains byte-identical.

The same scratch DB confirmed adjacent **silent literal dash** writes after meaningful
piped input: `bd note ID -` persisted notes `"-"`; `bd update ID --notes -` did likewise;
`bd close ID --reason -` persisted close_reason `"-"`. The patch maps only `note`'s
positional dash to its documented `--stdin`; it **refuses** dash values on `update`,
`close`, and `create` text flags rather than rewriting `update --notes` to `--stdin`
(which would change the *description*, not the notes), or changing positional close
reason assignment across multiple IDs. Explicit, documented file/stdin routes and
ordinary text arguments remain unchanged. A leading global option with dash text is
refused loudly instead of bypassing the positional guard. This is a guard against
silent data loss, not an attempt to reimplement the whole Beads argument parser.

## Falsification and exact-base tests

- New hermetic suite against the **unpatched** deployed shim: **7 passed / 16 failed**,
  including the missing plural stdin route, original bare dash, terminal/empty bodies,
  adjacent note/notes/reason text and leading-global-flag cases. Against the patched
  scratch shim: **23 passed / 0 failed**. The stub records argv and stdin only; it
  cannot touch a real bead.
- Existing `bd-shim.test.sh`: **15/15**; `bd-guard.test.sh`: **85/85**;
  `bd-worktree-decoy.test.sh`: **13/13** on the patched scratch tree. `bash -n`
  passes for both changed target files.
- Real-CLI GREEN, still in a **disposable DB** at
  `/tmp/agents-f6du-gb2w-red.RWbtWe`: under the patched shim,
  `bd comments add gb2w-0gd -` returned `Comment added`, and a fresh JSON reader
  returned one body exactly `"VERDICT: PASS\nDelta: control..tip\n"` with
  `parseable_verdict=true`. Empty/whitespace `--file -` returned nonzero and did
  not append a row (separate scratch verification). Real CLI proved explicit
  `bd comments add ID -f -` already reads stdin; the new rewrite uses that same
  supported flag path. Existing cases were never run against the live project DB.
- On `/tmp/agents-f6du-gb2w-final.qhqi6y`, strict `patch --batch --forward
  --dry-run --fuzz=0 -p1` and then apply both exited 0, created no rejects,
  produced byte-identical target hashes above, and ran the four suites above.

## Hub decision / installation boundary

The hub must check the **actual** `bin/bd` SHA-256 against the preimage above and
require `tests/bd-comments-dash.test.sh` to be absent; apply with `-p1 --fuzz=0`
only after independent review. Then run `bash tests/bd-comments-dash.test.sh`,
`bash tests/bd-shim.test.sh`, `bash tests/bd-guard.test.sh` and
`bash tests/bd-worktree-decoy.test.sh` in a disposable hub checkout before normal
hub installation. If another hub patch (including the elu6 → nbka → u2st
holder-diagnostic chain or the create-ID-window fix) lands first, **STOP**: these
hashes and results do not prove composition with that new file. Ask the owner for
an exact-base re-cut and a new review; do not rely on a fuzzy patch application.
No code in this artifact changes Beads' shared-lock implementation, database
semantics, or the landing helper's independent clearance checks.
