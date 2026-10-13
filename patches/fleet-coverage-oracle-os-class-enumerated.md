## `fleet-coverage-oracle-os-class-enumerated.patch` (agents-yhhi, agents-3gq1, agents-aung decision)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1...,
mtime 2026-10-12 19:42 - unchanged, re-read when this revision was cut.

## READ THIS FIRST - THESE PATCHES ARE ALTERNATIVES, NOT A SEQUENCE

**`fleet-coverage-oracle-binding-aware-subprocess-source.patch` (`agents-hbz3`, `b63a9b3`),
`fleet-coverage-oracle-module-binding-set-and-wrapped-imports.patch` (`agents-6r5g`, `fbabab4`),
`fleet-coverage-oracle-os-invocation-class-posix-spawn.patch` (`agents-aung`, `698420c`) and THIS one are
ALTERNATIVES against the same base file. Each was cut as a diff against the pristine oracle at the revision
above; none was cut from its predecessor. APPLYING THEM IN SEQUENCE WILL FAIL OR CORRUPT THE FILE**, because
each diff expects the original context the previous one removed. Apply ONE - the newest that carries what you
need. This revision carries the whole binding rule, both restored channels, and the os class.

This warning is the operative sentence `agents-3gq1` found missing from the round-7 note, and it is the second
instance of the `agents-arv4` class: a claim whose yardstick or precondition was left unstated.

## agents-yhhi: the widened os class re-opened phantom shapes

The round-7 revision used `[a-z_]*spawn[a-z_]*` to reach `os.posix_spawn`. That was a PREFIX WILDCARD, so it
also matched any attribute merely **containing** a spawn-ish substring - `os.respawn`, `os.child_spawn` - and
`exec[a-z_]*` matched `os.execute`. Nothing anchored the start of `os` either, so `chaos.respawn(...)` matched
on the `os.` inside `chaos.`. The note's claim that this reached the new attribute "without widening the class
to anything it did not already claim" was therefore inaccurate as stated.

**The class is now ENUMERATED rather than globbed, with a start boundary:**

    (?<![\w.])os\.(?:system|popen|posix_spawn|spawnl[a-z]*|spawnv[a-z]*|execl[a-z]*|execv[a-z]*)

`spawnl`/`spawnv`/`execl`/`execv` and their suffixed forms are the actual os family (`os.spawnlp`,
`os.execvpe`, and so on), so enumerating them is not narrower in practice than a glob - and it cannot admit
`os.spawn_thing`.

### THE CHECK THAT MAKES THE COST VISIBLE

`agents-yhhi`'s second requirement was that the cost of a widening must be **visible**, because a
`pdth`-allowlisted-module census can only see the eight modules it covers and the re-opened phantoms sat
outside them. So the check is not a census at all - it is a table of identifiers, each with an expected
verdict, driven directly against the spliced artefact:

| identifier | expected | v8 | round-7 |
| --- | --- | --- | --- |
| `os.system` | match | match | match |
| `os.popen` | match | match | match |
| `os.posix_spawn` | match | match | match |
| `os.spawnv` | match | match | match |
| `os.spawnl` | match | match | match |
| `os.spawnve` | match | match | match |
| `os.execv` | match | match | match |
| `os.execl` | match | match | match |
| `os.execvpe` | match | match | match |
| `os.respawn` | NO match | no match | **matched - the phantom** |
| `chaos.respawn` | NO match | no match | **matched - the phantom** |
| `os.child_spawn` | NO match | no match | **matched - the phantom** |
| `os.execute` | NO match | no match | **matched - the phantom** |
| `os.spawn_thing` | NO match | no match | **matched - the phantom** |
| `os.respawn` with no module mention | NO match | no match | no match |

Fifteen of fifteen. **This table is the check `agents-yhhi` asked to exist**: it enumerates the match set
instead of sampling modules, so a future widening that re-opens a shape fails here even though the census
would stay clean. The census remains useful for the phantom count; it simply cannot see this class.

### Census, with the counting method named (agents-3gq1)

`agents-3gq1` found the round-7 columns (OLD 12 -> 4) reproduce under none of the three counting methods the
reviewer drove, and that is right: those numbers are **suites the FOURTH SOURCE ALONE claims** - candidates
that fail the oracle's own import rule - not the oracle's omitted sets. Stated against the oracle's own
omitted lists, the reviewer's own measurement is (quoted, attributed - I did not re-derive it):

| module | oracle omitted, OLD -> new | fourth-source-alone, OLD -> new |
| --- | --- | --- |
| sandbox | 37 -> 32 | 7 -> 1 |
| findings | 28 -> 26 | 3 -> 1 |
| tool_pins | 39 -> 35 | 0 -> 0 |
| child_env | 16 -> 16 | 2 -> 2 |
| the other four | 2 -> 2 each | 0 -> 0 |
| **fourth-source total** | **33 -> 21** | **12 -> 4** |
| **net fourth-source contribution** | **11 -> 0** | - |

**The load-bearing claim reproduces under all three methods: NO MODULE GAINS A PHANTOM.** Round-8-only is
zero on this revision as well, re-measured rather than carried forward.

The remaining new-rule matches the reviewer named - `test_containment_egress`,
`test_station_trusted_tool_pins`, `test_store_lock_timeout`, `test_prompt_exposure` - are **real consumers**
(they import the module and spawn a subprocess), not phantoms, which is the `agents-aung`-era conclusion.
