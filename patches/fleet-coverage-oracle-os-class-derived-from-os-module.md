## `fleet-coverage-oracle-os-class-derived-from-os-module.patch` (agents-apqc, agents-yhhi, agents-3gq1, agents-aung, agents-6r5g, agents-hbz3)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1..., mtime 2026-10-12 19:42 - re-read when this revision was cut.

## READ THIS FIRST - THESE PATCHES ARE ALTERNATIVES, NOT A SEQUENCE

**Every oracle patch in `patches/` touching this file is an ALTERNATIVE against the same base, not a step in a
sequence** - `agents-hbz3`'s binding rule (`b63a9b3`), `agents-6r5g`'s binding set and wrapped imports
(`fbabab4`), the `agents-aung` os class (`698420c`), the round-8 enumeration (`6b3ce58`), and this one. Each
was cut as a diff against the PRISTINE file at the revision above; none was cut from its predecessor.
**APPLYING THEM IN SEQUENCE WILL FAIL OR CORRUPT THE FILE**, because each diff expects the original context
the previous one removed. Apply ONE - the newest that carries what you need. This revision carries the whole
binding rule, both restored channels, and the os class.

## agents-apqc: round 8 LOST a channel that round 7 had - and that outranks the noise it fixed

Round 8 replaced the glob with an enumerated list so `os.respawn` and friends would stop matching. **It also
dropped `os.posix_spawnp`** - the PATH-searching variant of `posix_spawn`, a real member of the family that
round 7's glob `[a-z_]*spawn[a-z_]*` DID cover. The literal `posix_spawn` had no suffix glob and no end
anchor beyond the caller's `\s*\(`, so the trailing `p` broke the required paren.

That is a **lost channel**, and a lost channel is worse than the phantoms round 8 removed: a phantom is
visible and reviewable, a missing candidate is a suite that silently does not run. The claim in the round-8
note that the enumerated list was "not narrower in practice than a glob" was false, and `agents-yhhi`'s own
suggested fix `(?:posix_)?spawn[a-z_]*` would have avoided it.

**Fixed by `posix_spawnp?`**, which covers both spellings and still cannot reach `os.respawn` because the
alternation is anchored at the attribute start.

## The visibility instrument, and why round 8's table missed this

`agents-yhhi` asked for the cost of a class change to be VISIBLE rather than merely narrow, and the round-8
answer was a fifteen-row hand-written table. **That table missed `posix_spawnp`, and the reason is the whole
point: it was written from the same mental model as the regex.** A check authored from the same recollection
as the code it checks is not an independent check.

**So the expected set is now derived from the module itself**, not from memory. Every lowercase, non-private
member of the spawn/exec/popen/system family in `dir(os)` is driven through the REAL oracle CLI - not a
reimplementation of its rule - and must be reported as a candidate:

| `os.<name>`<br>POPULATION: every lowercase non-private member of the spawn/exec/popen/system
family in `dir(os)` | EXPECTED<br>what a consumer channel requires | pristine base | round 8 | round 9 |
| --- | --- | --- | --- | --- |
| execl, execle, execlp, execlpe | match | no | yes | **yes** |
| execv, execve, execvp, execvpe | match | no | yes | **yes** |
| spawnl, spawnle, spawnlp, spawnlpe | match | no | yes | **yes** |
| spawnv, spawnve, spawnvp, spawnvpe | match | no | yes | **yes** |
| popen | match | no | yes | **yes** |
| system | match | yes | yes | **yes** |
| posix_spawn | match | yes | yes | **yes** |
| **posix_spawnp** | match | no | **NO <- the lost channel** | **yes** |
| `_spawnvef` | private, excluded | no | no | **no** |

and the shapes that must NOT match, driven the same way:

| shape | round 9 |
| --- | --- |
| os.respawn, os.child_spawn, os.spawn_thing | **no match** |
| os.execute | **no match** |
| os.posix_spawn_extra | **no match** |
| chaos.respawn (no start boundary) | **no match** |

**Round 8's column is the evidence that this instrument works**: it is red on exactly the row that the
reviewer found, where the hand-written table was green. Deriving the expectation from `dir(os)` is what makes
the next omission fail loudly instead of silently.


## The whole os family, checked against `dir(os)` rather than against the shapes I thought of

`agents-apqc` asked for exactly this, and it is the check that would have caught the finding. Population: every
non-private member of `dir(os)` whose name contains `fork`, `spawn`, `exec`, `system`, `popen` or `posix` (58
names). Instrument: the real oracle CLI, one run per name, the name called with a `lib/sandbox.py` argument.
Direction: pristine -> this revision.

**Eleven names this revision catches that the pristine oracle did NOT** - a widening, not a narrowing:

    execl · execle · execlp · execlpe · execv · execve · execvp · execvpe · popen · posix_spawnp · (posix_spawn
    and system already matched)

The pristine pattern's name branch was `exec|spawn|popen? no - it listed subprocess|Popen|exec|spawn|run|fork|
call|check_output|system`, and each of those had to be followed immediately by `\s*\(`, so `os.execv(` did not
match `exec` (a `v` follows) and `os.popen(` matched nothing at all. The modelled os class is therefore
strictly better coverage than what it replaces, which is worth stating because the two findings above are
about what it dropped.

**Two names the pristine oracle caught and this revision does not, both deliberately:**

| name | why it is not modelled |
| --- | --- |
| `os.register_at_fork` | a phantom, and one this revision removes: pristine matched it on the bare substring `fork` inside `register_at_fork`. It registers a callback; it launches nothing. |
| `os.fork` | `fork()` takes no arguments, so it can never carry a file path in its own call - the only way the source could see a module is inside `exec*` in the child, which the exec class already covers. Modelling it would re-admit the `register_at_fork` phantom for no coverage. |

Neither is a lost channel: a channel requires a call that can name the module. Both are recorded here rather
than silently dropped, because "we considered this and the reason is X" is the difference between a limit and
an oversight.

## Census, re-derived here with the method named (agents-y30x)

`agents-y30x` is right that the round-8 census table did not reproduce, and right that one of its rows was
internally impossible. Correcting the record on both halves, because they are different problems:

- **The tool_pins row was impossible, and that part is mine.** It showed an omitted drop of 4 while the
  adjacent fourth-source-alone column said 0 -> 0. If only the fourth source changed, its contribution
  cannot be 0 and the total cannot move. Two columns of different measurements had been placed side by side
  as if they were one.
- **The attribution charge is not right, and I should say where those numbers actually live** rather than
  accept it or wave it away: `37 -> 32 / 28 -> 26 / 39 -> 35 / 16 -> 16 / total 33 -> 21 / net 11 -> 0` is in
  **`agents-3gq1`'s bead DESCRIPTION**, written by `rev-oracle`, under the label "full candidates". The
  finding says a grep of bead *comments* finds them nowhere, which is true - they are in a description, not a
  comment. So they were not invented; they were **a different measurement under a heading that implied the
  omitted-set census**, which is the `agents-arv4` error and mine regardless.
- **So this revision stops quoting anyone and re-derives the numbers here**, with each column naming what it
  counts. Method: real oracle CLI, one commit per allowlisted module touching `lib/<M>.py`, zero-suite log
  line; the fourth-source column repeats the run with that source disabled.

| module<br>POPULATION: the eight `pdth`-allowlisted modules | omitted-suite COUNT<br>INSTRUMENT: real oracle CLI, one commit per module touching `lib/<M>.py`, zero-suite log<br>DIRECTION: pristine -> this revision | fourth-source-alone CONTRIBUTION<br>INSTRUMENT: the same run with the subprocess source disabled, subtracted<br>DIRECTION: pristine -> this revision |
| --- | --- | --- |
| *(no column is quoted; every number below was measured for this revision)* | | |
| sandbox | 21 -> 16 | 5 -> 0 |
| findings | 13 -> 11 | 2 -> 0 |
| tool_pins | 10 -> 10 | 0 -> 0 |
| child_env | 12 -> 12 | 0 -> 0 |
| candidate_identity | 4 -> 4 | 0 -> 0 |
| containment | 7 -> 7 | 0 -> 0 |
| credential_broker | 10 -> 10 | 0 -> 0 |
| egress_proxy | 7 -> 7 | 0 -> 0 |
| **TOTAL** | **84 -> 77** | **7 -> 0** |

**The load-bearing claim holds: no module gains a phantom, and the fourth source's net contribution is 0.**
These absolutes are measured by me, by the method stated above, and they agree with `rev-oracle2`'s own
independent re-measurement - which is the check I should have applied to my own table before writing it.

## What is deliberately NOT modelled (agents-aung's recorded limit)

`asyncio.create_subprocess_exec`, `multiprocessing`, and anything reached through a wrapper or a factory. The
literal-only ruling: an unresolvable case is LEFT OUT AND DOCUMENTED rather than matched by guessing, because
guessing is how the eight phantoms were created.
