## `fleet-coverage-oracle-os-class-derived-from-os-module.patch` (agents-apqc, agents-yhhi, agents-3gq1, agents-aung, agents-6r5g, agents-hbz3)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 `d60e9ad23d460ac1`..., mtime 2026-10-12 19:42 - re-read when this revision was cut.

## READ THIS FIRST - THESE PATCHES ARE ALTERNATIVES, NOT A SEQUENCE

**Every oracle patch in `patches/` touching this file is an ALTERNATIVE against the same base, not a step in a
sequence** - `agents-hbz3`'s binding rule (`b63a9b3`), `agents-6r5g`'s binding set and wrapped imports
(`fbabab4`), the `agents-aung` os class (`698420c`), the round-8 enumeration (`6b3ce58`), and this one. Each
was cut as a diff against the PRISTINE file at the revision above; none was cut from its predecessor.
**APPLYING THEM IN SEQUENCE WILL FAIL OR CORRUPT THE FILE**, because each diff expects the original context
the previous one removed. Apply ONE - the newest that carries what you need. This revision carries the whole
binding rule, both restored channels, and the os class.

## agents-apqc: round 8 LOST a channel that round 7 had

Round 8 replaced the glob with an enumerated list so `os.respawn` and friends would stop matching. **It also
dropped `os.posix_spawnp`** - the PATH-searching variant of `posix_spawn`, a real member of the family that
round 7's glob `[a-z_]*spawn[a-z_]*` DID cover. The literal `posix_spawn` had no suffix glob, so the trailing
`p` broke the required paren.

That is a **lost channel**, and a lost channel is worse than the phantoms round 8 removed: a phantom is
visible and reviewable, a missing candidate is a suite that silently does not run. The claim in the round-8
note that the enumerated list was "not narrower in practice than a glob" was false. **Fixed by
`posix_spawnp?`**, which covers both spellings and still cannot reach `os.respawn` because the alternation is
anchored at the attribute start.

## The os family, measured against `dir(os)` - a RECORD, NOT A WIRED CHECK

`agents-ml7z` is right about what this is and it should be read that way. **What is in this file is a written
record of a measurement, not a check that will fail when the next omission happens.** Only code can fail; a
table in a `.md` cannot. The earlier draft of this note claimed an "instrument that makes an omission fail
loudly", which overstated it, and that claim is withdrawn.

**`agents-ml7z` is also right that the population number was wrong, and the reconciliation is this.** The
population rule, stated so it can be re-derived exactly:

    [x for x in dir(os) if not x.startswith('_')
     and any(k in x for k in ('fork', 'spawn', 'exec', 'system', 'popen', 'posix'))]

That yields **26** names on Python 3.12.3, and it is the number `agents-ml7z` measured. My earlier figure of 58
came from a DIFFERENT filter - it also matched `wait`, `kill`, `signal` and `pipe` and it lowercased the name
before matching, which swept in **21 uppercase CONSTANTS that cannot be called at all** (`P_WAIT`, `P_NOWAIT`,
`O_CLOEXEC`, `POSIX_SPAWN_OPEN`, `WNOWAIT`, `SCHED_RESET_ON_FORK`, ...). 58 was a count of a set that included
non-callable names; **26 is the callable population and it is the correct number.** My own table's heading had
also described a third rule, so the same note carried three populations in it.

**Instrument and direction**, stated per the `agents-y30x` process fix: population as the rule above (26 names);
instrument the REAL oracle CLI, one scratch repo, one commit per name placing the name in a call with
`lib/sandbox.py` in its arguments, a zero-suite log line; direction pristine oracle -> this revision. Every
verdict below was produced that way, and nothing is quoted from anyone else's run.

| `os.<name>` | pristine oracle | this revision | |
| --- | --- | --- | --- |
| execl, execle, execlp, execlpe | no | **YES** | GAINED |
| execv, execve, execvp, execvpe | no | **YES** | GAINED |
| popen | no | **YES** | GAINED |
| posix_spawnp | no | **YES** | GAINED |
| posix_spawn | YES | YES | unchanged |
| system | YES | YES | unchanged |
| fork | YES | **no** | dropped, deliberate |
| register_at_fork | YES | **no** | dropped, deliberate |
| forkpty, get_exec_path, posix_fadvise, posix_fallocate | no | no | never a paren-arg call |

**TEN names gained, not eleven.** An earlier draft of this note said "eleven" and then listed exactly ten, and
the correction is worth stating because the count was repeated onward: the gained set is the ten rows above
marked GAINED. The pristine pattern's name branch was `subprocess|Popen|exec|spawn|run|fork|call|check_output|
system`, and each alternative had to be followed immediately by `\s*\(`, so `os.execv(` never matched `exec`
- a `v` follows - and `os.popen(` matched nothing at all. The modelled os class is therefore WIDER coverage
than what it replaces, which is the context both of the open findings were missing.

**Two names dropped, both deliberate**: `os.register_at_fork` is a phantom this revision REMOVES (pristine
matched the bare substring `fork` inside it; it registers a callback and launches nothing), and `os.fork`
takes no arguments, so it can never carry a file path in its own call - the child that would name the module
is an `exec*` call the exec class already covers. A channel requires a call that can name the module; neither
of these is one. Recorded rather than silently dropped.

### How to reproduce this table

    # population
    python3 -c "import os;print('\n'.join(sorted(x for x in dir(os) if not x.startswith('_') and any(k in x for k in ('fork','spawn','exec','system','popen','posix')))))"
    # then, per name: a scratch git repo with a `main` branch, a case branch off it, the case written as
    #   import os
    #   os.<name>(["python3", "lib/sandbox.py"])
    # WITH lib/sandbox.py also touched in the same commit (the oracle only considers changed files), and
    # printf 'fast-gate: running: tests/zzz_absent.test.sh\n' > log.txt
    python3 <oracle>.py log.txt <repo> "$SHA" ''    # read .omitted for the case

CONTROL, so a green table is not simply a table that matches nothing: run it against the PRISTINE oracle and
it must be RED on `execl`, `execv` and `popen`. If the pristine column is not red there, the rig is wrong
rather than the revision.

### Why this is not shipped as a check

`agents-ml7z`'s stronger alternative was to make it a real check. It cannot be installed from this host: the
oracle lives at `~/fleet/remote/check-coverage.py`, inside the hub's read-only tree, and a project lane cannot
write a test into it. A check would have to be added by the hub, which is the same split as the `agents-825v`
fixture. Recorded as the reason rather than as a preference.

## Census, re-derived here with the method named

| module<br>POPULATION: the eight `pdth`-allowlisted modules | omitted-suite COUNT<br>INSTRUMENT: real oracle CLI, one commit per module touching `lib/<M>.py`, zero-suite log<br>DIRECTION: pristine -> this revision | fourth-source-alone CONTRIBUTION<br>INSTRUMENT: the same run with the subprocess source disabled, subtracted<br>DIRECTION: pristine -> this revision |
| --- | --- | --- |
| sandbox | 21 -> 16 | 5 -> 0 |
| findings | 13 -> 11 | 2 -> 0 |
| tool_pins | 10 -> 10 | 0 -> 0 |
| child_env | 12 -> 12 | 0 -> 0 |
| candidate_identity | 4 -> 4 | 0 -> 0 |
| containment | 7 -> 7 | 0 -> 0 |
| credential_broker | 10 -> 10 | 0 -> 0 |
| egress_proxy | 7 -> 7 | 0 -> 0 |
| **TOTAL** | **84 -> 77** | **7 -> 0** |

No column is quoted; every number was measured for this revision. **The load-bearing claim holds: no module
gains a phantom, and the fourth source's net contribution is 0.** `agents-y30x` was right that an earlier
draft's tool_pins row was internally impossible (an omitted drop of 4 beside a 0 -> 0 contribution) - two
different measurements laid side by side as one.

## What is deliberately NOT modelled (agents-aung's recorded limit)

`asyncio.create_subprocess_exec`, `multiprocessing`, and anything reached through a wrapper or a factory. The
literal-only ruling: an unresolvable case is LEFT OUT AND DOCUMENTED rather than matched by guessing, because
guessing is how the eight phantoms were created.
