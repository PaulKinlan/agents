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

## The os invocation class: the rule, and how to re-measure it

**This section makes no numeric claim, deliberately.** Earlier drafts of this note stated a population size, a
gained count, and a per-name table, and each of those was wrong or incomplete once and each cost a review
round. A claim I cannot keep is worse than no claim, so the numbers are gone and the rule and the command
replace them.

**THE RULE**, verbatim, so it can be re-derived rather than recalled:

    [x for x in dir(os) if not x.startswith('_')
     and any(k in x for k in ('fork', 'spawn', 'exec', 'system', 'popen', 'posix'))]

**THE COMMAND THAT PRODUCES THE POPULATION:**

    python3 -c "import os;print('\n'.join(sorted(x for x in dir(os) if not x.startswith('_') and any(k in x for k in ('fork','spawn','exec','system','popen','posix')))))"

**WHAT THIS IS: a RECORD of a measurement taken once, not a check.** Only code can fail; a table in a
markdown file cannot. What follows is what was measured, not a mechanism that will notice the next omission.

**THE MEASUREMENT, and its control.** Each name in the population was placed in a call carrying
`lib/sandbox.py` in its arguments and driven through the REAL oracle CLI - never a reimplementation of the
oracle's matching rule - in a scratch git repo with a `main` branch and a case branch off it, with
`lib/<M>.py` also touched in the same commit because the oracle only considers CHANGED files, and with a
zero-suite log line so coverage is KNOWN rather than UNKNOWN. Each of those four details is a way to get an
all-empty result that reads as "no match" and therefore agrees with the wrong conclusion; they are listed so
the control below is meaningful.

**CONTROL**: pristine must be RED on the subset of the population whose name begins `exec`. Pristine's name
branch was `subprocess|Popen|exec|spawn|run|fork|call|check_output|system` with each alternative required to
be followed immediately by `\s*\(`, so `os.execv(` never matched `exec` - a `v` follows the `c`. If pristine
is not red there, the rig is wrong and no other column means anything. That subset is defined by a property
rather than by a hand-written list, so it cannot be incomplete.

**THE TWO EXCLUSIONS, justified by a criterion rather than by taste.** A name is a *channel* only if a call
carrying that name can put the module path in its OWN arguments:

- `os.fork` takes no arguments, so no `fork` call can name a module; the child that would name it is an
  `exec*` call, which the class already covers.
- `os.register_at_fork` registers a callback and launches nothing. Pristine matched it on the bare substring
  `fork`, and it is the phantom this class removes.

That criterion is the falsifiable part of this note, and it is the part worth arguing with: an objection to it
would make those two removals lost channels rather than correct exclusions.

**MATERIAL FOR A REAL CHECK, which cannot live here.** The stronger deliverable is a test that fails on the
next omission. It cannot be installed from this host: the oracle is at
`~/fleet/remote/check-coverage.py`, inside the hub's read-only tree, so a project lane cannot write a test
into it - the same split as the `agents-825v` fixture. What the hub needs to build one is:

1. the population one-liner above;
2. the control assertion above, defined by the `^exec` property;
3. the criterion above, which turns "neither pristine nor this revision matches this name" into a decision
   that must be made rather than a silence.

An assertion of that third kind is the one a table could not make: it fails when a NEW `os.spawn`-style
function appears, because the name is neither matched nor excused, and that is exactly the omission this
whole line of work was about.

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
