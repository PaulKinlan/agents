## `fleet-coverage-oracle-module-binding-set-and-wrapped-imports.patch` (agents-6r5g, partially)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1...,
mtime 2026-10-12 19:42 - unchanged, so this is a re-cut on the same base as the cleared
`fleet-coverage-oracle-binding-aware-subprocess-source.patch` (`agents-hbz3`, tip `b63a9b3`). That patch is
**untouched**; this one is a separate, bounded restoration and both are hub deliveries against the same file.

### Why this exists

`agents-6r5g` (from `rev-hbz3r5`) named three under-inclusion channels that the OLD oracle covered and the
binding-aware patch dropped: a dual plain-plus-alias import, a parenthesised from-import, and `os.posix_spawn`.

**TWO OF THOSE ARE BUGS WITH NO DECISION IN THEM**, which is why they are fixed here rather than held for the
scope discussion on `agents-aung`:

1. **THE MODULE BINDING WAS A SINGLE LAST-WINS STRING.** `_bind_attr` held one name, so a file containing
   BOTH `import subprocess` and `import subprocess as sp` lost the plain `subprocess.<X>` branch for the whole
   file. A file may legally hold both bindings and both are subprocess, so the module names bound to
   subprocess are now a **SET**, and a bare `import subprocess` is captured as well as the aliased form.
2. **A FROM-IMPORT MAY BE WRAPPED IN PARENTHESES.** Python's grammar allows it, and the old regex captured
   only the first line, so `from subprocess import (\n    Popen,\n    run,\n)` bound `'(Popen,'` and lost
   every continuation name. The parenthesised form is now read too, including the trailing-comma form.

### The third channel is a DELIBERATE LIMIT, NOT A FORGOTTEN ONE

`os.posix_spawn` is **not modelled**, and neither are `os.execv`, `asyncio.create_subprocess_exec`,
`multiprocessing`, or a helper that wraps any of them. That is the open question **which invocation channels
does the oracle model at all**, which is open-ended and is the decision recorded on `agents-aung` alongside
the look-alike-argument class. It is recorded here so the next reader does not re-file it as an oversight.
The modelled os channels are `os.(system|popen|spawn*|exec*)`.

### The load-bearing reason

**A LOST CHANNEL IS INVISIBLE; A PHANTOM IS VISIBLE.** A phantom costs seconds in a report and is
reviewable. A lost channel means a change to `lib/sandbox.py` skips the suite that asserts it, and nothing
says so. That is why a restoration bug outranks a noise bug, and why both fixes here restore rather than
tighten.

### Verification - the reviewer's own repros, driven first

| # | case | required | result |
| --- | --- | --- | --- |
| 1 | `import subprocess` AND `import subprocess as sp`, then `subprocess.run([...])` | match | **matches** - the branch is recovered |
| 2 | the same file, then `sp.run([...])` | match | **matches** - the alias branch still works |
| 3 | `from subprocess import (\n Popen,\n run,\n)` then bare `run([...])` | match | **matches** |
| 4 | `from subprocess import (\n Popen,\n)` then `Popen([...])` | match | **matches** |
| 5 | `from subprocess import (Popen, run)` one line | match | **matches** |
| 6 | `from subprocess import (\n Popen as P,\n)` then `P([...])` | match | **matches** |
| 7 | plain `import subprocess` then `subprocess.run([...])` | match | **matches** |
| 8 | `import os` then `os.system([...])` | match | **matches** (agents-ay0s, still restored) |
| 9 | `from subprocess import Popen as P` then `P([...])` | match | **matches** (agents-ay0s, still restored) |
| 10 | `os.posix_spawn(...)` mentioning the module | no match | **no match** - a stated limit, above |
| 11 | `from subprocess import PIPE as Q` then `Q([...])` | no match | **no match** - a non-call name is not an invocation |

One earlier probe of mine read `from subprocess import (\n Popen,\n)([...])` and failed; that string is not
valid Python (`SyntaxError`), so the probe was wrong rather than the pattern, and it is recorded here rather
than quietly dropped.

### The twelve binding cases still hold

All twelve from the hbz3 note re-run against this patch: six must-match and five must-not-match all correct,
including the dot-guard property (`self.run(self, sandbox)` with a from-subprocess binding does not match) and
the wildcard case (which matches by design).

### Census - round-6-only must be zero, because a restoration is where a phantom sneaks back

| module | OLD | this patch | fixed | round-6-only |
| --- | --- | --- | --- | --- |
| sandbox | 7 | 1 | 6 | **none** |
| findings | 3 | 1 | 2 | **none** |
| child_env | 2 | 2 | 0 | **none** |
| containment, egress_proxy, credential_broker, tool_pins, candidate_identity | 0 | 0 | 0 | **none** |
| **TOTAL** | **12** | **4** | **8** | **0** |

Both fixes restore channels and neither re-admits a phantom.
