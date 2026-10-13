## `fleet-coverage-oracle-os-invocation-class-posix-spawn.patch` (agents-aung decision, agents-6r5g channel 3)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1...,
mtime 2026-10-12 19:42 - unchanged. A HUB DELIVERY, separate from the cleared `b63a9b3` (binding rule) and from
`fbabab4` (agents-6r5g channels 1 and 2), neither of which it modifies. It carries the whole binding rule plus
the extension, because the file is patched as a unit.

### The decision this implements

`agents-aung` was the open scope question: **which invocation channels does the oracle model at all.** Coord's
ruling, now implemented:

* **MODELLED** - subprocess bindings (plain, aliased, wrapped, both in one file), and the **os attribute
  calls**: `os.(system|popen|[a-z_]*spawn[a-z_]*|exec[a-z_]*)`.
* **NOT MODELLED, AS A RECORDED LIMIT** - `asyncio.create_subprocess_exec` and friends, `multiprocessing`,
  and anything reached through a wrapper or a factory. **This is deliberate, not an oversight.** The reason
  is the literal-only ruling: a consumer oracle's output feeds SELECTION, so an unresolvable case is **left
  out and documented rather than matched by guessing** - guessing is exactly how the eight phantoms were
  created in the first place.

### The one extension, which was a hole in an existing class rather than a new policy

`os.posix_spawn` is an os attribute call, and the branch already claimed `os.spawn*` and `os.exec*`. It
escaped only because the attribute begins `posix_`, so `spawn[a-z_]*` could not reach it. The pattern is now
`[a-z_]*spawn[a-z_]*`, which covers `os.spawnv` **and** `os.posix_spawn` without widening the class to
anything it did not already claim.

### Verification - the extension, then the settled cases

| # | case | required | result |
| --- | --- | --- | --- |
| 1 | `os.posix_spawn("python3", ["lib/sandbox.py"], {})` | match | **matches** (was NOT matched before) |
| 2 | `os.spawnv(os.P_WAIT, "python3", ["lib/sandbox.py"])` | match | **matches** |
| 3 | `os.execv("python3", ["lib/sandbox.py"])` | match | **matches** |
| 4 | `os.system("python3 lib/sandbox.py")` | match | **matches** |
| 5 | `asyncio.create_subprocess_exec("python3", "lib/sandbox.py")` | no match | **no match** - recorded limit |
| 6 | `multiprocessing.Process(target=run, args=("lib/sandbox.py",))` | no match | **no match** - recorded limit |
| 7 | `os.posix_spawn("echo", ["hi"], {})` with no module mention | no match | **no match** |

Then the twelve settled binding cases re-run **12/12** - including the dot-guard property - and the census is
unchanged with **ROUND-7-ONLY ZERO**:

| module | OLD | this patch | fixed | round-7-only |
| --- | --- | --- | --- | --- |
| sandbox | 7 | 1 | 6 | **none** |
| findings | 3 | 1 | 2 | **none** |
| child_env | 2 | 2 | 0 | **none** |
| containment, egress_proxy, credential_broker, tool_pins, candidate_identity | 0 | 0 | 0 | **none** |
| **TOTAL** | **12** | **4** | **8** | **0** |

Extending a class is where a phantom sneaks back, so the census was re-measured rather than carried forward.
