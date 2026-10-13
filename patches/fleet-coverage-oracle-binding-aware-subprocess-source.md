## `fleet-coverage-oracle-binding-aware-subprocess-source.patch` (agents-hbz3 round 2, for agents-mjsq)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1..., mtime 2026-10-12 19:42.
This REPLACES `fleet-coverage-oracle-narrow-subprocess-source.patch` (round 1), which `agents-mjsq` failed
for under-inclusion and which should not be applied. Hub delivery; the file is in the fleet tree.

### The finding, and the principle

Round 1 qualified the call names to `subprocess.*` / `os.*`. It recovered the eight phantoms but **lost
genuine consumers**: a suite doing `from subprocess import Popen` and then calling the bare `Popen([...])`
is a real invocation and stopped matching. Under-inclusion is the worse half, because a mapping that
misses a real consumer is silent while a phantom is visible and reviewable.

**The name is not the evidence, the binding is.** Requiring `subprocess.Popen` excludes a legitimate
`from subprocess import Popen` call site; accepting `Popen` alone re-admits the method-name noise. So the
discriminator is WHERE THE CALLEE CAME FROM:

* **attribute branch** - `subprocess.<X>`, or `<alias>.<X>` for `import subprocess as <alias>`;
* **name branch** - `<X>` only when a `from subprocess import ...` in that module binds it, **and only
  when the call is a bare name**: a preceding dot means an object's method (`self.run(...)`,
  `runner.run(...)`), which is not a process whatever the method is called;
* a bare `run(` or `call(` with no subprocess binding stays out - that is the original noise.

`from subprocess import *` cannot be resolved by a binding rule at all. It is treated as binding the
known call names, i.e. it **fails open**, because for a consumer oracle a missed real consumer is silent.

### Does the fourth source deserve to exist?

Yes, and it is narrowed rather than deleted. A suite that runs `lib/x.py` as a command consumes it exactly
as an importer does, and nothing else in the oracle sees that channel. The next reader should not read
this as "the pattern was a mistake".

### Verification - twelve cases, both directions in one rig

| # | case | required | result |
| --- | --- | --- | --- |
| 1 | `from subprocess import Popen` then bare `Popen(["python3","lib/sandbox.py"])` | match | **matches** |
| 2 | `import subprocess` then `subprocess.run([...])` | match | **matches** |
| 3 | `import subprocess as sp` then `sp.Popen([...])` | match | **matches** |
| 4 | `subprocess.call([sys.executable,"-m","lib.findings"])` | match | **matches** |
| 5 | `from subprocess import Popen, run` then bare `run([...])` | match | **matches** |
| 6 | `from subprocess import run` then bare `run([sys.executable,"lib/sandbox.py"])` | match | **matches** |
| 7 | `self.run(self, sandbox)` **with** a `from subprocess import run` binding | no match | **no match** |
| 8 | `    def run(self, sandbox: Path)` with no binding | no match | **no match** |
| 9 | `-p test_sandbox*` inside a real `subprocess.run` | no match | **no match** |
| 10 | `self.run(self, sandbox)` **with** an alias binding | no match | **no match** |
| 11 | bare `run(self, sandbox)` with no binding | no match | **no match** |
| 12 | `from subprocess import *` then bare `Popen([...])` | (unresolvable) | **matches - fails open, stated above** |

Twelve of twelve, zero failures. Case 7 is the one that round 1 failed and case 3 is the alias form that
a fix must not silently drop.

**Phantom census, every module `pdth` allowlists, old oracle vs this patch:**

| module | OLD | round 2 | fixed | round-2-only |
| --- | --- | --- | --- | --- |
| sandbox | 7 | 1 | test_hermetic_env, test_path_security, test_pr_fixer_prepass, test_prepass_pin_boundary, test_report_schema, test_vuln_verify_prepass | none |
| findings | 3 | 1 | test_path_security, test_pr_fixer_prepass | none |
| child_env | 2 | 2 | - | none |
| containment, egress_proxy, credential_broker, tool_pins, candidate_identity | 0 | 0 | - | none |
| **TOTAL** | **12** | **4** | **8** | **0** |

### What it does not fix, stated rather than hidden

The four remaining are three different things, and only one of them is a defect of the same kind:

* `test_store_lock_timeout.py` (**not a defect**): it genuinely runs `lib/findings.py`, via
  `subprocess.run([sys.executable, str(ROOT / "lib" / "findings.py"), ...])`. A joined path is a real
  invocation and matching it is correct.
* `test_prompt_exposure.py` and the two `child_env` cases (**a different class**): the callee really is
  `subprocess.run` and the binding rule is satisfied; what matches is an **argument or keyword value that
  happens to be named after the module** - `["bash", str(sandbox.root, ...)]` and `env=child_env`. That is
  a look-alike local variable, not the module, and no binding rule on the callee can see the difference.
  The `child_env` pair predates this work (it is 2 in OLD as well).
* Round 1 had 12 and this has 4, with **no new noise in any module**.
