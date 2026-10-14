## `fleet-check-explain-foreign-config.patch` (agents-0r1c)

- **Target repository:** `PaulKinlan/fleet`
- **Target file:** `bin/fleet-check`, two insertions: the three diagnostic functions inside the worker
  heredoc (immediately before `finish()`), and their one call inside the worker's `finish()` — after
  the state has been derived and after the coverage extraction has read the log, but **before** the
  tail is captured, so the note lands in the record's tail and in the `[check]` message exactly once.
- **Baseline file hash (the live bytes this patch was generated against and applies to):**
  `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498  bin/fleet-check`
  (767 lines; patched result `93e270dc63f5889d6548ed726e0fe7f31082f99d421dd519bcded896a662a844`)
- **Revision (agents-e3aw, second round): the repair must RUN FROM WHERE IT IS READ, so its path is resolved.**
  The revision below offered `bash tools/check-cmd.sh --install` when the reader is present - and that is a
  RELATIVE path, which runs only from the repo root while the reader of the message is standing anywhere. Driven
  on the bytes of the first round: invoked from the repo root, from a subdirectory, and by absolute path from
  outside the repo, the note printed the IDENTICAL command, and running it then succeeded in the first case and
  failed with `No such file or directory` in the other two. The reader is designed to be called by a RUNNER and a
  runner's cwd is not guaranteed to be the repo root - the repo's own installer already calls it by absolute path
  (`install.sh`). The artifact now prints the path it JUST TESTED (`[ -f "$top/tools/check-cmd.sh" ]`), so the
  command cannot name a file that was not there, and the in-repo half of the same fix prints the reader's own
  resolved path from `BASH_SOURCE` - the same source `ROOT` is derived from. **THE TEST IS THE LESSON: the
  existing test asserted the printed STRING and ran it from the repo root, which is why four rounds of this family
  kept passing while the guidance was unrunnable. A test that runs a printed command in the one directory where it
  happens to work asserts the string rather than the property the string exists to deliver** - that test now runs
  the printed command from a directory that is NOT the repo (agents-e3aw), and with the relative form restored it
  goes red (measured: six failures), including every destination variant.
- **Revision (agents-e3aw, first round):** the repair line now names only what the reader can see. The first revision of
  this artifact printed *"Repair: give this repo its own config (bash tools/check-cmd.sh --install writes
  $HOME/.fleet/<repo>-check.conf) and point the gate at it with FLEET_CHECK_CONF, or re-install the host-wide
  file from the repo that should own it"* — which tells the reader to run an installer **in the repo the gate
  ran from**, the one repo that may not have it and precisely the situation the note exists for, and then says
  to fix the host-wide file "from the repo that should own it" **without naming it**, although the note had
  already resolved that repo from the config's own stamp (`prov`, printed as "was installed by …" one line
  above). Driven side by side on the same three inputs, the old text says that same sentence in every case,
  including the case where `tools/check-cmd.sh` does not exist; the new text offers the installer only when it
  is really there, and names the stamped repo by name or says plainly that the config carries no stamp. **Any
  evidence predating this revision is void: the patched bytes changed** (the artifact is a delivery to the hub,
  and has not been applied to any live `~/fleet`).
- **Revision history:** THIRD shape, and the name changed with it — the patch is
  `fleet-check-explain-foreign-config.patch` (it was `fleet-check-refuse-foreign-config.patch`, which
  described a refusal that no longer exists; the old artifact and its write-up are deleted in the same
  commit, and the patch had never been handed to the hub). Rounds one and two of the refusal shape
  FAILED review with four P2 findings between them — agents-wisk, agents-jqc4, agents-v0ip, agents-biz8
  — and every round was a narrower parse of a shell command line. **Any dry-run evidence predating this
  revision is void: the patched bytes changed, and so did what the patch does.**
- **Disposition:** DELIVERY ONLY — nothing has been applied to any live `~/fleet`. Unlike the previous
  revisions there is **no ordering hazard**: nothing is refused any more, so this patch is safe to apply
  in any order at any time, and that is a property of the shape rather than of luck.

### Problem Statement (agents-0r1c, the reader half of agents-0utp)

agents-0utp fixed the WRITER (a bare `--install` no longer rewrites the machine-global file) and
agents-p8lh made the repairs the tools print truthful. Neither touched the READER: a config already
installed by another repo keeps being read, and `bin/fleet-check` is that reader — it sources
`${FLEET_CHECK_CONF:-$HOME/.fleet/check.conf}` directly and never goes through `tools/check-cmd.sh`, so
an in-repo fix cannot close this. The live `~/.fleet/check.conf` carries `bash tools/fast-gate.sh` and a
suite command needing `tools/` and `tests/`, which exist only in agents-factory, so a gate run from any
other repo died with **EXIT 127** — a message about a *missing tool* when the truth was a *foreign
config*. The failure surfaced at the next repo's gate rather than at install time.

### Why the refusal shape was abandoned rather than repaired a third time

The first two revisions tried to REFUSE the command at hand-out time, on a prediction, and review broke
that prediction four ways on the same day:

| finding | the prediction was |
|---|---|
| agents-wisk | a MISS: `bash ./tools/fast-gate.sh` was handed out unrefused (exit 0) while the same command without `./` was refused |
| agents-jqc4 | an OVER-REFUSAL: `bash tools/fast-gate.sh > logs/result.log` refused, because the file it CREATES did not exist yet |
| agents-v0ip | an OVER-REFUSAL: `deno test` refused — deno's **subcommand** read as a script path |
| agents-biz8 | an OVER-REFUSAL: `timeout -k 30 60s bash tools/fast-gate.sh` refused and blamed **`60s`** — a wrapper's own option argument read as a command word |

The two error directions are not equal, and that is what settles it: **a false refusal breaks a WORKING
gate** (three of the four findings are exactly that), while a miss only fails to explain a 127 that was
going to happen anyway. Every round was a narrower parse of a shell command line, and the parser was
always wrong about some construct it had not anticipated — a parser guessing at a property it cannot
see. A gate that refuses a command it did not run has made a claim about the future.

### Changes

1. **NOTHING IS REFUSED.** The patch contains no refusal path at all: no `exit 2` for a config, no
   pre-run existence check, no candidate rule to get wrong. Whatever the config says is what runs.
2. **The diagnostic speaks after the failure, and only on the failure.** `finish()` already receives the
   exit code the worker OBSERVED. If — and only if — that code is command-not-found class (`127`, or
   `126` found-but-not-executable), the note names what is actually known: the config's own
   `# Project: <name> (<path>)` stamp (who installed it, written by the installer since agents-ia3p), the
   tokens the command names that do not resolve here, and the one-line repair. Any other exit code (a
   failing suite, a timeout, a pass) produces **no note at all**.
3. **It cannot change a verdict.** A 127 is still the failure it is; the note is added *to* the record,
   not instead of it. There is no cache write, no state change, no new exit path.
4. **The note is written to `$log`, not to stderr — and that is a measured constraint, not a style
   choice.** The worker is a generated self-contained script started with `setsid nohup … >/dev/null
   2>&1`, so anything it prints to stderr reaches nobody. The log, by contrast, is what the record
   embeds, what survives for a reviewer, and what the `[check]` message quotes. It is appended at the
   one point in `finish()` where the state has been derived and the coverage extractor has already read
   the log, so it cannot perturb either, and it is in place before the tail is captured, so it appears
   exactly once in the tail **and** in the notification.
5. **The extractor is deliberately dumb.** It reports the first word (if it does not resolve on PATH) and
   every slash-containing token (if it does not exist here). It decides nothing, so a wrong name can
   only make the explanation of an already-observed failure less precise — it cannot refuse a gate. No
   wrapper logic, no interpreter rules, no flag semantics: those were the three sources of the false
   refusals above, and none of them is needed to explain a 127.
6. **Attribution is a fact about the file, never a trigger.** A config whose tokens all resolve still
   gets its stamp named, and the note says explicitly that it *cannot* name a token and that the config
   must not be blamed. An unstamped config is never attributed to a repo (`carries no 'Project:' stamp`).

### The state map this patches against, and why the note matters more than it looks

`bin/fleet-check:430` maps `126|127` to `KILLED`, and a KILLED run deletes its record at the end of
`finish()` (*"a kill is not a verdict"*). So for exactly the case this bead is about, the only two
surfaces that reach a lane are **the log** and the **`[check]` message** — the record is gone by design.
The message a lane gets today reads `KILLED (exit 127 …) - NOT a verdict (never started, bound/timeout
or signal)`, which is indistinguishable from somebody killing the gate, and that is the confusion this
whole bead exists to end. This patch deliberately does NOT change the state map: reclassifying 127 would
ripple through every consumer of `KILLED` (including clearance invalidation), and it is out of scope for
a diagnostic. Instead the note is the thing that distinguishes the two, which is why it is appended to
the log and carried in the message.

### Verification

- **Applies cleanly to the live bytes:** `git apply --check` against a pristine copy of
  `~/fleet/bin/fleet-check` at the baseline hash above, and from `~/fleet` itself (check mode only) — no
  fuzz, no conflict. The applied result byte-matches the copy the behaviour below was measured on, and
  `bash -n` is clean.
- **Driven end-to-end on the patched runner**, in a scratch git repo with a scratch `HOME` and a scratch
  config, with a local sink on the inbox port to capture the `[check]` message the lane actually gets
  (the live `~/fleet` was never written to):
  - **the real case** — a stamped foreign config (`# Project: agents-factory (/some/other/checkout)`)
    naming `bash tools/fast-gate.sh` in a repo where that script is absent: the command RUNS, fails 127
    by itself, and the lane's message carries `NOTE (agents-0r1c) … was installed by agents-factory
    (/some/other/checkout) — it names [tools/fast-gate.sh], which do not resolve in <repo>` — **exactly
    once**, `refusals=0`, followed by the repair lines below;
  - **agents-e3aw (second round), the printed command RUN FROM A FOREIGN CWD**: the repaired note prints
    `bash <repo>/tools/check-cmd.sh --install`, and that command runs from the repo root, from the repo's own
    `tools/` directory, and from `/tmp` - whereas the first round's relative form ran only in the first case and
    failed with `No such file or directory` in the other two. The in-repo reader was fixed the same way and its
    suite now runs every printed repair from a directory that is not the repo: with the relative form restored,
    six tests fail (the three destination variants, the point-of-use warning, the repo-local case and the install
    header), and all 47 pass with the resolved path;
  - **agents-e3aw (first round), driven in three situations against the SAME extracted diagnostic, old
    revision beside new**: (1) repo HAS `tools/check-cmd.sh` + stamped config → new text offers
    `bash tools/check-cmd.sh --install`; (2) repo does NOT have it + stamped config → new text says there
    is no installer to run here, and names the stamped repo (`agents-factory (/some/other/checkout)`) as
    the owner of the host-wide file; (3) no stamp → says plainly that the config carries no stamp so the
    note cannot name the repo. In all three the OLD text printed the same unrunnable instruction, which is
    the defect this revision fixes;
  - **agents-v0ip, fixed:** `deno test` → runs; exit 1 from deno itself (no `deno.json`), no refusal;
  - **agents-biz8, fixed:** `timeout -k 30 60s bash tools/fast-gate.sh` → runs; `PASS`, exit 0, and no
    note (nothing failed, so there is nothing to explain);
  - **agents-jqc4, fixed:** `bash tools/fast-gate.sh > logs/result.log` → runs and the command creates
    the file; no refusal;
  - **agents-wisk, fixed:** the `./` form now goes through the same path as the un-prefixed one — the
    distinction the old rule invented does not exist here, because nothing is inspected before running;
  - **CONTROL (silence where there is no evidence):** a command that fails for its own reasons
    (`bash tools/fail.sh`, exit 1) produces **no note at all**, and neither does a run that passes;
  - **CONTROL (no token invented):** on a 127 from a config whose tokens all resolve, the note names the
    stamp and says it cannot name a token, rather than blaming one.
- **The in-repo half carries the same shape and its own tests** in agents-factory
  (`tests/test_gate_entrypoint_config.py`, class
  `TestTheReaderNeverRefusesACommandAndExplainsA127Afterwards`): the four repros above asserted
  together as "reported, not refused", the post-failure diagnostic naming stamp + token + repair, a
  PATH-lookup case, and the two controls (silent for any non-command-not-found code; no token named when
  everything resolves). The reader half exposes the same diagnostic as
  `tools/check-cmd.sh --explain-failure <code> [FIELD]`, so an in-repo caller that runs a gate can ask
  the same question the worker asks.

### Hub Application

```bash
cd ~/fleet
git apply --check /path/to/fleet-check-explain-foreign-config.patch   # expect clean
git apply /path/to/fleet-check-explain-foreign-config.patch
bash -n bin/fleet-check
```

No sequencing, no repair step first, no fleet-wide pause: this patch refuses nothing, so it cannot turn a
working gate into a refusal. It only makes a 127 that a foreign config caused say so.
