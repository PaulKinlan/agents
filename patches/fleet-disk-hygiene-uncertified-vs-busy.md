## `fleet-disk-hygiene-uncertified-vs-busy.patch` (agents-a0zr)

**Applies on top of** these three DEPLOYED revisions, `patch -p1` from the fleet root:

| file | bytes | sha256 (first 32) |
|---|---|---|
| `bin/fleet-path-idle.py` | 2735 | `3faa3c10a8d7493f0abe069c1e0d4ca3` |
| `bin/fleet-disk-hygiene` | 16145 | `7dcd224efd40fef89f55f6f7c2dfc09d` |
| `tests/disk-hygiene-health.test.sh` | 3424 | `4d35f2867bee5b79e741a7aaebb7a31f` |

A note on the base, because rule 257 applies: `~/fleet` on a project VM is a mixture of generations relative
to the canonical repo and the local snapshot has no remote, so the base named here is the DEPLOYED revision
that actually runs, not a commit. For `bin/fleet-disk-hygiene` this is known to be AHEAD of the snapshot's
`main` (deployed 304 lines here against 210 in the snapshot, recorded on agents-4wy1); for
`bin/fleet-path-idle.py` canon is not establishable from this VM. **The hub should confirm canon before
applying**, exactly as with the other hub-delivery artifacts of 2026-10-13/14.

### Why

`bin/fleet-path-idle.py` answers in THREE states, and the tooling around it collapsed them into a single
yes/no. That single predicate is this fleet's most repeated defect, and here it has a quiet and expensive
consequence: on any VM with one same-uid process whose `/proc/PID/fd` cannot be read (a non-dumpable
session helper - `(sd-pam)`, pid 390, on this VM), the checker answers `uninspectable` (rc 2) for EVERY
path, `bin/fleet-disk-hygiene` reads that as "not idle", the entry list comes out empty, and the run
**archives nothing while still reporting `done`**. Evidence grows uncompressed and the failure is one
stderr line nobody reads.

Measured on this VM, with `HOME`/`FLEET_EVIDENCE_KEEP_DAYS`/`FLEET_TMP_DIR` on temp paths so no live queue
or real repo was involved:

| | deployed | patched |
|---|---|---|
| checker on an idle evidence file | `uninspectable pid=390 state=S`, rc 2 | `uncertified pid=390 state=S reason=uninspectable`, rc 2 |
| checker on a tree with a LIVE holder | `uninspectable pid=390`, **rc 2 - the readable holder is MASKED** | `busy pid=3855002 ref=/proc/3855002/cwd path=...`, rc 1 |
| checker, bad invocation | rc 2 (same code as "I refuse") | rc 64 (so 2 means exactly one thing) |
| dry run | `agent-evidence: would archive 1 entr(y|ies) -> ...tar.gz` | same, plus `0 certified (removable), 1 uncertified (snapshot only, originals preserved), 0 busy, 0 checker error` |
| real run, archives written | **0** | **1**, containing `./run-001.log` |
| real run, input survives | yes (the safe direction) | yes |
| what the log says | `idle=no action=skip path=...` | `idle=no state=uncertified action=archive_only path=...` |
| how the run ends | `done: disk ...` | `done: ...` **plus** `NOT EVERYTHING DONE: 6 uncertified ... were PRESERVED, not removed` |
| certified entry (stub certifier) | removed | removed (unchanged), `reclaimed 4K` |
| one subject per run | processed **twice** (`*evidence` and `*-evidence` match the same dir) | once |

The masking row is the one that made the checker itself worth changing, not just its callers: because the
uninspectable branch `sys.exit(2)`d on the FIRST pid it met, a tree with a genuine live holder was reported
uncertified rather than busy on every VM that has a `(sd-pam)`. A proof that was available was thrown away
in favour of a refusal. `busy` now outranks `uncertified`: the scan records unreadable processes and keeps
looking, so the strongest available answer is the one returned.

The health check was red for the same reason, for the whole VM: `tests/disk-hygiene-health.test.sh` calls
the checker bare under `set -e`, so on this VM it exits 2 at its first invocation (`provision.sh` and
`hub-setup.sh` call the *other* health script, `remote/disk-hygiene-health.sh`, which checks the systemd
unit and passes - measured rc 0 - so provisioning is NOT broken by this; the failing file is the tooling's
own test, which `remote/check-map.tsv:36` maps to the checker).

### What it changes

**`bin/fleet-path-idle.py`** - the three answers become the documented contract (0 idle / 1 busy /
2 uncertified / 64 usage), the uninspectable process is recorded and the scan continues so that `busy`
wins when it can be proved, and the message gains `uncertified` + `reason=uninspectable` so a caller can
tell it from `busy` without guessing.

**`bin/fleet-disk-hygiene`** - `idle()` becomes `idle_state()`, which maps the checker's rc to
`idle|busy|uncertified|error`; `safe_remove` removes only on `idle`, and preserves with a DIFFERENT
message and a different log action for each of the other three; the evidence section builds two lists, so
an uncertified entry is **snapshotted but not removed** (a copy is not a deletion, and the original stays,
so a torn snapshot cannot lose anything); the dry run asks the checker the real run consults instead of
promising an intention it cannot fulfil; the empty-list case, which used to `continue` in silence, now
says so and logs it; the final line refuses to say `done` alone when anything was preserved; the git-gc
guard names which state skipped it; and the `*evidence`/`*-evidence` double-match is deduplicated.

**`tests/disk-hygiene-health.test.sh`** - an idle tree may answer 0 or 2, a 2 must SAY `uncertified` and
`reason=uninspectable`, and a live cwd/open fd must answer **1** rather than merely non-zero. That last
change is what ties the test to the checker fix instead of accepting any refusal as a pass.

### Application test

`patch -p1 --dry-run` is clean on all three files, and after a real apply the three files are
**byte-identical** to the authored fixed copies - the acceptance test for an insertion patch:

```
bin/fleet-path-idle.py             49abecf8d61aba30...   IDENTICAL
bin/fleet-disk-hygiene             d38cb7aa170d00ea...   IDENTICAL
tests/disk-hygiene-health.test.sh  be3f8d536feb3b99...   IDENTICAL
```

318 lines, 10 hunks, 3 files, 35 deletions / 169 insertions. Every single-file subset FAILS the health
check, so no part of this patch is decoration:

| | base test | fixed test |
|---|---|---|
| **base checker** | rc=2 (FAIL) | rc=1 (`FAIL: rc 2 without saying uncertified`) |
| **fixed checker** | rc=2 (FAIL) | **rc=0 PASS** |

### Residuals, stated rather than implied

* An uncertified entry is snapshotted again on each run until it can be certified, so while a blocker
  persists the archive store holds one copy per run (bounded by the archive keep-window, default 180 days,
  and by the blocker's lifetime). A content-identity guard would remove even that, and it is deliberately
  NOT in this patch: the safe direction costs bytes, not evidence.
* `bin/fleet-tmp-clean` collapses the same two states, but it already captures the checker's output as
  `reason=`, so it reports `uncertified` correctly the moment this patch lands - measured, no edit needed.
* Not in scope, and unaffected: the unlanded `tests/fleet-heavy-reclaim.test.sh` section 7, whose
  assertions are wrong in the same family (agents-zwtx).
