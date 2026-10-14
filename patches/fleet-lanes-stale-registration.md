## `fleet-lanes-stale-registration.patch` (agents-c3vf)

- **Target repository:** `PaulKinlan/fleet` (on this VM `~/fleet` is a synced, read-only copy and **not** a git
  repository, so this is delivered as an artifact under `patches/` and is **NOT applied here**).
- **Target files:**
  - `remote/lanes.sh` — the `check` subcommand's diagnosis and next-action for a registration whose `WORKDIR`
    holds no git repository at all.
  - `tests/lanes.test.sh` — a new section 30 pinning both.
- **Prerequisite base hashes** (sha256 of the files this patch was cut against; verify before applying):
  - `remote/lanes.sh` = `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`
  - `tests/lanes.test.sh` = `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5`
- **After applying** (`patch -p1 --fuzz=0` from `~/fleet`), the files are
  `bb85dbac5152de24fed82a4f9ab89e97b0556b6b1607dc622e9d2dc7be3b61aa` and
  `3f1db99d8cf943676edbf573ea55443f500c06e794d494f65aeae41519f92099`
  respectively — byte-identical to the copy both directions of the red/green were measured on.

### Why this patch exists, and how the bead's premise measured

agents-c3vf says *"`lanes.sh spawn` can produce a malformed conf (`WORKDIR=/tmp`, `BEAD` empty, list reports
checkout-broken) — the lane boots with no work and must cut its own worktree"*. **The producer half of that is
already closed and already tested**, and this was verified rather than assumed:

- `remote/lanes.sh:50` `write_conf` is the **only** writer of a lane conf anywhere in the fleet repo (checked by
  grep across `*.sh`/`*.mjs`/`*.js`), and it now emits five fields including `IMPL_MODEL`.
- `spawn` derives the worktree itself (`wt="$HOME/worktrees/$P-$name"`) and fails the spawn if the worktree cannot
  be cut, so `WORKDIR=/tmp` is not reachable through it; `default_conf` (the `start`-without-a-conf path) writes
  only `coord` and `merger` confs, and `start_lane` refuses any other lane for which no conf exists.
- `spawn` refuses an empty bead outright (fleet-kjm5), and the deployed suite passes on this VM with
  **198 passed, 0 failed**, including `26i empty bead is refused` and `26n worktree created for valid bead`.

The conf that prompted the bead is a **legacy artifact from before that validation**: on this VM,
`~/.fleet/lanes/imp-dflt.conf` is `ROLE`/`MODEL`/`WORKDIR=/tmp`/`BEAD=` — **four** fields, with
`MODEL='(default)'`, so it was written by the older writer. It is still there, on a lane that is currently
**busy and healthy**, which is exactly the shape this patch addresses.

### What was actually wrong, measured on this VM

```
$ lanes.sh list   | grep imp-dflt
imp-dflt  implementer  busy  deepseek/deepseek-flash  /tmp  [checkout-broken]
$ lanes.sh check
imp-dflt  checkout-broken  /tmp
     it exists but is not a usable git repo
     next: lanes.sh retire imp-dflt deregisters this lane and keeps the checkout.
```

Two things are wrong with that report, and only the second is cosmetic:

1. The **diagnosis** calls a registration with no git repository at all "not a usable git repo", which sends an
   operator looking for a broken repository. Nothing is broken: the registration never had a lane worktree.
2. The **next action** is `retire`. `retire` stops and deregisters the lane; it does **not** write a worktree
   into the conf, so it repairs nothing — and on a lane that is still working, following it stops real work.
   The action that repairs this is a **spawn**, which rewrites the registration and cuts a fresh worktree.

`run-lane.sh:93` exports `FLEET_WORKDIR=$WORKDIR` (and `:118` substitutes it into the lane's prompt), so a lane
booted on such a conf really does start with `/tmp` as its workdir and no bead — the "boots with no work" half of
the bead, which this patch does not change (see *Left for the hub* below).

### What the patch changes

- `check` now distinguishes the two sub-cases it was conflating: a **dead gitdir target** (unchanged wording, and
  17e-17g still pin it) versus a `WORKDIR` that **holds no git repository at all**. The second now says what it
  means — a registration with no lane worktree, the shape a pre-validation `spawn` wrote — and names the
  producer's fix (fleet-kjm5, fleet-c3vf).
- For that case only, `next:` becomes *re-spawn the lane*, and says explicitly that `retire` repairs nothing and
  must not be used while the lane is still working.
- The **state string is deliberately unchanged** (`checkout-broken`): the `list` marker's column position is
  parsed positionally by `autopilot.sh` (pinned by test 17j), and the patch adds no new value to a vocabulary
  other tooling may switch on.
- No behaviour changes for a healthy lane, and no checkout is ever touched: `check` remains report-only.

### Verification

Both directions were measured **in `/tmp` copies only**; nothing under `~/fleet` was edited or installed.

| run | result |
|---|---|
| patched copy | **205 passed, 0 failed** (198 pre-existing + 7 new) |
| same tests, `remote/lanes.sh` reverted to the pristine bytes | **201 passed, 4 failed** |

The four failures are `30b`, `30c`, `30d`, `30e` — the diagnosis and the guidance, i.e. the change itself. The
other three new assertions pass in **both** directions on purpose, because they are the controls for behaviour
this patch must *not* alter: the registration is still reported (30a), `check` still exits non-zero so a sweep
sees it (30f), and the `list` marker is still `[checkout-broken]` (30g). Red case 30e prints the old advice
(`lanes.sh retire stale-reg deregisters this lane…`) as its failure detail.

```
patch -p1 --fuzz=0 < patches/fleet-lanes-stale-registration.patch   # from ~/fleet, in a scratch copy
bash tests/lanes.test.sh                                            # expect 205 passed, 0 failed
```

### Left for the hub (deliberately not taken here)

1. **A distinct state for "no lane worktree".** `list` still shows `[checkout-broken]` for a registration that has
   no repository. A separate value would read better, but the vocabulary is consumed positionally by
   `autopilot.sh` (17j) and the hub owns that consumer, so the change is left to the hub with the parser question
   named rather than guessed at.
2. **A boot-time signal.** `run-lane.sh` boots a lane on whatever `WORKDIR` the conf holds. A lane whose workdir
   is not its own worktree could say so once, at start, instead of silently exporting `/tmp`. That touches the
   lane start path rather than a report, so it is proposed rather than shipped.
3. **Repairing existing legacy confs on each VM.** `lanes.sh check` now names them; whether the fleet also
   re-spawns or rewrites them is a fleet-wide call, and the safe next action is now printed.
