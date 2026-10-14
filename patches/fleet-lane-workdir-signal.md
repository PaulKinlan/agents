## `fleet-lane-workdir-signal.patch` (agents-uq0q)

- **Target repository:** `PaulKinlan/fleet` (on this VM `~/fleet` is a synced, read-only copy and **not** a git
  repository, so this is delivered as an artifact under `patches/` and is **NOT applied here**).
- **Target files:**
  - `remote/lane-workdir-signal.sh` — **new**, the signal itself.
  - `remote/run-lane.sh` — computes the signal, logs it as a WARNING, exports it, and substitutes it into the prompt.
  - `roles/common.md` — renders it where the lane is told what its working directory is.
  - `tests/lane-workdir-signal.test.sh` — **new**, 20 assertions including the false-alarm controls.
- **Prerequisite base hashes** (sha256 of the files modified; verify before applying):
  - `remote/run-lane.sh` = `c82b940d8834e22684ca320fd7a2643e3ee68d193ea3360a5db085be06280f4f`
  - `roles/common.md` = `1168a4628c88a0cc7036b9fac91aafa8c50fa90ec7d32ea2f582c959007a0c61`
- **Apply:** from `~/fleet`, `git apply patches/fleet-lane-workdir-signal.patch` — git format is used so the two
  new files keep mode `100755`; `patch -p1 --fuzz=0` also applies the content but loses the exec bits, so
  `chmod +x` those two files if applying that way.
- **After applying**, the four files are
  `b00c09096ef0620518932bc4afea4e68531c94e71c07f153d2caf3a4749bb45a`,
  `e2ce991e85b584f21bf10f583c75b9ec4b994f009c3d12b354308fe5013f7264`,
  `eb4c86d16d0024cf16adfa1252da46155c73c8702cc3bccfffb7394fde248aec` and
  `1d037b6a65d2727eff0d5592494d4e91c2074f86ecd4f3aed9f238855164da99`
  — byte-identical to the tree both directions of the red/green were measured on.

### Why (the hub's own words, 2026-10-14)

> "The fact that run-lane.sh exports FLEET_WORKDIR=/tmp into the lane env and prompt is not merely the
> boots-with-no-work half — it is the WORSE half, because a lane that boots with /tmp as its workdir LOOKS ALIVE."

`run-lane.sh:93` exports `FLEET_WORKDIR=$WORKDIR` and `:118` substitutes it into the lane's prompt, where
`roles/common.md:11` tells the lane *"Your working directory: `/tmp`. Do all your file edits there."* So the lane is
not merely misprovisioned: it is **instructed** to work in the wrong tree, and it reports as healthy. The nightly's
evidence is that a lane reporting **"boot blocked"** was correct and useful, while a lane booting on the wrong
worktree would have committed into it.

This is the runtime companion to `agents-c3vf`'s report-side patch (`patches/fleet-lanes-stale-registration.*`),
which fixed what `lanes.sh check` **says** about such a conf. That patch makes the state readable; this one makes
the lane that boots on it **know**.

### What it does

`remote/lane-workdir-signal.sh <role> <workdir> <repo>` prints one line, or nothing, and **always exits 0** —
a signal, never a refusal, so the lane still starts (the hub asked for a boot signal, and a lane that cannot start
is a lane that cannot tell anyone why). `run-lane.sh` then:

- writes `run-lane: WARNING: <note>` to `$LD/<lane>.log` — the location `fleet-kf7u` established for this class of
  warning, because the systemd unit sends stderr to journald, which no operational tool reads for lane errors, and
  the SDK host discards the stderr of a zero exit;
- exports `FLEET_WORKDIR_NOTE` and adds it to the prompt's `envsubst` list;
- `roles/common.md:11` renders it directly after the sentence that names the working directory, so the lane reads
  the warning exactly where the wrong directory is announced.

**The prompt cost is +22 bytes of template** (16365 → 16387) and **zero** for a healthy lane, because the note
substitutes to empty.

### The two cases it reports — and what it deliberately refuses to judge

1. **The workdir holds no git repository at all** (the `/tmp` case): *"…do not commit, report boot-blocked to coord,
   and ask to be re-spawned."*
2. **The workdir IS the project's canonical checkout**: *"…a timer resets that checkout to origin/main every 5
   minutes, so anything committed there can be destroyed."*

It does **not** judge a workdir by its **path shape**. A `coord` lane's working directory is `~/journal` on the hub
and the canonical checkout on a project VM — neither is under `~/worktrees`, and both are legitimate — so the roles
that are not supposed to have a worktree (`coord`, `hub`, `merger`) are exempt, an independent **clone** is silent
because `lanes.sh retire` keeps one on purpose, a **missing** directory is silent because the report-side bead owns
that state, and an unreadable or absent repository argument makes the helper say nothing it cannot support.

### Verification

Both directions measured in `/tmp` copies only; **nothing under `~/fleet` was edited or installed.**

| run | result |
|---|---|
| the same test against the pristine `~/fleet` | **0 passed, 18 failed** — the helper does not exist and neither does the wiring |
| the patched tree | **20 passed, 0 failed** |

The controls are the point of the suite, not the extras: 2a a lane's own worktree is silent, **2b a coord lane
working in `~/journal` is silent**, 2c merger/hub exempt, 2d an independent clone is silent, 2e a missing workdir is
silent, 2f/2g no repository is named that could not be compared against, 2h an empty workdir is silent. A false
alarm on a healthy lane would teach an operator to ignore the line, which is worse than no line.

**A REAL BUG THIS SUITE CAUGHT, recorded because it is the argument for the controls:** the first draft of the
helper printed *"…not this lane's worktree of `$repo`"* in case 1 — naming a repository it had never compared
against, so with an empty or nonexistent repo argument the note read *"worktree of ."*. The check now says what is
true of the directory alone (*"is NOT a lane worktree for this project"*), and controls **2f/2g** assert both that
the note still fires without a readable repo and that it names no repository it could not compare against.

```
git apply patches/fleet-lane-workdir-signal.patch   # from ~/fleet, in a scratch copy
bash tests/lane-workdir-signal.test.sh              # expect 20 passed, 0 failed
```

### Left for the hub (deliberately not taken here)

1. **Refuse rather than signal.** This ships the signal the hub asked for. Whether a lane on the wrong tree should
   fail to start is a behaviour change to the lane lifecycle, and the nightly's own evidence favours a lane that
   starts and reports over one that never does.
2. **Surface it in `lanes list`/`check`.** The companion state decision (a distinct value instead of
   `[checkout-broken]`) lands with its `autopilot.sh` positional parser; this patch does not touch that vocabulary.
3. **Whether `host`-side spawn replies should carry the same note**, so a coordinator sees it at spawn time rather
   than only in the lane's log.
4. Per hub decision 3, there is **no fleet-wide re-spawn** here and no change to any existing conf: only lanes that
   are actually broken should be re-spawned, and this patch is what lets an operator tell the two apart.
