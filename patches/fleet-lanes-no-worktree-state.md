## `fleet-lanes-no-worktree-state.patch` (agents-aaxx)

- **Target repository:** `PaulKinlan/fleet`
- **Target files (three):** `remote/lanes.sh` (the state token and its vocabulary), `remote/autopilot.sh` (the
  positional consumer), `tests/lanes.test.sh` (the pins, both directions).
- **Status:** the change and its consumer land TOGETHER, which is the point of the bead: a state string whose only
  positional consumer does not know it is a state nobody can act on.
- **Patch artifact hash:** `90e7dbe7a7000e6e5504403969d54d26ced1b1ae4beeca255b79aa95c736cada` (192 lines,
  3 files, +132/−7).

### THE BASE THIS IS A CLAIM ABOUT, AND WHY IT IS agents-c3vf's INSTALLED RESULT

**This patch applies to `remote/lanes.sh` and `tests/lanes.test.sh` AS agents-c3vf LEFT THEM, not to the deployed
files.** It is a stack member, and that is structural rather than a preference:

`patches/fleet-lanes-stale-registration.patch` (agents-c3vf) *deliberately* kept the state vocabulary unchanged
and said so in its own write-up: *"A distinct state for 'no lane worktree'. `list` still shows
`[checkout-broken]` for a registration that has no repository. A separate value would read better, but the
vocabulary is consumed positionally by `autopilot.sh` and the hub owns that consumer, so the change is left to
the hub"*. Its section-30 pin `30g` asserts `list` shows `[checkout-broken]` for exactly the registration this
bead exists to re-name, so c3vf's own test must MOVE with this change. There is no order in which the two can
both apply independently, and re-writing c3vf's diagnosis here would be duplicating it.

| file | algorithm | value | apparatus |
|---|---|---|---|
| `remote/lanes.sh` (pristine) | sha256 | `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa` | ADVISORY |
| `remote/autopilot.sh` (pristine) | sha256 | `e6e50c02630ff013cd6e890995da7cbddbe3cfbf34810a4877ca907d5f4c2bec` | ADVISORY |
| `tests/lanes.test.sh` (pristine) | sha256 | `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5` | ADVISORY |
| **`remote/lanes.sh` (THE BASE: c3vf applied)** | sha256 | `bb85dbac5152de24fed82a4f9ab89e97b0556b6b1607dc622e9d2dc7be3b61aa` | ADVISORY |
| **`tests/lanes.test.sh` (THE BASE: c3vf applied)** | sha256 | `3f1db99d8cf943676edbf573ea55443f500c06e794d494f65aeae41519f92099` | ADVISORY |
| `remote/lanes.sh` (this patch applied) | sha256 | `f8fa0de907a6721102cbac1faea9f8958cdbca1eae19ad44a225ccde285054e9` | result |
| `remote/autopilot.sh` (this patch applied) | sha256 | `0723bc2862f970eefe907994fb98b517c515f686e8f9eab665fed198cff4fdfb` | result |
| `tests/lanes.test.sh` (this patch applied) | sha256 | `9d71e033f6e5a2fa56221058435e9716ec13a9c5b3655e01bb417e301f70a14c` | result |

**ADVISORY, and it is not a formality.** This VM's `~/fleet` is a plain copy with no `.git` and no reachable fleet
canon (agents-x8ud: the internal origin is not routable and public GitHub needs auth), so every hash above was
read from THAT copy. The hub must reproduce the preimages from its own canon before applying. What was measured
here rather than assumed: applying `patches/fleet-lanes-stale-registration.patch` to the pristine files with
`git apply` yields **exactly** `bb85dbac…` and `3f1db99d…`, byte-identical to the two values that patch itself
declares — so the base this artifact is cut against is the same base c3vf's author measured on.

### Problem Statement

`checkout_state()` reduced two different faults to one string:

    $ lanes.sh list | grep imp-dflt
    imp-dflt  implementer  busy  deepseek/deepseek-flash  /tmp  [checkout-broken]

The lane had **no worktree at all** — its `WORKDIR` was `/tmp`, written by a pre-validation `spawn` — but it read
as a *broken* worktree. Those two states want opposite responses: a broken worktree is repaired where it is, while
"there is no worktree" is repaired by re-spawning (c3vf's whole point). An operator, or a timer, cannot tell them
apart from one string.

The harm is on the record: a lane in exactly this state **idled for hours holding real beads while reading as
alive** to every check except a watchdog that noticed the holder was not a running lane. A state an operator
cannot act on is the difference between a lane that is parked and a lane that is invisible.

And the consumer is the second half. `remote/autopilot.sh` decides whether to nudge coord by parsing `lanes.sh
list` **positionally**, and its expression was:

    bash "$HOME/fleet/remote/lanes.sh" list | awk '$1=="coord" && ($3=="running" || $3=="busy" || $3=="idle"){f=1} END{exit !f}'

It never looks past field 3, so **every** trailing marker is invisible to it. Driven here, with a coord row
carrying `[no-worktree]`, that parser answers "coord is busy" and the script proceeds to nudge — measured, not
argued (see VERIFICATION: the same fixture logs `skip: daily cap 8 reached`, i.e. it got PAST the parser).

### What it changes

1. **`remote/lanes.sh` — a distinct token: `no-worktree`.** A `WORKDIR` whose path holds **no `.git` at all** is
   now its own state; `checkout-broken` is kept for the case its own comment always described, "a `.git` IS
   present but is not a working repo (its gitdir target is gone)". `-e` is used rather than `-d` on purpose, so
   both forms of a worktree marker (the directory in a clone, the FILE in a linked worktree) count — and so a
   `WORKDIR` that is merely a SUBDIRECTORY of some unrelated repository no longer reads as a healthy worktree,
   which `git rev-parse --git-dir` alone happily does.
2. **The `list` vocabulary is stated where the format is stated** (the command header), and the marker stays
   **APPENDED** so the columns before it do not move. That is the contract the consumer depends on, and it is
   pinned rather than promised: test `17j` asserts it for `checkout-broken`, and this patch adds the same
   assertion for the new token (`31c`).
3. **`remote/lanes.sh` `check` keeps its diagnosis and its next action, reached by the new token.** c3vf's
   wording ("…no lane worktree…") and c3vf's action ("re-spawn the lane…, NOT retire") move with it unchanged,
   which is what makes the change expressible as a vocabulary promotion: `30b`–`30e` are the CONTROL that this is
   a naming change rather than a behaviour one, and they pass in every configuration below.
4. **`remote/autopilot.sh` — the parser NAMES its row shape and its marker vocabulary.** The row is named
   (`<lane> <role> <status> <model> <workdir> [<checkout-state>]`), field 3 is still the status, and the trailing
   marker must be one of the five tokens `checkout_state()` emits. A coord whose checkout is not usable is **not a
   live coord**; a marker outside the vocabulary is a **REFUSAL** with its own message, not a pass. This is the
   "no silent fall-through" the bead asks for: the failure mode being removed is precisely a parser that read a
   row shape it was not written against and said nothing.

### What it deliberately does NOT change

- **The producer refusal path is untouched.** `spawn` still refuses a missing bead before creation and exits
  before `write_conf` when the worktree cannot be cut; `fleet-lanes-stale-registration.patch` owns the
  registration diagnosis. This patch adds no validation.
- **Nothing re-spawns, restarts, stops or repairs a lane.** Hub decision 3 is that only genuinely broken lanes
  are re-spawned and that call is a human's, not a 10-minute timer's. `autopilot.sh` gains no new action at all —
  it gains a refusal. Pinned by `31m`, which records every invocation of `lanes.sh` from the consumer and asserts
  the only one is `list`.
- **No state token is removed**, so no existing consumer loses a value it knows: the vocabulary only grows.

### Verification

**The instrument is the fleet's own suite** (`tests/lanes.test.sh`), run in four configurations, each in a
COMPLETE tooling tree — `tests/lanes.test.sh` does `ln -s "$HERE" "$HOME/fleet"`, so a partial copy of `~/fleet`
makes every spawn/pick-model case fail for reasons unrelated to this change. That is not a note: the first
attempt here used a partial tree, produced 80 failures in sections 27–29, and was **discarded as an instrument
error rather than reported as evidence**. All four runs below are of the corrected harness.

| run | `remote/lanes.sh` | `remote/autopilot.sh` | `tests/lanes.test.sh` | result |
|---|---|---|---|---|
| **A** the artifact | `f8fa0de9` | `0723bc28` | `9d71e033` | **219 passed, 0 failed** |
| **B** parser red-first (pristine autopilot) | `f8fa0de9` | `e6e50c02` | `9d71e033` | 216 passed, **3 failed** |
| **C** state red-first (c3vf-only lanes.sh) | `bb85dbac` | `0723bc28` | `9d71e033` | 216 passed, **3 failed** |
| **D** deployed control | `7f0be214` | `e6e50c02` | `bbe6c933` | 198 passed, 0 failed |

- **Both directions are red, and each red set is exactly the change it stands for:**
  - B fails `31i no-worktree coord read as live`, `31j the no-worktree row reached past the parser`,
    `31l unknown marker fell through` — the parser half.
  - C fails `30g list marker`, `31a list marker for no worktree`, `31f check state for no-worktree` — the token
    half, and **only** those three: `31b` (the dead worktree still reads `checkout-broken`), `31c` (the positional
    contract) and `31g` (the two are distinguishable in `check` too) pass in the red case as well, because they
    are the controls for behaviour that must not move.
  - `D` is the control that the baseline is not what this patch is "fixing": the deployed pair fails nothing in
    the sections it has, and the artifact's FAIL set is identical to `D`'s (empty).
- **The parser's behaviour, driven across every marker** (fixture HOME, real `remote/autopilot.sh`, one crafted
  coord row, both revisions side by side):

  | coord row marker | pristine parser | this patch |
  |---|---|---|
  | *(none, healthy)* | passes → cap stage | passes → cap stage |
  | `[no-worktree]` | **passes → cap stage** | refused: *"the coord lane's checkout state is no-worktree, so it is not a live coord"* |
  | `[checkout-broken]` | **passes → cap stage** | refused, naming `checkout-broken` |
  | `[checkout-missing]` | **passes → cap stage** | refused, naming `checkout-missing` |
  | `[no-checkout]` | **passes → cap stage** | refused, naming `no-checkout` |
  | `[checkout-leaked]` | **passes → cap stage** | refused, naming `checkout-leaked` |
  | `[something-else]` | **passes → cap stage** | refused: *"carries a checkout marker this parser does not know"* |

- **An instrument defect of the author's, recorded rather than quietly fixed.** The first version of the autopilot
  fixture wrote an EMPTY `~/.fleet/env`; `autopilot.sh` runs under `set -u`, so it aborted at `FLEET_VM: unbound
  variable` before its first `say()` and wrote no log — and because `cat` on the missing log then aborted the test
  file under the `set -e` an earlier section had turned on, **five assertions never ran while the run still
  reported zero failures**. That is the class this whole bead is about (a check that cannot run reading as a check
  that passed), so the fix is two-sided: the fixture now carries a real env file, `ap_run` prints `<no log>`
  instead of dying, and `31n` asserts **before any other assertion reads a log** that the fixture produced one.
- **Base integrity, three ways:** `git apply --check` onto the c3vf result is **rc 0 with no fuzz**; onto the
  pristine files it is **rc 1**, failing in exactly `remote/lanes.sh:559` and `tests/lanes.test.sh:1082` — the two
  files c3vf itself rewrites, which is where a stack member must fail; and applying c3vf then this patch to
  pristine files reproduces the two post-apply hashes in the table above.
- **Not verified here:** the suite could not be run against a real lane on a real checkout (all fixtures are
  throwaway HOMEs), and nothing here measures how often a VM actually carries the legacy conf — c3vf measured one
  on this VM and it is still there.

### Hub Application

    cd ~/fleet
    git apply --check /path/to/fleet-lanes-stale-registration.patch   # agents-c3vf FIRST: this is cut on its result
    git apply /path/to/fleet-lanes-stale-registration.patch
    git apply --check /path/to/fleet-lanes-no-worktree-state.patch    # expect clean, no fuzz
    git apply /path/to/fleet-lanes-no-worktree-state.patch
    bash -n remote/lanes.sh && bash -n remote/autopilot.sh && bash -n tests/lanes.test.sh
    bash tests/lanes.test.sh        # the suite is the acceptance; expect the D+section-30+section-31 total, 0 failed

If the hub would rather land this BEFORE c3vf, the re-cut is mechanical and the check is named: apply c3vf, hash
the two files, and compare with `bb85dbac…`/`3f1db99d…` above.

### What a reader should expect to change

An operator (or the dashboard) reading `lanes.sh list` can now tell a lane with **no worktree** from a lane whose
**worktree is broken**, and `lanes.sh check` names each with the action that actually repairs it. `autopilot.sh`
stops nudging coord through a row whose coord cannot work, and refuses — loudly, and without touching any lane —
a row whose shape it does not recognise. Nothing is stopped, started, retired or re-spawned by either change.
