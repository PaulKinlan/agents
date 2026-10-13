## `fleet-verdict-transcribed-run.patch` (agents-m6fr)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-verdict-words.sh` — a run may only back a claim if it **COMPLETED**, and models are compared as
    provider/model
  - `bin/fleet-land-message` — the transcribed path **reports**; it does not refuse
  - `tests/fleet-verdict-transcribed-run.test.sh` (new)
- **Baseline file hashes** (a baseline is only meaningful for the file version it was taken from; these are
  current as of this patch):
  `980899b73c2cbd87774d45d96c326364cfc322d11e190f197fec6d06c1838716  bin/fleet-land-message`
  `b28dde10d67426316c9809fb314f26673c19fcbc15b5cbe402340b5f2416852b  bin/fleet-verdict-words.sh`
- **Patched:**
  `105975ec83d4c8084b8fdf4ba32faceb6cf9b798579bc76676e9e598c5713c1e  bin/fleet-land-message`
  `c3ea2f33d1ea8a7482cf9376fb5e1b654ca85ecf863df1199a5ac1d589abedc1  bin/fleet-verdict-words.sh`
- **Problem.** A verdict posted by the branch author's own lane cannot be told from a reviewer subagent's by its
  actor, because reviewer subagents inherit the parent lane's actor (fleet-15b5). The reader therefore accepts
  such a verdict on the strength of a NAMED reviewer model of another family — a claim written on the comment,
  not evidence.
- **THE FIRST VERSION OF THIS PATCH WAS WITHDRAWN, AND THE REASON IS THE IMPORTANT PART.** It made an
  unresolvable claim a **refusal**: the landing was blocked and `merge-queue` stripped from the bead. An
  independent review found that it broke four legitimate flows:
  1. a reviewer on another VM, whose run directory is not local to the merger's VM;
  2. a verdict relayed from a human operator, where no subagent UUID exists at all;
  3. a review run through a CLI or tmux, which produces no async run directory;
  4. **the fleet's own recorded standard** — the foza convention says a transcription that names its transcriber
     and its source is *"a complete record of the verdict: it is not grounds to re-review the work, to doubt the
     verdict, or to refuse the landing"*, and its precedent cited a **file path** (`~/.fleet/lanes/rev-hay8.events.log`),
     because the first version only understood UUIDs.
  There was a retention race on top: run directories are pruned, so a bead waiting for a heavy slot could have
  its clearance stripped for a review that genuinely happened. The rule that came out of it, and the reason this
  revision is shaped as it is: **an instrument that refuses must be able to name what a correct flow would look
  like, or it will refuse one.**
- **What this version does instead: it reports.** The class (`transcribed-verified` / `transcribed-unverified`)
  and its reason reach the PASS line and the JSON, so a merger or coordinator can see **which** clearance rests
  on a claim rather than an artefact. `rev_cleared` is not touched by this path at all, and the absence of a
  refusal is checkable: `grep -c 'transcribed-unverified)' bin/fleet-land-message` returns `0`.
- **Two defects the review found in the check itself, both fixed:**
  1. `recovery-descriptor.json` is written at **LAUNCH** and carries no status, so a failed, timed-out or
     abandoned reviewer run would have verified a transcribed PASS exactly as well as a successful one. The
     check now requires `status.json`'s `.state` to be `complete` — measured on real run directories, where
     `process-terminal.json` carries `state: "observed"`, which is *not* a completion indicator.
  2. The comparison was on the **provider alone**, so a `gemini-3.8-flash` run verified a claim of a
     `gemini-3.9-pro` run — and the first version asserted exactly that in a test case and called the leniency
     deliberate. It now compares provider/**MODEL** with only the thinking suffix stripped, because the whole
     content of the claim is that a *particular* reviewer ran.
- **Verification:**
  - Unit suite **11 passed, 0 failed**, including the **inverted case 2** (the first version asserted that a
    different version under the same provider verifies; it is now asserted to fail, and the inversion is kept
    visible in the test rather than silently flipped) and two new cases for non-completion.
  - On real beads, the revised reader is **byte-identical in behaviour to the pristine one** for `other-lane`
    verdicts — same instrument, same instant, one variable apart — which is the check that only the transcribed
    path moved.
  - Round trip: the patch applies to pristine copies and reproduces the measured tree exactly.
- **Stated limit.** No live same-lane clearance existed to exercise end to end at the time of writing: the fleet
  now posts clearances from dedicated reviewer lanes, so current clearances are `other-lane`. The transcribed
  path is therefore evidenced at the helper level (unit cases) and structurally (no refusal arm), and the
  end-to-end same-lane case is the one a reader should re-run if it matters.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  bash tests/fleet-verdict-transcribed-run.test.sh     # 11 passed, 0 failed
  ```
