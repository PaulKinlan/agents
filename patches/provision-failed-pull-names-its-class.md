## `provision-failed-pull-names-its-class.patch` (agents-rn78, agents-uvzh)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/provision.sh` (one helper function + the `~/agents` pull failure branch)
  - `tests/provision.test.sh` (new section 17: the classifier is extracted from the real script and
    driven, plus the wiring assertion)
- **Baseline file hashes:**
  `31d1669c85dcdd86de490633832940f10fc20bbfd9a350ffd398d93f189e2607  remote/provision.sh`
  `f890c2be8ca2948f47b7cdd9872eccf286e7fb9314d0fffc246cd7a3273abc3c  tests/provision.test.sh`
  (patched: `abb3c8d87a624f16cdbf5a4378cb6047480dd326b878c772521705495bd88e7a`,
  `f82384da29eae231cd7785cad9c4baecf7943e37fe3e786f6acb03d1bae87238`)
- **Problem statement (agents-rn78, P2, found reviewing agents-a1ko).** The Software Factory's
  provisioning path cannot tell an operator *why* its update failed. `remote/provision.sh:988` pulls
  `~/agents` and, on failure, emits one generic line — `WARN: agents pull failed` — which is the same
  sentence for a transient network outage and for a checkout that has diverged, two failures that want
  opposite responses (retry later vs investigate the host). `git`'s own text is in `provision.log`, but
  the warning an operator greps for names no class.

- **Problem statement 2 (agents-uvzh, found reviewing the first delivery of this patch).** The classifier
  conflated an **authentication denial** with an **unreachable remote**, and the two want opposite
  responses. Git's text for them OVERLAPS: a refused key prints `Permission denied (publickey).` and then
  `fatal: Could not read from remote repository.` (MEASURED with a real `git pull --ff-only -q` against an
  `ssh://` origin and a `GIT_SSH_COMMAND` stub that refuses). Because `Permission denied` and
  `Could not read from remote repository` sat in the unreachable arm, a wrong credential was reported as
  `remote-unreachable: ... usually transient - retrying the pull later is safe`. That is worse than no class
  at all: the wording is an *instruction*, and retrying cannot fix a credential.

- **Established, by reading and by measuring:**
  1. **The installer's classifier is unreachable in provisioning** (the reason this patch is not in
     `install.sh`). `install.sh:59-61` takes `FACTORY_DIR="$SCRIPT_DIR"` when the script lives inside a
     checkout, so its classified, fatal pull never runs there; `provision.sh:988` pulls first and
     `:995` then invokes `./install.sh` from *inside* the checkout. The reviewer reproduced it on a
     real clone whose bare origin was deleted: `bash /tmp/install.sh -d ~/agents` → rc=1 with
     `FAILURE CLASS: remote-unreachable`, while `(cd ~/agents && bash ./install.sh)` → rc=0, no class.
  2. **The class is therefore only obtainable where the pull happens** — this line. That is what the
     patch changes; the installer's own classifier stays (it is correct for its own path, the
     documented one-liner run with an existing target directory).
  3. **The two git messages below are measured, not invented** (real git, project VM, 2026-10-13):
     - remote deleted: `fatal: '/tmp/.../agents' does not appear to be a git repository` +
       `fatal: Could not read from remote repository.`
     - diverged with `--ff-only`: `fatal: Not possible to fast-forward, aborting.`
  4. **The severity is deliberately NOT changed here.** This step is non-fatal today
     (`|| warn`), while the installer's own pull is fatal (agents-yow5). Provisioning can therefore
     continue with a stale `~/agents` and still exit 0 — the class is now named, but whether a stale
     checkout should fail provisioning is a decision for the fleet's owner, not a side effect of a
     diagnosis fix. Recorded as an open observation rather than silently re-scoped (see below).

- **Changes:**
  - `agents_pull_failure_class()` maps git's own message onto one of FOUR classes — `remote-auth-denied`,
    `remote-unreachable`, `checkout-diverged`, `checkout-local-state-or-unrecognised` — and prints the class
    *with the operator action* so one log line is actionable. The **auth arm comes FIRST and before the
    unreachable arm**, because the unreachable arm's own patterns match git's auth text as well; `Permission
    denied` was removed from that arm for the same reason, since a pattern no later arm can reach is a dead
    arm inside an alternation (the same defect class the registry guards reject). The vocabulary and the class-splitting mirror `install.sh`
    (agents-a1ko) on purpose: the same failure should read the same way in `provision.log` and in the
    installer's output. **The third case is the default**, so a failure git words in a way this script
    has never produced is reported as unrecognised rather than guessed into one of the two whose
    actions are opposite.
  - The `~/agents` pull failure branch now captures git's output and calls that helper inside the
    warning, keeping git's text verbatim on the same line as the evidence.
  - One wording constraint came from the fleet's own structural test, TWICE: section 12v scans
    `provision.sh` for bare `which` calls, and the prose of both the unreachable arm ("which is usually
    transient") and the auth arm ("which is NOT transient") tripped it. The patch is `which`-free. Both
    were found by running the suite, not by reading it.

- **Verification:**
  - **The fleet's own harness, pristine vs patched** (`bash tests/provision.test.sh`, fake HOME,
    throwaway git repos, no network, no root): pristine **207 passed, 3 failed**; patched
    **216 passed, the same 3 failed** (`16a`, `16s1`, `16t1` — beads/Dolt config assertions that fail
    identically on the unpatched copy in this environment, so they are not from this change). The 9 new
    assertions are section 17.
  - **The classifier is driven with the measured messages**, not asserted: `17c` network →
    `remote-unreachable`, `17d` diverged → `checkout-diverged`, `17e` the two strings differ, `17f` an
    unseen message lands in the unrecognised class (the control that keeps `17c`/`17d` from passing for
    a classifier that answers one class to everything), `17h` the measured auth pair →
    `remote-auth-denied`, and `17i` that class must NOT contain the unreachable arm's wording, because that
    wording is an instruction to retry. `17h`/`17i` are the pair that pins the ARM ORDER: swap the two arms
    and both fail.
  - **The wiring is pinned** (`17g`): the failure branch must call the helper, so the function cannot
    become decoration.
  - `git apply --check` passes against pristine copies of both files, and applying it reproduces the
    patched hashes above exactly.

- **Application (fleet/hub side):** `cd ~/fleet && git apply <this patch>` (or from anywhere:
  `git -C ~/fleet apply /path/to/provision-failed-pull-names-its-class.patch`), then
  `bash ~/fleet/tests/provision.test.sh` — section 17 must report 7 ok. Nothing imports the helper and
  no other caller changes, so the patch is independent of the `agents` repo's own release cycle.

- **Open observation, for the fleet's owner to decide (NOT changed by this patch):** the update's
  *fatal-ness* differs between the two paths. `install.sh` exits 1 on a failed pull because a stale
  checkout must not look like a successful install (agents-yow5); `provision.sh:988` warns and carries
  on, and because the installer is then run *inside* the checkout (finding 1) nothing downstream
  raises it either — so a VM whose remote is unreachable is provisioned against a factory of unknown
  age and provisioning exits 0. This patch makes that case *diagnosable* (`[remote-unreachable]` in
  `provision.log` and in `~/.fleet/provision-warnings`); making it fatal is a behaviour change to a
  provisioning path used by every project VM, so it is left as a decision with the measurement above
  rather than taken here.

- **Deliberately NOT changed:** `install.sh`'s own classifier and the yow5 pins (exit 1, the wording
  about the stale checkout, "nothing was installed from it"); the confined tool lookup; and the
  `git clone` branch of the same step (a failed first clone has no local state to classify).
