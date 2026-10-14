## `fleet-implementer-new-file-consumers.patch` — an added file's lib imports are checked before the heavy gate (agents-j00v)

WHAT: one paragraph added to the implementer preflight (`roles/implementer.md`, step 3). When the
delta ADDS a file, list the `lib/*` modules it imports and confirm each is mapped to it in the repo's
fast-gate map (`tools/fast-gate-arms.d/`, or `tests/fast_gate_allowlists.d/` for a measured exemption),
then run the repo's consumer-coverage suite (`tests/test_fast_gate_consumer_coverage.py`) in the
foreground before asking for the gate.

WHY: the map is a contract about who tests whom, so adding a consumer is adding a promise - and the
promise is currently discovered at the END of the work, after a heavy gate slot, instead of in one
local command. Three lanes hit this class in a single hour on 2026-10-14: the sweep's tool needed an arm
plus a deletion-inventory row; agents-5jjf needed an arm for `lib/sinks/github.py`; an implementer's new
test file importing `lib/embargo.py` needed the embargo arm. The guard that catches it is doing its job
correctly - the cost is the TIMING of the paperwork, which lands on the author at the worst moment.

ARTIFACT: `fleet-implementer-new-file-consumers.patch`, 1265 bytes, 1 hunk, file-section:
`roles/implementer.md`. sha256 `ff1cc4e589ad786cfced11f3f5f209a46bd01645f8c5c67daaf5948da66d6695`.

EXPECTED BASE: `roles/implementer.md` sha256
`8c08378ae39bad82f4c4b351f201fb0fe0293107a0fa50b8213d6f9eefefb4f6`, 3515 bytes - it applies to the
step 3 paragraph beginning "Before handing off: rebase on the latest main ...".

DESTINATION SHAPE: measured present. `~/fleet/roles/implementer.md` (the deployed synced copy) and
`~/fleet-copy/roles/implementer.md` (the git clone) both carry that exact base sha as of 2026-10-14, and
applying the patch yields `e0256ba55a38fd6367a14c853e9b6f1215314a700e6e51a9357dccb6a0cd28f9`, 4150 bytes
(+635). Verified with `patch -p1` in a scratch copy: dry run clean, real run clean, and the inserted
sentence is present exactly once.

PREREQUISITES: none. Checked for collisions BY PATH before cutting, per the fleet rule that a name is an
identifier a second deliverer can collide with: no artifact in `patches/` has `roles/implementer.md` as
a file-section. `fleet-merger-refusal-stops-script.patch` mentions that path, but only in prose inside
its `roles/merger.md` hunk, so the two artifacts are independent and either order applies.

HOW TO APPLY: `cd <fleet repo> && patch -p1 < fleet-implementer-new-file-consumers.patch` (or `git
apply`). Then confirm `grep -c 'consumer-coverage suite in the foreground' roles/implementer.md` is 1 and
the file sha256 is the applied result above. This artifact is a HUB DELIVERY: nothing in the
agents-factory checkout applies it, and the deployed `~/fleet` on the hub is hard-reset every few
minutes, which is why the change travels as a patch rather than as an edit.

WHY A LINE AND NOT A TOOL (the ruling, and the counterargument that won): the consumer oracle already
runs inside the fast gate, so nothing is silently missed today - what is missing is WHEN the author
learns it. Engineering a new checker to save heavy-gate cycles is only right when the engineering costs
less than the cycles it saves; here one sentence moves the discovery from after a heavy gate to the
author's own preflight, at zero tooling cost. This bead stays open only until that sentence exists.

MEASURED INSTANCE, so the line is specific rather than generic advice: a new file
`tests/test_station_candidate_accounting.py` imported `lib/embargo.py` while the `lib/embargo.py)` arm
did not select it, so `tests/test_fast_gate_consumer_coverage.py` failed with rc=1 on the tip that had
just been handed for review - and that tip's fast gate had recorded STALE (the `agents/` ctime mechanism
of agents-fxg2), which MASKED the real rc=1 rather than merely lagging it. One foreground run of that
suite finds it in about 13 seconds.
