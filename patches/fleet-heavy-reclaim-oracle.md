## tests/fleet-heavy-reclaim.test.sh section 7: drive a copy of the tool with a deterministic oracle - `fleet-heavy-reclaim-oracle.patch` (agents-33br)

Repo-side content (the artifact is committed here; the file it fixes lives in the fleet tree). Preimage:
`tests/fleet-heavy-reclaim.test.sh` SHA256 `a65b35600ad2b56d`. **The two assertions are UNCHANGED** - the fix is
entirely in how the fixture generates the state they read.

### The symptom, and why it is worse than a normal failure

On the **unmodified** file in a **complete** tree, section 7 failed twice: `the second run overwrote the first
(0 archive(s))` and `one.txt is gone`. A suite that fails on its own base does not just fail: it turns **every
other change red by association**, so unrelated lanes and reviewers lose the signal they are reading.

### The diagnosis, from the tool's own log rather than from reasoning

`bin/fleet-disk-hygiene` archives through a liveness gate: `idle() { python3 "$PATH_IDLE" "$1"; }`, where
`PATH_IDLE` is derived from **the tool's own directory** (a sibling `fleet-path-idle.py`), with no environment
override. Its log for this fixture says `idle=no action=skip` for both files, and a verbose run names the reason:
**`uninspectable pid=390 state=S`**. On this lane VM that process is the same user's `(sd-pam)`, whose
`/proc/390/fd` is not readable - so the oracle cannot prove the entry idle, and the tool conservatively skips the
archive. `find -mtime +0` matches both files, so the fixture's *generation* is fine; the **oracle** is what varies
by machine.

### Which side is stale: the ASSERTION, not the tool

This is the second of the two options on the bead - **an assertion that reads state it does not own** - and not a
fixture that fails to generate the right tree. The tool is **correct as written**: for a destructive step, refusing
to archive what it cannot prove is idle is exactly the behaviour to want, and its own comment says as much ("An
archive step that deletes its input on failure is a deletion step"). The assertion, meanwhile, silently depended
on the machine's process table. So the tool is untouched and the assertion is untouched; what changes is that the
fixture now **makes the oracle deterministic** instead of inheriting it from the VM.

### The fix

Section 7 copies the real tool into a temp directory and places a stub `fleet-path-idle.py` beside it, then drives
the copy. That is possible precisely because the oracle is directory-relative, so no tool change is needed and no
override is invented. Liveness itself is tested by sections 1-3, which is where it belongs; section 7 tests that
**two runs produce two archives**, which is what its comment has always said.

### Evidence, driven, with both directions of control

| drive | result |
|---|---|
| deterministic oracle (rc 0 = idle) + real tool | **2 archives**, `one.txt` recoverable -> the two assertions **pass** |
| CONTROL: stub reports NOT idle | **0 archives** -> fails, proving the stub is wired in and the gate is live rather than decorative |
| CONTROL: the real bug - a month-stamped archive name | **1 archive**, `one.txt` **gone** -> fails, proving the fixed fixture still catches the defect section 7 was written for |

Delivery contract, driven: `patch -p1 --fuzz=0` applies onto the recorded preimage, and the applied copy parses.

### The asymmetry, and a boundary I did not widen

The bead's own framing is right and is the reason this was filed rather than folded in: a suite that fails on its
own base is a worse signal than a suite that names an environmental mismatch. For the same reason I am not
widening this fix: on a **lane** VM sections 1 and 2 also misbehave (they reclaim against the machine's real
heavy-holder state) and section 4 exceeded a 400s bound, and those are the same machine-state dependence in
different clothes. They are recorded here rather than silently "fixed" in a bead that is about section 7.
