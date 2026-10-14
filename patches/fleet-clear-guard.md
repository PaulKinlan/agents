## fleet-clear-guard.patch — the clearance surface checks the reviewer's EFFECTIVE family (agents-ayqi)

WHY. A verdict is free text. `roles/reviewer.md` has the reviewer record `cleared:<tip-short>` with a `bd update`,
and `bin/fleet-verdict-words.sh` parses the VERDICT token out of that prose — so **no record anywhere names the
model that RAN**. Measured on 2026-10-14: three reviewer rounds on this fleet were drawn into their author's
family and were caught only because the lane volunteered `$PI_MODEL`, i.e. the cross-family rule was being
enforced by honesty rather than by the record. `agents-kq0r` guards the fallback at startup
(`bin/fleet-fallback-guard`); this guards the other end, where the clearance is actually written.

WHAT THE PATCH DOES. Adds `bin/fleet-clear <bead> <lane> <tip-short>`: the same label write the reviewer already
performs, wrapped in a check of the reviewer lane's effective models, derived by the EXISTING auditor
`bin/fleet-model-audit` (fleet-r3j4, in `--asked` mode it checks EVERY recorded turn) from the lane's own runtime
records. It REFUSES — non-zero, no labels written — when the effective model is the author's own model, when any
effective model's family is the author's family (`IMPL_MODEL`'s provider prefix, the same definition
`remote/pick-model.sh` uses), and when the family cannot be established at all: no `IMPL_MODEL`, no turn record,
an empty record, an unreadable line, a duplicate key, or a case-only difference. **An unestablished family is a
BLOCKED clearance, not a satisfied one.** `roles/reviewer.md`'s clearance step now names the tool.

THREE FILES: `bin/fleet-clear` (new), `tests/fleet-clear.test.sh` (new, 16 drives), `roles/reviewer.md` (one
paragraph added to the passing-verdict step, nothing else changed). Revision 2 changes only the two new files.

BASE. Cut against the DEPLOYED tree, as coord directed, because `agents-kq0r` is measured **not installed** on
live `~/fleet` (no effective-family guard in `remote/lanes.sh` or `remote/run-lane.sh`) and this defect exists
now. The one file the patch EDITS is recorded exactly:

- `roles/reviewer.md` — 11924 bytes, sha256 ad225a927e292365019947390c1b9275fc2eeb9f434e23e0e237fd4d17f001a8

## REVISION 2 — fixes `agents-b1ld` (P2), found by the `agents-ayqi` review

THE DEFECT, REPRODUCED BEFORE FIXING. `fleet-clear` CLEARED a reviewer that had run a turn in the AUTHOR'S FAMILY, whenever any other turn in the same lane was cross-family. Two cases, both measured on the reviewed revision:
1. turns `deepseek/deepseek-chat` then `antigravity/gemini-3.8-flash` (author `deepseek/deepseek-flash`) -> **CLEARED, rc 0, one label written**.
2. turns `deepseek/deepseek-flash` then `antigravity/gemini-3.8-flash` — i.e. the author's EXACT model on one turn -> **CLEARED, rc 0**.

TWO INDEPENDENT CAUSES, AND THE SECOND IS THE ONE THAT MATTERS.
* The auditor names every non-matching turn **on one line**, and the old parse used `sed -n 's/.* ran a turn on \([^,]*\), which is not .*/\1/p'` — a greedy `.*`, so with two named turns it kept only the LAST one. The same-family turn was dropped and the family check never saw it.
* Worse: a turn that ran the author's EXACT model is a MATCH, and the auditor does not name matching turns at all. So the clearest possible violation — a reviewer that ran the author's own model for part of its session — was invisible to a parse that only reads MISMATCH lines, whatever the regex.

THE FIX, IN ONE PLACE. The audit is now asked with a **sentinel** (`fleet-clear/sentinel`) rather than with the author's model, so **every** recorded turn is a mismatch and **every effective model is named** — verified by driving both lanes above, where the sentinel call names both models on both lanes. The verdict is then the family comparison over that COMPLETE set, and the parse takes **every occurrence on every line** (`grep -o 'ran a turn on [^,]*, which is not'`) instead of the last one. A sentinel that ever MATCHES is itself refused (rc 3), because that would mean the lane's records are not what the check assumes.

EVIDENCE, RED THEN GREEN. Before: cases 1 and 2 both CLEARED rc 0 with a label written. After: both REFUSE rc 1 with NO labels, naming the model and the family ("the reviewer ran deepseek/deepseek-chat (family deepseek, the author's), among deepseek/deepseek-chat antigravity/gemini-3.8-flash - ANY same-family turn makes the verdict not independent"). The CONTROL is unchanged and still green: a lane whose every turn is cross-family CLEARS, and a same-family *id-level* fallback under a different author family still clears. `tests/fleet-clear.test.sh` now has **16 drives (was 12)**, adding the two multi-turn cases the reviewer identified as missing plus a same-family-fallback mixture, and passes **16/0** in the freshly patched tree.

**RISK, FLAGGED: if `agents-kq0r`'s patch is installed first, it does not touch `roles/reviewer.md` (it creates
`bin/fleet-fallback-guard` and gains `tests/fleet-fallback-guard.test.sh`, hooking `sdk-host/host.mjs`), so the
two should not collide — but the hub must re-verify THIS patch against its own tree, which is how every
hub-delivery artifact tonight has been handled.** The two new files have no base.

APPLIES: `patch -p1 --fuzz=0` against those originals → **rc 0, no rejects, no `.orig`, no fuzz or offset
messages**, and the result is byte-identical to the development tree. **INSTALL NOTE: `patch` does not set the
executable bit from the `new file mode 100755` lines, so the install must run `chmod +x bin/fleet-clear
tests/fleet-clear.test.sh`.**

EVIDENCE (revision 1, superseded). `tests/fleet-clear.test.sh` passes 12/0 in the freshly patched tree, driven against the REAL auditor
with synthesised lane records (`FLEET_LANES_DIR`), not a mock: cross-family clears and writes `reviewed` +
`cleared:abc1234` in one update; a fallback WITHIN a cross-family direction clears (families, not ids); a
same-family fallback and the author's own model are refused with no labels written; all four unestablished cases
are refused; `bd` failing refuses rather than passing silently. THE CONTROL that makes the refusals mean
something: the same effective model with a DIFFERENT author family CLEARS, so the refusal is the comparison and not
a tool that always says no. **AND THE TEST FOUND A REAL DEFECT, RED THEN GREEN:** a turn record with a blank line
makes the auditor report UNKNOWN *and* a MISMATCH for the lines it could read, with exit code 1 — so an rc-only
consumer read "some other model ran" and CLEARED on a record the auditor had just said it could not read in full.
The check is therefore on the auditor's OUTPUT (line-anchored `^`UNKNOWN``), not on its exit code's precedence.
