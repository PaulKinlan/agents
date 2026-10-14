## patches/fleet-inbox-park-refuse-overlong-reason.patch

HUB-DELIVERY PATCH for `inbox/beads.mjs`, answering `agents-x1ij` (filed by the merger). The tool silently truncated a
park reason at 500 characters and still returned `ok:true`; it now refuses instead, and writes nothing.

## Reproduced on the CURRENT deployment, not described

Driven through the real client against the live service (`pid 2875978`, `node ~/fleet/inbox/server.mjs`, port 7777):

| reason length in | stored, read back from the response | response |
|---|---|---|
| **800** | **exactly 500** | **`ok:true`** |
| **406** | 406 | `ok:true` |

The probe used a clearly-named branch (`fleet/impl-l2-0utp2-x1ij-probe`) and was **unparked immediately afterwards**
(`{"ok":true,"parked":false,"entry":null}`), so nothing was left behind. The read-back is what settles it: the
response **already carried the stored entry**, so the truncation was visible to anyone who asserted on the contents
instead of trusting `ok:true` - which is how the merger found it.

## Where it actually lives, which is NOT where the bead pointed

`fleet-park` is a **client**: it POSTs JSON to `http://localhost:${port}/park` (`fleet-park:32`) and echoes the
server's response verbatim (`:43`). The cut is **server-side**, in **`inbox/beads.mjs:589`**, inside
`export function park({branch, reason, bead, by, unpark})` (`:572`):

    reason: String(reason).slice(0, 500),

That line is why 800 became exactly 500 **and** why the caller saw `ok:true`: the function writes the truncated entry
and then returns `{ ok: true, ... }` (`:596`) regardless. **`fleet-park` contains no truncation at all**, so a fix
aimed at the client would have changed nothing.

## The fix, chosen and stated

**REFUSE RATHER THAN SILENTLY TRUNCATE.** `park()` now returns `ok:false` when the reason exceeds 500 characters,
naming the actual length, the number of characters to cut, and the first 60 characters of the tail that would have
been dropped - **nothing is written on that path**. The plumbing for the refusal already exists and needed no
change: `server.mjs:327` maps `ok:false` to **HTTP 400**, and `fleet-park:36-41` prints `.error` and exits
**non-zero**.

The alternatives were considered and rejected, and the reasons are the point: **silently raising the cap is not a
fix**, because it defers the same cut to a longer reason; and a **loud truncation** (naming the dropped count and
tail) is acceptable but strictly weaker, because it still decides on the caller's behalf which sentence is
expendable.

**The rule behind it:** a write that fails in the direction of looking successful is worse than a write that fails -
the same sentence this fleet already uses about unread-back ledger writes and a lease that does not move. Applied
here: the fields most likely to sit at the END of a long justification are the **release condition** and the
**unpark trigger**, so a silent cut preferentially destroys the part that says **when a hold ends** - which is how a
hold becomes permanent by accident, and a park whose trigger is gone is indistinguishable from one nobody intends
to lift.

## Driven: fails before, passes after, with a control

Both harnesses are built from the **files' own `park()` text** - the patched file's, and the preimage's - and run
against a scratch `HOME`:

| reason length | **patched** | **preimage (the control)** |
|---|---|---|
| **800** | **`ok=false`**, error names 800 / the 500 limit / 300 to cut / the dropped tail | **`ok:true`** - the defect |
| **406** | `ok=true`, stored **406** | `ok=true`, stored 406 |

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `e0959022ab6c1d20da1d0544d14ad443dc41559f46ba83ef92435fb04b9cf724` (`~/fleet/inbox/beads.mjs`, 31230 bytes) |
| result | `9bc6ce88236dbb6383581fbe25ab7540a83d204e17ab6337cb731efbf9fed1bf` - **differs from the preimage**, asserted |
| patch | **1566 bytes, 1 hunk**, non-empty asserted so a zero-byte clean apply cannot read as a pass |
| apply | `patch -p1 --fuzz=0` on the committed artifact -> rc 0, zero rejects, byte-identical to the intended result |
| syntax | `node --check` on the patched module: clean |

**ADVISORY:** the preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin (`agents-x8ud`).

## Placement, and one operational consequence

`inbox/beads.mjs` is **fleet canon in the provisioned mirror** - not ours to edit, with no repo route (`git ls-tree
-r --name-only origin/main | grep inbox/beads.mjs` matches nothing in this repository). So this patch is the whole of
what we can ship and the hub applies it. **It is a live service**, at approximately a day and a half of uptime:
applying the patch means **restarting `inbox/server.mjs`**, so it should land with that in mind rather than during a
landing burst.

**Live evidence the fix does not disturb, as requested:** the merger's **HOLD on `fleet/impl-eea2-etvw` is intact**
and names both superseded tips (`25426cc5` design A, `9af8e451` design B) with the trigger written first. This patch
changes only the **pre-write validation** on the argument path and never rewrites a stored entry, so that hold is
preserved by construction - and it is why refusal rather than a rewrite is the right shape: a fix that rewrote
stored reasons would have been the thing that endangered a live hold.
