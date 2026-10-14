## patches/fleet-tmp-clean-scratch-rotation.patch

HUB-DELIVERY PATCH for `bin/fleet-tmp-clean`, answering `agents-pm4q`. The fleet-wide case is `fleet-r5uje`
(mwg-train's breakdown) and this references it rather than re-arguing it.

## A correction to the bead's own premise, found by reading the tool

The bead's structural point was that `/tmp` is "the one directory no lane owns" and that the hygiene tooling has
"NO `/tmp` ARM AT ALL". The second half is true of `bin/fleet-disk-hygiene`, but **`/tmp` DOES have an owner**:
`bin/fleet-tmp-clean`, whose header says the split is deliberate - *"`tmp-clean` owns `/tmp` and language caches;
this owns GIT OBJECTS, the fleet's own check/log store, and evidence directories"*. So the gap was not an absent
arm, it was a **bound**: `fleet-tmp-clean`'s general rule prunes at **`-mtime +2` (two days)**, while a throwaway
copy of the fleet repo is ~430-446 MiB because `sdk-host/node_modules` is inside it. Measured on this VM: five such
copies were back the **same evening** as the sweep that removed them, 446 MiB each - so a two-day bound cannot bite
before the disk is under pressure. **The fix belongs in the existing owner, at a shorter bound**, not in a new tool.

## What the patch adds

Rule 2b, age-bounded and prefix-recognised, with `KEEP`, `contains_checkout` and the report/log idiom all reused:

| knob | default | meaning |
|---|---|---|
| `FLEET_TMP_SCRATCH_MIN_AGE_MIN` | `180` | the AGE bound, in minutes |
| `FLEET_TMP_SCRATCH_PREFIX` | `fleet-scratch-*` | the **promise** prefix: naming your scratch here relaxes the blanket checkout protection |
| `FLEET_TMP_SPOOL_PREFIX` | `nbs-spool-*` | ephemeral Dolt block-store spools, safe at a short age (a stale or zero-length one is itself a known fault) |

**Neither bound is a heuristic**, per the bead and `fleet-2o7hq`: it is **age** plus **liveness**, never how a run
ended. A `lsof` that cannot prove an entry idle causes a **skip**, never a delete; a timeout causes a skip too.

## Evidence, every number measured on this VM

`du`/`df` before and after, the threshold used, what was deliberately kept, and the free space that resulted:

| | before | after |
|---|---|---|
| `df -h /` free | 7.6G (66% used) | **8.7G (63% used)** |
| `/tmp` | 4.4G | 4.1G |
| `nbs-spool-*` entries | 1004 | **0** |
| summary | - | `reclaimed=1034MB (dead_pids=1007 [789508KB], stale_tmp=1047 [37716KB], home_caches=231700KB)` |

**Age threshold used:** the default 180 minutes. **Deliberately kept**, verified on the WHOLE candidate list and
again after the run rather than by eyeballing a head: `rev-s-o7b8-*` (a live review's scratch), `pi-subagents-uid-*`,
`snap-private-tmp`, `fleet-heavy`, and `rev-oi002-*`. Each appears **zero** times among the 745 rule-2b candidates.

**Two controls, because a rotation that cannot be shown to refuse is not a rotation:**

1. **Liveness is load-bearing.** With a deterministic oracle, the run reclaims 1034MB. With the same tool and the
   oracle reporting **not idle**, the summary is `reclaimed=0MB` and the spool population is **unchanged**. So the
   liveness bound - not luck - is what stops a live run's directory being taken.
2. **The prefix is the mechanism, in both directions.** A probe directory **named** `fleet-scratch-*` and containing
   a `.git` is **REMOVED**; an **unnamed** probe containing a `.git` is **PROTECTED**, however old. With both
   prefixes pointed at a name matching nothing, rule 2b reports **0** candidates while rule 1 still reports its own -
   so the two rules are independent and the prefix, not a guess, is what selects.

## An operational finding the hub should know before installing

On this VM `bin/fleet-path-idle.py` reports **`uninspectable pid=390 state=S`** (a same-user `sd-pam` whose
`/proc/<pid>/fd` is not readable), so `safe_remove` conservatively reclaims **nothing** - and that is true of the
pre-existing rules too (rule 1 had 1007 candidates and removed none). The refusal is **correct** for a destructive
step, and it is the same condition `agents-33br` fixed in the `fleet-disk-hygiene` FIXTURE. The practical
consequence: **on a VM where the shared oracle cannot prove idleness, this rotation is inert** - fail-safe, and
silent except for its `idle=no action=skip ... reason=uninspectable` log line. The drives above therefore stub the
oracle beside a full copy of `bin/` (the tool resolves it **relative to its own directory**, which is why a copy must
carry `bin/` with it - a lesson `agents-33br` and `agents-o7b8` each paid for separately).

## Preimage, by algorithm and by value

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `e7713057c7c32063f1d83a1ee04d09fd604d898086a7f47efc92f6f4e2410b69` |
| resulting | `9cb80e90b2cb9a9c39b0eb3109c476a612ee37c0fb2335c46fb0a01f6710859d` |
| apply | `patch -p1 --fuzz=0` -> rc 0, **zero rejects**, byte-identical re-application. `diff -rq` against the deployed `bin/` shows **only** `fleet-tmp-clean` differs |

**Install order: unconstrained.** This touches `bin/fleet-tmp-clean`; the gate patches under discussion tonight
(`agents-dbit`, `agents-o7b8`, `agents-nuyw`) touch `bin/fleet-check`. **No file is shared, so there is no collision
and no ordering requirement between them.**

**ADVISORY:** the preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin (`agents-x8ud`).
Verify by the chain you observe rather than against a stored number.

## The convention half, which the rotation cannot enforce by itself

The rotation can only take what it can recognise. A harness that creates a scratch tree should take one of two
options: **dispose of it when it finishes**, or **name it into `fleet-scratch-*`** so the rotation may take it at the
short bound. A copied repo that is *not* so named is deliberately never touched - which is why tonight's 446 MiB
copies (`can4`, `can5`, `can6`, `base7`, `sc`) survived this patch and will keep surviving until their creators
name them or clean up.
