## A rejected push is UNKNOWN, not a failure: retry the identical push before re-merging

`agents-zmuj` (P2). Filed from the merger's own report: a push of `tpw5` v2 returned a bare
`! [remote rejected] HEAD -> main (failed)`, the landing was reported as FAILED, and a re-merge onto "the new main"
was announced - while the measurement showed **there was no new main**: `origin/main` had not moved, **zero commits
arrived**, the commit was a plain fast-forward of it, and retrying the **identical** push succeeded to `ac79405b`.
The cost of this shape is not the retry. **It is that a false failure prompts a re-merge, and that is how landed
work gets reverted by a careful actor.**

## Reproduced against a scratch remote, on the current tip

A transient is by definition hard to summon, so I built one rather than waiting for one: a **one-shot** `pre-receive`
hook that fails once and then disarms. That is what a transient *is* - a rejection whose cause is gone by the time
you retry.

| case | observed |
|---|---|
| push with the one-shot hook | `remote: rejected by one-shot hook` then `! [remote rejected] main -> main (pre-receive hook declined)` and `error: failed to push some refs` |
| `origin/main` after that rejection | **UNMOVED** - before and after are the same sha; nothing arrived |
| **retry, byte-identical push** | **SUCCEEDS**: `7042932..cff87bf  main -> main`, and the old tip **is an ancestor** of the new one - a plain fast-forward |
| CONTROL: permanent rejecting hook | first push fails, **the retry fails too**, and `origin/main` is **still unmoved** |
| **LIVE: this bead's own push, real remote** | bare `error: failed to push some refs to '.../agents.git'` with no reason, then the **retry says `Everything up-to-date`** - the push had succeeded |

## Then the REAL REMOTE produced the silent variant, unprompted

My scratch hook carries a reason (`pre-receive hook declined`), so I first recorded the **silence** as not
reproduced. The live system retired that caveat while this bead was being delivered: pushing **this bead's own
branch** reported `error: failed to push some refs to 'https://github.int.exe.xyz/PaulKinlan/agents.git'` with **no
reason at all**, and the immediate read-back of the branch came back **empty** - so by the letter of the output the
push had failed. **It had succeeded.** The identical retry printed `Everything up-to-date`, the remote ref was
identical to my local HEAD, and `git merge-base --is-ancestor <sha> origin/<branch>` returned true. Both halves are
therefore measured on the live system now: the **silent** rejection, and the **identical retry succeeding**.

**AND IT WAS NOT A MERGER PUSH.** That was an ordinary implementer lane pushing a feature branch, so the shape is not
specific to landing on main or to the landing tooling: any lane's push can report a failure that did not happen. The
cost is the same and arguably worse outside the merger, because an implementer who believes a false failure may
re-cut, re-gate or re-point a branch whose content is already on the remote.

## The rule, three clauses, all of the middle one measured

1. **RETRY THE IDENTICAL PUSH ONCE, BEFORE RE-MERGING.** A retry is cheap and idempotent; a re-merge is not.
2. **A BARE REMOTE REJECTION IS `UNKNOWN`, NOT A FAILURE** - the same reading the fleet already applies to exit 124.
   The load-bearing half is measured and holds in **both** cases above: **A REJECTED PUSH LEAVES THE REMOTE REF
   UNMOVED.** So the question "did my work land?" is answerable without trusting the message: read the remote ref.
3. **NEVER RE-MERGE ONTO A MAIN THAT HAS NOT MOVED.** This is the clause that prevents the damage. A re-merge of
   already-landed work onto an unchanged main is not a recovery, and if the push had in fact succeeded it is a revert
   waiting for a window. Before any re-merge: `git ls-remote origin <default>` and compare with what you had.

## Where the fix belongs, and what is not ours to change

Checked the paths **before** proposing anything, as `agents-zmuj` instructed:

| candidate | finding |
|---|---|
| the landing helper | `~/fleet/bin/fleet-land-message`, **64670 bytes, mode 755** - it contains the push itself (`:18` documents `git push origin HEAD:<default>`) and a search for retry/rejection handling finds **none**. **This is FLEET CANON, in the provisioned mirror: NOT ours to edit from a project VM, and there is no repo route to it (`agents-x8ud`).** |
| the merger's procedure | `~/fleet/roles/merger.md` - **also fleet canon**, not ours. |
| this repository | **zero `roles/` files**, confirmed with `git ls-tree -r --name-only origin/main`. So this write-up is the whole of what we can land, and the tooling half is the hub's. |

**The hub's half, in one change:** in `bin/fleet-land-message`, where it pushes, retry the identical push **once** on a
remote rejection; if the retry fails, **read the remote ref** and report `NOT LANDED` or `UNKNOWN (remote unmoved)`
rather than a flat failure; and make the tool **refuse or loudly warn on a re-merge when the remote ref has not
moved**. Anything less leaves the false failure able to prompt the re-merge, which is the actual defect.

## Second instance of the shape

I looked, and I am **not** filing one: the bare-push-rejection shape appears once in the reports and once in the
tooling, and the wider family it belongs to - an instrument reporting a state that is not there - is already on the
board (`agents-vcha` for the ready-list false green, and the false red I filed against my own `bd list` read). Widening
this bead to that family would bury the one actionable clause.
