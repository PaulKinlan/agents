## `fleet-land-message-refusal-atomic.patch` (agents-p1c2)

- **Target repository:** `PaulKinlan/fleet`
- **Target files (exact base - these are the live bytes on 2026-10-14 this patch was made against):**
  - `bin/fleet-land-message` - `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee`
  - `roles/merger.md` - `56ef087d06fabcda86c88a2a1a8eb20f7edc4ecacb0fbf4f10f905cdf1c607f6`
  - `tests/fleet-land-message.test.sh` - `91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77`
- **Related, NOT in this patch:** `agents-urh9` (a clearance consumed by landing cannot be un-consumed
  by a later tip move). Same bead family, different mechanism, different review brief - split out on
  purpose.

### Problem Statement (agents-p1c2)

A landing was in flight on 2026-10-14: main was `aa8c8b43`, the branch tip was `07605704`, the full gate was
running, and `origin/fleet/impl-guard` moved to `6dc64986` underneath it. `fleet-land-message --gate` then
**refused on ancestry - correctly** ("does not contain fleet/impl-guard"). The refusal was not fatal to the
sequence: the landed commit `2eb0ae20` **carried a truncated body**. The commit body on the default branch is
the durable account of what landed and why, and a truncated one is indistinguishable from a complete one to
every later reader - the same shape as the fabricated SHA256 tails (`agents-oa1e`) and the `state=STALE`
field that carried neither PASS nor FAIL (`agents-lgdv`): a record that looks like evidence and is not.

**What this patch MEASURED before changing anything**, because the tool and the caller have different
hazards and only one of them is a bug in the tool:

1. **The tool already emits NOTHING on a refusal.** `bash bin/fleet-land-message --gate <main-sha> <bead>
   fleet/<moved-branch>` writes **0 bytes to stdout** and exits 1. All refusal paths exit before the emit
   section, and `tests/fleet-land-message.test.sh` already pins one of them (`10y3`, `10za3`). So the truncation
   is not the tool writing a partial message.
2. **The hazard is the CALLER's redirect, and it is a shell property.** `helper > file` opens `file` with
   `O_TRUNC` *before* the helper runs, so a wrapper that reuses ONE message file across the two steps - the
   merge message first, then the gate record - has the complete message **destroyed by the shell** even though
   the helper writes nothing. A wrapper that then ignores the refusal amends and pushes the remains. The
   documented amend step also used `git commit --amend -F <(helper --gate ...)`, where process substitution
   hands the amend whatever was printed before the refusal - the same partial body, one indirection later.

### What this patch changes

1. **`bin/fleet-land-message`: the emit is now atomic.** The text message is assembled into a temp file and
   flushed in ONE `cat` at the end (`msg_out=$(mktemp)` + `{ ... } > "$msg_out"` + flush + remove, with an EXIT
   trap so a mid-assembly exit emits nothing and cleans up). This is the "write to a temp path and rename"
   shape for a tool that only prints, and it makes "a refusal emits nothing" a property of the code path
   rather than of the order today's refusal checks happen to run in. A refusal added *below* the emit point in
   future can no longer leak half a message to a caller.
2. **`bin/fleet-land-message`: the ancestry refusal names HOW the branch moved** (bead fix shape c). It now
   prints the branch tip as it is now and how many commits the gate commit does not contain, so the operator
   decides between re-gating the merged tree and re-pinning the review instead of discovering which happened.
   The refusal's first line is unchanged, so the existing contract assertions still hold.
3. **`bin/fleet-land-message` + `roles/merger.md`: the taught sequence CHAINS the refusal.** The amend step's
   process-substitution form is replaced by a block that checks the rc, amends only on success, and exits
   without amending or pushing on a refusal; the merge step gets the same shape (and `git merge -F "$msg"`
   instead of reusing the file). The tool's own *printed* guidance for the no-cached-verdict case teaches the
   same block, because a printed instruction is a behaviour of the tool.
4. **`tests/fleet-land-message.test.sh`: 18 new assertions** (10 here in round 1, plus the 8 in Round 2
   below, which the round-1 wording used to imply was the patch's total). The count is CHECKABLE rather
   than asserted, because the harness prints a pass total and the artifacts only add assertions: 295 before
   this patch, 305 after round 1, 313 after round 2, against 301/307 for the same harnesses on the
   unpatched tool. It includes the one thing that was not covered -
   the SEQUENCE's durability - and a negative control that makes it a measurement:

   - `10d1`/`10d2`: the printed guidance does NOT teach the refusal-hiding process substitution, and DOES
     teach the chained form.
   - `40a1`-`40a4`: a refusing `--gate` returns non-zero, writes 0 bytes into the message file, and leaves an
     **existing message file byte-identical** (sha256 and size both compared).
   - `40b1`/`40b2`: **negative control** - the naive `helper > file` form really does REFUSE and truncate the
     complete message to 0 bytes. Without this control, `40a2` could be passing because nothing was at risk.
   - `40c1`-`40c3`: the ancestry refusal still names the branch (existing contract) and now also names the tip
     as it is now and the commit count.
   - `40d1`/`40d2`: a DIFFERENT refusal shape (an unresolvable `--gate`) also emits 0 stdout bytes, so the
     invariant is about every refusal path rather than one branch of it.

### Round 2 (same bead, NEW TIP): what the round-1 clearance's notes asked for

The round-1 tip was cleared `PASS-with-notes` and **explicitly NOT for landing**: its commit body claimed
"every non-message exit writes 0 bytes to stdout" and the review's notes showed that claim was false as
written. Three notes, all addressed here:

1. **The USAGE path was the one early exit that wrote to stdout.** `bin/fleet-land-message:60` printed 19 lines
   of usage to stdout and exited 2 - **measured: 1316 bytes stdout, 0 bytes stderr** - so a caller whose
   invocation was mistyped had its message file CREATED AND FILLED WITH USAGE TEXT, which `git commit --amend
   -F` would then record as the landing body. The tool now sends the usage text to **stderr**, like every other
   refusal in the file. Every other early exit (including the bead-lookup failure at `:123`) already wrote
   nothing to stdout; the reviewer checked them directly, so this was the only site.
2. **The claim is now pinned as a FAMILY property rather than for two branches of it.** The new `40e` block
   asserts, for each early exit, `rc != 0` AND stdout is 0 bytes AND a diagnostic is on stderr - for the usage
   failure (`40e1`-`40e3`), an unknown flag (`40e4`/`40e5`) and the **bead-lookup failure** (`40e6`-`40e8`,
   the round's own P3 note). The lookup path is drivable with no live beads DB because the harness stubs `bd`
   from `$FIX`, so an absent `show.json` IS the lookup failure.
3. **`LM_OVERRIDE` now fails loudly when it is not a file.** The round's notes were produced against a tool
   selected by `LM_OVERRIDE`, and the natural mistake is to pass a DIRECTORY (reading "another revision" as
   "another tree"), which makes `bash <directory>` fail once per fixture while the summary still prints a
   verdict-shaped line: **measured, `65 passed, 248 failed`, IDENTICALLY against a patched and an unpatched
   tool**. The harness now refuses with a message naming the shape it wants, so a red/green measurement cannot
   be silently wrong. (Same trap one level down: the tool needs its sibling `bin/fleet-verdict-words.sh`; a
   partial copy without it makes every fixture fail the same way, which is why the Apply section names it.)

### Verification (measured, on this VM, 2026-10-14)

The hub's own suite is self-contained (throwaway repo + stubs, no network, no beads DB) and supports
`LM_OVERRIDE` to run the same fixtures against another revision of the tool - which is how the red was
produced rather than asserted:

```
# GREEN: the patched tool + the new assertions (applied from THIS patch's bytes)
bash tests/fleet-land-message.test.sh                      # 313 passed, 0 failed
# RED: the SAME new assertions against the UNPATCHED tool
LM_OVERRIDE=/home/exedev/fleet/bin/fleet-land-message bash tests/fleet-land-message.test.sh
                                                           # 307 passed, 6 failed
```

The six red failures are exactly the assertions that depend on the tool change: `10d1`, `10d2`, `40c2`,
`40c3` from round 1, plus `40e2` ("usage went to stdout") and `40e3` ("stderr was empty") from round 2 - the
two that pin the usage fix. So each new assertion is load-bearing, and the 307 that pass in both directions are
the suite's existing coverage, unbroken. THE APPLY IS VERIFIED TWICE, because `--fuzz=0` is `patch`'s flag and
not `git apply`'s: `git apply --check` reports clean, and `patch -p1 --fuzz=0 < this.patch` applies all three
files with the result BYTE-IDENTICAL (`cmp`) to the tree the 313/0 run was taken from.

### Note on `agents-qngy`'s earlier artifact (why this refreshes a fix rather than duplicating one)

`patches/fleet-merger-refusal-stops-script.patch` (`agents-qngy`) already identified the caller-side hazard and
fixed the same two places. **It is not applied in `~/fleet`** (measured: `roles/merger.md` step 1 still shows
the process-substitution form, and the tool still PRINTS that form), **and its recorded baseline hash for
`bin/fleet-land-message` (`980899b7...`) no longer matches the live file (`f6de0939...`)**, so it can no longer
be applied as written. That is why the same incident recurred on `2eb0ae20`. This patch therefore lands the
doc/guidance half onto today's exact base, records today's hashes, and adds the tool-side atomicity plus the
BEHAVIOURAL tests that the earlier artifact did not carry. The `agents-qngy` artifact should be treated as
superseded by this one for those two files.

### Apply

`--fuzz=0` is `patch`'s option, NOT `git apply`'s - this section previously taught `git apply --fuzz=0`,
which is a usage error that applies nothing. Both instruments, as run here:

```
cd /path/to/fleet
git apply --check /path/to/fleet-land-message-refusal-atomic.patch      # clean
patch -p1 --fuzz=0 < /path/to/fleet-land-message-refusal-atomic.patch  # applies all three files
bash tests/fleet-land-message.test.sh     # expect: 313 passed, 0 failed
```

Apply it into a COMPLETE tree (or with `bin/fleet-verdict-words.sh` present): the tool sources that sibling for
its verdict vocabulary and exits 3 without it, and a tree missing it produces the same 65-passed/248-failed
signature as a wrong `LM_OVERRIDE`.
