## `fleet-bd-lock-holder-role-hermetic.patch` (agents-m784)

**Status:** reviewable overlay for a *parked, not installed* hub artifact. The test file
`~/fleet/tests/bd-lock-holder.test.sh` was **absent** on this project VM when this overlay was
prepared. This branch does not edit `~/fleet` and does not claim any hub installation or live
suite result. The hub owns when and whether to apply it.

## Exact prerequisite and output

1. Start with the **reviewed agents-elu6 patch**, from carrier
   `origin/fleet/impl-ozmt-elu6` at commit
   `dc65e4d00cce74f9723dcdc294c58d35ed8d0045`, tree
   `a6ffe586e39bcc79f6a8d05a6de5c057842b1ac7`,
   `patches/fleet-bd-lock-holder.patch` blob
   `9e9502ca0ad0510feb699b0a1703bd21c62fd344` / SHA-256
   `5a009ccd25659836487df69565cb1035a45127ae6438058b8889eb34c1110197`.
   That patch applies to the deployed 14,480-byte `bin/bd` at SHA-256
   `f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478`.
2. **Before this overlay**, the *applied* elu6 `tests/bd-lock-holder.test.sh` must hash
   `8e9606c299dd6789dacde9feee3df1dd101ad43e5d03e2ddaa9f2113679c4588`.
   Hash the hub's actual file, not its path's expected role; stop if it differs.
   This overlay only changes that test file and leaves `bin/bd` untouched.
3. On a disposable copy of the hub tree, first run
   `patch --batch --forward --dry-run --fuzz=0 -p1 -i <path-to-this-patch>`;
   after prerequisites and review are satisfied, the **hub** may apply it with the
   same `--batch --forward --fuzz=0 -p1` flags through its own delivery process.
   The resulting test hash must be
   `057809264c134a53bc53f998cefc2a599afcb1fd30c0de1da2a66e86c51e9532`.
   On a scratch copy, strict `--fuzz=0` dry-run and apply produced that byte-identical
   result, and `bin/bd` stayed at `5fc55aed8ea42865892e8c5bfd1c5d29c3db5ef6a4427d3a9b602a89c49e9e3f`.
   The separately reviewed nbka queue patch applied after elu6 on a scratch copy at
   `--fuzz=0`; it changed only the bin hash to
   `d9270c1042fbd160467f28990164b07152948d3c03380efafbffafd2a61b1681`
   while leaving this test at the exact overlaid hash above. If the hub's later
   bin shim includes nbka or reporter patches, this test-only overlay can be
   considered **only if the test file itself matches the exact base hash**;
   do not assume any unmeasured patch is composable from the name alone.

## Why and what changes

The existing `shim()` helper passes `FLEET_ROLE=${ROLE:-implementer}` to its **waiter**,
not to `hold_shim()` or the direct holders in cases 9, 11 and 12. Those children inherit
an operator's ambient `FLEET_ROLE`. With a reviewer-role caller, the hub shim's
role guard refuses `work`, `slow-run`, and a freeform command before the holder writes
the lock record, so six assertions report a false regression. This is a test-fixture
hermeticity defect, not a change to locking or `bin/bd` behaviour.

At suite startup, before any holder or waiter spawns, the patch clears ambient
`FLEET_BD_LOCKED` and `ROLE`, then exports `FLEET_ROLE=implementer` as the test-wide
default. All children inherit this default. Per-call roles intentionally set by the
adversarial tests still override it, including the injected non-vocabulary role in
case 13 and the explicit implementer in case 15; case 6 can still set
`FLEET_BD_LOCKED=1` for its nested escape. Clearing those two inherited helper
variables prevents the operator's environment from silently changing the role or
bypassing the lock in unrelated cases.

## Evidence (all on `/tmp` copies; no live hub or project suite was touched)

- Materialised the pinned elu6 patch with `patch --batch --fuzz=0 -p1` onto a copy of
  the deployed `bin/bd` and obtained the exact prerequisite and output hashes above.
- RED control under `FLEET_ROLE=reviewer`: **57 passed / 6 failed**, rc 1; failures
  `2d`, `3c`, `9a`, `9b`, `11b`, `12b` (log
  `/tmp/agents-f6du-m784-red-reviewer.log`). These match the filed finding.
- GREEN on the overlaid copy: `FLEET_ROLE=reviewer`, `env -u FLEET_ROLE`, and
  `FLEET_ROLE=implementer` each returned **63 passed / 0 failed**, rc 0
  (`/tmp/agents-f6du-m784-green-{reviewer,unset,implementer}.log`). A fourth
  hostile control with `FLEET_ROLE=reviewer ROLE=reviewer FLEET_BD_LOCKED=1` also
  returned **63/0** (`/tmp/agents-f6du-m784-green-hostile.log`). Each invocation
  used `timeout -k 20 105`, an isolated stub HOME, and the scratch-copy shim.
- With the nbka queue patch applied strictly after elu6 in a disposable copy,
  the corrected holder suite under `FLEET_ROLE=reviewer` also passed **63/0**, rc 0
  (`/tmp/agents-f6du-m784-post-nbka-reviewer.log`). The later reporter-lifecycle
  overlay was not tested; it remains a separate prerequisite/installation decision.
- This is not a gate verdict on this agents repository. Its exact-tree fast gate
  must be run after committing this patch and write-up; hub installation remains a
  separate, owner-controlled step.

The existing elu6 tests include the P1 lock-lifetime case (a killed shim must not
release a lock held by live bd work) and the P2 privacy probes. Their green results
under four ambient environments are included above; this patch must not weaken or
replace those discriminators.
