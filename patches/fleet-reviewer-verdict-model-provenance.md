# `fleet-reviewer-verdict-model-provenance.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target file:** `roles/reviewer.md` (the verdict shape, and the same-family instruction)
- **Baseline:** `roles/reviewer.md` as deployed on this VM, 11916 bytes
- **Bead:** agents-q7v2 (P2, process). Cross-linked with **agents-kq0r increment C** - the sdk-host half of the same
  question (a loud refusal when a reviewer's effective family equals the implementer's). Same root, different layers:
  this patch is the HUB half (what a reviewer must state), kq0r C is the MECHANICAL half (what the system can refuse).

## Problem

A reviewer subagent dispatched by an implementer **inherits the DISPATCHER's `FLEET_LANE`**, so the lane in the
reviewer's environment is the implementer's own. Transcribing a subagent's verdict does not change that attribution,
and it cannot: the lane is not the reviewer's identity and cannot support an independence claim.

Two measured costs, both this VM, both tonight:

1. **A clearance was retracted** because the reviewer's announced model was not the model that ran. The verdict was
   sincere and the claim was false; the retraction was correct, and "the field says otherwise" is the only repair (a
   different family member that had been believed, and that a reader could not check).
2. **The base rate is not small:** 29 lane logs across this VM record a model fallback, 23 of them the same
   sonnet -> deepseek-flash one. So a lane's *announced* model is not evidence of the model that ran, and the fallback
   is common enough to matter rather than exotic.

Independence shape today is `Delta:`/`Gate:`/`Reproduced:` - all of them name EVIDENCE rather than conclusions, except
independence, which rested on a lane name or on the reviewer's own sincerity. That is the gap this closes.

## Changes

1. **The verdict shape gains `Independence:`** - `PI_MODEL=<you> PI_PROVIDER=<you> vs author <model from the bead or
   lane record>`. One more line of the same kind as `Gate:`, which already tells a reader what to re-check.
2. **A short rationale beside it**, because a rule without its reason gets dropped: the two measured reasons above,
   named as such - the inherited lane, and the fallback rate.
3. **The same-family instruction is sharpened to point at the field** ("say so in `Independence:` with the quoted
   fields - a lane name cannot show it"), so the existing rule and the new line cannot drift apart.

## Verification

- The patch applies to a pristine copy of the deployed `roles/reviewer.md` with `patch -p1 --fuzz=0` and the result is
  byte-identical to the assembled file.
- 11916 -> 13212 bytes (+1296). The prompt budget is not a constraint here: `bin/fleet check_prompts` meters
  `roles/common.md` (16384 target, 65536 hard), and this file is 13212 after the change.
- **The requirement is followable, demonstrated on this VM:** `printenv PI_MODEL PI_PROVIDER` returns
  `deepseek-flash` / `deepseek`. That is the line a reviewer pastes - and it is exactly the check that fails when an
  announced model is not the running one.
- **The practice already exists and was praised tonight:** rev-l80j2's verdict stated `PI_MODEL=gpt-6-sol
  (openai-codex), author deepseek`, and coord has adopted the quoted-field form as standing. This patch does not
  invent a requirement; it writes down the one that has already proved itself, in the file the reviewer reads.
- **Deliberately NOT touching `remote/lanes.sh`:** that file already refuses to spawn a reviewer LANE on the
  implementer's family (`fleet-ccfq`, lanes.sh:361-389, with `IMPL_MODEL` recorded for later re-picks and an explicit
  UNGUARDED notice when the implementer's model is undeterminable). The defect this bead describes is the SUBAGENT
  case, where `lanes.sh` never runs at all - so a change there would be inert for the actual gap. Saying which half is
  which is the point of cross-linking kq0r C, which is the half that can refuse mechanically.

## Hub application

```bash
cd ~/fleet
git apply /path/to/fleet-reviewer-verdict-model-provenance.patch
# the reviewer role is a prompt, not a program: nothing to run, and the next verdict carries the line
grep -n "Independence:" roles/reviewer.md
```
