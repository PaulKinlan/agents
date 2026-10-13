# `fleet-reviewer-verdict-model-provenance.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:** `roles/reviewer.md` (the verdict shape) and `remote/lanes.sh` (a runtime-model audit)
- **Baseline (measured against the LIVE hub files, and re-checked after a sync moved them):**
  `roles/reviewer.md` 11924 bytes, sha256 `ad225a927e292365019947390c1b9275…`; `remote/lanes.sh` 35527 bytes,
  sha256 `a5dfb8b0faa6ce347ad9391d0d30d87a…`. While this delivery was being written a sync changed both files (by 8
  and 2 bytes), so rather than assume, I re-measured and re-checked: the patch applies to the LIVE files at `fuzz=0`
  AND passes `git apply --check`, both clean. An earlier revision of this document quoted 11916 bytes - a figure
  measured before that sync, and therefore stale prose about a file that has moved, which is exactly the kind of note
  that invites a wrong conclusion about an artifact that is in fact fine. The measured numbers above replace it.
- **Beads:** agents-q7v2 (P2) with the runtime-vs-intent half of the spawn P1, delivered as ONE artifact per
  coord's ruling. Cross-linked with **agents-kq0r increment C** - same root, different layers: this patch is what
  the HUB can do (state the field, and make drift visible), C is the mechanical refusal in the SDK host.

## The root, in one paragraph

A reviewer subagent dispatched by an implementer **inherits the DISPATCHER's `FLEET_LANE`**, so the lane in the
reviewer's environment is the implementer's own - and transcribing a subagent's verdict cannot change that
attribution, because the lane is not the reviewer's identity. Meanwhile a lane's **runtime model can differ from the
model it was spawned with**: 29 lane logs on this VM record a model fallback, 23 of them the same sonnet ->
deepseek-flash one. So the independence guard at spawn (`fleet-ccfq`) reasons about an INTENT, and an intent that is
not what runs cannot support the claim it was guarding. Both layers are one question: *what model is actually
reviewing this, and how would a later reader check?*

## Changes

1. **`roles/reviewer.md` - the verdict shape gains `Independence:`**: `PI_MODEL=<you> PI_PROVIDER=<you> vs author
   <model>`. One more line of the same kind the shape already has, since `Delta:`, `Gate:` and `Reproduced:` all name
   EVIDENCE and independence was the one claim resting on a lane name or on the reviewer's sincerity. A short
   rationale follows it (so the rule is not dropped), and the same-family instruction is sharpened to point at the
   field rather than the lane.
2. **`remote/lanes.sh` - `lanes.sh model-audit`**, plus a marker in `lanes.sh list`. It reads the runtime truth from
   the pi child's environ - the same source the SDK-mode ownership check already uses - and compares it with the
   lane's recorded intent (`.model`, else `MODEL` in the conf):
   - `DRIFT` when the recorded intent is not what is running;
   - `UNSAFE` when a REVIEWER's EFFECTIVE family equals the `IMPL_MODEL` it was guarded against - the guard's own
     question, asked of the runtime rather than of the intent;
   - exit 1 when anything is drifted or unsafe, so a hub-side sweep can act without parsing text;
   - `LD` now honours `FLEET_LANES_DIR` (default unchanged) so the audit is testable without touching the real lanes.
3. **The audit is deliberately a report, not a kill**: nothing here stops or restarts a lane. A drift is a fact to
   surface; the decision to act belongs to coord, and a check that silently kills a running lane would be a worse
   bug than the drift it found.

## Verification

- Applies to pristine copies of both deployed files with `patch -p1 --fuzz=0`, byte-identical to the assembled files;
  `bash -n remote/lanes.sh` clean.
- **Discriminator driven in four directions on real machinery** (a fixture lane whose child carries the runtime env,
  `FLEET_LANES_DIR` pointed at a scratch dir, so the real lanes directory is never touched):

  | case | setup | result |
  |---|---|---|
  | i | intent == runtime | `ok`, exit 0 |
  | ii | recorded intent a different family | `DRIFT recorded=zai/glm-5.3 but running=deepseek/deepseek-flash`, exit 1 |
  | iii | reviewer, effective family == `IMPL_MODEL` family | `UNSAFE`, exit 1 |
  | iii-b | the SAME reviewer against a gemini implementer | `ok`, exit 0 |

  iii-b is the case that matters: without it, an always-on alarm would pass i-iii. The check is a comparison, not a
  verdict about reviewers.
- **Live run on this VM**, real lanes, real children: `impl-l2xb ok deepseek/deepseek-flash`, `impl-ozmt ok
  deepseek/deepseek-flash`, `rev-2tov4 ok antigravity/gemini-3.8-flash`, `merger ok deepseek/deepseek-flash`, and
  not-running lanes reported as such rather than as failures.
- The requirement is followable: `printenv PI_MODEL PI_PROVIDER` returns `deepseek-flash` / `deepseek` here, and the
  practice already exists - rev-l80j2 stated its field voluntarily and coord adopted that form as standing.

## Limits, stated rather than overclaimed

- **An earlier fixture of mine was vacuous** (`bash -c 'VAR=x sleep'` execs into `sleep`, so there were no children and
  every arm collapsed to `not-running`). It is called out here because the first four-way run *looked* like a pass; the
  fixture now asserts the child exists before the audit runs.
- **`ls`-adjacent pre-existing fragility, not touched:** `lanes.sh list` sources the conf and prints `"$ROLE"` under
  `set -u`, so a conf without `ROLE` aborts it (`line 530: ROLE: unbound variable`). A real lane conf always has
  `ROLE`, and this patch neither causes nor fixes it - noted because my fixture exposed it.
- **This does not make a same-family review impossible**, only visible and recorded. The refusal half is kq0r C.
- `remote/lanes.sh` is a shared hub file: no other parked delivery here touches it (kxbv's upstream half is
  `.beads/hooks`, elu6/3avt are `bin/` and `remote/check-coverage.py`), so ordering with them does not matter.

## Hub application

```bash
cd ~/fleet
git apply /path/to/fleet-reviewer-verdict-model-provenance.patch
grep -n "Independence:" roles/reviewer.md
lanes.sh model-audit            # one line per lane; exit 1 if any DRIFT/UNSAFE
```
