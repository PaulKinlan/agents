## `fleet-land-message-independence-fail-closed.patch` — fail closed on unresolved landing-review independence (agents-ct2j)

**Target:** the hub's `PaulKinlan/fleet`, **not** this repository's runtime. The paired artifact is [`fleet-land-message-independence-fail-closed.patch`](fleet-land-message-independence-fail-closed.patch). It is **not installed** on any hub by this branch. The hub owner must check the actual deployed whole-file preimages and apply the **helper and its contract tests together**. A factory fast-gate PASS on this repository is not hub installation clearance.

| Exact deployed preimage | SHA-256 | Git blob |
| --- | --- | --- |
| `bin/fleet-land-message` (64,670 bytes) | `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee` | `54577cea62768723086d1682c2da6b3a994e4ebb` |
| `tests/fleet-land-message.test.sh` (91,463 bytes) | `91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77` | `bea65a811e885a6eb41f6a6490ca5a103427ed2a` |

The unmodified shared parser `bin/fleet-verdict-words.sh` was SHA-256 `b28dde10d67426316c9809fb314f26673c19fcbc15b5cbe402340b5f2416852b` (blob `54d105e1e7a35ab686e30d5f123eabf36898c1f5`). In particular, the pending `fleet-land-message-author-identity.patch` is **not** installed on this base; it touches the same helper and must be re-cut if applied first. Do not assume another patch's preimage or a factory branch's merge implies any hub file changed.

## RED, using an actual isolated Beads record

In `/tmp/agents-f6du-ct2j-realbd.cgsLSc/repo`, an independently initialized embedded-Dolt Beads DB with **no remote** held a real `ct2jprobe-cf4` bead. A handoff comment from `test-vm-imp-x` contained a `LAND-SUMMARY`; a later review comment from `test-vm-rev-x` contained `VERDICT: PASS` and a valid `main..<tip> branch fleet/ct2j` pin, but no effective reviewer model. The branch was a real scratch Git commit. `--repo` pointed the landing helper at that scratch checkout and `HOME` was a disposable home; no live bead, Git remote, or hub file was changed. With the exact deployed helper, `--print-json` reported `review.cleared=true, review.independence=other-lane, reviewer_model=""`. The same record with this patched helper reports `cleared=false, independence=reviewer-model-unresolved` and the named reason `reviewer lane rev-x model record missing`. A subsequent **real** Beads verdict from the same reviewer actor adding `Cleared-by: test-vm-rev-x (not-a-model-check)` returned `cleared=true` with `independence="cleared-by test-vm-rev-x (not-a-model-check)"`; see `/tmp/agents-f6du-ct2j-realbd.cgsLSc/{deployed-before,patched-scratch,explicit-actor}.json`. The scratch-only focused control was independently RED against the deployed helper (9 expected assertions failed; `/tmp/agents-f6du-ct2j-focused-red.log`) and GREEN with the patch (12/12; `/tmp/agents-f6du-ct2j-focused-green.log`).

## Contract change, including both intentionally permissive tests

- **Old §27 contract was deliberate:** another actor's model-less PASS cleared as `other-lane`. **New §27:** that PASS is `reviewer-model-unresolved`, `cleared=false`, with a diagnostic naming the missing reviewer lane model. Actor inequality alone is not model-family independence. The old §25 FAIL still wins selection, but its unknown reviewer is classified unresolved rather than independent.
- **Old §32 contract was deliberate:** no `LAND-SUMMARY` yielded `independence=unknown`, `cleared=true` (though other landing guards could still refuse). **New §32:** `branch-author-unresolved`, `cleared=false`, and a refusal naming the missing summary/author. An authority declaration cannot bypass this absence.
- An *author* model missing from both the verdict and its recognized lane record is `incomplete-provenance`, `cleared=false`, with a missing/empty/invalid author-record reason. A *reviewer* without an effective-model attestation is `reviewer-model-unresolved`, `cleared=false`, with a named missing/empty/pointer-only reviewer-record reason. A reviewer lane pointer contradicting the attested model is diagnosed as `pointer stale or inconsistent` and refuses (the pointer is intent, not proof of the effective run). A named reviewer and author with different provider families still clear as `other-lane` or `cross-family`; a known same-family pair still refuses, **even if an authority marker is present**. A same-actor unmodelled verdict remains `self-certified` and refuses.
- **The one explicit escape hatch** for genuinely unresolvable relayed/CLI reviews is a standalone verdict-comment line `Cleared-by: <exact Beads verdict author> (not-a-model-check)`. It works only for an actor different from the handoff author, when at least one model side cannot be resolved; it does **not** declare a model comparison, override a known same-family result, authorize an author's self-review, or supply a missing `LAND-SUMMARY`. The matched actor and `not-a-model-check` appear verbatim in `review.independence` and the landing message. A different name, prose mention, or implicit actor inequality does not clear. This is an explicit actor-attested exception, not proof of cross-family independence; operators should use it only when they are accepting that authority rather than a model-family result.
- `--print-json` adds `review.model_lookup.{reviewer,author}` and `review.independence_reason` so failed lookup reasons are machine-readable as well as visible on refusal lines. Existing JSON keys, exit-code meanings, PASS markers, pin-quality ranking and comment ordering remain. In the parser/ranking test sections unrelated to independence, the **test fixture writes** a literal, actor-matched authority line (and a fixture summary if absent) into its temporary comments JSON before running the real helper. It is opt-in via `FIXTURE_AUTHORITY`; sections 25–32 and the new §36 disable it so the no-model/no-summary refusals are tested against raw, unaugmented comments. The fixture declaration is not a production default.

## Validation and limitations

The scratch applied helper and **updated** test suite passed `317 passed, 0 failed` via `bash tests/fleet-land-message.test.sh` (`/tmp/agents-f6du-ct2j-suite-final.log`). New §36 covers missing author/reviewer independently; empty/invalid author records, empty/pointer-only/contradictory reviewer records; a genuine cross-family result; wrong and matching actor declarations; same-family refusal despite declaration; and no-summary refusal despite declaration. `bash -n` and `git diff --check` passed. Both preimages and after-images were checked bytewise; the expected after-images are:

| Strict-apply output | SHA-256 | Git blob |
| --- | --- | --- |
| `bin/fleet-land-message` | `2c92af52914338c703be8a96c4f17e8d2e0c6edff624309768a651f01c78d541` | `daa045c9805cb77b80983806042d9728ebea427a` |
| `tests/fleet-land-message.test.sh` | `7b771e5d081dc2f700d913e1fb99f6e4060e861c70401a94c46be50876740953` | `81501003659f751bfef4acf88d7ad8ed01fb2e6d` |

Hub-owner recipe **only**, never execute on a project VM's `~/fleet`:

```bash
cd "$HUB_FLEET_CHECKOUT"
sha256sum bin/fleet-land-message tests/fleet-land-message.test.sh
# STOP unless both whole-file preimages match the table above.
patch --dry-run --fuzz=0 -p1 < "$AGENTS_REPO/patches/fleet-land-message-independence-fail-closed.patch"
patch --fuzz=0 -p1 < "$AGENTS_REPO/patches/fleet-land-message-independence-fail-closed.patch"
sha256sum bin/fleet-land-message tests/fleet-land-message.test.sh
bash tests/fleet-land-message.test.sh
```

**Residual:** An effective reviewer model attested in a verdict is an actor claim; without a durable run audit on the landing VM, a dishonest declaration cannot be authenticated. An existing local `.model` pointer is checked for contradiction, not treated as runtime proof. Cross-VM/CLI reviewers with no resolvable model must either supply both attestations for comparison or use the visible actor-authority exception. Composing with the pending author-identity and effective-model-audit patches needs fresh hub-owner preimage verification and a new exact-base artifact; this patch does not silently stack them.
