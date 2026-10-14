## `fleet-land-message-composition.patch` — rank-selection and JSON-harness composition (agents-ak50)

**Revision 2 — 2026-10-14.** This is the only current delivery of this composed helper/test image. **Revision 1 acceptance is VOID:** red 367/8, green 363/12 had two common failures and ten green-only failures. Do not quote those counts as a passing gate. The previous `f7190c0c` two-artifact stack/wwss proposal and the `/tmp/ozmt/p1.base.patch` + `p2.base.patch` scratch series are inputs to this *integrated* replacement, not additional patches to apply after it.

**State:** delivery artifact, **PENDING independent review and hub installation**. A factory `patches/` commit is not an installed `~/fleet/bin/fleet-land-message`. No `~/fleet` file was modified to prepare this artifact.

### Why and what

- **agents-ak50:** author attribution comes from the registered lane owning the **branch**, not the actor appending `LAND-SUMMARY`. The single derived author reference governs every tip and fallback pool, demotion, disagreement, transcription flag and output field. A self-posted author-model cue is not its own trust anchor. In the two-verdict control, the coordinator appends the summary, a reviewer posts a tip-pinned PASS, and the branch author posts a newer bare self-PASS: the old rank selection selects the self-PASS; the corrected selection demotes it and selects the reviewer.
- **agents-nykl (separate helper defect):** remove the tip-rank read of uninitialised `$_own_auth`. The tip pool already scans `$_tip_auth`; the older-commit pool has its own scoped `$_own_auth`. Do not suppress or treat an `unbound variable` diagnostic as clean JSON.
- **agents-wbph (separate harness defect):** `--print-json` keeps stderr out of stdout for **all** JSON invocations, preserving stdout for `jq`. Unexpected stderr is still recorded and fails the suite; a two-stream canary asserts both observability and correct parsing. The live hub-suite analogue is separately tracked by **agents-zcxb**; this artifact alone does not install that hub correction.
- **Landed agents-m6fr policy:** absent/unresolvable RUN provenance remains visible as `transcribed-unverified` and `run_reason`, **classification only**, not a clearance gate. The new 38r1 assertion checks `[independence, cleared]` **together** as `['transcribed-unverified', true]`. No fabricated RUN is inserted into 38q or 38r, or into any verdict to manufacture clearance; existing earlier fixture RUN values are not new evidence for 38r.

A fixture discriminates only on the axis where red and green actually differ. The first 38q tested shared no-RUN behavior and could not distinguish them. The corrected 38q tests **rank selection between candidates**, the actual red-tree defect. `38q4` (`CURRENT`) and `38r1` (the no-RUN policy pair) are **assertions**, not discriminators.

### Exact input, application and result

The single patch targets four files and must be applied **once** to an exact prior bundle, *not* blindly to the currently installed helper:

| Path | Required input SHA-256 | Result SHA-256 |
|---|---|---|
| `bin/fleet-land-message` | `980899b73c2cbd87774d45d96c326364cfc322d11e190f197fec6d06c1838716` | `86c07477b1daa8010ab54f31982263226b898d72dd9f7e75a0dcf00356838848` |
| `bin/fleet-verdict-words.sh` | `b28dde10d67426316c9809fb314f26673c19fcbc15b5cbe402340b5f2416852b` | `1ca7d346439fd67da090e0029d75b65deda36a5878661197253efdc3e89c3702` |
| `tests/fleet-land-message.test.sh` | `647694f31286dce3da614b100a6b7178c90b07ca834fb7b6c7dc4b400dd3b2fa` | `c83940149dc4d84f8477423ab7680a49ddc97535db1cb80e8eabbe5f5bcc8059` |
| `tests/fleet-verdict-transcribed-run.test.sh` | absent | `b8d252d7e3ad77f0b23fab4de45b3d536b6abc2bdf820c2aacff293c1e713a57` |

Patch SHA-256: `069be1d13ebe5ae1bd9234bbd81779bdc7c25bafaf0e78a1e2e7c41e7bbffffa`. In a fresh copy of the pinned base, `patch -p1 --fuzz=0 --dry-run` and then `patch -p1 --fuzz=0` applied all four files without offsets, fuzz or rejects. Every resulting file compared **byte-for-byte** with the green control image. The live helper was observed at SHA-256 `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee`, **not** the required input hash; the hub must reconcile its executable generation first and cannot claim this artifact was applied directly.

### Acceptance at this revision (scratch control, not the commit gate)

Identical red/green fixture SHA-256 `c83940149dc4d84f8477423ab7680a49ddc97535db1cb80e8eabbe5f5bcc8059`: **red 368 passed / 6 failed; green 374 passed / 0 failed; 374 unique IDs; 6 discriminators; 368 guards.** Each of `37a`, `38k`, `38q2`, `38q3`, `39a`, `39b` is **red FAIL / green PASS**. Thus `R\F=D`, `R∩F=∅`, `F\R=∅`, every guard passes, no duplicate IDs. `38q4`, `38r1`, `38r3`, `38r4`, `H1`, `H2`, `H3` all pass on **both** sides. Twelve revision-1 failures were corrected as fixture/setup artifacts (per-invocation lane state, mismatched registered branch actor/model, inconsistent VM prefix), not by weakening the six controls. The run finished normally after 180s elapsed including queue wait; that is not a claim about active suite runtime or fast-gate cost. Evidence: `/tmp/agents-f6du-ak50-{red,green}-control.out`, `/tmp/agents-f6du-ak50-accept.out`, and the `agents-ak50` bead comments. The transcribed-run focused unit script passed 8/8 on the applied bundle.

The exact commit-tip fast-gate verdict and cross-family review are **still required** before clearance. A reviewer must pin the resulting patch and write-up bytes, not accept this scratch control or an earlier reviewed input patch as clearance for the new tip.
