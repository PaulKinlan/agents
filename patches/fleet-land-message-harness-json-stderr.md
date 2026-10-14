## `fleet-land-message-harness-json-stderr.patch` (agents-zcxb)

**Target repository:** `PaulKinlan/fleet`, not this project. This project VM's `~/fleet` is read-only; this is an unapplied hub-delivery artifact.

| Field | Exact value |
| --- | --- |
| **Artifact** | `patches/fleet-land-message-harness-json-stderr.patch` — **2,767 bytes**, SHA-256 `f06f46e3017b7620144c06fe261b0bb5d3757f1013b528ae163d492ae9c5c124`; one file section, `tests/fleet-land-message.test.sh` only. |
| **Exact base** | The DEPLOYED `~/fleet/tests/fleet-land-message.test.sh`: **91,463 bytes**, SHA-256 `91dfa5c97995244b3733aca102d3c81e7846d95b632c67435901fef67ad15a77`. The helper under test remains **64,670 bytes**, SHA-256 `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee`; this patch does not edit it. |
| **Destination shape** | On an isolated copy of that exact test-file base, `git apply --check` passes; applying this artifact yields **93,669 bytes**, SHA-256 `93b2180b8e23b6157c405a350f15b062921329ad76491b44cc5d3fdc90fbdf43`. `git apply --reverse --check` passes on the patched scratch file; `bash -n` passes. Readback of both live hub files after verification still equals the base hashes above — nothing was applied to `~/fleet` here. |
| **Prerequisites and order** | **None for this deployed-base patch.** Do not compose its `run()` hunk with `fleet-land-message-composition.patch` (agents-ak50/agents-wbph) or `fleet-land-message-author-identity.patch`: those factory-side artifacts target a DIFFERENT 88,074-byte test-file lineage and also use the old `run()` line as an edit/context anchor. If hub later adopts that lineage, re-cut this fix against its resulting test file rather than applying two competing `run()` replacements. Other hub patches whose hunks are well below line 79 need their own base checks before integration. |

**Problem:** the installed harness defines one global `run()` around line 79 with `bash "$LM" "$@" 2>&1`. There are 29 `run --print-json` call sites; they pass the resulting combined stream into `jq` or JSON assertions. A harmless stderr-only diagnostic before valid JSON is consequently parsed as JSON data. Measured with a shim injecting `INJECTED-WARNING-ON-STDERR` ahead of the REAL deployed helper: old `run()` returned **rc 0** while `jq -r '.summary.comment_index'` failed to parse and produced the empty string, rather than the helper's valid JSON value `0`. Merely fixing the helper's warning trigger does not repair this harness-wide stream boundary. Non-JSON refusal assertions, conversely, intentionally read diagnostic stderr through the combined text stream and must keep doing so.

**Change and structural acceptance:** make `run()` recognize `--print-json` and its `--json` alias. For those calls only, stdout remains unmodified machine-readable JSON; stderr goes to `$ROOT/fix/json-stderr` and is forwarded to the harness's own stderr, with the helper's exit code saved and returned. All non-JSON calls retain their original `2>&1`. Immediately after `run()`, add H1–H4, which wrap the REAL helper with an injected stderr-only warning and assert: `jq` parses `.summary.comment_index == 0`, the warning is retained/visible, rc stays `0`, and the warning is absent from JSON stdout. The same focused guard with old `run()` is **RED: 1 passed / 3 failed**, specifically H1/H2/H4; with this patch it is **GREEN: 4 passed / 0 failed** (`/tmp/agents-f6du-zcxb-{red,green}.log`). An independent two-stream scratch control also measured old `jq` output `[]` versus separated `[0]` while the non-JSON refusal remained rc `1` with its stderr visible (`/tmp/agents-f6du-zcxb-two-stream-control.log`). This is a guard on the parser's actual input, not a grep for a line of test code.

**Target suite verification:** against the byte-exact applied scratch test file and unchanged deployed helper, bounded `fleet-gate agents-zcxb-hub-selftest -t 600` exited **0 after 22 seconds**, **296 passed / 0 failed**, including H1–H4. Log `/tmp/impl-f6du-agents-zcxb-hub-selftest.log` shows the injected warning forwarded OUTSIDE JSON, then all four controls passing. The hub's larger/full gate has not run in this lane; the project branch still needs its own exact-tip fast gate and independent cross-family review before landing.

**Limits:** diagnostics on JSON runs are surfaced rather than silently dropped; this patch does not declare every warning fatal. If the hub wants a stricter *no stderr allowed* policy, it must decide that explicitly instead of contaminating JSON or hiding diagnostics. The saved stderr file is a per-fixture observation and the test's temp root is removed at exit. When using `git diff --check` on the outer project commit, a unified `.patch` can contain context-prefixed blank lines; source-side `git diff --check`, exact-base apply and the parser-driven regression are the meaningful checks.

**Hub application, only in a writable hub-owned checkout:**
```bash
# First compare the deployed tests/fleet-land-message.test.sh hash with the exact base above.
git apply --check /path/to/patches/fleet-land-message-harness-json-stderr.patch
git apply /path/to/patches/fleet-land-message-harness-json-stderr.patch
bash tests/fleet-land-message.test.sh
# Then gate the combined hub tree. Stop and re-cut if the deployed base differs.
```
