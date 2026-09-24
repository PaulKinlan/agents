# Audit: engine dispatcher & adapter auth parity (`agents-vkw`)

**Question audited:** does the factory dispatcher invoke `pi`, `claude`, and `antigravity` on the
developer's existing session auth, without requiring additional API keys?

**Verdict:** `pi` and `claude` yes, but only after two fixes — before them the `claude` path
*abandoned* session auth whenever an API key was present in the caller's environment, and hung.
`antigravity` does not run at all on this machine (`agentapi` is absent) and used to report
success anyway.

Date: 2026-09-24 · Engines installed: `pi` 0.85.1, `claude` 2.1.265, `agentapi` **not installed**.

## Method

Not "does it serve" — every engine was driven through the real dispatcher
(`python3 factory run <agent> --target <dir> --engine <engine>`), with the deterministic pre-pass
included, and the produced run artifacts inspected. Auth precedence was probed directly by
exporting a deliberately stale key. Regression tests stub the engine binary and assert on the
environment it was launched with, so they are deterministic and need no model call.

## Results

| Engine | Adapter flags valid against installed CLI | Runs on session auth | Before | After |
|---|---|---|---|---|
| `pi` | `--no-session --skill <dir> -p` ✅ | ✅ | works | works (unchanged, documented) |
| `claude` | `--plugin-dir <dir> -p` ✅ | ⚠️ only if no key in env | **hung** (killed at 150 s, exit 124) | ✅ exit 0, full run |
| `antigravity` | `agentapi new-conversation` | ❌ `agentapi` missing | **exit 0 with a placeholder**, recorded as a clean scan | exit 1, loud |

## Findings

**F1 — `claude` silently abandoned session auth (High, fixed).**
Claude Code gives `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` precedence over the claude.ai
login. A stale key exported in the caller's shell was therefore inherited by the adapter's child
process and used for inference. Verified directly:

```
$ ANTHROPIC_API_KEY=sk-ant-invalid-000 claude -p 'Reply with exactly: ok'
⚠ claude.ai connectors are disabled because ANTHROPIC_API_KEY or another auth source is set
  and takes precedence over your claude.ai login · Unset it to load your organization's connectors
(no output; killed after 120 s)
```

`claude.sh` unsets those variables **only when a session credential exists**
(`~/.claude/.credentials.json`), so the CI plane — API key, no login on the runner — is
unaffected. Consistent with PLAN §"Local plane — session auth / CI plane — API key".

> **Corrected 2026-09-24 (`agents-e3u`):** the first fix removed two variables and this
document described the result as "session auth takes precedence over stale keys". That claim
was wider than the code — the adapter's own log line said `Auth: developer session` while a
run diverted by `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_USE_BEDROCK` or `CLAUDE_CODE_USE_VERTEX`
hung. The adapter now removes the nine known precedence-affecting variables it can be handed,
and reports which ones it scrubbed. The precise invariant, and the only one claimed here, is:
**when a session credential exists the child process does not receive any of those
variables.**

**F2 — the auth pre-check was a model call (Medium, fixed).**
`claude.sh` ran `claude -p "ping"` as a health check: a full inference per run, and it matched a
single error string, so every other auth failure fell through to a generic "Error executing
claude". Replaced with a deterministic credential-presence check (non-negotiable #1,
deterministic-first). No model call remains on the failure path.

**F3 — `antigravity` reported runs that never happened (High, fixed).**
With `agentapi` absent the adapter wrote the literal text
`[antigravity adapter] Handled via session skill integration.` into `model_output.txt` and exited
0. The dispatcher saw the file, failed to parse JSON, warned, and stored a **zero-finding report** —
indistinguishable from a genuinely clean scan on the target's tracker. The adapter now fails
loudly and writes no artifact, so the dispatcher aborts with exit 1.

**F4 — presence is not authentication (Medium, not fixed — recorded).**
`choose_engine` selects `antigravity` on `shutil.which("agentapi")` alone. A binary that exists but
is signed out would be auto-selected. Left alone deliberately: no deterministic local signal for
agentapi's auth state was established during this audit, and inventing a probe for a binary that
is not installed here would be guesswork. F3 means such a run now fails loudly rather than
silently, which is the property that actually mattered.

**F5 — SKILL_DIR and TARGET_DIR are not validated (Low, recorded).**
The claude adapter ran to completion with a bogus `--plugin-dir` (a scratch directory with no
plugin manifest). A mistyped agent directory degrades to "no skill loaded", i.e. an unguided
agent, with no warning.

**F6 — prompt text is passed in `argv` (Low, recorded).**
The prompt contains scanner excerpts from the target and is visible to other local users via `ps`.
Unchanged here; noted for the containment work rather than fixed in an auth audit.

## Evidence

Before — unfixed `main` (1ca94aa) in a scratch tree, stale key exported:

```
$ ANTHROPIC_API_KEY=sk-ant-stale-key timeout 150 python3 factory run docs-drift \
    --target /tmp/sf-before --engine claude --sink file
BEFORE EXIT=124          # hung; killed at the timeout
```

After — this branch, same stale key exported:

```
$ ANTHROPIC_API_KEY=sk-ant-stale-key timeout 240 python3 factory run docs-drift \
    --target ~/worktrees/agents-vkw --engine claude --sink file
[claude adapter] Auth: developer session (/home/paulkinlan/.claude/.credentials.json)
[Step 1/3] Deterministic pre-pass (check_docs.py)...
-> Deterministic scanner found 91 candidate matches.
[Step 2/3] Invoking engine 'claude' for triage and judgement...
[Step 3/3] Processing findings through deduplication and sink adapter...
[Findings Store] Target: agents-vkw | Delta: 3 new, 0 regressed, 0 fixed, 0 unchanged
AFTER EXIT=0
```

All provider keys stripped, `pi` engine: exit 0, 88 candidates triaged, run complete.
`antigravity` engine with `agentapi` absent: `Model output not produced: [antigravity adapter]
Error: 'agentapi' not found on PATH`, dispatcher exit 1.

```
$ python3 -m unittest discover -s tests -v     # 7 tests, OK
```

## Does an override actually divert a signed-in run?

`agents-e3u` noted this was asserted from documented precedence rather than measured. Measured
now, against the real `claude` binary (2.1.265), with the ambient API key stripped so every probe
starts from the same signed-in session:

| probe | environment | outcome | reads as |
|---|---|---|---|
| A | session only | `ok`, exit 0, ≈15 s | the baseline answers quickly |
| B | `ANTHROPIC_BASE_URL` → dead endpoint | no output, killed at 120 s | the endpoint was honoured |
| C | `CLAUDE_CODE_USE_BEDROCK=1` | no output, killed at 45 s | the run left the session path |
| D | `CLAUDE_CODE_USE_VERTEX=1` | `API Error: Could not load the default credentials` (Google), exit 1 | diverted to Vertex and failed on missing GCP credentials |

Probes B and C hang rather than fail, so the evidence is the *differential* against A, not the
absence of an error. End to end, with a session and five overrides exported:

```
BEFORE (main):  Auth: developer session (...)      -> killed at 90 s, no output
AFTER  (this):  Scrubbed ambient auth overrides: ANTHROPIC_API_KEY ANTHROPIC_BASE_URL
                CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX AWS_BEARER_TOKEN_BEDROCK
                Auth: developer session (...)      -> exit 0, correct JSON
```

That is the honest statement of what was wrong: the old adapter logged `Auth: developer session`
while the run used a different credential path.

The same class of variable was confirmed present in the installed binary for
`ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS` and `CLAUDE_CODE_USE_GATEWAY`; those are
scrubbed too, but only B, C and D were exercised end to end.

## Residual risk

- The claude fix keys off `~/.claude/.credentials.json`; if a future Claude Code release moves or
  renames that file, the adapter stops preferring the session (it does not break — the key path
  still works, and the no-credential error message tells the operator to run `claude login`).
- **Trade-off, deliberate:** a developer who needs `ANTHROPIC_BASE_URL`, custom headers or a
gateway *and* has a login on disk will find those variables removed during a factory run, at
which point the run takes the direct session path. The adapter prints what it scrubbed so this
is visible rather than mysterious. Setting up the session-less (CI) environment is the
escape hatch; there is deliberately no bypass flag, because a containment switch people flip is
not a containment switch.
- The override list is a blocklist. It is complete for the variables the installed CLI reads
today (`strings` over 2.1.265), not for every variable a future release might add; a release
that introduces another auth-override variable silently reopens this. An allowlisted child
environment would close that class — suggested in `agents-e3u`, not done here because dropping
the wrong variable breaks network egress for exactly the users hardest to debug.
- `antigravity` remains unverifiable end-to-end on this machine until `agentapi` is installed and
  signed in. Its parity claim is therefore **unverified**, not passing. F4 is the open question.
- Independent review by a different model family is still outstanding; the findings and the
  before/after evidence above are what a reviewer should try to falsify.
