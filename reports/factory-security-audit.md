# Security & threat-model audit: The Software Factory

**Scope:** `lib/`, `factory`, `.github/`, `agents/*/agent.yaml`, `targets/`, `THREAT_MODEL.md`, audited
against the eight non-negotiables in [`AGENTS.md`](../AGENTS.md).
**Tree audited:** `fbb1a14` (main, after PR #1 merged).
**Auditor:** factory-opus (opus). **Date:** 2026-09-24.

**Method:** claims were falsified, not read. Every finding below was reproduced by running the real
code — stub binaries on `PATH` that record what they were asked to do, the real dispatcher, the real
findings store. Commands and output are given verbatim so a reviewer can re-run them. Where I did
**not** verify something I say so explicitly rather than inferring.

> [!NOTE]
> **Disclosure check on this document.** This is a self-audit of a public repository whose code is
> already readable. It contains no credential values, no live exploit against a third-party target,
> and nothing that is not evident from reading `lib/findings.py` and `factory`. The findings are
> missing checks and unimplemented enforcement, not a weaponisable chain. SF-01 and SF-03 are the
> two a reader might reasonably argue belong in a private channel first; flagged to the operator,
> who owns that call at the merge gate.
>
> Every identifier below is written so it cannot match `secret-scan`'s own regexes. Verified: the
> scanner reports **0 candidates** on this tree with this file present (see "Self-contamination
> check").

---

## Summary

| # | Bead | Finding | Rule broken | Severity | Verified |
|---|---|---|---|---|---|
| SF-01 | `agents-681` | Beads sink has no severity guard; the GitHub sink does | Disclosure rule | **High** | ✅ end-to-end |
| SF-02 | `agents-pnu` | `containment`, `capabilities`, `budget` are decorative — nothing reads them | #2 | **High** | ✅ static + grep |
| SF-03 | `agents-94f` | The public-disclosure guard's only input is a model-supplied field that fails open | #2 | **High** | ✅ end-to-end |
| SF-04 | `agents-rvz` | No environment scrubbing — adapters inherit the full parent environment | #4 | **Medium** | ✅ stub engine |
| SF-05 | `agents-ywe` | `shell=True` on an operator string in the hill-climb bench path | #1 (spirit) | **Medium** | ✅ static |
| SF-06 | `agents-76b` | No `timeout=` on any dispatcher `subprocess.run` | — | **Medium** | ✅ static |
| SF-07 | `agents-1r5` | `report.schema.json` is never loaded or validated by anything | #1 | **Medium** | ✅ grep |
| SF-08 | `agents-pr7` | Discovery and verification share the findings store | #3 | **Medium** | ✅ static |
| SF-09 | `agents-5rx` | `visibility:` in `targets/*.yaml` is never read by any code | Disclosure rule | **Medium** | ✅ grep |
| SF-10 | `agents-cfx` | CI action clones unpinned `main` into a step holding both tokens | Supply chain | **Medium** | ✅ static |
| SF-11 | `agents-pgr` | Prompt text exposed via `argv` **and** a world-readable `prompt.txt` | #4 | **Medium** | ✅ argv from PR #1; disk mode verified here |
| SF-12 | `agents-411` | The committed suppressions file is never read; the one the store reads is gitignored | Noise control | **Medium** | ✅ end-to-end |

Four of these (SF-01, SF-03, SF-09, and the disclosure half of SF-02) are the same underlying
problem seen from different angles: **the factory decides what is safe to publish using values it
does not control and does not validate.**

A second, smaller pattern runs through SF-02, SF-07, SF-09 and SF-12: **four separate configuration
surfaces are declared, documented, and read by nothing.** Each looks like a control while being
inert.

---

## SF-01 — The beads sink has no severity guard. The GitHub sink does. (High)

`_dispatch_github` refuses to publish `critical` and `high` findings. `_dispatch_beads`, twenty
lines above it, publishes `critical`, `high`, *and* `medium` with no guard at all.

```python
# lib/findings.py:254  — beads
if f["state"] in ("new", "regressed") and f["severity"] in ("critical", "high", "medium"):

# lib/findings.py:280  — github
if f["severity"] in ("critical", "high"):
    print(f"[SECURITY GUARD] Suppressing public GitHub issue for {f['severity']} finding: ...")
    continue
```

**Verified.** Same three findings (one critical, one high, one medium) through each sink, with a
stub `bd` and a stub `gh` on `PATH` that log what they were asked to create:

```
$ … --sink beads
Created bead for: PROBE CRITICAL leaked key
Created bead for: PROBE HIGH rce
Created bead for: PROBE MEDIUM nit

$ … --sink github-issues
[SECURITY GUARD] Suppressing public GitHub issue for critical finding: PROBE CRITICAL leaked key
[SECURITY GUARD] Suppressing public GitHub issue for high finding: PROBE HIGH rce
Created GitHub issue: …          # only the medium one
```

**Why this matters more than a missing `if`.** The bead body is assembled in `lib/findings.py`
(line 256) and embeds the finding's `snippet` verbatim:

```python
desc = f"{f['description']}\n\nPath: …\nFingerprint: …\nSnippet:\n{f['snippet']}"
```

For `secret-scan`, `snippet` **is the matched line** (`scan.py:105`, `snippet = line.strip()`), or
under gitleaks the matched secret itself (`scan.py:61`). So a critical secret-scan finding becomes a
bead whose description contains the credential.

Beads databases sync over the project's git remote. Verified on this repository:

```
$ git ls-remote origin | grep dolt
…  refs/dolt/data
```

`origin` here is `https://github.com/paulkinlan/agents.git`, which `gh repo view` reports as
**PUBLIC**. Two configured targets route to beads and declare themselves public:

```
targets/chrome-agent-platform.yaml -> sink=beads visibility=public
targets/voicebox.yaml              -> sink=beads visibility=public
```

*Not verified:* that those two repositories' beads remotes are themselves public — both paths are
absent on this host (`~/Code/chrome-agent-platform`, `~/Code/voicebox` → MISSING), so I could not
check their remotes. The routing defect is verified; the blast radius for those two targets is not.

**Fix.** Apply the same embargo to every sink, not one. Better: make the guard a single function
that every sink calls, so adding a sink cannot silently omit it.

---

## SF-02 — Containment, capabilities and budgets are decorative (High)

Every `agent.yaml` declares `containment`, `capabilities: {write, network, browser}` and
`budget: {max_minutes, max_usd}`. Across the 22 agents:

```
14  containment: t0-readonly
 7  containment: t2-local
 1  containment: t1-fetch

write: true    → docs-write, perf-hillclimb, perf-review, pr-fixer
network: true  → deps-supply-chain, issue-triage
```

Nothing reads any of it. The only occurrence of the word in executable code is a `print`:

```
$ grep -rn "containment\|t0-readonly\|t2-local" --include=*.py factory lib/
factory:207:    print(f"  Containment: {agent_cfg.get('containment', 't0-readonly')}")

$ grep -rn "capabilities\|max_minutes\|max_usd" --include=*.py factory lib/
(no output)
```

So the banner prints `Containment: t0-readonly` while the agent runs as the developer, in the
developer's environment, with the developer's full filesystem and network access. `AGENTS.md` says
*"Anything above `t2` requires manual approval per run"* — there is no approval code path:

```
$ grep -rn "approval\|approve\|confirm\|input(" --include=*.py factory lib/
(no output)
```

**Reading against non-negotiable #2** (*never use a model as a containment boundary*): the rule is
satisfied only in the degenerate sense that there is no boundary of any kind. The printed tier is
worse than nothing, because it reads as an assurance to whoever is watching the run.

THREAT_MODEL.md §6.1 states as an invariant that `t0-readonly` agents *"must have zero filesystem
write access, zero network access, and zero ambient shell command capabilities."* That invariant is
currently unimplemented, and §7 already accepts unsandboxed local execution for trusted targets —
so the honest position is that this is **planned, not built**.

**Fix (smallest useful step).** Either enforce the declared tier, or stop printing it as though it
were enforced. A cheap first increment: refuse to run `write: false` agents with any engine
adapter that can write, and print `Containment: t0-readonly (declared, NOT enforced)` until it is.

---

## SF-03 — The disclosure guard trusts a model-supplied field, and it fails open (High)

The public-disclosure guard branches on `f["severity"]`. That value originates in the model's JSON
output — it is parsed out of free text by `extract_json_from_output` (`factory:165`), handed to the
store, and defaulted when absent:

```python
# lib/findings.py:121
"severity": item.get("severity", "medium"),
```

`medium` is precisely the band the GitHub sink publishes. So the failure mode is **open**: a model
that omits the field, or that labels a credential leak `low`, gets published to a public tracker.

**Verified.** Two findings sent to the GitHub sink — one with the `severity` key deleted entirely,
one a serious issue labelled `low`:

```
$ … --agent secret-scan --sink github-issues
PUBLISHED PUBLICLY: [factory:secret-scan] PROBE finding with NO severity field
PUBLISHED PUBLICLY: [factory:secret-scan] PROBE critical bug mislabelled low by model
```

No `[SECURITY GUARD]` line. Both reached the tracker.

This is the clearest violation of non-negotiable #2 in the repository. The containment boundary for
public disclosure *is* a model's self-report, with a default that leans toward publishing. It is
also the exact failure THREAT_MODEL.md §4 warns about — *"Model responses are untrusted and must be
robustly parsed and structured before execution"* — applied to a field with security consequences.

**Fix.** Three things, cheapest first:
1. Default absent severity to `critical`, not `medium`. Fail closed.
2. Reject findings whose `severity` is not in the enum, rather than passing the string through.
3. Do not let the model's severity alone authorise publication. Any finding from a
   credential-class agent (`secret-scan`, `vuln-*`) should be embargoed from public sinks on the
   *agent's* identity — a deterministic fact — regardless of what the model called it.

---

## SF-04 — No environment scrubbing; adapters inherit everything (Medium)

Non-negotiable #4: *"No credentials in an agent's environment. No `~/.aws`, `~/.ssh`, `.env`."*

Every `subprocess.run` in `factory` and `lib/` is called without `env=`, so the child inherits the
parent's entire environment:

```
$ grep -rn "env=" --include=*.py factory lib/
(no output)
```

The one exception is the fix landed in PR #1, which unsets two variables in `claude.sh` — and, as
recorded in `agents-e3u`, four other precedence-affecting variables survive into the child. There is
no allowlist anywhere; the model process sees whatever the operator's shell had, including cloud
credentials and unrelated project tokens.

The CI plane makes this concrete. `.github/actions/factory/action.yml` puts both a GitHub token and
a model key into the environment of the step that runs the dispatcher:

```yaml
env:
  GH_TOKEN: ${{ inputs.github_token }}
  GITHUB_TOKEN: ${{ inputs.github_token }}
  GEMINI_API_KEY: ${{ inputs.model_api_key }}
  ANTHROPIC_API_KEY: ${{ inputs.model_api_key }}
```

Those are inherited all the way down into the engine process that is reading untrusted target code.

**Fix.** Build the child environment explicitly from an allowlist (`PATH`, `HOME`, `LANG`, plus the
one credential that engine needs) instead of subtracting from the inherited one. Subtraction can
never be complete; addition can.

---

## SF-05 — `shell=True` on an operator-supplied string (Medium)

```python
# lib/bench/runner.py:126
res = subprocess.run(bench_cmd, shell=True, cwd=str(target_dir), capture_output=True, text=True)
```

`bench_cmd` reaches this only from `--bench-cmd` on `runner.py`'s own CLI (`runner.py:190`). The
`factory hillclimb` path calls `measure_target(target_dir)` with no command, so **today this is
operator-supplied, not target-supplied**, which is why it is Medium and not High.

It is still the wrong shape in the one place that already edits files and re-measures them. If a
future change sources a benchmark command from a target's config or a model's proposal — an
obvious next step for a Class C optimizer — this becomes arbitrary command execution from untrusted
input, with no further code change required to make it dangerous.

**Fix.** Take a list, drop `shell=True`, and add a timeout.

---

## SF-06 — No timeouts on the dispatcher's subprocess calls (Medium)

Two of the fourteen `subprocess.run` calls in `factory` and `lib/` pass `timeout=` (both added
recently, in `lib/findings.py`). None of the dispatcher's own calls do:

```
factory:227   pre-pass scanner          — no timeout
factory:267   engine adapter            — no timeout
factory:308   findings store            — no timeout
factory:481   git worktree add          — no timeout
factory:534   git worktree remove       — no timeout
lib/scheduler.py:183,239,241,255,264    — no timeout
```

`agent.yaml` declares `budget.max_minutes` for every agent; nothing enforces it (SF-02). The
consequence is concrete for scheduled runs: a hung engine holds the slot indefinitely, and the
launchd job never completes. This is exactly what PR #1's audit observed when a stale key made
`claude` hang — the run had to be killed externally at 150s because nothing in the factory would
have stopped it.

**Fix.** Pass `timeout=` derived from `budget.max_minutes`, and treat expiry as a station failure.

---

## SF-07 — The output contract is never enforced (Medium)

Every agent ships a `report.schema.json` and every `agent.yaml` names it under `output.schema`.
Nothing loads it:

```
$ grep -rn "report.schema.json\|jsonschema\|validate" --include=*.py factory lib/
(no output)
```

The only code that mentions the file is `agents/qa-station/scripts/audit_factory_quality.py`, which
checks that the file **exists**. Model output goes through `extract_json_from_output` — three
increasingly loose attempts ending in "take everything between the first `{` and the last `}`" —
straight into the findings store.

This is what lets SF-03 happen: an unvalidated `severity`, or its absence, flows to a security
decision. It is also a quiet correctness risk, since a malformed report yields findings with
`None` fields that are then formatted into reports and issue bodies.

**Fix.** Validate against the declared schema before the store sees the data; treat a schema
failure the same way the dispatcher already treats unparseable output — skip the store update
rather than write a half-formed record.

---

## SF-08 — Discovery and verification share the findings store (Medium)

Non-negotiable #3 requires *"different processes, zero shared session state, context, or
conversation history."* The process separation is real and correct — `vuln-discovery` and
`vuln-verify` are separate `agent.yaml`s, separate runs, separate engine invocations. No complaint
there.

But `vuln-verify`'s deterministic pre-pass reads the shared store, and failing that, reads
discovery's own run directories:

```python
# agents/vuln-verify/scripts/prepare_verification.py
store_path = FACTORY_ROOT / "findings" / f"{target_name}.json"          # :24
pattern = re.compile(rf"^(?:vuln-discovery|threat-model)-{…}-\d{{8}}-\d{{6}}$")   # :43
```

That is by design — a verifier needs candidates to verify. The problem is that the store record
carries discovery's `title`, `description` and `severity`, so the verifier is primed with
discovery's *conclusions*, not just its *locations*. The skill file is strongly worded in the right
direction (*"ASSUME EVERY CANDIDATE FINDING IS A FALSE POSITIVE"*), but a prompt is the weakest
available control, and PLAN §5 is explicit that combining the two roles loses true positives.

There is also a plane-level wrinkle: `run_line` passes one `engine_arg` to every station
(`factory:344`), so in a `project-audit` line, discovery and verification run on the **same model
family** by default. Clean session isolation is preserved; family diversity is not.

**Fix.** Pass the verifier locations and raw snippets only — strip `title`, `description`,
`severity`, `remediation` before handing candidates over. Optionally let a line pin a different
engine per station.

---

## SF-09 — `visibility:` is declared on every target and read by nothing (Medium)

All five target manifests declare `visibility: public`. No code reads the key:

```
$ grep -rn "visibility" --include=*.py factory lib/
(no output)
```

The disclosure guard is therefore severity-only. A private target gets the same embargo as a public
one (harmless, if noisy), and — combined with SF-01 — a public target routed to beads gets no
embargo at all. The manifests look as though they carry a policy signal; they do not.

**Fix.** Read it, and make it the primary input to the guard: `visibility: public` should tighten
what may be dispatched, independently of severity.

---

## SF-10 — The CI action clones unpinned `main` into a credentialed step (Medium)

```yaml
# .github/actions/factory/action.yml:54
git clone --depth 1 https://github.com/paulkinlan/agents.git "$RUNNER_TEMP/software-factory"
```

Whatever is on `main` at run time is fetched and executed (`:79`) in a step that holds `GH_TOKEN`
and a model key. `AGENTS.md` opens by calling this repository *"the highest-privilege component in
the system… a compromise here is a supply-chain compromise of every target it touches"* — and this
is the line that makes that literally true for every consumer of the action.

No active workflow directory exists under `.github` on this tree, so nothing runs this today;
`docs/ci-workflow.yml` is a template, not an active workflow. That is why it is Medium.

> [!IMPORTANT]
> **This mitigation expires when PR #2 lands.** That PR moves the template into an active workflow
> path, which makes the composite action live. SF-10 should be re-rated at that point, and
> `agents-8vr` — filed during the PR #2 review, for the same activation printing `secret-scan`
> output into public CI logs — is the immediate consequence.

**Fix.** Pin the clone to a tag or commit SHA, and split the "fetch the factory" step from the
"run with credentials" step so the token is not present while third-party code is being fetched.

---

## SF-11 — Prompt text exposed via `argv` and a world-readable `prompt.txt` (Medium)

Carried forward from PR #1's audit (F6), re-confirmed here: `factory:266` passes the full prompt —
which contains scanner excerpts from the target, up to 50 candidate records (`factory:256`) — as a
command-line argument, visible to any local user via `ps`. For `secret-scan` those excerpts are
matched credential lines.

**Second exposure path, found while checking the first.** The same prompt is also written to disk at
`factory:264`:

```python
(run_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
```

with no mode argument, so it lands at the process umask. Verified on this host (`umask 0022`):

```
dir  mode: 0o755
file mode: 0o644
```

World-readable, and unlike the `argv` exposure it is **persistent** — the run-artifact directory is
gitignored but never cleaned, so every prompt ever sent accumulates on disk readable by any local
user. That makes the disk path the more durable of the two.

**Fix.** Pass the prompt on stdin, and create `run_dir` `0700` with `prompt.txt` `0600` so the
retained copy is not world-readable.

---

## SF-12 — The committed suppressions file is never read (Medium)

`AGENTS.md` states the noise-control contract plainly: *"`wontfix` requires a written reason in a
committed suppressions file."* No path currently satisfies that sentence.

**Wrong file.** The store builds its suppressions path in `lib/findings.py` (line 45) by
interpolating the target name into a per-target JSON filename under the findings directory. The
repository commits `findings/suppressions.yaml`. Different name, different extension, different
per-target scoping — the committed file is read by nothing.

**Wrong format.** `_load_suppressions` calls `json.loads` (`lib/findings.py`, line 60). The
committed file is YAML with comments. Even with a matching name it would raise, and the `except`
swallows that to a warning and returns `{}` — so a malformed or misnamed suppressions file **fails
silently open**, suppressing nothing.

**The working path cannot be committed.** `.gitignore:6` is `findings/*` with allowlist exceptions
only for `.gitkeep` and `suppressions.yaml`. The single file the code honours is gitignored.

**Verified** with a probe finding (fingerprint `da9a0757dc96c26a…`), both halves run through the real
store:

```
A: suppression appended to the committed YAML register
   -> Delta: 1 new, 0 suppressed        # ignored

B: same suppression written to the per-target JSON path the store computes
   -> Delta: 0 new, 1 suppressed        # honoured
   -> git check-ignore: that file IS ignored
```

So an operator either edits the committed file and silently gets no suppression, or edits the
effective file and cannot commit it. Either way every `wontfix` is invisible to review and recurring
runs re-report suppressed findings forever — precisely the noise-control failure the fingerprint
design exists to prevent.

One further consequence worth noting: `agents/qa-station/scripts/audit_factory_quality.py` reads
`findings/suppressions.yaml` to compute per-agent `wontfix` rates. The QA meta-agent is therefore
measuring a file that has no effect on behaviour.

**Fix.** Pick one path and make it consistent — cheapest is to have `_load_suppressions` read the
already-allowlisted `findings/suppressions.yaml` and parse it as YAML. Separately, make a parse
failure loud rather than an empty dict; a suppressions file that silently becomes `{}` is worse than
one that refuses to load.

*Found while checking whether this report itself introduced scanner noise — see below.*

---

## What is working

Worth recording, so a later reader does not assume everything is broken:

- **Deterministic-first is real.** Every agent with a pre-pass runs the scanner before the model,
  and the model's job is triage. `short_circuit_empty` skips inference entirely on a clean scan.
- **Rule 8 is honoured.** The pre-commit hook installed by `factory hook install` is pure Python
  regex with no model call. PR #1 removed the last model call from an auth path.
- **Fingerprints are line-number independent** and verified as such by tests — the noise-control
  design in `AGENTS.md` is implemented, not just documented.
- **The findings store fails safe on unparseable model output** (`factory:275-283`): it skips the
  store update rather than recording everything as `fixed`. That is a thoughtful failure mode.
- **Scanners exclude their own output** (`findings`, `runs` in `IGNORE_DIRS`), closing the feedback
  loop THREAT_MODEL.md §5 warns about.
- **The GitHub sink's embargo works** when severity is accurate — the guard fires and the finding
  is held. The defect in SF-01/SF-03 is coverage and input trust, not the guard's own logic.
- **PR #1's fail-closed fix is genuine.** The `antigravity` adapter no longer fabricates clean
  scans; independently confirmed against `main` before and after.

---

## Self-contamination check

THREAT_MODEL.md §5 records that scanners reading their own output create false-positive feedback
loops. `reports/` is **not** in `IGNORE_DIRS` for either scanner and is not gitignored, so this
document is inside the scan scope of the very agents it describes. Both were checked.

**`secret-scan` — clean throughout.** Every identifier above is written to avoid matching its
patterns, verified before and after each edit:

```
$ python3 agents/secret-scan/scripts/scan.py --target .
scanner: builtin-regex candidates: 0
```

**`docs-drift` — this document failed its own standard twice before passing.** `check_docs.py`
resolves backticked paths as file references and reports the unresolvable ones as drift.

Round one, the original draft:

```
94 candidates on main  ->  97 with this report   (3 new, all from reports/)
   doc-missing-file  lib/findings.py:256     # a file:line citation, not a path
   doc-missing-file  .github/workflows/      # true when written; false once PR #2 lands
   doc-missing-file  runs/                   # gitignored by design, absent on a clean tree
```

Round two — the SF-12 section written to document this very problem reintroduced it, citing the
suppressions filename and two more `file.py:line` references, for 97 again. Rewritten a second time
to describe those paths in prose.

```
final:  94 candidates   (0 from reports/)   — exactly the main baseline
        secret-scan: 0 candidates
```

Recorded rather than quietly fixed, because the sequence is the point. An audit that adds false
findings to the tracker it is auditing has failed the standard it holds others to — and the section
about that failure failed the same way on its first draft. The rule is cheap to state and easy to
violate: **in a document that lives inside the scan scope, describe paths, do not cite them.**

It is also how SF-12 surfaced. Checking whether this noise could legitimately be suppressed revealed
that the suppressions mechanism does not work at all.

If a future edit to this file trips either scanner, that is a bug in the file, not a finding.

---

## Not covered

- **`antigravity` end-to-end.** `agentapi` is not installed on this host. Inherited from PR #1 as
  an open question, unchanged.
- **The 22 `SKILL.md` files were not reviewed for prompt-injection resistance.** I checked them
  only for engine-specific leakage (one cosmetic hit in `docs-drift`, quoting a path inside an
  example finding). A skill-level review is a separate job.
- **Live behaviour of the target repositories.** `~/Code/chrome-agent-platform` and `~/Code/voicebox`
  do not exist on this host, so their sink configuration could not be checked against reality.
- **Impact confirmation for `agents-e3u`.** That the four unscrubbed variables actually divert a
  session run is inferred from documented precedence, not tested against the real binary. Recorded
  as unverified in the bead.

---

## Beads filed

All twelve findings are filed in this repository's beads database, each carrying its reproduction
commands and its verified/not-verified boundary.

| Bead | Finding | Priority |
|---|---|---|
| `agents-681` | SF-01 — beads sink has no severity guard | **P1** |
| `agents-94f` | SF-03 — disclosure guard fails open on model-supplied severity | **P1** |
| `agents-pnu` | SF-02 — containment/capabilities/budget decorative | **P1** |
| `agents-rvz` | SF-04 — no environment scrubbing | P2 |
| `agents-ywe` | SF-05 — `shell=True` in bench path | P2 |
| `agents-76b` | SF-06 — no subprocess timeouts | P2 |
| `agents-1r5` | SF-07 — schema never validated | P2 |
| `agents-pr7` | SF-08 — verifier primed with discovery's conclusions | P2 |
| `agents-5rx` | SF-09 — `visibility:` never read | P2 |
| `agents-cfx` | SF-10 — unpinned clone in credentialed CI step | P2 |
| `agents-411` | SF-12 — committed suppressions file never read | P2 |
| `agents-pgr` | SF-11 — prompt in `argv` + world-readable `prompt.txt` | P3 |

Existing related beads from the PR #1 review: `agents-e3u` (P2), `agents-p2c` (P2), `agents-d06`
(P3), `agents-u5x` (P3). Note `agents-rvz` (SF-04) subsumes `agents-e3u` — an allowlisted child
environment makes the partial-scrub question moot.

### Suggested order of work

`agents-681` + `agents-94f` together are one afternoon and close the entire disclosure hole: one
shared embargo function, called by every sink, defaulting closed, keyed on the *agent's* identity
rather than the model's self-report. `agents-5rx` folds into the same change by making
`visibility:` that function's primary input.

`agents-pnu` is the larger piece of work and the one worth deciding deliberately — enforcing
containment is a real project, whereas changing the banner to stop claiming enforcement is a
one-line honesty fix that should land immediately either way.
