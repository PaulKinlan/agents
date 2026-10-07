# THREAT MODEL: The Software Factory (agents)

This threat model defines the trust boundaries, actors, assets, and security invariants for the **Software Factory** (the `agents` repository) itself, as well as the agents and orchestrators executing within it. 

---

## 1. System Overview & Architecture

The Software Factory is a security-sensitive orchestration layer designed to execute SDLC agents locally (using the developer's active session authentication) and in CI pipelines (using short-lived repository tokens). It consists of:
- **The `factory` CLI**: A central Python command dispatcher that resolves targets, runs deterministic pre-scanners, and coordinates engine execution.
- **Deterministic Pre-Pass Scanners**: Lightweight Python scripts (e.g. `agents/secret-scan/scripts/scan.py` and `agents/threat-model/scripts/mine_history.py`) that pre-scan directories to build high-recall datasets.
- **Engine Adapters**: Bash scripts (`lib/adapters/`) that invoke underlying AI tools (`pi`, `claude`, `antigravity`) non-interactively using host sessions.
- **Findings Store & Sinks**: A Python module (`lib/findings.py`) that manages finding identities, runs state-machine transitions, deduplicates issues, and dispatches them to sinks (local files, beads, or GitHub issues).

---

## 2. Trust Boundaries & Actors

```
                      [ Host Developer Machine ] (TRUSTED)
                     +-------------------------------------+
                     |  • Developer Credentials            |
                     |  • factory CLI / local schedules    |
                     +-------------------------------------+
                                       | (Executes via Bash)
                                       v
                     +-------------------------------------+
                     |  Engine Adapters (claude.sh, pi.sh) |
                     +-------------------------------------+
                                       | (Executes model in target CWD)
                                       v
[ Untrusted Target Repo ]            [ LLM Runtime Engine ] (PARTIALLY TRUSTED)
+-----------------------+            +----------------------------------------+
| • Source files        | <--------> | • Interprets prompts & source text      |
| • Scanned components  |  (Reads)   | • Executes custom tools (if enabled)   |
+-----------------------+            +----------------------------------------+
```

### Actors:
- **System Owner / Developer (Host)**: High-privilege actor who maintains the machine, runs schedules, and has access to active API keys and OAuth sessions. Highly trusted.
- **Target Repository (Audited Code)**: The codebase being analyzed. Untrusted, especially in public or collaborative settings. May contain malicious files, dependencies, or malicious prompt engineering designed to hijack agents.
- **Agent Engine Runtime (`pi` / `claude` / `antigravity`)**: Evaluates the codebase and runs the skill. Partially trusted, but stochastic and susceptible to prompt injection.
- **External Attacker**: An adversary who can submit code (PRs, issues) to target repositories, aiming to compromise the host machine or trigger unauthorized findings leakages.

### Key Boundaries:
1. **Host OS vs. Untrusted Target Code**: The critical boundary separating the developer's private assets (SSH keys, session tokens, AWS credentials) from code running or analyzed in the target directory.
2. **Inference / Prompt Boundary**: The interface between raw text gathered by deterministic scanners and the LLM engine, which could be subverted via semantic prompt injection.
3. **Public Disclosure / Sink Boundary**: The line separating private internal logs from public-facing trackers (like GitHub Issues).

---

## 3. Explicitly Trusted (Non-Threats)

To prevent model hallucination and alert fatigue, the following components are defined as **explicitly trusted**:
- **Local User Configuration**: Files under `targets/*.yaml` and macOS `schedules/*.plist` are under the developer's direct control and are trusted.
- **Mock Secrets in Test Directories / Findings Store**: Mock tokens (e.g. mock AWS keys `AKIA...` or GitHub PAs `ghp_...` used for redaction tests) are explicit non-vulnerabilities. 
- **Local Loopback Communication**: Any traffic strictly bound to `127.0.0.1`.
- **Local Git History**: The integrity of local `.git` metadata for target repositories is assumed authentic.

---

## 4. Untrusted Attack Surfaces

- **Target Codebase Content**: Any scanned file may contain code designed to exploit pre-pass scripts or prompt text designed to hijack the LLM runtime.
- **Model Responses**: Raw model output is untrusted and must be robustly parsed and structured before execution.
- **Scanner Pre-Pass Inputs**: File names and relative paths scanned by Python scripts are untrusted and must be sanitized to prevent path traversal or shell injection in downstream processors.

---

## 5. Bug-Shape Hints from History

- **Contamination of Scanned Scope (Feedback Loops)**: Historical fix `6c7fde4f95` indicates that deterministic scanners must strictly exclude their own output directories (`findings/`, `runs/`). Otherwise, they scan past findings, creating a cyclic feedback loop of false positive results.
- **Unembargoed Public Disclosures**: Highly sensitive credentials or zero-day vulnerabilities must never be pushed to public trackers. Sinks must explicitly filter out critical/high findings from public channels.
- **Credential Redaction at the Publish Boundary**: A finding's `snippet` is whatever the scanner matched, which for `secret-scan` is the credential itself. Every published render (delta report, step summary, tracker sink, scanner stdout) is masked by `lib/redaction.py`; raw values stay only in the gitignored run artifacts and findings store, because a human needs to see what leaked in order to rotate it. Masking is structural, never a prompt instruction — see non-negotiable #2.
- **Stochastic Drift**: Unchanged target files may occasionally trigger new model findings due to LLM non-determinism. This is normal and must be handled gracefully by the findings store using stable fingerprints.

---

## 6. Security Invariants for Auditors

Discovery and verification agents must check for and respect the following invariants:
1. **Isolate Execution Context (Containment)**: `lib/containment.py` reads each agent's `containment`, `capabilities` and `budget`, and fails closed.
   - **Refusals.** Any of these refuses the run: an unknown tier, capability or budget key; a non-boolean capability; a malformed budget; a capability above its tier's ceiling; or a `requires` entry that brings the pre-pass a network credential (`gh`) without `capabilities.network`. `t3-sandbox` is refused because no sandbox runner exists.
   - **The grant.** The tier is a ceiling on what an agent may declare, not a grant. A model session gets the `read-only` tool policy — no write, shell, network, browser or MCP tools — **except** that a *proposer* declaring `write` within a tier that allows it (`t2-local`) is granted `worktree-write` (agents-6ce): the engine runs in a disposable detached git worktree of the target's HEAD, placed under the run directory the OS sandbox already binds read-write, so the model can edit files but only there. The target checkout stays read-only and is never modified, and the staged session diff collected as `run_dir/session.patch` *is* the proposal; the worktree is always discarded afterwards. Because the worktree's `.git` marker file lives
     inside the writable run directory, a write-enabled model could rewrite it (e.g. to
     `gitdir: <target>/.git`) to try to redirect the host-side diff collection at the operator's
     real repo and index. The dispatcher defeats this: it captures the worktree's admin gitdir at
     creation, refuses collection when the marker no longer matches it, and pins every host-side
     git call with `--git-dir`/`--work-tree`, so a rewritten marker cannot stage the operator's
     work (review P1-1, agents-6ce). An *optimizer* (perf-hillclimb) is excepted — it returns structured steps its driver (`run_hillclimb`) applies in its own measure-change-remeasure worktree, so its model session stays read-only. A target that is not a git repository downgrades the grant to `read-only` and re-withholds `write` with that specific reason, so the banner and `policy.json` stay honest. Each engine adapter enforces the granted policy with the engine's own flags (pi adds `edit,write`; claude adds `Edit,Write` under `--restricted`, which still confines the file tools to the working directory), and an adapter that cannot enforce it (deepseek, antigravity) refuses.
   - **The dispatcher.** It sets the policy itself, never from the caller's environment, and records it in the run's `policy.json`.
   - **The OS sandbox (agents-9n7).** On Linux hosts with bubblewrap, the engine session and the deterministic pre-pass run inside `lib/sandbox.py`'s bwrap wrapper: the target is bound read-only, the run directory is writable, the factory root is read-only with other runs masked, and everything else — including all of `$HOME` (`~/.pi/auth.json`, `~/.ssh`, `~/.aws`, …) — is invisible. Engine auth crosses the boundary only as the `lib/child_env.py` environment allowlist. A private PID namespace keeps host processes and their environs out of reach. The banner and `policy.json` state exactly what was enforced; on hosts without a sandbox they keep saying NOT confined.
   - **No arbitrary PATH directories (review P1).** The child's executables are bound by *name* from a narrow allowlist (`lib/sandbox.py` `ENGINE_EXECUTABLES` / `PREPASS_EXECUTABLES` plus the agent's `requires`), resolved across PATH and bound only as their own install tree or launch path — never as whole directories. A directory an operator happens to leave on PATH therefore cannot smuggle a canary or credential file into the engine's read scope; a tool that is not allowlisted simply fails to resolve, which fails the scan loudly rather than widening the sandbox.
   - **Fail closed when the sandbox cannot run (review P0).** For an engine whose read scope is confined *only* by the OS sandbox (`SANDBOXED_ENGINES` — pi's read tool is not path-confined by its own flags), a host where bubblewrap cannot run **refuses the run** before any run directory exists, rather than silently falling back to an unsandboxed session that could read any file the operator can. The single explicit exception is `FACTORY_ALLOW_UNSANDBOXED=1`, the trusted-target mode below; it runs unsandboxed and the banner and `policy.json` then say NOT confined.
   - **Not enforced yet.** Network egress is not filtered (the engine reaches the model API over the operator's network), and the engine's own `/proc/self/environ` is readable by its own read tool — bun/pi needs a real procfs — so the engine's API keys are in reach of a prompt-injected session; published output is redacted (`lib/redaction.py`) and a credential-broker proxy is the follow-up. Declared `network` and `browser` stay withheld until an egress allowlist and a localhost-only browser exist (`write` is now granted via the disposable worktree, agents-6ce).
   - **Tests.** `tests/test_containment.py` asserts the validation, the adapter flags, the dispatcher's refusals, and — end to end against a stub engine inside the real sandbox — that a canary outside the target is unreadable, that a pi run is *refused* when bubblewrap cannot run, and that the only unsandboxed path is the explicit opt-in. It also asserts that a granted `write` runs in a disposable worktree — the engine's edits are collected as `session.patch`, the worktree is discarded, and the target's `git status` stays clean, both unsandboxed and inside the enforced sandbox — and that a non-git target downgrades to read-only, and that a rewritten worktree `.git` marker is refused without staging the operator's index (review P1-1). `tests/test_sandbox.py` asserts the bwrap argv shape, that only allowlisted executables are bound (never whole PATH directories), and the live confinement probes.
2. **Sanitize Fingerprints**: The findings store must normalize path structures and text sequences to prevent directory traversals when storing reports.
3. **Strict Embargo Checks**: High/critical findings must bypass public trackers and be written to private local stores or draft security advisories.
4. **No Ambient Credentials**: Environment variables like `~/.aws/` or `~/.ssh/` must never be mounted inside any execution container or active agent session.
5. **Published Findings Are Redacted**: Any change to `lib/findings.py`, the sink adapters, `agents/secret-scan/scripts/scan.py`, or the composite action must keep the redaction boundary intact. A credential finding (by agent or by rule id) publishes **scanner-controlled facts only** — rule, location, severity, fingerprint — because prose cannot be checked for an echo of a value whose shape is unknown; its model-written title, description and remediation, plus the matched value, stay in the local run artifact. Every published surface counts, including log lines such as `Created bead for: …` and the security guard's own message. Identity fields are **not** trusted: `agent`, `rule_id` and `path` arrive as model-returned strings, so they are masked like any other text and then shape-checked — a long opaque run in a rule id or a path segment makes the field fall back to a placeholder rather than publishing it. Whole-block patterns (PEM) must run before header-only patterns, or the header is replaced first and the body escapes. `tests/test_redaction.py` asserts the value cannot reach a report, a tracker field (title or body), a log line, a rule/path field, or stdout.

---

## 7. Explicit Exclusions (Wontfix / Accepted Risks)

- **Unsandboxed Local Development**: Running local plane tools *directly* (outside `factory run`) on the developer's host machine is accepted for personal convenience, provided that the target repositories are trusted. Through the factory CLI on Linux, the engine and pre-pass run inside the bubblewrap sandbox (agents-9n7). For an engine confined only by that sandbox (pi), a host where bubblewrap cannot run **refuses** the run rather than degrading silently; the explicit `FACTORY_ALLOW_UNSANDBOXED=1` is the one unsandboxed path, is meant only for a **trusted target**, and makes every run banner and `policy.json` say NOT confined. Containerization or sandboxing (gVisor) is still required when *executing* untrusted code (t3 PoC verification).
- **Deterministic Scanners False Positives**: Naive regex matches (such as regexes matching other regex patterns) are accepted as low-priority/info findings and must be filtered at the model-triage stage.