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
1. **Isolate Execution Context (Containment)**: Agents running under `t0-readonly` must have zero filesystem write access, zero network access, and zero ambient shell command capabilities.
2. **Sanitize Fingerprints**: The findings store must normalize path structures and text sequences to prevent directory traversals when storing reports.
3. **Strict Embargo Checks**: High/critical findings must bypass public trackers and be written to private local stores or draft security advisories.
4. **No Ambient Credentials**: Environment variables like `~/.aws/` or `~/.ssh/` must never be mounted inside any execution container or active agent session.
5. **Published Findings Are Redacted**: Any change to `lib/findings.py`, the sink adapters, `agents/secret-scan/scripts/scan.py`, or the composite action must keep the redaction boundary intact. A credential finding (by agent or by rule id) publishes **scanner-controlled facts only** — rule, location, severity, fingerprint — because prose cannot be checked for an echo of a value whose shape is unknown; its model-written title, description and remediation, plus the matched value, stay in the local run artifact. Every published surface counts, including log lines such as `Created bead for: …` and the security guard's own message. `tests/test_redaction.py` asserts the value cannot reach a report, a tracker field (title or body), a log line, or stdout.

---

## 7. Explicit Exclusions (Wontfix / Accepted Risks)

- **Unsandboxed Local Development**: Running local plane tools directly on the developer's host machine is accepted for personal convenience, provided that the target repositories are trusted. Containerization or sandboxing (gVisor) is required when scanning public or untrusted codebases.
- **Deterministic Scanners False Positives**: Naive regex matches (such as regexes matching other regex patterns) are accepted as low-priority/info findings and must be filtered at the model-triage stage.