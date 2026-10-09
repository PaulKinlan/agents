# The Software Factory — conventions

A fleet of SDLC agents that run locally (`antigravity` / `claude` / `pi`, session auth) and in
GitHub Actions (API keys). See [docs/PLAN.md](docs/PLAN.md) for the full design and rationale.
For automated or manual setup in target repositories (GitHub Actions, pre-commit hooks, local
targets, or agent skills), see [docs/INTEGRATION.md](docs/INTEGRATION.md).

> [!IMPORTANT]
> **This repo is the highest-privilege component in the system.** It holds model API keys and
> GitHub tokens, runs unattended on a schedule, and has write access to other repositories.
> A compromise here is a supply-chain compromise of every target it touches. Treat changes to
> `lib/adapters/`, `.github/`, and any agent with `write: true` as security-sensitive.

## Non-negotiables

1. **Deterministic-first.** Agents shell out to real tools (`semgrep`, `gitleaks`, Lighthouse,
   existing project harnesses) and use the model for *triage, synthesis, and judgement*. Never ask
   a model to do work a scanner does better.
2. **Never use a model as a containment boundary.** Scope is enforced by the network layer, the
   filesystem, and the container — not by prompt text and not by a reviewing model. See PLAN §5.
3. **Discovery and verification are separate agents.** Different processes, zero shared session
   state, context, or conversation history. Discovery optimises recall; verification optimises
   precision and is prompted to *disprove*. Different model families are supported where helpful,
   but clean session isolation is the hard requirement. Combining them loses true positives.
4. **No credentials in an agent's environment.** No `~/.aws`, `~/.ssh`, `.env`. Short-lived scoped
   tokens only, injected by the runner.
5. **Findings go to the target's own tracker.** Never create a parallel one. See "Sinks" below.
6. **Propose, don't apply.** Agents open PRs and file findings; they never push to a default
   branch. The human merge is the control point.
7. **The factory takes toil, not thinking.** If an agent is making a genuine design decision, it
   should be producing a proposal, not a commit.
8. **No model calls in a blocking trigger.** Anything a human waits on — pre-commit, pre-push, a
   required status check — runs deterministic tools only, with a sub-five-second budget. A hook
   people bypass protects nothing. Model work goes async. See PLAN §13.

## Anatomy of an agent

```text
agents/<name>/
├── agent.yaml          # class, plane, containment, capabilities, schedule, budget
├── SKILL.md            # portable behaviour — must run on all three engines
├── scripts/            # deterministic pre-pass
└── report.schema.json  # output contract
```

`SKILL.md` must contain **no engine-specific logic**. Anything engine-specific belongs in
`lib/adapters/`.

### Required `agent.yaml` fields

| Field | Values |
|---|---|
| `class` | `observer` (read→report) · `proposer` (read→PR) · `optimizer` (measure→change→re-measure) |
| `plane` | `local` · `ci` · `both` |
| `containment` | `t0-readonly` · `t1-fetch` · `t2-local` · `t3-sandbox` |
| `triggers` | `schedule` · `manual` · `git-hook` · `repo-event` · `webhook` · `agent` |
| `blocking` | `true` only if deterministic and sub-5s (see rule 8) |

Default to `t0-readonly`. The tier is a ceiling on what an agent may declare, and
`lib/containment.py` refuses a run whose `capabilities` exceed it (THREAT_MODEL.md §6.1).

The tier is not a grant. A model session runs with the `read-only` tool policy — **except** that
a *proposer* declaring `write` within a tier that allows it (`t2-local`) is granted `worktree-write`
(agents-6ce): the engine edits files inside a disposable git worktree of the target, placed under
the read-write run directory, so the target checkout stays read-only and the collected session
diff (`run_dir/session.patch`) *is* the proposal; the worktree is discarded afterwards. The grant
also requires an **OS-sandboxed engine** (review P1-2, agents-6ce): only `pi` under a working
bubblewrap qualifies, because the worktree is safe only while the target itself is kernel-confined
read-only. A non-git target, or an engine that cannot be OS-sandbox-verified (`claude`, which
relies on `--restricted` rather than a kernel boundary), downgrades to `read-only`. An *optimizer*
(perf-hillclimb) stays read-only — it
returns structured steps its driver applies in its own worktree. Declared `network` is now
granted when the run's egress is actually filtered (agents-2x6: `--unshare-net` plus the
per-run egress-allowlist proxy, derived from the agent's own `requires`); when it is not — no
OS sandbox, or a model provider the credential broker cannot cover — it is honestly
re-withheld for that run. `browser` stays withheld until a localhost-only browser exists.

On Linux hosts with bubblewrap, the engine session and the pre-pass additionally run inside an
OS sandbox (`lib/sandbox.py`, agents-9n7): the target read-only, the factory repo and system dirs read-only,
`$HOME` hidden (auth via env only). The child's executables are bound by *name* from a narrow allowlist, never as
whole PATH directories, so an unrelated directory on PATH cannot leak into the read scope.
For an engine confined only by this sandbox (pi), a host where bubblewrap cannot run **refuses**
the run rather than degrading silently; `FACTORY_ALLOW_UNSANDBOXED=1` is the one explicit
unsandboxed path, and since agents-bp0 it is an attestation rather than a switch: it unlocks
only for a target whose own manifest declares `trusted: true` with `visibility: private`
(`targets/<name>.yaml`) — public/unknown-visibility targets and raw `--target` paths always
refuse, so nothing that can merely set an environment variable can widen the read scope. The
banner and `policy.json` say which boundary was actually up, and report NOT enforced with the
opt-in and trusted target named when it was not. A sandboxed engine's model API key
crosses the boundary through a localhost credential broker (agents-8h4), not as an env var: the
engine gets a non-secret placeholder plus the broker URL and the dispatcher injects the real key
host-side when it forwards the request, so a prompt-injected session cannot read the key from the
engine's own `/proc/self/environ` (`lib/credential_broker.py`).

`t3-sandbox` needs a gVisor-class runner and manual approval per run for *executing* untrusted
code. Neither exists, so it is refused; the bubblewrap wrapper is a filesystem/credential
boundary for read-only sessions, not that runner.

## Sinks

A committed `targets/<name>.yaml` sink takes precedence over general task-tracker prose in
another repository's `AGENTS.md`. Findings dispatch to **`beads`** automatically (agents-eyo):
internal findings file directly into the target's configured `beads_path` without a public issue
or human triage gate, deduped by fingerprint (`external_ref: factory:<fingerprint>`). Public GitHub
issues are exclusively for public-input triage (`issue-triage` station); `--sink github-issues` is
rejected for findings. Without an explicit sink, repository guidance is consulted and
then `file` is the local fallback. After human triage applies the
`factory-approved` label to a public input issue, use
`factory promote --target NAME --issue URL` to create one linked bead in the target's
explicitly configured `beads_path`.

| Target | Sink | Notes |
|---|---|---|
| `agents`, `chrome-agent-platform`, `voicebox`, `aifocus` | `beads` | Findings file to beads automatically; public input is triaged via issue-triage. |
| `fauxmium` | `file` | No beads DB configured yet; local evidence only until its destination is declared. |
| *default* | `file` | Local JSON for targets without a configured beads DB. |

### Severity & Public Disclosure Rules

> [!IMPORTANT]
> Findings file to the target's Beads DB automatically without a public issue or human gate
> (agents-eyo). Public GitHub issues are exclusively for public-input triage. Missing/invalid
> target `visibility` withholds high/critical findings from the synced beads tracker (`embargo_reason`).
> `--sink github-issues` is rejected for findings. For public-input issues, once human triage
> applies `factory-approved`, `factory promote` creates the linked bead.

## Noise control

Recurring runs are worthless if they re-report the same things. Every finding carries a
fingerprint that **excludes line numbers**:

```
sha256(agent + rule_id + normalized_path + normalized_snippet)
```

Lifecycle: `new → accepted | wontfix → fixed → regressed`. `wontfix` requires a written reason in
a committed suppressions file.

> [!NOTE]
> Discovery is **stochastic**. A new finding on an unchanged file is normal, not a regression.
> Stop-condition is *net-new finding rate* falling below a threshold, never zero.

## Engines

| | invocation | skills | tool policy flags (factory runs) |
|---|---|---|---|
| `antigravity` | headless conversation API | plugin dir / symlink into the engine config dir | refused: agentapi has no tool controls |
| `claude` | `claude -p` | `--append-system-prompt-file` in factory runs, because the Skill tool is withheld; `factory skills install` links them into `~/.claude/skills` for interactive use | read-only: `--restricted --tools Read,Grep,Glob --strict-mcp-config`. A write declaration always downgrades to read-only at runtime (claude is not OS-sandbox-verified, so it never receives worktree-write; the adapter's Edit,Write arm exists but is never taken) |
| `pi` | `pi -p` | `--skill` | read-only: `--tools read,grep,find,ls --no-extensions --no-approve` · worktree-write adds `edit,write` (confined by the OS sandbox: the worktree is read-write, the target read-only) |

Install locally by symlinking this repo into the engine's plugin directory — the same pattern as
`web-resilience-plugin`.

## Self-hosting

This repo is itself a factory target. See PLAN §12 for what that does and does not prove.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
