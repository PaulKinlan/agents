# The Software Factory — conventions

A fleet of SDLC agents that run locally (`antigravity` / `claude` / `pi`, session auth) and in
GitHub Actions (API keys). See [docs/PLAN.md](docs/PLAN.md) for the full design and rationale.

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

Default to `t0-readonly`. Anything above `t2` requires manual approval per run.

## Sinks

Findings are written to whatever tracker the target already uses.
Discovery order for sink selection:
1. **Target repository guidance**: Check the target's `AGENTS.md` or repository rules first.
2. **Explicit target config**: Look up `targets/<name>.yaml`.
3. **Fallback / Interactive**: Ask the user or fall back to `file` (local JSON/markdown).

| Target | Sink | Notes |
|---|---|---|
| `chrome-agent-platform` | `beads` | **Hard rule in that repo's AGENTS.md**: `bd` is the only tracker. Raw findings → wisps; verified → `bd promote`; chains → `bd link --type discovered-from`. |
| `voicebox` | `beads` | **Mandated in `voicebox/AGENTS.md`**: Uses `bd` (beads) for task tracking; falls back to local `file` sink if `.beads` is not yet initialized. |
| `fauxmium` | `github-issues` | Label machine findings so they're filterable. |
| `aifocus` | `file` | Hugo + Cloudflare Workers blog/demos (`findings/aifocus-latest.md`). |
| *default* | `file` | Local JSON, for targets with no tracker. |

### Severity & Public Disclosure Rules

> [!CAUTION]
> **Never publish unembargoed high or critical security findings to a public tracker.**
> If the target repository is public:
> - High/critical findings must be routed to a private channel (draft GitHub Security Advisory, local private bead/file, or private review queue).
> - Public issue creation is restricted to non-sensitive findings (lint, docs drift, bundle metrics) or private repos.
> - When in doubt, hold findings locally in `file` sink and alert the operator.

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

| | invocation | skills |
|---|---|---|
| `antigravity` | headless conversation API | plugin dir / symlink into the engine config dir |
| `claude` | `claude -p` | `--plugin-dir` |
| `pi` | `pi -p` | `--skill` |

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
