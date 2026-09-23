# Targets

One file per project the factory runs against. Declares which agents apply, where findings go,
and any target-specific scoping.

See [../docs/PLAN.md](../docs/PLAN.md) §6 (pilots) and §12 (self-hosting).

| Target | Sink | Role |
|---|---|---|
| `fauxmium.yaml` | `github-issues` | Walking skeleton — small, dormant, cheap to eyeball |
| `chrome-agent-platform.yaml` | `beads` | Scale — partitioning, dedupe, existing-harness triage |
| `agents.yaml` | `file` | Self-hosting — supply chain, workflow security, docs drift |
