# Targets

One file per project the factory runs against. Declares which agents apply, where findings go,
and any target-specific scoping.

Each manifest declares `visibility: public | private`. The dispatcher reads it and passes it to
the publication embargo: only a target that explicitly declares `private` may dispatch the
high/critical bands to its own tracker, because a private tracker is not a public disclosure. A
missing or unrecognised value is treated as public, and the run banner prints the effective
value.

See [../docs/PLAN.md](../docs/PLAN.md) §6 (pilots) and §12 (self-hosting).

| Target | Sink | Role |
|---|---|---|
| `fauxmium.yaml` | `github-issues` | Walking skeleton — small, dormant, cheap to eyeball |
| `chrome-agent-platform.yaml` | `beads` | Scale — partitioning, dedupe, existing-harness triage |
| `agents.yaml` | `file` | Self-hosting — supply chain, workflow security, docs drift |
