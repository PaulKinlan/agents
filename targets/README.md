# Targets

One file per project the factory runs against. Declares which agents apply, where findings go,
and any target-specific scoping.

Each public-issue target explicitly declares `visibility: public` and `repo: OWNER/REPO`.
The publisher verifies the destination really is public on github.com before disclosing
any finding, including high/critical under Paul's 2026-10-07 approval. Missing/invalid
visibility does not authorise disclosure; a raw path without a manifest remains file-only.
Do not derive `repo:` from a checkout remote (which may be github.int.exe.xyz).

See [../docs/PLAN.md](../docs/PLAN.md) §6 (pilots) and §12 (self-hosting).

| Target | Sink | Role |
|---|---|---|
| `fauxmium.yaml` | `file` | No verified public repo configured yet; local evidence only |
| `chrome-agent-platform.yaml` | `github-issues` | Public triage before explicit, approved bead promotion |
| `agents.yaml` | `github-issues` | Self-hosting public issue triage; sensitive prose redacted |
