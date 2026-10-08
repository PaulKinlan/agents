# Targets

One file per project the factory runs against. Declares which agents apply, where findings go,
and any target-specific scoping.

Findings file to **beads** automatically (agents-eyo): `sink: beads` dispatches every
finding into the project's Beads DB with no public GitHub issue and no human step. The
`beads_path:` field names that initialized project Beads DB; the factory never guesses the
location from a checkout remote.

GitHub issues are the place for **public input**, not findings: the `issue-triage` station
reads issues the public raises in `repo: OWNER/REPO`, and `factory promote` is the explicit,
human-approved issue -> bead link. `visibility: public` still matters — missing visibility
withholds high/critical from the synced beads tracker — and it authorises promotion. Do not
derive `repo:` from a checkout remote (which may be github.int.exe.xyz).

See [../docs/PLAN.md](../docs/PLAN.md) §6 (pilots) and §12 (self-hosting).

| Target | Sink | Role |
|---|---|---|
| `fauxmium.yaml` | `file` | No beads DB configured yet; local evidence only |
| `chrome-agent-platform.yaml` | `beads` | Findings file to the project Beads DB automatically |
| `agents.yaml` | `beads` | Self-hosting; findings file to beads, public input via issue-triage |
