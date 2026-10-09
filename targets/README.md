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

### Declaring visibility

A target whose findings go to a synced tracker must declare `visibility: public|private`.
For a **named** target it is a field in this file, and the manifest wins over the command line:

```yaml
name: my-project
sink: beads
visibility: public
```

A **hand-run against a raw path** loads no manifest, so declare it on the command line —
the same declaration a scheduled run makes, accepted by `run`, `line` and `hillclimb`:

```bash
factory run docs-drift --target /path/to/project --sink beads --visibility public
factory line project-audit --target /path/to/project --sink beads --visibility public
```

`--sink beads` is part of the recipe, not decoration: a raw path defaults to the `file` sink,
which is local evidence and is never embargoed, so no tracker is involved and nothing needs a
declaration. Both halves are required — `--sink beads` selects the synced tracker and
`--visibility` authorises publication to it.

Without a declaration `lib/embargo.py` fail-closes: **high and critical findings are withheld**
from the synced tracker. The run still succeeds (exit 0) and the local delta report still lists
them, so a green run is not evidence they were filed. Nothing is silent about it in the log, but
there is only one line, and only for the sink that was holding them:

```
[Sink beads] 1 finding(s) held locally: visibility must be explicitly declared before synced-tracker publication.
```

A `file` sink is unaffected — it is local evidence, not a publication — which is the usual reason
a hand-run looks fine: nothing was ever going to a tracker.

See [../docs/PLAN.md](../docs/PLAN.md) §6 (pilots) and §12 (self-hosting).

| Target | Sink | Role |
|---|---|---|
| `fauxmium.yaml` | `file` | No beads DB configured yet; local evidence only |
| `chrome-agent-platform.yaml` | `beads` | Findings file to the project Beads DB automatically |
| `agents.yaml` | `beads` | Self-hosting; findings file to beads, public input via issue-triage |
