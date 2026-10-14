## `fleet-check-start-observation.patch` — a RUNNING check can already have started (agents-80np)

**Hub-only artifact, not installed.** This patch changes `PaulKinlan/fleet` `bin/fleet-check`
(status **reader only**) and adds the independent `tests/fleet-check-start-observation.test.sh`.
It does not change the per-tree verdict writer, cached record format, queue, gate command,
`run_s`/`wait_s`, or merger controls. Sibling agents-6upw is a different binary:
`bin/fleet-gate`; its existing wg7i→lyrw artifacts distinguish NEVER RAN from a
command verdict and **do not** fix this status surface. Do not present either patch as
covering both beads.

### Three moments, driven against the deployed executable

A disposable Git repository, HOME/cache, private `FLEET_HEAVY_DIR` and `flock` holder
ensured the deployed `fleet-check` and `fleet-heavy` genuinely queued; the stdout
marker inside the command proved when it started. A fake `curl` captured the wake
without POSTing to the live inbox. The original scratch run recorded:

| Moment and positive witness | Fresh `fleet-check --status --fast` | Wrong inference |
|---|---|---|
| PRIVATE ticket and waiting log, 0 gate-start markers | `RUNNING`, pid present, `run_s`/`wait_s` **absent** | Timing absence is not a queue status, though the separate ticket/log show this particular run was queued. |
| Holder released, real command running, 1 gate-start marker and `status-probe-start` | **Same** `RUNNING`, pid and both timing keys absent | Inferring "still queued" here would discard executed work. |
| Command exited; later reader | `PASS`, `run_s:9`, `wait_s:4` | This PASS is only for an echo/sleep fixture, **not** a project suite verdict. |

Evidence: `/tmp/agents-f6du-80np-status-fixture.log`; scratch root
`/tmp/agents-f6du-80np-status.S9kFIr`. The private slot was independently read
back FREE. This is consistent with the merger's four real preemptions after
**36–89s** of execution; do not use missing finish-time fields as a preemption
criterion.

### Narrow reader change and falsification

After checking the record's own tree/kind identity, the `--status` path reads only the
record's *current regular log*. For a `RUNNING` record, it adds a query-time observation:

- `run_start_observation:"OBSERVED"` if a well-formed `=== fleet-check gate started HH:MM:SS`
  marker is present. This proves **at least one attempt started**, not that the current
  attempt still runs: a previously started attempt could have been preempted and queued.
- `run_start_observation:"NOT_OBSERVED"` if no such line can be read, with a note
  explicitly saying that this does **not** prove queued or never-ran. Dependency
  setup, queueing, an inaccessible log or a timing race remain possible.

Completed records keep their measured `run_s`/`wait_s` and do not gain the live-only
observation. Missing log evidence is **not** rewritten as a confident QUEUED phase.
This uses the same start marker the existing timing derivation uses, without racing
another writer to change the JSON record while the worker starts. The marker is an
observation from the existing local log, not authenticated proof against a same-UID
writer or arbitrary log corruption; nothing in this patch claims that wider property.

The NEW hermetic test runs the real binaries with a **private** heavy slot and no
live inbox. On the pinned deployed executable it is **6 passed / 2 failed**,
failing specifically because both reader observations are absent. On the strictly
patched scratch copy it is **8 passed / 0 failed**; fresh reader snapshots are:

```
QUEUED:  RUNNING, run_start_observation=NOT_OBSERVED, no run_s/wait_s, marker_count=0
STARTED: RUNNING, run_start_observation=OBSERVED,     no run_s/wait_s, marker_count=1
FINISHED: PASS,                            run_s=6, wait_s=4
```

Evidence: `/tmp/agents-f6du-80np-strict-{red,green}.log`. The fixture frees its
private lock and stops only its own disposable processes. The echo fixture's PASS
must never be quoted as a code quality or project fast-gate verdict. One six-second
fixture is the hub test cost; no shared 2,700-line gate test file was edited.

### Pinned preimages and installation boundary

All following digests use **SHA-256** (not Git blob SHA-1 or MD5):

| Path | SHA-256 and status |
|---|---|
| Deployed `~/fleet/bin/fleet-check` preimage | `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498` |
| New `~/fleet/tests/fleet-check-start-observation.test.sh` preimage | **absent** |
| Patched `bin/fleet-check` | `c06c5e39f901ecf108a7811a340280886f0d60f59b4f69b863728716e96fd2c7` |
| Added regression test | `307c22d9c9166cde97b5229c666a7b31e4ef7d4b1642643e94ec99e8cbcc017a` |
| This `.patch` artifact | `18b4bbe0a9a1ea43085ce19df2e602b5eae8de843a49309b68aedaf289910259` |

`patch --batch --forward --dry-run --fuzz=0 -p1` and then strict apply on the
exact deployed preimage both succeeded with **zero rejects** and produced the two
byte-identical expected files above. The hub owner must independently check those
preimages and run the new focused test in a disposable hub checkout before any
installation. A separate staged `fleet-check-branch-fields.patch` (agents-npyn)
also expects the deployed `bin/fleet-check` preimage. If it or any other patch
changes that binary first, **STOP** and obtain a new exact-base composition/review;
neither textual applicability nor this test on the old tree proves the new stack.
No hub install, full union gate, or production preemption outcome is claimed.
