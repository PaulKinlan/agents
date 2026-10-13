## `fleet-check-scope-worker-teardown.patch` (agents-825v, the fleet-repo half)

**Applies to** `~/fleet/tests/fleet-check-scope.test.sh` as it stands at 6966 bytes, sha256
`a26f08aa7e4fcd9c...`, mtime 2026-10-12 21:11:02. Plain diff form; it replaces ONE line
(`T=$(mktemp -d); trap 'rm -rf "$T"' EXIT`) with a teardown.

## WHAT THIS IS AND WHY IT EXISTS

agents-825v has two halves. The agents-factory half landed long ago:
`tests/test_gate_entrypoint_config.py` registers every temp HOME and fails at teardown if a live process still
references it (branch `fleet/impl-l2xb-51` at `a3acef8`, cleared). The remaining half is THIS fixture, which
lives in the hub's tree.

The fixture already privatises `FLEET_HEAVY_DIR` - its own comment records the 2026-10-12 measurement where
the suite held the hub's single slot for 34 minutes. That fixed starvation of the SHARED queue. **It did not
fix the leak**: the teardown was `rm -rf "$T"`, which deletes the checks dir and the temp HOME out from under
a worker that `fleet-heavy` detached. The worker is then reparented to pid 1 with a DELETED cwd and keeps
holding its heavy slot - the husks diagnosed on 2026-10-12, three of them alive for over an hour, one at
1h50m, on a 2-vCPU VM whose single heavy slot they therefore occupied.

**This is a COPY, not an authoring task**, which is the point of delivering it here: the hub's job is to apply
it. If the hub has already fixed this fixture another way, **do not apply this** and close agents-825v on that
fix - the two are alternatives, not a sequence, and the bead should not read as competing work.

## WHAT IT DOES

1. **Kills this suite's own workers before their directories are deleted.** The identifying property is the
   mktemp path: a leaked worker's command line embeds the script `fleet-heavy` wrote into this suite's checks
   dir, so it contains `$T`, and nothing else on the VM has that path in its argv. This is deliberate,
   because it avoids the two cleanup traps this fleet has already paid for:
   - `pgrep -f`/`pkill -f` with a pattern taken from the SUBJECT also matches the **invoking shell's own
     command line**. That cost this lane two shells at exit 143 during the original diagnosis, and a third
     while this patch was being written.
   - a pattern that a real gate also matches kills an honest job (coord's rule 52: a cleanup pattern must
     match a property the leak has and the real job does not).
   A mktemp path has both properties: the invoking shell's argv does not contain it, and no real gate was ever
   handed it.
2. **And it FAILS the suite if it had to kill anything**, printing the pids it killed.

**Why both halves, which is the design point.** A teardown that only asserted "nothing survives" would leave
the husk holding the slot. A teardown that only killed would hide the leak behind a green suite. Doing both
releases the slot AND makes the leak visible - the same two-sided rule as the control in agents-yltq: **an
instrument must not be able to report success on a dead one.** A first draft killed and then asserted, which is
always green; its own red case caught that.

There is also a short grace period (about 2 s) before the kill, so a gate that is merely parking is not a leak
yet and does not turn a legitimate finish into a red suite.

## HOW IT WAS TESTED, with a two-sided harness

The teardown block was extracted VERBATIM from the patched file and driven, rather than retyped:

| case | expected | measured |
| --- | --- | --- |
| GREEN - nothing outlives the suite | exit 0, tree removed | exit 0, tree removed, no output |
| RED - a detached worker whose cmdline contains `$T` | exit 1, worker killed, pids named | exit 1, `FAIL 1 worker(s) ... pids: <pid>`, worker gone |
| CONTROL - an unrelated detached process (cmdline does NOT contain `$T`) | survives both cases | survived both |

The control is the half that stops this being a blanket kill of anything loosely matching. `bash -n` passes
on the patched file.

**One honest limitation, stated rather than glossed**: the harness exercises the teardown block against a
synthetic worker, not the real suite against a real leaked gate worker. Running the fixture end to end needs
the hub's `~/fleet` tree, which a project lane cannot modify.

## TWO DEFECTS ITS OWN TEST CAUGHT, recorded because they are the same family

- The first draft **counted the survivors after killing them**, so it printed `FAIL 0 worker(s)` - a report
  about an empty set, because killing is what emptied it. The set must be captured before the kill.
- Reading `/proc/<pid>/cmdline` for a process that vanishes mid-scan emits the SHELL's own redirection error,
  which the `2>/dev/null` on `tr` does not suppress. A readability guard on the file fixes it.
