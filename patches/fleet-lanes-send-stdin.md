## `fleet-lanes-send-stdin.patch` (agents-esdx; hub finding fleet-f60xy)

**Delivery only.** This project VM's `~/fleet` is a synced, read-only, git-less deployment;
this branch does not edit, install into, or claim a live run on the hub. The hub owns the
canonical `fleet-f60xy` issue and must decide when to apply this patch. The patch contains
`remote/lanes.sh`, `remote/check-map.tsv`, and a new, isolated, executable
`tests/lanes-send-stdin.test.sh`. It does not alter `bin/bd` or a real lane socket.

### Exact deployed prerequisites

The following are **contents at the project VM's deployed `~/fleet`**, not a guessed hub
commit. Check the hub's actual files before installation; do not use `patch`'s context
matching as a substitute for whole-file identity:

| Path | Required preimage | Result after one application |
| --- | --- | --- |
| `remote/lanes.sh` | 40,537 bytes; SHA-256 `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`; Git blob `ef05d57f0901017fb8a5e895a2ca61eef8d4bb0a` | SHA-256 `228351941ad852df91d7bff6b4df6a767c2851d6f16187015b4d7e5475be7189` |
| `remote/check-map.tsv` | 4,710 bytes; SHA-256 `47f01a973c2cd03f201c4549019229b8284923e4b77ec163e195ca0d70a65764`; Git blob `67a2615f302379daf7a2a1c9ded58898ed2b4690` | SHA-256 `54d1d4f8d0d7804003936ef35a2b3cedb2b612393cd58ad6e9c14e23548c5b0d` |
| `tests/lanes-send-stdin.test.sh` | **must not exist** | mode `0755`, SHA-256 `7870c73f63ee03e13b7bd19872f3eef02163dc9c5ee6a8427a35c99abda73536` |

Artifact SHA-256: `48efa480c156935fd0b8dd313568d41876e592fdc8fcf2568954ed136fe5913d`.
On a fresh `/tmp` copy of BOTH exact deployed files, `patch --batch --forward --dry-run
--fuzz=0 -p1 -i <artifact>` and then `patch --batch --forward --fuzz=0 -p1 -i
<artifact>` both returned 0 with no offsets, fuzz or rejects. `cmp` matched each of the
three output files byte-for-byte to the separately tested source, and the new test
was executable. Evidence: `/tmp/agents-f6du-esdx-strict-apply.log` and
`/tmp/agents-f6du-esdx-verify-suite.log`. If any prerequisite has moved, stop and
re-cut/review for the real hub base; do not fuzzy-apply or silently stack another patch.

### Behaviour and boundary

`lanes.sh send <lane> <text...>` used `$*` unchanged. With `printf 'Please review\n' |
lanes.sh send trial -`, the lane received JSON `{"type":"prompt","message":"-"}` and
`{"ok":true}` still acknowledged the command. Four real dispatches/no-ops motivated this
finding. The sibling `fleet-send` uses `-` for stdin; the `bin/bd` shim's fleet-w9ot
precedent rewrites a bare `-` for piped/file stdin and refuses a terminal. This
change adopts that **exact bare-argument** rule here: bounded stdin read for one `-`
from a pipe/file; exit 2 with `REFUSED` for one `-` on a tty, a missing message,
or empty/whitespace-only input. Multiple explicit arguments still join with spaces,
and `- suffix` is not mistaken for the marker. Command substitution strips trailing
newlines, matching `bin/fleet-send`'s established `text=$(cat)` behaviour. The
control socket `nc -N -U` invocation and message JSON fields remain unchanged.
The self-doc header now names `send` and its stdin contract.

A separate small test file is selected whenever `remote/lanes.sh` changes by adding
`lanes-send-stdin` to that file's existing check-map row. Unlike adding a case to
`tests/lanes.test.sh` (already 1,067 lines and heavily shared), it has a bounded
fixture: fake `HOME`, fake `fleet.conf`, and fake `nc` under a temp directory, so
**no prompt can reach a live lane**. It checks piped and file stdin, old multi-arg
behaviour, exact bare-dash scope, tty refusal (pty), empty/whitespace stdin and
no-argument refusal. New test source can itself be selected by the hub fast gate
under the test-file arm; this branch does not add time to the agents-factory fast
gate beyond its patch write-up/structural checks.

### RED/GREEN evidence (all outside the live `~/fleet` tree)

- Old deployed script with `HOME=/tmp/agents-f6du-esdx-hub/fake-home` and fake
  `nc`: piped prompt was discarded and literal `-` reached the request file with
  rc 0 and an `ok:true` response (`/tmp/agents-f6du-esdx-hub/red-stdout.txt`).
  The new 9-control regression test on the old copied script returned **rc 1** at
  its first control: the pipe yielded `message:"-"`, not the body
  (`/tmp/agents-f6du-esdx-red-suite.log`). This is the *specific* failing
  assertion, not an incidental failure to start a lane.
- With patched files strictly applied in another `/tmp` tree, the new test returned
  **9/9 PASS**, rc 0 (`/tmp/agents-f6du-esdx-verify-suite.log`). `bash -n`
  passed for the patched script and test. There is no real hub-side run claim.
- **Actual transport, not just a fake `nc`:** a separate temp `AF_UNIX` listener
  received bytes via the real `nc -N -U` and acknowledged. The old deployed script
  delivered `message:"-"`; the patched copy delivered
  `message:"Actual socket payload"` and received `ok:true`.
  Logs: `/tmp/agents-f6du-esdx-socket-{red,green}.log`. Both listener and socket
  lived under an isolated temporary `HOME` and closed when the probe ended.

The hub should apply only after reviewing the exact base and run the focused
`bash tests/lanes-send-stdin.test.sh` plus its own affected check for
`remote/lanes.sh`; the merger here gates only the agents-factory artifact tree.
