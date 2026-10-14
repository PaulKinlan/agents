## `fleet-check-tree-stability-inbox.patch` (agents-97kx)

**Delivery artifact, not an installed hub change.** The patch touches ONLY
`tests/fleet-check-tree-stability.test.sh` in `PaulKinlan/fleet`; it does not change
`bin/fleet-check`, `bin/fleet-gate`, or the production notifier. It is separate from
`fleet-check-no-notify.patch` (agents-94j9, which covers the **scope** test) and
from the in-review `agents-o7b8` changes to `bin/fleet-check`'s `finish()` fragment.

### Pin and boundary

| object | SHA-256 | size |
| --- | --- | ---: |
| mirrored `~/fleet/tests/fleet-check-tree-stability.test.sh` **preimage on this project VM** | `8cc667daef33635fddcb648415df99defa329cc64f84dc4f860fdc4710b57067` | 12,295 bytes |
| `patches/fleet-check-tree-stability-inbox.patch` | `66e2a36686c790fa4b8ad13fdc204d99149f18847efddfd16e867bed1eec15dc` | 2,069 bytes |
| strictly patched test output on that preimage | `d578d6e43bb7ad7611152e70e675263dcd8f0b1622e226de1b8c8a4295600bd1` | 12,697 bytes |

The preimage above is **advisory**, measured from this project VM's `~/fleet` mirror,
not an assertion about the hub's executable or its current checkout. A hub owner must
measure the hub's OWN test file, select the matching generation, use `patch -p1
--fuzz=0`, inspect offsets/rejects, and compare its resulting SHA-256; STOP if the
preimage is different or any hunk moves. No copy of `~/fleet` was edited here.

### Measured root, not just a plausible grep hit

The scope test is already covered by agents-94j9's separate artifact. This test's
`curl` stand-in had two branches: the held-POST arm waits then exits, but every
non-held synthetic notification ran `exec /usr/bin/curl "$@"`, directly to
`http://localhost:${FLEET_INBOX_PORT:-7777}/msg`. Its `FLEET_LANE=arx8-test`
merely changed the destination **lane name**, not the TCP destination. The
fleet-check worker falls back to `FLEET_LANE` when the record has no waiters;
HOME and the private `FLEET_HEAVY_DIR` do not isolate the inbox. That fallback
was independently observed during agents-o7b8; the gate checks at
`fleet-check:186` that `FLEET_LANE` is nonempty, so simply unsetting it would
prevent the fixture from exercising any gates. This patch clears the inherited
lane then explicitly sets the synthetic one, fences `FLEET_INBOX_PORT=9`, and
makes the curl stand-in **consume** ordinary and held notifications without
network I/O. Arm 7 still simulates a blocked POST until release, preserving its
publication-order assertion. The real production POST path remains intact.

The experiment drove the **actual 7-arm fleet test** and mirrored real
`bin/fleet-check` in disposable HOME/git repos with its own heavy queue. A
private `127.0.0.1:0` HTTP capture stood in for the inbox; the environment
pointed the pristine fixture at its chosen port (never the real port 7777).
Unpatched: 14 passed/0 failed, **6 synthetic POSTs** captured, 9.51s. Patched:
14 passed/0 failed, **0 POSTs**, 9.54s. A separate factory regression in
`tests/test_fleet_check_tree_stability_inbox.py` probes a private listener
using a mutant forwarding stand-in (one POST captured), then executes the
actual resulting stand-in from this patch both ordinarily and with a released
hold marker (zero POSTs). Thus a zero-count capture is not mistaken for an
unreachable listener. Test time is ~0.5s. No live inbox or shared heavy slot
was used in either control.

### Install check (hub owner, NOT performed by this project lane)

```bash
cd ~/fleet
sha256sum tests/fleet-check-tree-stability.test.sh  # verify hub preimage, never assume the project VM's SHA-256
patch -p1 --fuzz=0 --dry-run < /path/to/fleet-check-tree-stability-inbox.patch
patch -p1 --fuzz=0 < /path/to/fleet-check-tree-stability-inbox.patch
sha256sum tests/fleet-check-tree-stability.test.sh  # expect d578d6e43bb7ad7611152e70e675263dcd8f0b1622e226de1b8c8a4295600bd1 ONLY on the named preimage
```

The fleet-side integration gate must check `agents-94j9` and this test-only
patch against the hub's actual file generations. A successful project-branch
merge, patch dry-run on a mirror, or fast-gate verdict does **not** install
anything on the hub.
