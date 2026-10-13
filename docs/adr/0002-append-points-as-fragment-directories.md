# ADR 0002: Serialising Append Points — Registries Become Directories of Fragments

- **Status:** Accepted (design `agents-cchd`; adopted for `patches/` in `agents-hzug` and for the
  fast-gate allowlists in `agents-nerv`; the remaining candidates are scored in §4 with one
  implementation follow-up filed)
- **Deciders:** Software Factory Architecture, Core Coordination, Tooling Implementers
- **Context:** Bead `agents-iery` (this record), `agents-cchd` (design), `agents-hzug` (patches
  adoption), `agents-nerv` (allowlist adoption), `agents-1mz0` (ADR pointers), `agents-02s9`
  (allowlist carries no prose reasons)
- **Updated:** 2026-10-13

---

## 1. Context and Problem Statement

A **serialising append point** is a tracked file that every delivery appends to: a registry, a
list, or a document with one section per item. Two failures follow from that shape, and only the
first is about git.

1. **Scheduling.** N deliveries in flight that all append to one file means N−1 of them must
   reconcile with the others **at that file** — a hand-resolved conflict in a file nobody meant to
   change. And reconciling is expensive here in a way an ordinary merge is not: a rebase moves the
   branch tip, and a verdict is pinned to a tip, so the delivery loses its gate record *and* its
   review — a re-gate (tens of seconds to minutes) and a re-review (minutes to an hour) for work
   that did not change. **The rebase is caused by `origin/main` advancing, which no shape of any
   file can prevent (§6, item 1); what the shared file adds is the conflict, and the second look at
   a merge nobody intended.** This section's table measures the collision; §6 states the limit.
2. **Containment.** In a shared markdown document, an unclosed code fence swallows the section
   after it. No text-based merge check sees this: both sides' diffs are individually well-formed,
   and the damage is to the *neighbourhood*. This is not hypothetical for this repository — the
   guard that replaced one such document names it as the reason (`tests/test_patch_writeups.py`,
   "two real defects were produced").

### What the contention actually measures

Measured over **367 landing merges** on `origin/main` (2026-09-23 → 2026-10-13; method in §8),
**131 (merge, file) events** in which the *same file was changed on both sides* of a landing,
across **80 of the 367 landings** and **37 distinct files**. The head of that list:

| file | landings that touched it | landings where BOTH sides changed it |
|---|---:|---:|
| `tools/fast-gate.sh` | 144 | **40** |
| `factory` | 108 | **15** |
| `tests/test_fast_gate_mapping.py` | 73 | **11** |
| `lib/findings.py` | 73 | **7** |
| `tests/test_containment.py` | 67 | **5** |
| `tests/test_gate_entrypoint_config.py` | 43 | 4 |
| `tests/test_factory_core.py` | 66 | 4 |
| `AGENTS.md` | 56 | 3 |
| `tests/test_sinks.py` | 48 | 3 |
| `lib/credential_broker.py` | 19 | 3 |

The metric that matters is *how many of those are appends to a registry*, and that is not
recoverable from diff arithmetic alone. Two measures, and the honest statement of each:

- **Registry appends, named explicitly.** `tools/fast-gate.sh` carries a `case "$f" in` arm table
  from which the fast gate resolves a changed file to the suites that must run. At its creation
  (2026-10-08, `0ad5b73`) it had **3 arms**; today it has **77** — about 15 arms a day. **84 of the
  367 landings appended an arm**, and in **7 of them both sides appended an arm to the same table
  in one landing** (`cfe5ac25`, `2b95c958`, `7af2a61a`, `c4286539`, `ea734666`, `3e57caa7`, …) —
  about one such collision a day over the five days the table has existed.
- **A stricter diff test undercounts, and is recorded so it is not mistaken for the truth.** A
  numstat test (both sides' changes contain only insertions) finds **7 of the 131** contended events.
  That is a different seven from the seven arm collisions above, and the fact that a much stricter
  measure finds *fewer* is the point: numstat is blind to an append that also adjusts a trailing
  separator, a neighbour's comment or a shared context line — i.e. blind to most real appends. The
  ADR therefore rests on the registry-specific numbers above, where "this delivery added an arm" is
  observable directly.

The second half of that measurement is the important negative: **most contention in this repository
is not append-shaped at all.** Only 7 of the 40 both-sided `tools/fast-gate.sh` landings are two
appends to the arm table; the other 33 are edits to the file's shared logic, and
`factory` / `lib/findings.py` are central-logic files whose two sides edited the same behaviour.
Fragmenting fixes registries; it does nothing for those, and §6 says so.

## 2. Decision

**A registry becomes a directory of fragments.** The shared file is replaced by:

```text
<registry>/                 the shared file becomes a directory (or keeps a preamble + a sibling)
    README.md               what the shape is and how the reader aggregates it
    <item>.md | *.json      one file per item: exactly one delivery touches exactly one file
```

and the *aggregator* — the code or the reader — is what reconstitutes the whole:

- **machine-read registries** keep a loader that globs the directory (`tests/fast_gate_allowlists.d/*.json`
  is read by `tests/test_fast_gate_consumer_coverage.py`);
- **human-read documents** get their index from `ls`, never from a maintained list in prose
  (`patches/README.md` says this in as many words: "a list would be the same shared append point
  this split exists to remove, and it would go stale the first time someone forgot to update it");
- **ordering**, when the artefact needs it, belongs in the item's own key or name, not in the
  position of a line in a shared file.

### The criterion for applying it

Apply the split when **all three** hold:

1. the artefact is a **set of items** with a key that is knowable at delivery time (a patch name, a
   fingerprint, a module path, a suite name) — not one argument that happens to be long;
2. the artefact is **machine-read or ls-read**, so an aggregation step can replace the shared list;
3. the measured contention is **append-shaped** — two deliveries add an item, they do not rewrite
   one behaviour (see §4 for how each candidate was scored, and §1 for why the distinction is real).

Do **not** apply it to a narrative document read whole, or to a module whose contention is edits to
shared logic; §6 names both.

## 3. Adopted instances (the evidence this decision already has)

### `patches/` — `agents-hzug`, `fd4a55d` (2026-10-13)

Before: `patches/README.md` was a **587-line** document, one section per patch, and every patch
delivery appended to it. After: a 23-line preamble plus one `patches/<artifact>.md` write-up per
`.patch`, whose filename is the artifact name it explains.

- Size of the change: **14 files, +665 / −579**.
- Two properties replaced one: the *fence* is per file, so the worst case is contained in the file
  that caused it, and the *artifact* stays reachable from its explanation because the filename
  carries the artifact name.
- Both are pinned by `tests/test_patch_writeups.py` — a fragment directory needs its own guards, and
  this is what that costs: **78 lines and five tests at adoption** (100 lines and six today) — no
  fence left open at the end of a file; every `.patch` named by a write-up's heading; every write-up
  begins with a section heading; the README's length and wording deliberately not pinned.

### Fast-gate allowlists — `agents-nerv`, `9659edf` / `1169e40`

Before: `CONSUMER_COVERAGE_ALLOWLIST` and its sibling were literal dicts inside
`tests/test_fast_gate_consumer_coverage.py`; every new module whose omission was accepted appended
an entry to one dict. After: `tests/fast_gate_allowlists.d/*.json`, one fragment per allowlist, read
by the test.

The directory also demonstrates the *reader* half of the decision: it carries no prose reasons
(`agents-02s9` — a reason used to sit beside each entry and was **false for half the modules it
described**), and a reader is pointed at the ADR that holds them by
`TestTheAllowlistPointsAtItsDocumentedReasons`, which fails if that pointer rots (`agents-1mz0`).

### Precedent already in the repository

The pattern is not new here; it is the house style wherever the artefact is per-item:
`targets/<name>.yaml`, `agents/<name>/agent.yaml`, `lines/<name>.yaml`, `patches/<artifact>.md`. This
ADR makes the reason explicit and generalises it to *any* artefact whose contention is appends. The
two remaining candidates below are the ones that are still shared files.

## 4. Remaining candidates, scored

| candidate | measured contention | shape | verdict |
|---|---|---|---|
| `tools/fast-gate.sh` arm table (77 arms) | 144 landings touched the file, 40 both-sided, **84 arm appends**, **7 both-sides arm appends**; 3→77 arms in 5 days | append, machine-read | **ADOPT** — filed as `agents-v8xv` (implementation is follow-up work, not this record) |
| `tests/test_fast_gate_mapping.py` | 73 landings, 11 both-sided | grows *with* the arm table; a suite that owns its subject | **FOLD INTO THE ABOVE** — it is downstream of the arm table, not a second registry |
| `AGENTS.md` (397 lines) | 38 commits, 7 authors, 3 both-sided | narrative appended in paragraphs | **DO NOT** — it is the contract every lane must read whole; fragments make it unfindable, and its appends collide cheaply and *semantically* (two conventions that must be read together) |
| `THREAT_MODEL.md` (110 lines) | 41 commits, 6 authors, 0 both-sided | one argument, revised | **DO NOT** — churn is revision, not appending; a fragment set cannot make a threat model cohere |
| `findings/suppressions.yaml` (438 lines) | 3 commits, 3 authors, **one bulk of 101 entries** | register, machine-read | **NOT YET** — one writer per night (the triage) plus occasional humans, and review depends on reading the register whole. **Criterion to revisit:** a second concurrent writer per night, or a single delivery that edits entries another delivery is adding |
| `factory`, `lib/findings.py`, `lib/containment.py`, `tests/test_containment.py`, the remaining suites | 108 touched/15 both-sided, 73/7, 43/2, 67/5, … | rewrite of shared behaviour, not appends | **OUT OF SCOPE** — §6 |

## 5. Costs (paid, not hypothetical)

- **More files, and a reader who must look at a directory.** The `patches/` split turned one 587-line
  document into 14 files and removed 579 lines from the shared one. Anyone who wanted "all patch
  write-ups in one scroll" lost that; `ls` is the index now.
- **An aggregation step exists in code, and it is paid per invocation.** `tools/fast-gate.sh` is
  executed by the mapping suite in dry runs, so a fragment directory would be read on every gate and
  every dry run. Measured on this VM: sourcing **77 fragments totalling 1925 lines takes 3 ms**
  against **0 ms** for the same text in one file. Against a ~35 s fast gate that is noise, and it is
  recorded because "it is a directory scan" should be a number, not a worry.
- **Each split needs its own guards.** Fragment directories lose two whole-file properties (fence
  containment, one coherent read) and gain two new failure modes (a stale item, two fragments
  claiming one key). Both adoptions in §3 brought a test with them; a split without one is
  unfinished work, not a smaller change.

## 6. What this decision does NOT fix

Said plainly, because an ADR that reads as a silver bullet is worse than none:

1. **It does not remove rebasing.** A delivery still rebases when `origin/main` moves — that is
   caused by main advancing, not by a file being shared. Fragments turn a *conflict* into a *clean*
   rebase, so the manual work and the re-review of a conflicted file disappear; the re-gate of the
   rebased tip does not. For scale, the upper bound on re-gating here is large and *confounded*:
   of 493 cached fast-gate records for this repository on this VM, 427 (87%) belong to a
   (changed-set, command) key that was gated on more than one tree — 331 more runs than one per key,
   ≈3.2 h of VM time at ~35 s each. That figure **includes genuine fix iterations on the same files
   and runs from different lanes**, so it is an upper bound on the serialisation tax, not the tax.
2. **It does not fix the dominant contention.** On the measured history the two most contended
   files are central logic (`tools/fast-gate.sh` 40 both-sided landings, `factory` 15), and only 7
   of those 40 `tools/fast-gate.sh` landings are two appends — the rest edit shared behaviour.
   Their remedy is splitting the module or the test along its responsibilities — a different
   decision with a different cost profile, and not this one.
3. **It does not prevent semantic collisions.** Two deliveries can still add fragments with the same
   key, or two mutually inconsistent policies. Ordering and key uniqueness belong to the aggregator's
   guard.
4. **It is not a substitute for a keyed check.** Where the item is a finding fingerprint
   (`findings/suppressions.yaml`), the interesting failure is not the append but the *wrong entry*;
   fragmenting such a register without a validator buys conflict-freedom and nothing else.

## 7. Alternatives considered

- **Batch the appends at landing time** (the merger appends every delivery's section to the shared
  file when it lands). Rejected: it moves work to the single most throughput-critical lane in the
  fleet, and it serialises on the merger instead of on git. It also leaves the fence-containment
  problem entirely intact, because the file is still assembled by one writer appending text.
- **One-line rows in a shared table** (a table row instead of a section). Reduces textual conflicts
  and does nothing about the two failures that motivated the decision: a row still collides with a
  row, and a row is not a boundary that contains anything.
- **One generated file, regenerated at landing from per-item sources.** Same conflict (two writers
  regenerate the same artefact) plus a generated file that is either committed (stale) or absent
  (unreadable on a fresh checkout). Rejected.
- **An append-only log parsed by the reader** (JSONL of items, one line per delivery). Works for the
  machine-read cases and is rejected for the human-read ones: a 587-line narrative in one append-only
  file has exactly the containment problem it was meant to solve, and no reader can scan it.

## 8. Method (so the numbers can be re-derived rather than trusted)

All measurements were taken on this checkout at `origin/main` = `025efba` on 2026-10-13.

```bash
# landings, and the files changed on BOTH sides of each landing merge
git rev-list --merges origin/main                      # 367
# for each merge M with parents P1,P2: intersect
#   git diff --name-only M^1 M   and   git diff --name-only M^2 M

# registry appends to the fast-gate arm table (an arm looks like '    <pattern>)')
git diff -U0 M^1 M -- tools/fast-gate.sh | grep -E '^\+    [A-Za-z0-9_.*/-]+\)$'

# the arm table's growth
git show <rev>:tools/fast-gate.sh | awk '/^  case /,/^esac/' | grep -cE '^    [A-Za-z0-9_.*/-]+\)$'

# the loader cost of the fragment shape (77 fragments × 25 lines = 1925 lines, this VM)
time ( for f in /tmp/frags/*.arms; do source "$f"; done )    # 3 ms
source /tmp/one.arms                                          # same 1925 lines in one file: 0 ms

# the re-gate upper bound
python3 -c '...'  # ~/.fleet/checks/*.fast.json, grouped by (coverage.changed, cmd) -> distinct trees
```

## 9. Consequences

- A delivery that adds an item to a fragmented registry touches **one new file and nothing shared**,
  so it cannot *conflict* with a delivery in flight, and no lane has to hand-resolve and then re-review
  a merge that two appends to one file produced. **It is NOT immunity from re-gating, and an earlier
  version of this bullet claimed that it was** (`agents-d8uv`, a review of the first version of this
  record): `origin/main` advancing moves every in-flight branch whatever changed, and a verdict is
  pinned to a tip, so a rebase still puts the rebased tip back in front of a reviewer (§6, item 1).
  What the split removes is exactly the work the shared file itself caused — the conflict, and the
  second look at a merge nobody meant to change — which is the smaller claim §1's table supports.
- Every fragmented registry must ship an aggregator and a guard for its own failure modes; the two
  existing adoptions do, and §4's follow-up must.
- Registries that are *not* fragmented now carry the reason in this document, which is what makes the
  next reader's "why is this list still shared?" answerable without re-deriving the history.
