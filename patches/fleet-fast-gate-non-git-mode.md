## A plain checkout must RUN its in-scope suites, not refuse - \`fleet-fast-gate-non-git-mode.patch\` (agents-i4u9)

Hub-side artifact for \`remote/fast-gate.sh\`, plus a new driven fixture. **Option (a), chosen over retirement,
and the assessment that decided it is below.** Coord's rule: a test in scope either RUNS or is NAMED as
skipped-with-a-reason - silence is neither.

### Why (a) and not (b), in one measurement

The gate touches git in exactly two places, and I read the whole file to be sure: the refusal
(\`git rev-parse --git-dir\`, lines 47-48) and the delta resolution (lines 67-73). Everything after selection is
git-free, and the \`--all\` path that enumerates \`tests/*.test.sh\` already existed (line 63). So the non-git mode
is a bounded change at the refusal site, not a rework: **a plain checkout simply has no delta, and the honest
response to no delta is to run everything and say so.** Retirement would have been the larger lie - the file is
in scope, and \`remote/retired-files.txt\` would have had to claim either that something else covers the
behaviour or that nothing does and we chose not to care.

### What changed

\`\`\`
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "fast-gate: NOT a git work tree ($TREE): no delta to map, so EVERY in-scope suite runs (the --all set)" >&2
  echo "fast-gate: coverage will be UNKNOWN for this reason - a real verdict on what ran, not a claim about what changed" >&2
  ALL=1
fi
\`\`\`

The distinction the gate's output must make is stated in two lines and in the exit status: **ran and passed**
(exit 0 after really running the suites) versus **not applicable, here is why** (the banner, and coverage
reported UNKNOWN with that reason). It no longer returns a status that verified nothing.

### Evidence

- **Driven discriminator, the same fixture against both revisions:** DEPLOYED **4 assertions failed** - exit 2,
  the suite marker absent, no reason stated, no selection offered. PATCHED **ok 4, 0 failed**.
- The fixture is a temp plain checkout with two dummy suites that write markers, so "it ran" is a fact on disk
  rather than an inference from the exit code.
- \`patch -p1 --fuzz=0\` CLEAN against the live \`~/fleet/remote/fast-gate.sh\`, byte-identical after apply, and
  the APPLIED copy then drives the same check end to end (rc=0, suite marker present, reason stated).
- Strict preimage: \`remote/fast-gate.sh\` SHA256 \`47a4b3cf837621aa\`. \`tests/fast-gate-nongit.test.sh\` is new.

### What this does NOT fix, stated plainly

Coverage for such a run is UNKNOWN, because there is no delta to map - that is the honest answer and it is
labelled as such, not a pass. And this makes the hub's OWN suite runnable where the repo is deployed as plain
files; whether every one of those suites then passes is a separate question, and one of them
(\`pick-model-crossfamily\`) was red until \`agents-shua\` repaired it.
