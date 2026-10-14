## A clearance spent by landing must survive a branch deleted afterwards: route-B case for agents-qzy3

A `.md`-ONLY artifact, for the same reason as the case-36 artifact: the suite it belongs to,
`tests/fleet-land-message.test.sh`, lives on the hub with `bin/fleet-land-message` and is in neither this repository nor
the canonical checkout, so the case TEXT is the deliverable.

## What it pins down

The UNPINNED arm applies `rm_labels` and refuses, and it is reached when the branch cannot be resolved at all. That
happens when a branch is DELETED AFTER ITS WORK LANDED. In that situation the reviewed commit is usually still
reachable - it is an ancestor of the default branch - so the clearance was SPENT, and spent-ness is decidable. The arm
does not ask, strips `merge-queue` and every `cleared:` label, and reports that the verdict "named no commit SHA",
which is false: the verdict named one and it is the BRANCH that is gone.

This case asserts the two halves that make it a measurement: the spent clearance SURVIVES, and the message names the
branch. Its control asserts that a clearance whose commit is NOT on the default branch is still invalidated, so a fix
that simply stopped stripping in this arm would fail here.

## Where it goes

Append before the summary block (`if [ "$FAIL" -gt 0 ]; then`). It uses only the suite's own idiom - `ok`, `bad`, `has`,
`hasnt`, `eq`, `run()`, `$ROOT/repo`, `$B`, `$FIX`, `$ROOT/fix` - and builds its own branch, so it depends on no
earlier case's state.

## The case

```bash
echo "38. qzy3: a clearance spent by landing survives a branch deleted afterwards"
probe_branch() {   # $1 = spent | unspent
  # SPENT means the reviewed commit IS an ancestor of refs/remotes/origin/main, so the default branch must contain it:
  # setting origin/main to main's own tip does NOT do that, because the reviewed commit is a DESCENDANT of main. My
  # first version of this fixture made exactly that mistake and the case then failed for a fixture reason rather than
  # for the defect - a case that fails on the ground truth is testing its own fixture.
  git -C "$ROOT/repo" checkout -q main
  git -C "$ROOT/repo" branch -D fleet/cur38 >/dev/null 2>&1 || true
  git -C "$ROOT/repo" checkout -q -b fleet/cur38
  echo r38 > r38.txt; git -C "$ROOT/repo" add r38.txt
  git -C "$ROOT/repo" -c user.email=t@t -c user.name=t commit -q -m "feat: cur38"
  cur38_full=$(git -C "$ROOT/repo" rev-parse fleet/cur38)
  cur38_tip=$(git -C "$ROOT/repo" rev-parse --short fleet/cur38)
  git -C "$ROOT/repo" update-ref refs/remotes/origin/fleet/cur38 "$cur38_full"
  if [ "$1" = "spent" ]; then
    git -C "$ROOT/repo" update-ref refs/remotes/origin/main "$cur38_full"
  else
    git -C "$ROOT/repo" update-ref refs/remotes/origin/main "$(git -C "$ROOT/repo" rev-parse main)"
  fi
  git -C "$ROOT/repo" checkout -q main
  cat > "$B" <<J
[{"author":"proj-rev-1","created_at":"2026-10-12T11:00:00Z",
  "text":"VERDICT: PASS\nDelta: tk-1 base..$cur38_tip branch fleet/cur38\nGate: fleet-check PASS for $cur38_tip"}]
J
  cat > "$ROOT/fix/show.json" <<'J'
[{"id":"tk-1","title":"Add the thing","description":"The thing was missing.","status":"open","priority":2,"labels":["merge-queue","cleared:abcd123"]}]
J
  : > "$FIX/bd-updates.log" 2>/dev/null || true
  : > "$FIX/bd-comments-added.log" 2>/dev/null || true
  # THE BRANCH IS DELETED AFTER ITS WORK LANDED: gone from origin and locally, which is what makes
  # target_ref empty and tip the literal string "unknown".
  git -C "$ROOT/repo" update-ref -d refs/remotes/origin/fleet/cur38
  git -C "$ROOT/repo" branch -D fleet/cur38 >/dev/null 2>&1 || true
}
probe_branch spent     # the reviewed commit IS an ancestor of origin/main, so the clearance was SPENT
out_spent=$(run tk-1 fleet/cur38); rc_spent=$?
hasnt "$(cat "$FIX/bd-updates.log" 2>/dev/null)" "--remove-label merge-queue" "38a a SPENT clearance survives a deleted branch (no label stripped)"
hasnt "$(cat "$FIX/bd-comments-added.log" 2>/dev/null)" "clearance rejected" "38b ...and no rejection comment is written"
hasnt "$out_spent" "named no commit SHA" "38c ...and the message does not claim the verdict was unpinned"
has "$out_spent" "origin/fleet/cur38" "38d ...and the message names the BRANCH, which is the object actually missing"
# CONTROL: same deleted branch, but the reviewed commit is NOT on the default branch - the clearance was never spent,
# so it MUST still be invalidated. Without this pairing a fix that simply stopped stripping would pass 38a-38d.
probe_branch unspent
out_unspent=$(run tk-1 fleet/cur38); rc_unspent=$?
has "$(cat "$FIX/bd-updates.log" 2>/dev/null)" "--remove-label merge-queue" "38e control: an UNSPENT clearance is still invalidated"
eq "$rc_spent" "1" "38f the spent case still refuses the delta"
```

## Driven, and red for the defect's own reason

The case was injected into a copy of the deployed suite and run against two revisions, with every revision staged
BESIDE its sibling files (`fleet-land-message` reads `fleet-verdict-words.sh` from its own directory; a tool copied out
alone refuses to run and any number from such a staging is meaningless):

| revision | 38a | 38b | 38c | 38d | 38e control | 38f | whole suite |
|---|---|---|---|---|---|---|---|
| canon (`f6de0939`) | **FAIL** | **FAIL** | **FAIL** | ok | ok | ok | 295 passed, 3 failed |
| `a96f732b` (the content of `f76665d3`) | **FAIL** | **FAIL** | **FAIL** | ok | ok | ok | 295 passed, 3 failed |
| the `qzy3` fix (`181393fd`) | ok | ok | ok | ok | ok | ok | 298 passed, 0 failed |

IDENTICAL ON THE FIRST TWO, which is the point worth keeping: the defect is NOT something the recent work introduced. It
is older than every revision in the table, and this case is the first thing in the suite that would have caught it. The
third row is what the fix buys, and it is the discrimination that makes the case a measurement rather than a
description.

READING THE TABLE HONESTLY, because three of six assertions carry the red and three do not. 38a-38c are the ones that
distinguish a fixed tool from a broken one. 38d passes on the broken revisions too, because the current wording already
mentions `origin/fleet/cur38` - it is there so a fix cannot quietly drop the branch name while satisfying 38c. And 38e
is a CONTROL IN THE OPPOSITE DIRECTION from the usual one: it does not go red on the defect, it goes red on a LAZY FIX.
A patch that simply stopped stripping labels in this arm would satisfy 38a-38c and fail 38e, because an UNSPENT
clearance must still be invalidated. That is the assertion that makes the other three evidence rather than a
description.

AND THE FIXTURE ITSELF HAD TO BE CORRECTED, recorded because it is the same class of error as the readings above: the
first version set `refs/remotes/origin/main` to `main`'s own tip, which does NOT make the reviewed commit an ancestor,
because that commit is a DESCENDANT of main. The spent case therefore failed for a fixture reason rather than for the
defect, and an unspent-looking fixture cannot show a spent clearance being kept. It now sets `origin/main` to the
reviewed commit. A case that fails on the ground truth is testing its own fixture.

The raw behaviour on the revision under test, from the same fixture setup:

    branch PRESENT : state=CURRENT   cleared=true
    branch DELETED : state=UNPINNED  cleared=false  rc=1
                     strips: bd update tk-1 --remove-label merge-queue --remove-label cleared:abcd123
                     text:   merge-queue clearance rejected: review verdict was PASS but named no commit SHA
