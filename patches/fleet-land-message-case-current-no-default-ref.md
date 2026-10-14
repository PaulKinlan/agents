## A CURRENT landing with NO refs/remotes/origin/<default> must proceed: regression case for agents-7jco

THIS IS A `.md`-ONLY artifact on purpose: the suite it belongs to, `tests/fleet-land-message.test.sh`, lives on the hub
with `bin/fleet-land-message` and is in neither this repository nor the canonical checkout, so there is no patch of ours
to ship. What ships is the case text, DRIVEN and validated, so it goes over as a working artifact rather than as a
description of one.

## Where it goes and what it may assume

Append it to `tests/fleet-land-message.test.sh` immediately BEFORE the summary block (`if [ "$FAIL" -gt 0 ]; then`). It
uses only that file's own idiom and namespace: `ok`, `bad`, `has`, `hasnt`, `eq`, the `run()` helper, `$ROOT/repo`, `$B`
and `$ROOT/fix`, and `$LM` (so it honours `LM_OVERRIDE` and can be run against any revision). The suite counts its own
assertions, so no other edit is needed.

## The case

```bash
echo "36. agents-7jco: a CURRENT landing with NO refs/remotes/origin/<default> must proceed silently"
# This case builds its OWN branch rather than reusing one from an earlier section: the tip of a reused branch has
# been moved by sections 11 and 12, so the review would not be CURRENT and the case would fail for a reason that
# has nothing to do with the property under test. Independence is the point, not tidiness.
git -C "$ROOT/repo" checkout -q main
git -C "$ROOT/repo" checkout -q -b fleet/cur36
echo cur36 > cur36.txt
git -C "$ROOT/repo" add cur36.txt
git -C "$ROOT/repo" -c user.email=t@t -c user.name=t commit -q -m "feat: cur36
Release-note: none"
cur36_tip=$(git -C "$ROOT/repo" rev-parse --short fleet/cur36)
git -C "$ROOT/repo" update-ref refs/remotes/origin/fleet/cur36 "$cur36_tip"
git -C "$ROOT/repo" checkout -q main
# The shape that broke the ancestry half: no default-branch remote ref exists at all in this repository.
git -C "$ROOT/repo" update-ref -d refs/remotes/origin/main 2>/dev/null || true
if git -C "$ROOT/repo" rev-parse -q --verify refs/remotes/origin/main >/dev/null 2>&1; then
  bad "36a precondition: no refs/remotes/origin/main in the fixture" "the ref exists"
else
  ok "36a precondition: no refs/remotes/origin/main in the fixture"
fi
cat > "$ROOT/fix/show.json" <<'J'
[{"id":"tk-1","title":"Add the thing","description":"The thing was missing.","status":"open","priority":2,"labels":["merge-queue","cleared:abcd123"]}]
J
cat > "$B" <<J
[{"author":"proj-lane-1","created_at":"2026-10-12T10:00:00Z",
  "text":"LAND-SUMMARY\nWHAT: adds the thing to the widget.\nWHY: the widget had no thing.\nEFFECT: users see the thing."},
 {"author":"proj-rev-1","created_at":"2026-10-12T11:00:00Z",
  "text":"VERDICT: PASS\nDelta: tk-1 base..$cur36_tip branch fleet/cur36\nGate: fleet-check PASS for $cur36_tip"}]
J
out_cur=$(run tk-1 fleet/cur36); rc_cur=$?
eq "$rc_cur" "0" "36b a CURRENT landing with no origin/<default> succeeds (no refusal)"
has "$out_cur" "PASS (verdict: PASS) for commit $cur36_tip" "36c ...and the CURRENT verdict is still honoured"
hasnt "$out_cur" "cannot test whether" "36d ...and no ancestry note is emitted for a CURRENT landing"
hasnt "$out_cur" "is not an ancestor of refs/remotes/origin" "36e ...and no spent/invalidated wording either"
hasnt "$out_cur" "REFUSING" "36f ...and nothing is refused"
```

## It was driven, and the driving is what found a second defect

Each revision was staged BESIDE its sibling files, because `fleet-land-message` reads `fleet-verdict-words.sh` from its
own directory: a tool copied out alone refuses with "cannot read the shared verdict vocabulary" and every number taken
from such a staging is meaningless.

| revision | case 36 | whole suite |
|---|---|---|
| canon | 6 ok | 298 passed, 0 failed |
| `agents-p1c2` base | 6 ok | 298 passed, 0 failed |
| ancestry at OUTER SCOPE | **4 FAIL** | 231 passed, 67 failed |
| ancestry inside the arm, REF ABSENT refusing | 6 ok | **289 passed, 9 failed** |
| ancestry inside the arm, REF ABSENT following p1c2 | 6 ok | 298 passed, 0 failed |

**THIS CASE AND THE EXISTING NINE ARE NOT THE SAME TEST, which is the point worth taking.** Case 36 catches the
PLACEMENT defect: a CURRENT landing refused or annotated because the ancestry check sat at outer scope. It does NOT
catch the nine failures, because those are tip-moved landings with no default-branch ref, and the existing
`11f`, `11g`, `11g2`, `11h`, `11h2`, `11z`, `12g`, `12h`, `12k` cases already exercise them. Driving the case is what
showed that the second revision was nine short - a reviewer would otherwise have found it.

## The fixture lesson, because my first version got it wrong

The first version reused `fleet/thing`, whose tip sections 11 and 12 had ALREADY MOVED, so the verdict was not CURRENT
and the case failed **on canon too**. A case that fails on the ground truth is testing its own fixture. Running it
against canon is what caught that, not reading it - and it is the same order-dependence pathology a test that inherits
another test's state always has.
