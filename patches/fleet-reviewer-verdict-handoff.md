## fleet-reviewer-verdict-handoff.patch (agents-53l0)

**Kind:** HUB-DELIVERY artifact for `PaulKinlan/fleet`, `roles/reviewer.md` ONLY. Landing this artifact in `PaulKinlan/agents` is **not** installation on any VM. The hub must apply it against the verified preimage and read back the installed role. Do not change `bin/fleet-land-message`: its refusal to infer a verdict from prose is correct.

| Object | SHA-256 |
|---|---|
| `roles/reviewer.md` verified VM preimage | `ad225a927e292365019947390c1b9275fc2eeb9f434e23e0e237fd4d17f001a8` |
| `roles/reviewer.md` expected post-apply | `eec4dac15a923177cf535418ccdb2f8a512e390f874e58f46cf74eacc9983ca8` |
| `patches/fleet-reviewer-verdict-handoff.patch` | `d6efd1ec927c6b00e686a949977198333ba99adaddf9f902d434ca6af001d26b` |

### Why this file, not a new checker

`~/fleet/roles/reviewer.md` is the mechanism reviewers already follow. Its old lines 69-106 gave a verdict template and `cleared:<tip-short>` recipe without naming the bead the merge queue consumes or requiring a readback before a reviewer sends a PASS message. The merger's existing missing-verdict refusal is correct. A standalone checker in this project would not be invoked by the reviewer or hand-over, so this change is the *minimal hub role brief*, not a new tool or a parser change.

The role now says which object to use when the assignment differs from the deliverable (post to the deliverable and name the discrepancy to coord), puts one commit-pinned `VERDICT:` on the FIRST LINE of a comment on that object, applies `cleared:<tip-short>` there for PASS, and requires reading the latest comment plus **structured** Beads `status` and `labels` before any 'review complete' lane message. If the readback fails or the clearance is missing, the reviewer withholds PASS and says BLOCKED. That ordering is the guard; a comment on a finding or a predecessor, or PASS sent only as a lane message, cannot satisfy it. The patch does not alter fleet canon here and a project merge does not install it.

**Scope limit:** These are reviewer instructions with an explicit early readback, not an independently enforced daemon. Coord must identify the deliverable bead in the hand-off; a reviewer cannot deduce the right human work item from a standalone verdict token. The installed merger remains the final fail-closed boundary.

### Focused control (exact installed parser, disposable repository)

The following control ran against the current `~/fleet/bin/fleet-land-message` in an isolated Git fixture. It does not write the live Beads DB or fleet canon. Run from any clone on a VM with that helper installed; the contents of the stub Beads responses, not ambient machine state, determine the result:

```bash
timeout -k 20 100 python3 - <<'PY'
import json, os, shutil, subprocess, tempfile
from pathlib import Path
fleet=Path.home()/'fleet'
def call(cwd,env,*argv,ok=True):
    r=subprocess.run(argv,cwd=cwd,env=env,capture_output=True,text=True,timeout=25)
    if ok: assert r.returncode==0,(argv,r.stderr)
    return r
with tempfile.TemporaryDirectory(prefix='review-object-') as t:
    p=Path(t); home=p/'home'; b=home/'fleet'/'bin'; b.mkdir(parents=True)
    (home/'.fleet').mkdir(); (home/'.fleet'/'default-branch').write_text('main\n')
    for name in ('fleet-land-message','fleet-verdict-words.sh'):
        shutil.copy2(fleet/'bin'/name,b/name)
    (b/'bd').write_text('#!/bin/bash\ncase "$1" in\n show) cat "$FIX/$2-show.json";;\n comments) cat "$FIX/$2-comments.json";;\n dep) echo "[]";;\n *) echo "[]";; esac\n')
    (b/'bd').chmod(0o755)
    (b/'fleet-check').write_text('#!/bin/bash\necho \'{"state":"NONE"}\'\n')
    (b/'fleet-check').chmod(0o755)
    env=dict(os.environ,HOME=str(home),FIX=str(p),PATH=f'{b}:'+os.environ['PATH'],FLEET_VM='test-vm')
    repo=p/'repo'; repo.mkdir()
    call(repo,env,'git','init','-q','-b','main')
    call(repo,env,'git','-c','user.name=Probe','-c','user.email=p@invalid','commit','-q','--allow-empty','-m','base')
    base=call(repo,env,'git','rev-parse','HEAD').stdout.strip()
    call(repo,env,'git','checkout','-q','-b','fleet/item')
    (repo/'changed').write_text('real change\n')
    call(repo,env,'git','add','changed')
    call(repo,env,'git','-c','user.name=Probe','-c','user.email=p@invalid','commit','-q','-m','change')
    tip=call(repo,env,'git','rev-parse','HEAD').stdout.strip()
    call(repo,env,'git','update-ref','refs/remotes/origin/fleet/item',tip)
    call(repo,env,'git','update-ref','refs/remotes/origin/main',base)
    def c(author,text): return dict(author=author,created_at='2026-10-14T20:00:00Z',text=text)
    summary=c('test-vm-impl','LAND-SUMMARY\nWHAT: file added\nWHY: needed\nEFFECT: none: internal')
    review=c('test-vm-rev',f'VERDICT: PASS @{tip} (reviewer qwen-token-plan-individual/qwen3.8-max; author openai-codex/gpt-6-sol)\nDelta: good {base[:7]}..{tip} branch fleet/item\n')
    for bead in ('good','finding'):
        (p/f'{bead}-show.json').write_text(json.dumps([dict(id=bead,title=bead,description='branch fleet/item',labels=['merge-queue'])]))
    def set_comments(good,finding):
        (p/'good-comments.json').write_text(json.dumps(good))
        (p/'finding-comments.json').write_text(json.dumps(finding))
    def check(bead):
        r=call(repo,env,str(b/'fleet-land-message'),'--print-json',bead,'fleet/item')
        j=json.loads(r.stdout); return j['review']['state'],j['summary']['comment_index'],j['review']['cleared']
    set_comments([summary],[])
    message=call(repo,env,str(b/'fleet-land-message'),'good','fleet/item',ok=False)
    assert message.returncode!=0 and 'no review verdict found on bead good' in message.stderr
    print('message-only:',check('good'))
    set_comments([summary],[review])
    print('finding verdict, ask deliverable:',check('good'))
    print('finding verdict, ask finding:',check('finding'))
    assert check('good')==('NONE',0,False) and check('finding')==('CURRENT',None,True)
    set_comments([summary,review],[])
    print('deliverable verdict, ask deliverable:',check('good'))
    assert check('good')==('CURRENT',0,True)
PY
```

Actual result (fixture commit SHA varies; state/summary/clearance do not):

```
message-only: ('NONE', 0, False)
finding verdict, ask deliverable: ('NONE', 0, False)
finding verdict, ask finding: ('CURRENT', None, True)
deliverable verdict, ask deliverable: ('CURRENT', 0, True)
```

The normal landing path in the message-only fixture returned nonzero and printed `REFUSING: no review verdict found on bead good ... merge-queue label left as it was` — do not remove this refusal. The paired finding-bead probe matters: `CURRENT` on the *wrong* bead is not evidence for the deliverable. The role now requires the reviewer to read back the comment and structured label/status **on the actual deliverable** before sending PASS; this is earlier than the merger's refusal, and does not relax it.

### Apply and verify (hub owner only)

1. Verify the hub-canonical `roles/reviewer.md` SHA-256 above immediately before applying; if it differs, **do not force** this patch: re-cut on the actual hub preimage.
2. Copy the verified canon preimage into an isolated scratch repository; `patch --fuzz=0 -p1 < patches/fleet-reviewer-verdict-handoff.patch` with rc 0, no rejects or offsets, then verify the post SHA-256. If the hub uses a different preimage, **re-cut** rather than force applying. Never edit/reset the project's `~/fleet` mirror on this VM.
3. Exercise a fresh different-family reviewer with a genuine deliverable and a mismatched-finding control. Read the structured `bd comments ... --json` / `bd show ... --json` fields on the deliverable: latest first line `VERDICT:` with reviewed tip, label list with `cleared:<tip-short>` on PASS, and `status` as the real field, not the display glyph. Verify the reviewer withholds PASS when the wrong bead is returned. A project's fast gate or project merger alone is not this installed-role proof.
