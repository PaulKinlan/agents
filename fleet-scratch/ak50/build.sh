#!/usr/bin/env bash
# ONE repeatable tree build with a guard: after this runs, the trees hold (B) + the complete assertion repairs and NO world edits.
set -e
python3 - <<'PY'
import subprocess, sys
sys.path.insert(0,"/tmp/ozmt")
from repairs2 import repairs
def sh(c, cwd=None):
    r=subprocess.run(c, shell=True, cwd=cwd, capture_output=True, text=True)
    assert r.returncode==0, (c, r.stderr)
for t,pats in (("B2",["p1.base.patch"]),("C2",["p1.base.patch","p2.base.patch"])):
    sh("rm -rf /tmp/ozmt/"+t); sh("cp -a /tmp/ozmt/A /tmp/ozmt/"+t)
    for p in pats: sh("patch -s -p1 --fuzz=0 < /tmp/ozmt/%s"%p, cwd="/tmp/ozmt/"+t)
    repairs("/tmp/ozmt/%s/tests/fleet-land-message.test.sh"%t)
    print("  %s: pristine + %s + complete assertion repairs"%(t," + ".join(pats)))
PY
python3 /tmp/ozmt/b_narrow.py
python3 /tmp/ozmt/deadarm.py
python3 - <<'PY'
import subprocess
MUST=["src_author=\"$src_who\"", "_cue_is_self_claim", "transcription-without-registered-lane", "author-withdrawal", "cue-contradicts-lane"]
for t in ("B2","C2"):
    h="/tmp/ozmt/%s/bin/fleet-land-message"%t; s=open(h).read()
    for m in MUST: assert m in s, (t,"missing (B) marker: "+m)
    assert "unestablished-author" not in s, (t,"blanket refusal is back")
    assert subprocess.run(["bash","-n",h]).returncode==0
    ts="/tmp/ozmt/%s/tests/fleet-land-message.test.sh"%t
    assert subprocess.run(["bash","-n",ts]).returncode==0
    n=sum(1 for l in open(ts) if l.startswith("printf '%s' '"))
    assert n==0, (t,"world edits present in the base: %d"%n)
    print("  GUARD OK %s: (B) markers present, no blanket refusal, parses, NO world edits, helper %s"%(t, subprocess.run(["sha256sum",h],capture_output=True,text=True).stdout[:12]))
PY
