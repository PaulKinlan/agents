for t in ("B2","C2"):
    p="/tmp/ozmt/%s/bin/fleet-land-message"%t; L=open(p).read().split("\n")
    i=next((k for k,l in enumerate(L) if l.strip()=="unestablished-author)"), None)
    if i is None: continue
    assert L[i+1].strip()=="rev_cleared=false" and L[i+2].strip().startswith('rev_block="independence: unestablished-author')
    j=next(k for k in range(i,len(L)) if L[k].strip()==";;")
    del L[i:j+1]; open(p,"w").write("\n".join(L)); print("  %s: dead arm removed"%t)
