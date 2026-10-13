import sys
def block(L, start_pred, indent):
    i=next(k for k,l in enumerate(L) if start_pred(l))
    depth=0; j=i
    while True:
        s=L[j].strip()
        if s.startswith("if ") or s=="if": depth+=1   # elif/else are NOT new levels: counting them swallowed 67 lines
        if s=="fi":
            depth-=1
            if depth==0: break
        j+=1
    return i,j
def fix(path):
    L=open(path).read().split("\n")
    # ---- 1. the strip block: keep src_lane from the branch ONLY, and add the LAST-RESORT author (coord (B)) ----
    i,j=block(L, lambda l: l.strip().startswith('if [ -z "$src_lane" ] && [ -n "$src_who" ]; then'), 0)
    assert j-i<=14 and 'src_author_source="summary-author"' in "\n".join(L[i:j+1]), (path, j-i)
    L[i:j+1]=['if [ -z "$src_lane" ] && [ -n "$src_who" ]; then',
      '  # THE STRIP IS GONE (agents-ak50(b)): a LANE was derived here by removing a VM prefix from whoever appended the',
      '  # summary. That was a derivation from the wrong object AND its product did not stay local - it fed the',
      '  # $HOME/.fleet/lanes/<lane>.model lookup, so a coordinator-appended summary could hand the comparison the',
      '  # coordinator lane\'s own model. src_lane now comes from the BRANCH or not at all.',
      '  # coord (B) 2026-10-13: the appender may still supply a DIAGNOSTIC author, so attribution, the pool split and the',
      '  # reported fields keep working - but a last-resort author can never supply a CLEARANCE. The two places that could',
      '  # turn it into one are closed below: a cue used as the comparator by the party being checked, and a transcription',
      '  # clearing without a registered lane.',
      '  src_author="$src_who"',
      '  src_author_source="summary-author"',
      'fi']
    # ---- 2. the blanket refusal goes: (B) narrows it to a clearance rule ----
    i,j=block(L, lambda l: l.strip().startswith('if [ "$src_author_source" = "summary-author" ]; then'), 0)
    assert 'unestablished-author' in "\n".join(L[i:j+1]), path
    L[i:j+1]=[]   # no blanket refusal: unregistered costs a CLEARANCE, not a landing
    # ---- 3. the cue is a claim, and WHOSE claim decides how it may be used ----
    i,j=block(L, lambda l: l.strip().startswith('if [ -n "$_cue_author_model" ] && [ -z "$_cue_block" ]; then'), 0)
    assert 'untrusted-author-claim' in "\n".join(L[i:j+1]) or 'cue-contradicts-lane' in "\n".join(L[i:j+1]), path
    L[i:j+1]=['# THE CUE IS A CLAIM, AND WHOSE CLAIM IT IS DECIDES HOW IT MAY BE USED (coord (B), the field rule).',
      '#  * verdict posted by the AUTHOR\'S OWN LANE: the cue is the checked party\'s claim about itself, so it can never be',
      '#    the comparator. With no lane record the author-pool path above yields incomplete-provenance, which is refused.',
      '#  * verdict posted by ANOTHER lane: the cue is that INDEPENDENT reviewer\'s own statement of who it reviewed, and with',
      '#    no lane record to contradict it, it is the only operand there is - usable as the comparator.',
      '#  * a lane record IS present and the cue contradicts it: a REFUSAL printing both values (coord (B) clause 2).',
      '_cue_is_self_claim=""',
      'if [ -n "$_author_ref" ] && [ "$rev_who" = "$_author_ref" ]; then _cue_is_self_claim=1; fi',
      'if [ -n "$_cue_author_model" ]; then',
      '  if [ -n "$rev_author_model" ]; then',
      '    if [ "$(fleet_verdict_model_family "$_cue_author_model")" != "$(fleet_verdict_model_family "$rev_author_model")" ] && [ -z "$_cue_block" ]; then',
      '      _cue_block="cue-contradicts-lane"',
      '    fi',
      '  elif [ -z "$_cue_is_self_claim" ] && [ -z "$_cue_block" ]; then',
      '    rev_author_model="$_cue_author_model"',
      '    rev_author_model_source="verdict cue (independent verdict, no registered lane for ${src_lane:-the branch})"',
      '  fi',
      'fi']
    # ---- 4. a transcription may only CLEAR when the lane is registered ----
    k=next(n for n,l in enumerate(L) if l.startswith('  if [ -n "$_author_ref" ] && [ "$rev_who" = "$_author_ref" ] && [ "$rev_independence" = "cross-family" ]; then'))
    L[k:k+1]=[L[k],
      '    if [ "${src_author_source:-}" != "branch-name" ]; then',
      '      # coord (B) clause (ii) / variant 2: a transcription can only CLEAR when the LANE IS REGISTERED. Here the',
      '      # comparator came from an explicit --author-model operand while the lane is not registered, so the clearance is',
      '      # refused and both values are named rather than falling through to a clear.',
      '      _cue_block="transcription-without-registered-lane"',
      '      rev_run_reason="the author operand ${rev_author_model:-<none>} does not make the lane registered (source: ${src_author_source:-unknown}); register ~/.fleet/lanes/${src_lane:-<branch-lane>}.model, or have the branch lane post the verdict"',
      '    else']
    m=next(n for n in range(k,len(L)) if L[n]=="  fi" and n>k)
    L[m+1:m+1]=['    fi']
    # ---- 5. wire the new class into the gate, or the guard is decorative ----
    g=next(n for n,l in enumerate(L) if l=="      same-family)")
    L[g:g]=['      transcription-without-registered-lane)',
      '        rev_cleared=false',
      '        rev_block="independence: transcription-without-registered-lane ($rev_run_reason) - the verdict was posted by the branch author\'s own lane (a transcription) and the comparator came from an operand rather than a REGISTERED lane record. A transcription can only clear when the lane is registered (coord (B)); an unregistered author costs the clearance, not the landing."',
      '        ;;']
    open(path,"w").write("\n".join(L)); print("  (B) applied to", path)
for t in ("B2","C2"): fix("/tmp/ozmt/%s/bin/fleet-land-message"%t)
