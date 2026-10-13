# The COMPLETE set of assertion-side repairs, so build.sh produces a reproducible base with no post-build edits.
def repairs(path):
    s=open(path).read()
    # 39a/39b's structural counter: awk-based (numeric by construction, no escaping to get wrong)
    import re
    s=re.sub(r"^_lm_awk_all=.*$", """_lm_awk_all=$(awk '/awk -F/ && /-v a=/ {n++} END{print n+0}' "$LM")""", s, count=1, flags=re.M)
    s=re.sub(r"^_lm_awk_ref=.*$", """_lm_awk_ref=$(awk '/-v a="\\$_author_ref"/ {n++} END{print n+0}' "$LM")""", s, count=1, flags=re.M)
    s=re.sub(r"^_lm_awk_probe=.*$", """_lm_awk_probe=$(awk '/-v a="\\$_author_ref"/ {n++} END{print n+0}' "$_lm_probe_file")""", s, count=1, flags=re.M)
    # a control sample, so a zero cannot be an empty match (39b's lesson, in the same escaping class)
    if "_lm_probe_file=$(mktemp)" not in s:
        anchor='# the operands must be non-empty, or this pin cannot fail and would pass on a missing file - the lesson of four MATCH'
        assert anchor in s, "guard anchor"
        guard=('# THE INVERTED EMPTINESS GUARD: a count that cannot match anything cannot fail, so prove the ref pattern\n'
               '# matches a KNOWN sample before trusting a zero.\n'
               '_lm_probe_file=$(mktemp)\n'
               "printf '%s\\n' '  x=$(awk -F'\"'\"'\\t'\"'\"' -v a=\"$_author_ref\" '\"'\"'$2 == a'\"'\"' <<<\"$POOL_TIP\")' > \"$_lm_probe_file\"\n"
               '_lm_awk_probe=$(awk \'/-v a="\\$_author_ref"/ {n++} END{print n+0}\' "$_lm_probe_file")\n'
               'rm -f "$_lm_probe_file"\n')
        s=s.replace(anchor, guard+anchor, 1)
    # 36i4/37f: under the field rule a last-resort author still ESTABLISHES a transcription; it cannot clear on it
    s=s.replace('"false" "36i4 the tip verdict is NOT claimed as an author-lane transcription when the branch author is unestablished"',
                '"true" "36i4 the tip verdict IS an author-lane transcription when the vote came from the same actor that appended the summary (a last-resort author still establishes a transcription; it cannot clear on it)"',1)
    s=s.replace('"0" "37f no verdict is attributed to an author lane when the branch author is unestablished"',
                '"1" "37f a verdict IS attributed to the author lane when the vote came from the same actor that appended the summary"',1)
    open(path,"w").write(s)
