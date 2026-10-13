#!/usr/bin/env bash
# Restore the ak50-M state EXACTLY, in three steps, each of which is checked:
#   1. build.sh            -> guarded base: (B) + the complete assertion repairs, no world edits, no shape
#   2. install the shape   -> by SED EXTRACTION from shape.sh, never re-typed
#   3. declare 14 worlds   -> the declarations that did not move the control
# Target state: red 362/6 (control = precisely the six discriminators), green 345/23, NO case failing on both sides.
# Written with the file tool on purpose: writing a script through a shell heredoc mangles backslash-n literals,
# which broke this script twice and build.sh once.
set -e
bash /tmp/ozmt/build.sh >/dev/null
echo "  step 1: base built and guarded"

NL=$(printf '\n_')
sed -n '/^LANE_DECLARED=()/,/^lane_actor/p' /tmp/ozmt/shape.sh > /tmp/ozmt/_helpers.txt
test "$(wc -l < /tmp/ozmt/_helpers.txt)" -ge 6 || { echo "  shape extraction failed"; exit 1; }
grep -q '^lane_fixture()' /tmp/ozmt/_helpers.txt || { echo "  shape extraction has no lane_fixture"; exit 1; }

for T in B2 C2; do
  S=/tmp/ozmt/$T/tests/fleet-land-message.test.sh
  grep -q '^LANE_DECLARED=()' "$S" && { echo "  shape already installed in $T"; continue; }
  # insert the helper block after the default-branch line, via a temp file built with sed (no shell interpolation)
  L=$(grep -n 'echo main > "$HOME/.fleet/default-branch"' "$S" | head -1 | cut -d: -f1)
  head -n "$L" "$S" > /tmp/ozmt/_new.sh
  cat /tmp/ozmt/_helpers.txt >> /tmp/ozmt/_new.sh
  tail -n "+$((L+1))" "$S" >> /tmp/ozmt/_new.sh
  # and wrap the runner so every invocation ends from a clean world
  sed -i 's|^run() { GATE_FIXTURE="$ROOT/fix/gate.json" timeout 60 bash "$LM" "$@" 2>&1; }$|run() { GATE_FIXTURE="$ROOT/fix/gate.json" timeout 60 bash "$LM" "$@" 2>\&1; local _rc=$?; lane_reset; return $_rc; }|' /tmp/ozmt/_new.sh
  grep -q 'lane_reset; return' /tmp/ozmt/_new.sh || { echo "  runner wrap failed in $T"; exit 1; }
  mv /tmp/ozmt/_new.sh "$S"
  echo "  step 2: shape installed in $T"
done

cat > /tmp/ozmt/_restore.py <<'PYEOF'
import re
LABELS = [("12a","delta1"),("12d","delta1"),("12p","delta1"),("12r","delta1"),("12t","delta1"),("12w","delta1"),
          ("25a","thing2"),("28b","thing2"),("30d","thing2"),("36b2","rebase5br9"),("36c","rebase5br9"),
          ("36d1","rebase5br9"),("36e1","rebase5br9"),("37e","delta1")]
NL = chr(10)
for t in ("B2","C2"):
    p = "/tmp/ozmt/%s/tests/fleet-land-message.test.sh" % t
    L = open(p).read().splitlines()
    n = 0
    for lab, lane in LABELS:
        i = next((k for k, l in enumerate(L) if re.search(r'\b%s\b' % lab, l) and not l.strip().startswith("#")), None)
        if i is None:
            print("  %s: label %s NOT FOUND" % (t, lab)); continue
        j = i
        while j > 0 and 'cat > "$B" <<J' not in L[j]:
            j -= 1
        close = next(x for x in range(j + 1, len(L)) if L[x].strip() == "J")
        run = next((x for x in range(close + 1, min(close + 28, len(L)))
                    if re.search(r'\brun\b.*fleet/%s\b' % lane, L[x])), None)
        if run is None:
            print("  %s: no run for %s" % (t, lab)); continue
        body = NL.join(L[j:close + 1])
        mm = re.findall(r'(?:vs )?implementer ([A-Za-z0-9/._-]+?)\.?[\s,\\")\\n]', body)
        model = mm[-1] if mm else "deepseek/deepseek-flash"
        L[run:run] = ["lane_fixture %s '%s'   # declared world (%s)" % (lane, model, lab)]
        n += 1
    open(p, "w").write(NL.join(L))
    print("  step 3: %s has %d declaration(s)" % (t, n))
PYEOF
python3 /tmp/ozmt/_restore.py
bash -n /tmp/ozmt/B2/tests/fleet-land-message.test.sh
bash -n /tmp/ozmt/C2/tests/fleet-land-message.test.sh
echo "  restored. Target: red exactly the six pins, green 23, no case failing on both sides."
