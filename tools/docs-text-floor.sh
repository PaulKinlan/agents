#!/usr/bin/env bash
# docs-text-floor.sh - measure the RENDERED font size of every text-bearing leaf element on every docs page,
# and report any element below a floor (default 12px). agents-e3aw.
#
# WHY THIS EXISTS: the ui-ux-audit rule that found four sub-12px labels reads DECLARATIONS, so it can miss a size
# that becomes too small at render time (an inherited or relative value, a value set by another stylesheet, an
# inline style). This measures what the browser actually paints. It is also the check that would catch a FIFTH
# site rather than assuming the four known ones are all of them.
#
# USAGE
#   docs-text-floor.sh [--docs DIR] [--floor PX] [--inject-fifth-site]
# Exit: 0 = nothing below the floor; 1 = offenders found (printed); 2 = usage/setup error.
#
# A TOOL THAT REPORTS ITS OWN BREAKAGE IS WORTH MORE THAN ONE THAT REPORTS NOTHING, and this one is loud on
# purpose. Both of the defects found while building it were found by RUNNING it: `set -e` with `pipefail` killed the
# script the first time a page produced no result, before its own error branch could run (hence NO RESULT rather
# than silence), and a placeholder substitution also matched the marker text it was printing. If an edit makes
# every page print NO RESULT, suspect the injected JS first - that is the tool telling you it is broken.
#
# --inject-fifth-site is the CONTROL: it adds a synthetic label at 11px to a copy of one page, so the sweep has to
# go red. A sweep that cannot fail proves nothing, and this flag is how you show it can.
set -euo pipefail
# tools/ sits one level under the repo root, so the default docs dir is resolved from the script's parent.
docs="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)/docs"
floor=12
inject=0
while [ $# -gt 0 ]; do
  case "$1" in
    --docs) docs="$2"; shift 2;;
    --floor) floor="$2"; shift 2;;
    --inject-fifth-site) inject=1; shift;;
    *) echo "usage: $0 [--docs DIR] [--floor PX] [--inject-fifth-site]" >&2; exit 2;;
  esac
done
[ -d "$docs" ] || { echo "no docs dir: $docs" >&2; exit 2; }
# A sweep that measures nothing cannot fail, so it must not report a verdict. Without this guard an empty
# docs dir left the glob literal, the tool measured a file called "*.html", got no answer, and exited 0 -
# a clean run for a tree it never looked at (measured while writing tests/test_docs_text_floor.py).
# Builtin glob only: a guard written with `ls` misfires in exactly the environment where the tool is being
# asked whether its PATH is usable - measured, with PATH emptied it reported "nothing to measure" for a docs
# dir holding six pages. `set --` overwrites the positional parameters, which the option parsing above has
# finished with.
set -- "$docs"/*.html
[ -e "$1" ] || { echo "no *.html pages in $docs: nothing to measure" >&2; exit 2; }
chrome="$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || true)"
[ -n "$chrome" ] || { echo "no chrome/chromium on PATH" >&2; exit 2; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp -r "$docs"/. "$work"/
if [ "$inject" = 1 ]; then
  # The control patches the measured copy: a rule in css/factory.css and a label in index.html. If either target is
  # absent the control CANNOT fire, and it has to say so. Measured before this guard existed, pointed at a tree
  # without css/factory.css: "/tmp/.../css/factory.css: No such file or directory" and exit 1 with NO RESULT on
  # every page - a control that reports nothing is the failure mode this tool exists to expose. The label is
  # checked for AFTER the patch for the same reason: a page with no `</body>` takes no label, and the sweep would
  # then have gone on to report a clean run for a control it never actually applied.
  if [ ! -f "$work/css/factory.css" ] || [ ! -f "$work/index.html" ]; then
    echo "CONTROL UNAVAILABLE: --inject-fifth-site patches docs/css/factory.css and docs/index.html; $docs lacks one of them" >&2
    exit 2
  fi
  printf '\n.__fifth_site { font-size: 11px; }\n' >> "$work/css/factory.css"
  python3 - "$work" <<'PY'
import sys, pathlib
page = next(pathlib.Path(sys.argv[1]).glob("index.html"), None)
if page:
    page.write_text(page.read_text().replace("</body>", '<p class="__fifth_site">synthetic fifth site</p></body>', 1))
PY
  if ! grep -q '__fifth_site' "$work/index.html"; then
    echo "CONTROL UNAVAILABLE: the synthetic label did not reach the measured index.html (no </body> to patch)" >&2
    exit 2
  fi
fi
# The measuring script runs INSIDE each page and writes its verdict into the DOM, which --dump-dom then prints,
# so this needs no CDP client and no library - only a browser.
payload='<script>window.addEventListener("load",function(){var f=__FLOOR_PX__, out=[], else_=0, SKIP={SCRIPT:1,STYLE:1,TITLE:1,META:1,LINK:1,HEAD:1,BASE:1,NOSCRIPT:1,TEMPLATE:1}; document.querySelectorAll("*").forEach(function(el){ if(SKIP[el.tagName]) return; if(el.children.length) return; if(!el.textContent.trim()) return; var px=parseFloat(getComputedStyle(el).fontSize); if(px<f) out.push((el.tagName.toLowerCase())+"."+(el.className||"-")+"="+px.toFixed(2)+"px"); }); var d=document.createElement("div"); d.id="__floor_result"; d.textContent="FLOOR_RESULT page="+location.pathname.split("/").pop()+" floor="+f+"px below="+out.length+(out.length?(" ["+out.slice(0,10).join(", ")+"]"):""); document.body.appendChild(d); });</script>'
python3 - "$work" "$floor" "$payload" <<'PY'
import sys, pathlib
work, floor, payload = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
payload = payload.replace("__FLOOR_PX__", str(int(floor)))  # a NUMBER: the unit is added in the message, not in the expression  # a placeholder that cannot collide with the marker text
for page in sorted(work.glob("*.html")):
    page.write_text(page.read_text().replace("</body>", payload + "</body>", 1))
PY
fail=0
for page in "$work"/*.html; do
  dom="$("$chrome" --headless=new --disable-gpu --no-sandbox --virtual-time-budget=4000 --dump-dom "file://$page" 2>/dev/null || true)"
  # Match the ELEMENT, not the script source that also contains the literal (the id prefix makes it unique),
  # and keep `set -e` from killing the script when a page produces no result at all.
  line="$(printf '%s' "$dom" | grep -o '__floor_result">[^<]*' | tail -1 | sed 's/.*>//' || true)"
  [ -n "$line" ] || { echo "  $page: NO RESULT (page did not run the measuring script)" >&2; fail=1; continue; }
  echo "  $line"
  case "$line" in *"below=0"*) ;; *) fail=1;; esac
done
exit $fail
