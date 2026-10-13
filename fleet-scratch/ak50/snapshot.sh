#!/usr/bin/env bash
# copy a run's outputs to label-stable names, so a later run can never overwrite the evidence
L="${1:-run}"; cd /tmp/ozmt
for f in suite-red.out suite-green.out redfirst.result; do [ -f "$f" ] && cp "$f" "$L.$f"; done
for f in "$L".suite-red.out "$L".suite-green.out; do [ -f "$f" ] && echo "  $f: $(tail -1 "$f")"; done
