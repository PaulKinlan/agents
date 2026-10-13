# THE SHAPE, verified in isolation before it was ever written into the tree:
#   declare thing2 (+coord) -> run() -> 0 files -> re-declare delta1 -> exactly 1 file.
# Install immediately after `echo main > "$HOME/.fleet/default-branch"`, and wrap run() with the post-reset.
# --- the world a case declares -------------------------------------------------
# The author identity comes from the BRANCH, so a case whose subject is the author lane has to DECLARE the lane record
# its branch would have in a real landing. One line per case: lane_fixture <lane> <model> [...]. A declaration starts
# from an EMPTY world, and run() resets it after every invocation - so no case can inherit another's world. That is the
# isolation the scattered mkdir/printf/rm triples were reaching for, in one place that cannot drift. lane_actor gives the
# actor a fixture's comments should carry for a lane, so a transcription case is visible rather than inferred.
LANE_DECLARED=()
lane_reset() { local l; for l in ${LANE_DECLARED[@]+"${LANE_DECLARED[@]}"}; do rm -f "$HOME/.fleet/lanes/$l.model"; done; LANE_DECLARED=(); }
lane_fixture() {   # lane_fixture <lane> <model> [<lane> <model> ...]
  lane_reset; mkdir -p "$HOME/.fleet/lanes"
  while [ "$#" -ge 2 ]; do printf '%s' "$2" > "$HOME/.fleet/lanes/$1.model"; LANE_DECLARED+=("$1"); shift 2; done
}
lane_actor() { printf '%s' "${FLEET_VM:-test-vm}-$1"; }
# and replace the runner line with:
# run() { GATE_FIXTURE="$ROOT/fix/gate.json" timeout 60 bash "$LM" "$@" 2>&1; local _rc=$?; lane_reset; return $_rc; }
