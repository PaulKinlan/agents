# tools/fast-gate-arms.d/075-factory_identity.sh — 1 arm(s). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_075_factory_identity() {
  case "$1" in
    .factory-identity)
      # agents-hc2wp: this file IS the repository's self-target identity. Every checkout carries it,
      # and `agents/threat-model/scripts/mine_history.py` decides "is this the Software Factory?"
      # by comparing a target's copy BYTE-FOR-BYTE with the installation's - the only identity
      # probe that still answers inside the os sandbox, where a linked worktree's object database
      # is outside the read scope. Editing the marker (any byte) therefore changes who the pre-pass
      # recognises, in exactly the direction the noise/sink trade-off is graded, so the suite that
      # owns that contract is the one that must run. It is also read by every fixture in that suite:
      # the fixtures copy the committed bytes rather than inventing them, so a marker change is a
      # fixture change.
      mapped="$mapped tests/test_threat_model_prepass.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_075_factory_identity"
