# A changed target inventory must run the assertion that reads its real markdown rows.
# Keep this exact-path arm separate from targets/*.yaml; changing other target selection
# would broaden the gate beyond this documentation pin.
fast_gate_arms_215_targets_README_md() {
  case "$1" in
    targets/README.md)
      # tests/test_target_readme_inventory.py compares every listed sink against the
      # named target manifest. A wrong sink in the README fails this suite; walking
      # markdown for drift candidates alone does not assert the inventory's content.
      mapped="$mapped tests/test_target_readme_inventory.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_215_targets_README_md"
