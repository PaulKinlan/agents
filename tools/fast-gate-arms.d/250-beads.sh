# tools/fast-gate-arms.d/250-beads.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_250_beads() {
  case "$1" in
    .beads/hooks/*)
      # agents-kxbv: a git hook is CODE that runs on every commit in this repo, so unlike the rest of
      # .beads/ it is not "the scanner never sees it" material - it has a suite that fails on its
      # content (the fail-open policy and the bound). This arm must sit BEFORE the `.beads/*` ignore
      # below, because PRECEDENCE IS FIRST MATCH WINS.
      mapped="$mapped tests/test_beads_hook_fail_open.py"
      ;;
    # --- Ignore list (agents-9nir) -----------------------------------------------------
    # RULE: an ignore must be a DELIBERATE CASE ARM WITH A REASON, never a default.
    # "No arm" used to mean two different things - a considered exclusion and an
    # oversight - and they were indistinguishable, so every unmatched file was silently
    # masked by the smoke fallback below and the verdict read PASS for an unrelated
    # suite. The *) arm at the bottom fails loudly and NAMES any file no arm claims;
    # the smoke fallback after the loop is for ignored docs/config-only changes ONLY.
    # To exempt a path, add an arm here with the reason it needs no suite.
    # WARNING, learned the hard way (agents-9nir review, three instances in one bead): a
    # path grep cannot prove a path class is consumer-free, because a file can be consumed
    # WITHOUT BEING NAMED - by a WALKER (agents/*/SKILL.md via check_docs.py's os.walk),
    # by a GLOB (targets/*.yaml via lib/scheduler.py:140-144), and by a SUBPROCESS WITH A
    # DEFAULT PATH (tools.yaml via CONFIG_PATH / load_tool_pins in lib/tool_pins.py, read in
    # test_child_env.py's probes). Cited by SYMBOL, not by line: the line number this used to
    # name had drifted onto the FACTORY_TOOL_PINS override docstring (agents-lyqx).
    # So the reason in an ignore arm must record the SEARCH PERFORMED AND ITS RESULT,
    # never a judgement about who reads the path - a judgement is unfalsifiable, and that
    # is what made the original canvas `*.md` ignore arm's reason false.
    .beads/.gitignore|.beads/README.md|.beads/config.yaml|.beads/hooks/post-checkout|.beads/hooks/post-merge|.beads/hooks/pre-commit|.beads/hooks/pre-push|.beads/hooks/prepare-commit-msg|.beads/interactions.jsonl|.beads/metadata.json)
      # The scanner never sees these: it skips dot dirs and .beads is in DEFAULT_IGNORE_DIRS
      # (lib/exclusions.py:23-43). Search performed: every .beads reference in tests mkdirs
      # its own tmp fixture (test_bd_json_contract.py:64, test_factory_core.py:727, test_sinks.py:92,
      # test_store_lock_timeout.py:277) - none reads the committed files. agents-xgha: the three
      # corrected numbers were 190/4/4 lines stale; the fourth (:64) held, and THAT is why this list
      # was reported at a different size every time it was scanned. Each number below is that suite's
      # own `.beads` fixture line.
      # agents-3jb4 (P3, found while verifying agents-dxtx, which narrowed `.codex/*` for the same
      # reason): this arm was `.beads/*`, i.e. as broad as the DIRECTORY, and the directory is NOT inert -
      # it holds five executable git hooks (.beads/hooks/*), so the glob was a permanent exemption for
      # exactly the class of file the unmatched-path protection exists to catch. Reproduced with the glob:
      # FAST_GATE_DRY_RUN=1 GIT_CHANGED=.beads/unexpected.sh bash tools/fast-gate.sh -> rc 0 and an empty
      # suite list. The exemption is now the ten TRACKED paths, listed from
      # `git ls-tree -r --name-only origin/main .beads/`, so a new file in that directory resolves to
      # nothing and the gate refuses loudly and names it. A new tracked file under .beads/ must be added
      # here deliberately, with its own recorded search - and tests/test_fast_gate_mapping.py asserts both
      # halves of that (every tracked path exempt, every other path in the directory refused by name).
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_250_beads"
