# tools/fast-gate-arms.d/250-beads.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_250_beads() {
  case "$1" in
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
    .beads/*)
      # The scanner never sees these: it skips dot dirs and .beads is in DEFAULT_IGNORE_DIRS
      # (lib/exclusions.py:23-43). Search performed: every .beads reference in tests mkdirs
      # its own tmp fixture (test_bd_json_contract.py:64, test_factory_core.py:727, test_sinks.py:92,
      # test_store_lock_timeout.py:277) - none reads the committed files. agents-xgha: the three
      # corrected numbers were 190/4/4 lines stale; the fourth (:64) held, and THAT is why this list
      # was reported at a different size every time it was scanned. Each number below is that suite's
      # own `.beads` fixture line.
      ;;
    # --- Ignored agent configuration (agents-l80j) --------------------------------------
    # Six paths that no arm claimed, so a lane editing one of them could not get a green fast gate
    # at all. Each reason below records THE SEARCH PERFORMED AND ITS RESULT, including the three
    # shapes the WARNING above names - a WALKER, a GLOB, and a SUBPROCESS WITH A DEFAULT PATH -
    # because a path grep alone cannot prove a class is consumer-free.
    .codex/*)
      # Searches performed: `git grep -n -- '.codex/config.toml'`, `-- '.codex/hooks.json'`,
      # `-- 'config.toml'` and `-- 'hooks.json'` all return NO hits repo-wide. Both walkers a suite
      # runs against this tree skip leading-dot directories (agents/docs-drift/scripts/check_docs.py:492
      # and :155; agents/modern-web/scripts/scan_modern_web.py:1405), and no glob in tools/, lib/,
      # tests/ or agents/ matches `.codex/`. Default-path shape: the Codex CLI reads these when invoked
      # in a workspace - an external AGENT does that, not a suite; the files are the `bd setup codex`
      # integration (AGENTS.md:375) binding lifecycle events to `bd codex-hook <event>`
      # (.codex/hooks.json:7,19,31,43), and no suite runs those hooks.
      ;;
    .agents/skills/beads/agents/openai.yaml)
      # Searches performed: `git grep -n -- 'openai.yaml'` and `-- 'openai.yml'` return NO hits
      # repo-wide; the file's own field names (display_name / short_description / default_prompt,
      # :2-4) match only the file itself. The directory is dot-prefixed so both walkers skip it
      # (check_docs.py:492,:155); no glob matches it - the SKILL.md arm at 180-agents_SKILL_md.sh:7 is
      # rooted at `agents/`, not `.agents/`. The skill-interface file the external agent reads is the
      # hub copy under ~/.agents/skills, installed FROM the factory's agents/ directory
      # (install.sh:138,153), never this repo's .agents/ copy.
      ;;
    .claude/settings.json)
      # Searches performed: the only repo-wide hit for the path is lib/adapters/claude.sh:99-100,
      # a comment about the TARGET repository's file recording that the factory neutralises it with
      # `--restricted` (passed at claude.sh:108; the flag is pinned at
      # tests/test_containment_adapters.py:204,624 - a pin on the FLAG, not on this file's content).
      # `git grep -n 'SessionStart\|hook-json\|bd prime' -- tests/ tools/ lib/` returns NO hits, so no
      # suite reads the committed file. Dot dir, so both walkers skip it (check_docs.py:492,:155);
      # no glob matches.
      ;;
    .agents/skills/beads/SKILL.md)
      # Searches performed: `git grep -n -- '.agents/skills/beads/SKILL.md'` repo-wide returns a prose
      # pointer (AGENTS.md:378) and this repo's own gate fixtures; the docs-drift scanner - the only
      # station walker a suite runs against this repo (tests/test_docs_drift.py:108,195,382) - skips
      # dot dirs twice (agents/docs-drift/scripts/check_docs.py:492, :155), so it never opens the file;
      # no glob matches it; install.sh:138,153 and the factory's loader read the factory's own
      # agents/*/SKILL.md, not this .agents/ copy. It is the beads-integration document this repo
      # tracks for its own agents, with no suite that fails on its content.
      ;;
    skills)
      # Searches performed: a repo-wide grep for references to the path (the pattern
      # `skills/` plus the quoted forms `"skills"` and `skills"`, over tests, tools, lib and
      # agents, excluding .agents/skills/*) returns only unrelated hits - three
      # ~/.gemini/plugins/*/skills/ paths (agents/memory-profile/SKILL.md:9,
      # agents/memory-profile/scripts/scan_memory_leaks.py:130, agents/resilience/SKILL.md:9) and a
      # command-name check (tools/gen_site.py:571) - so nothing reads this path. It is a SYMLINK to
      # agents/ (`readlink skills` -> agents), i.e. the same tree under a second name; the installer
      # sources the real directory (install.sh:138 AGENTS_SRC="$FACTORY_DIR/agents"), no walker roots
      # itself at `skills/`, and no other arm names it.
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_250_beads"
