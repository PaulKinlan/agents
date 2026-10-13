# tools/fast-gate-arms.d/180-agents_SKILL_md.sh — 3 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_180_agents_SKILL_md() {
  case "$1" in
    agents/*/SKILL.md)
      # The docs-drift scanner os.walk()s every committed .md outside IGNORE_DIRS (both walks live
      # in agents/docs-drift/scripts/check_docs.py, at :256 and :491; agents-xgha: the :466-478 range
      # cited here before is that file's markdown tree-block PREFIX parsing, which contains no walk)
      # and its real-tree suite pins the
      # agents/*/SKILL.md candidate set by count (tests/test_docs_drift.py:384-394). A path
      # grep cannot see this consumer - a walker consumes a CLASS of paths (agents-9nir review).
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    agents/*/agent.yaml)
      # Station manifests are read off the real tree: tests/test_docs_design.py globs
      # agents/*/agent.yaml to check stations.html, and the credential-grant drift guard
      # globs them for the same reason (agents-9nir review). guards: agents-3iog moved that
      # guard into tests/test_containment_declarations.py, which is why this arm now runs 25
      # declaration tests instead of the whole 220-test containment suite; the dispatcher
      # suite holds no station-manifest consumer (its manifests are tmp trees), measured by
      # mutating agents/accessibility/agent.yaml: this arm red, the others green.
      mapped="$mapped tests/test_docs_design.py tests/test_containment_declarations.py"
      ;;
    agents/*/report.schema.json)
      # agents-9iyf. A MAPPING, not an ignore arm, and the chain is measured rather than
      # assumed: every agent.yaml names this file under output.schema (lib/report_schema.py:4),
      # lib/report_schema.py:38 validate() checks a model's report against that declared schema
      # subset at runtime, and tests/test_report_schema.py is that module's contract suite. So
      # the committed schema is not a test INPUT (see the search below) but the contract of the
      # code that consumes it is the honest thing to run.
      # SEARCH PERFORMED: `grep -rn report.schema.json tests/ lib/ tools/ factory` gives, apart
      # from agents/threat-model - which ALREADY had its own arm, the one beneath the
      # `agents/threat-model/report.schema.json)` pattern above (agents-22kv: cited by PATTERN, not
      # by line; the number that used to be here, :426, points at the tools/audit-tool-pins.sh arm)
      # and is why that file was never in the abort set (a first-match-wins case statement means my
      # duplicate arm for it was dead code, caught and removed before review):
      # test_adapter_auth_failure.py:128/:239, test_report_schema.py:107-123,
      # test_perf_review.py:945 - EVERY one writes a report.schema.json into a TMP fixture and
      # reads that back.
      # CONTRACT CHECK: tests/test_report_schema.py asserts every committed report.schema.json
      # stays inside the supported keyword subset and satisfies the report anatomy contract
      # (object type, required findings array with string rule_id and exact severity levels; agents-tz2y).
      # LIMITATION: structure is test-checked, but station-specific semantic fit still surfaces
      # only where the schema is consumed at runtime (agents-us59).
      mapped="$mapped tests/test_report_schema.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_180_agents_SKILL_md"
