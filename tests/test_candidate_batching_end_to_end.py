#!/usr/bin/env python3
"""End-to-end: a station with more candidates than its per-call bound runs in bounded batches.

chrome-agent-platform-rn0ky. The nightly lost a 47-candidate perf-review to a completion cut mid-JSON
(50,314 bytes, cut after candidate 45) and the run reached the operator as "no verdict". These tests
drive the real dispatcher (`factory run`, a stub engine, a real pre-pass) and pin the three things the
bead asked for:

  * the candidate list is split into deterministic BOUNDED batches, each its own engine call;
  * each batch's answer is parsed and validated against the report contract SEPARATELY, and the
    report the run records is the deterministic merge of them (every presented id accounted for);
  * a cut batch is a NAMED truncation error in the run directory, not a silent no-verdict.

The engine is a stub because what is under test is the dispatcher's batching and contract handling,
not a model. The truncation case uses the nightly's exact shape: valid JSON head, hard stop mid-string.
"""

import json
import os
import stat
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from containment_harness import ContainmentHarness  # noqa: E402

CANDIDATE_COUNT = 8
PER_CALL = 3

PREPASS = f'''
import argparse, json, sys
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
candidates = [
    {{
        "candidate_id": f"cand-perf-{{i:03d}}",
        "rule_id": "layout-thrashing-forced-reflow",
        "path": f"src/file{{i}}.ts",
        "line_number": i + 1,
        "severity": "high",
        "snippet": "el.offsetWidth",
    }}
    for i in range({CANDIDATE_COUNT})
]
open(args.output, "w", encoding="utf-8").write(json.dumps({{"candidates": candidates}}))
'''

AGENT_YAML = f"""name: probe
class: proposer
plane: [local]
containment: t2-local
triggers: [manual]
blocking: false
short_circuit_empty: false
summary: batched probe
capabilities:
  write: false
  network: false
  browser: false
  requires: []
budget:
  max_minutes: 5
output:
  schema: report.schema.json
  max_candidates_per_call: {PER_CALL}
"""

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ProbeReport",
    "type": "object",
    # perf-review's own schema requires `target` (agents/perf-review/report.schema.json), so the probe
    # does too: a weaker probe left the per-batch contract untested at production strength (review).
    "required": ["summary", "target", "findings"],
    "properties": {
        "summary": {"type": "string"},
        "target": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["rule_id", "path", "snippet", "severity", "title", "description",
                             "remediation"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "snippet": {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low", "info"]},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                    "candidate_id": {"type": "string"},
                    "false_positive": {"type": "boolean"},
                },
            },
        },
    },
}

# Answers exactly the candidates the prompt carried: the ids are read back out of the prompt, which is
# also how the test proves each engine call saw only its own batch. Bash + builtins only: a test stub
# must not widen the engine sandbox's executable allowlist to get python3.
IDS_AND_ROWS = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
declare -A seen=()
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  if [ -n "${seen[$id]:-}" ]; then continue; fi
  seen[$id]=1
  ids+=("$id")
done
joined=$(printf '%s,' "${ids[@]}")
printf 'BATCH_IDS:%s\n' "${joined%,}"
out='{"summary":"batched","target":"probe-target","findings":['
first=1
for id in "${ids[@]}"; do
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"layout-thrashing-forced-reflow\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"el.offsetWidth\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$id\"}"
done
"""

# Every batch answers in full.
BATCH_STUB = IDS_AND_ROWS + r"""printf '%s]}\n' "$out"
"""

# The nightly's shape: the second batch's completion is CUT mid-string, leaving no decodable object.
TRUNCATING_STUB = IDS_AND_ROWS + r"""if [[ " ${ids[*]} " == *" cand-perf-003 "* ]]; then
  printf '%s{"rule_id":"r","path":"p","snippet":"s","severity":"high","title":"t","description":"partial'
else
  printf '%s]}\n' "$out"
fi
"""

# A per-batch CONTRACT failure: batch 2 answers in valid JSON but omits the required `target`, so that
# batch is rejected on its own and the run must not record the other batches as a complete verdict.
SCHEMA_BREAKING_STUB = IDS_AND_ROWS + r"""if [[ " ${ids[*]} " == *" cand-perf-003 "* ]]; then
  printf '%s]}\n' "${out/,\"target\":\"probe-target\"/}"
else
  printf '%s]}\n' "$out"
fi
"""

# Prose instead of a report: a different failure, and it must not be named truncation.
PROSE_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
cat >/dev/null
echo "I reviewed the diff and found nothing of note."
"""


class BatchedStation(ContainmentHarness):
    """The real dispatcher, a real pre-pass, a stub engine; batching declared in agent.yaml."""

    def agent(self, yaml_text):  # noqa: D401 - the harness's own staging, extended
        directory = self.root / "agents" / "probe"
        (directory / "scripts").mkdir(parents=True, exist_ok=True)
        (directory / "agent.yaml").write_text(yaml_text, encoding="utf-8")
        (directory / "SKILL.md").write_text("# Probe\n", encoding="utf-8")
        (directory / "report.schema.json").write_text(json.dumps(SCHEMA, indent=2),
                                                      encoding="utf-8")
        (directory / "scripts" / "prepass.py").write_text(PREPASS, encoding="utf-8")

    def stub(self, script):
        stub = self.bin / "pi"
        stub.write_text(script, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def run_batched(self):
        self.agent(AGENT_YAML)
        self.stub(BATCH_STUB)
        return self.factory("pi")

    def run_dir(self):
        dirs = self.run_dirs()
        self.assertEqual(len(dirs), 1, f"expected one run directory, got {dirs}")
        return dirs[0]


class TestBoundedBatching(BatchedStation):
    def test_a_large_candidate_list_runs_in_bounded_batches_and_merges(self):
        res = self.run_batched()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()

        prompts = sorted(run.glob("prompt.batch*.txt"))
        self.assertEqual(len(prompts), 3,
                         f"{CANDIDATE_COUNT} candidates at {PER_CALL} per call is 3 batches, got {prompts}")
        seen = []
        for prompt in prompts:
            text = prompt.read_text(encoding="utf-8")
            ids = sorted(set(__import__("re").findall(r"cand-perf-\d{3}", text)))
            self.assertLessEqual(len(ids), PER_CALL, f"{prompt.name} carried {len(ids)} candidates")
            seen.extend(ids)
        self.assertEqual(sorted(seen), [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)],
                         "every candidate is presented exactly once, across the batches")

        outputs = sorted(run.glob("model_output.batch*.txt"))
        self.assertEqual(len(outputs), 3, "each batch keeps its own raw output")
        recorded = []
        for output in outputs:
            line = next(l for l in output.read_text(encoding="utf-8").splitlines()
                        if l.startswith("BATCH_IDS:"))
            recorded.append(line.split(":", 1)[1])
        self.assertEqual(recorded, ["cand-perf-000,cand-perf-001,cand-perf-002",
                                    "cand-perf-003,cand-perf-004,cand-perf-005",
                                    "cand-perf-006,cand-perf-007"],
                         "each engine call saw exactly its own batch, in pre-pass order")

        presented = json.loads((run / "presented_candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(presented["presented"], CANDIDATE_COUNT)
        self.assertEqual(presented["batch_count"], 3)
        self.assertEqual(presented["candidate_ids"],
                         [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)])

        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        cited = [f["candidate_id"] for f in report["findings"]]
        self.assertEqual(cited, [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)],
                         "the merged report keeps pre-pass order and loses no row")

    def test_the_accounting_population_is_every_batch_not_the_first_slice(self):
        # The whole point of the merge: a run that presented 8 candidates across 3 calls must be
        # judged on all 8, not on the first CANDIDATE_PROMPT_SLICE of a single prompt.
        #
        # THE SLICE ARGUMENT IS THE POINT, and it is why this test can fail (rn0ky, ported): called
        # with the default slice the payload and the recorded population are both 8 ids, so ignoring
        # presented_candidates.json changed nothing and this assertion passed. Passing the station's
        # per-call bound as the slice - 3, against 8 presented - is the state the feature exists for:
        # the OLD reading would judge the run on the first 3 candidates and the batched reading judges
        # it on all 8. Measured: with lib/findings.py ignoring the recorded population, this fails.
        res = self.run_batched()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from lib.findings import read_presented_candidate_ids

        ids = read_presented_candidate_ids(self.run_dir(), PER_CALL)
        self.assertEqual(ids, [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)])

    def test_a_station_without_the_bound_stays_one_call(self):
        self.agent(AGENT_YAML.replace("  max_candidates_per_call: 3\n", ""))
        self.stub(BATCH_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        self.assertFalse(list(run.glob("prompt.batch*.txt")),
                         "batching is opt-in: an undeclared bound must not split the call")
        self.assertTrue((run / "prompt.txt").exists())


# agents-gwucz: TWO candidates against a bound of EIGHT. The count fits, the BYTES do not (7 KB each
# against a 12 KB batch budget), so the plan must split on the byte bound - the dispatcher used to
# invoke the planner only when the count was exceeded.
BIG_PREPASS = '''
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
candidates = [{"candidate_id": f"cand-perf-{i:03d}", "rule_id": "layout-thrashing-forced-reflow",
               "path": f"src/big{i}.ts", "line_number": i + 1, "severity": "high",
               "snippet": "x" * 7000} for i in range(2)]
open(args.output, "w", encoding="utf-8").write(json.dumps({"candidates": candidates}))
'''

# A stub that answers with the LAST three ids whatever batch it is given, so batch 1 attributes rows to
# candidates that were presented in a later batch.
SWAPPED_IDS_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
cat > /dev/null
out='{"summary":"swapped","target":"probe-target","findings":['
first=1
for id in cand-perf-005 cand-perf-006 cand-perf-007; do
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$id\"}"
done
printf '%s]}\n' "$out"
"""


# agents-ju56b: REAL pre-passes mix rows that carry a candidate_id with rows that carry none (the retained
# vuln-verify bundle has ids on 2 of 5). Batching must not turn that into "identity-matched 2/5" and an
# INCOMPLETE station on a complete answer.
MIXED_PREPASS = f'''
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
candidates = []
for i in range({CANDIDATE_COUNT}):
    row = {{"rule_id": "layout-thrashing-forced-reflow", "path": f"src/file{{i}}.ts",
            "line_number": i + 1, "severity": "high", "snippet": "el.offsetWidth"}}
    if i % 4 == 0:
        row["candidate_id"] = f"cand-perf-{{i:03d}}"
    candidates.append(row)
open(args.output, "w", encoding="utf-8").write(json.dumps({{"candidates": candidates}}))
'''

# Answers EVERY candidate in the prompt by PATH, carrying no candidate_id of its own - a dismissal-style row
# set that must be judged by count when the presented set has no complete identity.
PATH_ROWS_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
out='{"summary":"by-path","target":"probe-target","findings":['
first=1
for path in $(printf '%s' "$prompt" | grep -o "src/file[0-9][0-9]*\.ts" | sort -u); do
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"$path\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\"}"
done
printf '%s]}\n' "$out"
"""


class TestMixedIdentityIsCountOnly(BatchedStation):
    def test_a_partial_identity_bundle_is_judged_by_count_not_by_its_few_ids(self):
        self.agent(AGENT_YAML)
        (self.root / "agents" / "probe" / "scripts" / "prepass.py").write_text(MIXED_PREPASS, encoding="utf-8")
        self.stub(PATH_ROWS_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()

        presented = json.loads((run / "presented_candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(presented["identity"], "partial")
        self.assertIsNone(presented["candidate_ids"],
                          "a partial id list must never be recorded as the presented population")
        self.assertEqual(presented["candidates_without_id"], CANDIDATE_COUNT - 2)

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from lib.findings import candidate_coverage, read_candidate_count, read_presented_candidate_ids
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        coverage = candidate_coverage(read_candidate_count(run), len(report["findings"]),
                                      presented_ids=read_presented_candidate_ids(run))
        self.assertEqual(coverage["identity"], "count-only", coverage)
        self.assertTrue(coverage["complete"],
                        f"a complete answer must not read INCOMPLETE just because ids are partial: {coverage}")


# agents-exhhl review P1: vuln-verify's contract requires a SECOND row array, `verifications`, and merge
# used to drop it. The probe mirrors that shape so the merge is exercised against a real two-array contract.
VERIFY_SCHEMA = dict(SCHEMA)
VERIFY_SCHEMA["required"] = ["summary", "target", "findings", "verifications"]
VERIFY_SCHEMA["properties"] = dict(SCHEMA["properties"])
VERIFY_SCHEMA["properties"]["verifications"] = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["candidate_id", "verdict"],
        "properties": {"candidate_id": {"type": "string"}, "verdict": {"type": "string"},
                       "reasoning": {"type": "string"}},
    },
}

VERIFY_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
declare -A seen=()
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  if [ -n "${seen[$id]:-}" ]; then continue; fi
  seen[$id]=1
  ids+=("$id")
done
f='['
v='['
first=1
for id in "${ids[@]}"; do
  if [ $first -eq 0 ]; then f="$f,"; v="$v,"; fi
  first=0
  f="$f{\"rule_id\":\"r\",\"path\":\"src/$id.ts\",\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$id\"}"
  v="$v{\"candidate_id\":\"$id\",\"verdict\":\"confirmed\",\"reasoning\":\"r\"}"
done
printf '{"summary":"verified","target":"probe-target","findings":%s],"verifications":%s]}\n' "$f" "$v"
"""


class TestVerificationsSurviveTheMerge(BatchedStation):
    def test_a_second_required_array_is_merged_row_for_row(self):
        self.agent(AGENT_YAML)
        (self.root / "agents" / "probe" / "report.schema.json").write_text(
            json.dumps(VERIFY_SCHEMA, indent=2), encoding="utf-8")
        self.stub(VERIFY_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        expected = [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)]
        self.assertEqual([r["candidate_id"] for r in report["findings"]], expected)
        self.assertIn("verifications", report, "a required row array must survive the merge")
        self.assertEqual([r["candidate_id"] for r in report["verifications"]], expected,
                         "every batch's verifications rows, in pre-pass order")


class TestBatchingIsDecidedByThePlan(BatchedStation):
    def test_a_small_list_of_big_candidates_is_still_split(self):
        self.agent(AGENT_YAML.replace("max_candidates_per_call: 3", "max_candidates_per_call: 8"))
        (self.root / "agents" / "probe" / "scripts" / "prepass.py").write_text(BIG_PREPASS, encoding="utf-8")
        self.stub(BATCH_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        prompts = sorted(p.name for p in run.glob("prompt.batch*.txt"))
        self.assertEqual(prompts, ["prompt.batch1.txt", "prompt.batch2.txt"],
                         f"2 candidates over the byte bound must be 2 calls, not 1: {prompts}")
        self.assertTrue((run / "model_output.batch1.txt").exists())
        self.assertTrue((run / "model_output.batch2.txt").exists())


class TestCrossBatchAttribution(BatchedStation):
    def test_a_batch_answering_another_batch_s_candidates_fails_the_run(self):
        self.agent(AGENT_YAML)
        self.stub(SWAPPED_IDS_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0,
                            "a batch that answers another batch's candidates must not be merged")
        run = self.run_dir()
        combined = ""
        for name in ("failure_reason.txt",):
            path = run / name
            if path.exists():
                combined += path.read_text(encoding="utf-8")
        combined += res.stdout + res.stderr
        self.assertIn("batch 1", combined, f"the offending batch must be named: {combined[-500:]}")
        self.assertIn("cand-perf-005", combined, f"the misattributed id must be named: {combined[-500:]}")


class TestTruncationIsNamed(BatchedStation):
    def test_a_batch_cut_mid_json_is_a_named_truncation_error(self):
        self.agent(AGENT_YAML)
        self.stub(TRUNCATING_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a cut report must not be recorded as a verdict")
        run = self.run_dir()

        reason = (run / "failure_reason.txt").read_text(encoding="utf-8")
        self.assertIn("TRUNCATED", reason)
        self.assertIn("batch 2/3", reason, f"the failure names WHICH batch was cut: {reason}")

        # PER BATCH: a single output_classification.json let one batch's evidence overwrite another's
        # (found in review), so the artifact is tagged with the batch it describes.
        self.assertTrue((run / "output_classification.batch2.json").exists(),
                        f"batch 2's classification must be its own artifact: {sorted(p.name for p in run.glob('output_classification*'))}")
        classification = json.loads((run / "output_classification.batch2.json").read_text(encoding="utf-8"))
        self.assertEqual(classification["kind"], "truncated")
        self.assertEqual(classification["batch"], 2)
        self.assertEqual(classification["batches"], 3)
        self.assertEqual(classification["batches_with_output"], 3)
        self.assertTrue(classification["in_string_at_end"],
                        "the nightly's shape: the completion ended inside a string")

    def test_a_batch_that_breaks_the_report_contract_fails_alone(self):
        # The per-batch contract clause: batch 2 omits a required field while batches 1 and 3 are
        # complete. The run must fail, name the batch and the violation, and must NOT settle the
        # other batches' findings as a verdict - a partial triage is not a clean result.
        self.agent(AGENT_YAML)
        self.stub(SCHEMA_BREAKING_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a schema violation in one batch must fail the run")
        run = self.run_dir()
        failure = (run / "failure_reason.txt").read_text(encoding="utf-8") if (run / "failure_reason.txt").exists() else ""
        combined = failure + res.stdout + res.stderr
        self.assertIn("schema", combined.lower(), f"the violation must be named: {combined[-400:]}")
        self.assertIn("batch 2/3", combined, f"the failing batch must be named: {combined[-400:]}")
        # The other batches DID answer, and the point is that their rows are not settled as a verdict:
        self.assertTrue((run / "model_output.batch1.txt").exists())
        self.assertTrue((run / "model_output.batch3.txt").exists())
        classification = sorted(run.glob("output_classification*.json"))
        self.assertTrue(classification, "the rejected batch's evidence must be kept")

    def test_prose_instead_of_a_report_is_no_json_not_a_truncation(self):
        self.agent(AGENT_YAML)
        self.stub(PROSE_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0)
        run = self.run_dir()
        classification_files = sorted(run.glob("output_classification*.json"))
        self.assertTrue(classification_files, f"the classification must be kept: {sorted(p.name for p in run.iterdir())}")
        classification = json.loads(classification_files[0].read_text(encoding="utf-8"))
        self.assertEqual(classification["kind"], "no_json")


if __name__ == "__main__":
    unittest.main()
