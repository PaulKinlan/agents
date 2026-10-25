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


# agents-g42wa: vuln-verify's pre-pass ids SOME candidates and not others. Batching then has to describe a
# batch by its POPULATION, not by the ids it happens to carry - naming only the ids described a
# 4-candidate batch with 1 id as though the ids were the batch, and the model skipped the unnamed rows
# (the reported "13/16 verified, 3 silently dropped").
PARTIALLY_IDENTIFIED_PREPASS = f'''
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
candidates = [
    {{
        "candidate_id": (f"cand-perf-{{i:03d}}" if i < 5 else None),
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


class TestAMixedBatchNamesItsUnidentifiedRows(BatchedStation):
    """The pre-pass identifies 5 of 8 candidates, so the batches are: [0,1,2] all identified,
    [3,4,5] two identified, and [6,7] with no ids at all. Each brief must state the true population."""

    def agent(self, yaml_text):  # noqa: D401 - stage the mixed pre-pass instead of the uniform one
        super().agent(yaml_text)
        (self.root / "agents" / "probe" / "scripts" / "prepass.py").write_text(
            PARTIALLY_IDENTIFIED_PREPASS, encoding="utf-8")

    def test_each_brief_states_the_population_and_the_unidentified_count(self):
        self.agent(AGENT_YAML)
        self.stub(BATCH_STUB)
        self.factory("pi")
        run = self.run_dir()
        briefs = [p.read_text(encoding="utf-8") for p in sorted(run.glob("prompt.batch*.txt"))]
        self.assertEqual(len(briefs), 3, [b[:60] for b in briefs])

        self.assertIn("holds 3 candidate(s), each with a candidate_id", briefs[0])
        self.assertIn("holds 3 candidate(s): 2 carry a candidate_id", briefs[1])
        self.assertIn("the other 1 carries NO candidate_id", briefs[1])
        self.assertIn("holds 2 candidate(s) and NONE of them carry a candidate_id", briefs[2])
        # and the payload still carries every record of the batch, not only the identified ones
        # (parse the Scanner Data block: counting "rule_id" in the whole prompt also counts the schema)
        for index, brief in enumerate(briefs, start=1):
            payload = brief.split("Scanner Data:\n", 1)[1].split("\n\nYour final answer", 1)[0]
            rows = json.loads(payload)
            self.assertEqual(len(rows), 3 if index < 3 else 2,
                             f"batch {index} lost candidates from its payload: {len(rows)} rows")


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

    def test_a_station_under_the_bound_stays_one_call(self):
        # The bound is enforced, not opt-in (agents-tq1lt), but a list that FITS the bound must still be
        # one call: batching a list of 3 against a ceiling of 8 would only add engine starts.
        self.agent(AGENT_YAML.replace("max_candidates_per_call: 3", "max_candidates_per_call: 8"))
        self.stub(BATCH_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        self.assertFalse(list(run.glob("prompt.batch*.txt")),
                         f"{CANDIDATE_COUNT} candidates under a bound of 8 must not split the call")
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


# agents-00sew: a model mistranscribes ONE candidate id (here a dropped character, the real shape from
# chrome-agent-platform-z427f). The dispatcher must recognise it as a unique near match, repair it, record
# the repair, and let the run complete instead of reporting a partial triage.
MISTRANSCRIBING_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
declare -A seen=()
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  if [ -n "${seen[$id]:-}" ]; then continue; fi
  seen[$id]=1
  ids+=("$id")
done
out='{"summary":"t","target":"probe-target","findings":['
first=1
for id in "${ids[@]}"; do
  cite="$id"
  if [ "$id" = "cand-perf-003" ]; then cite="cand-prf-003"; fi
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$cite\"}"
done
printf '%s]}\n' "$out"
"""


class TestMistranscribedIdsAreRepaired(BatchedStation):
    def test_a_unique_near_match_is_repaired_recorded_and_accounted(self):
        self.agent(AGENT_YAML)
        self.stub(MISTRANSCRIBING_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        cited = [row.get("candidate_id") for row in report["findings"]]
        self.assertIn("cand-perf-003", cited, f"the mistranscribed id must be repaired: {cited}")
        self.assertNotIn("cand-prf-003", cited)

        repairs = []
        for path in sorted(run.glob("candidate_id_repairs*.json")):
            if "_refused" in path.name:
                continue
            repairs.extend(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual([(r["cited"], r["repaired"], r["rule"]) for r in repairs],
                         [("cand-prf-003", "cand-perf-003", "near")],
                         "the repair is recorded with the rule that justified it")

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from lib.findings import candidate_coverage, read_candidate_count, read_presented_candidate_ids
        coverage = candidate_coverage(read_candidate_count(run), len(report["findings"]),
                                      presented_ids=read_presented_candidate_ids(run),
                                      cited_ids=cited)
        self.assertTrue(coverage["complete"], f"a repaired answer must account: {coverage}")


# agents-amgst: every row of a batch answers the batch's FIRST candidate while keeping its own page's
# path - the measured 2026-10-23 modern-web shape, where six per-page dismissal rows cited five distinct
# ids and one duplicate. The id-text rules cannot see it (each cited id IS presented), so the run would
# otherwise read "cited 2 of the 3" and go INCOMPLETE; the row's own path is the evidence that re-binds it.
DUPLICATE_CITING_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  case " ${ids[*]:-} " in *" $id "*) continue;; esac
  ids+=("$id")
done
out='{"summary":"t","target":"probe-target","findings":['
first=1
for id in "${ids[@]}"; do
  idx=$((10#${id#cand-perf-}))
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"src/file$idx.ts\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"low\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"${ids[0]}\"}"
done
printf '%s]}\n' "$out"
"""


class TestADuplicatedCitationIsReBoundByItsOwnPath(BatchedStation):
    """agents-amgst. The dispatcher must hand the repair the pre-pass paths, or the measured failure is
    unfixable no matter what lib/findings can do: this is the wiring half of the change."""

    def test_a_per_page_row_citing_another_page_is_re_bound_and_the_run_accounts(self):
        self.agent(AGENT_YAML)
        self.stub(DUPLICATE_CITING_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        expected = [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)]
        self.assertEqual(sorted(row["candidate_id"] for row in report["findings"]), expected,
                         "every presented candidate is cited exactly once after the path repair")

        repairs = []
        for path in sorted(run.glob("candidate_id_repairs*.json")):
            if "_refused" in path.name:
                continue
            repairs.extend(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual([r["rule"] for r in repairs], ["path"] * (CANDIDATE_COUNT - 3),
                         f"one row per batch correctly kept its own id, the rest were re-bound: {repairs}")
        self.assertEqual([(r["repaired"], r["path"]) for r in repairs],
                         [(f"cand-perf-{i:03d}", f"src/file{i}.ts") for i in (1, 2, 4, 5, 7)])

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from lib.findings import candidate_coverage, read_candidate_count, read_presented_candidate_ids
        coverage = candidate_coverage(read_candidate_count(run), len(report["findings"]),
                                      presented_ids=read_presented_candidate_ids(run),
                                      cited_ids=[row["candidate_id"] for row in report["findings"]])
        self.assertTrue(coverage["complete"], coverage)


# agents-fv5uk: batch 1 cites a candidate that belongs EXACTLY to a sibling batch. The ids are one edit
# apart by construction ("cand-perf-004" vs "cand-perf-005"), so the repair must refuse and the run must
# reject the row - never re-attach it to batch 1's neighbour.
FOREIGN_CITING_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  case " ${ids[*]:-} " in *" $id "*) continue;; esac
  ids+=("$id")
done
out='{"summary":"t","target":"probe-target","findings":['
first=1
for id in "${ids[@]}"; do
  cite="$id"
  if [ "$id" = "cand-perf-000" ]; then cite="cand-perf-006"; fi
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$cite\"}"
done
printf '%s]}\n' "$out"
"""


# agents-afx5o: a citation that matches nothing at all. The repair refuses, the run fails closed - and the
# refusal is RECORDED, because otherwise the operator sees a rejection with no evidence of what was compared.
HOPELESS_CITING_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  case " ${ids[*]:-} " in *" $id "*) continue;; esac
  ids+=("$id")
done
out='{"summary":"t","target":"probe-target","findings":['
first=1
for id in "${ids[@]}"; do
  cite="$id"
  if [ "$id" = "cand-perf-000" ]; then cite="cand-perf-998"; fi
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"r\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"s\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$cite\"}"
done
printf '%s]}\n' "$out"
"""


class TestARefusedRepairIsRecordedWithItsReason(BatchedStation):
    def test_a_citation_that_matches_nothing_is_recorded_and_still_fails(self):
        self.agent(AGENT_YAML)
        self.stub(HOPELESS_CITING_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "an unaccountable citation must still fail the run")
        run = self.run_dir()

        refusals = []
        for path in sorted(run.glob("candidate_id_repairs_refused*.json")):
            refusals.extend(json.loads(path.read_text(encoding="utf-8")))
        cited = [r["cited"] for r in refusals]
        self.assertIn("cand-perf-998", cited, f"the refused citation must be recorded: {refusals}")
        reason = next(r["reason"] for r in refusals if r["cited"] == "cand-perf-998")
        self.assertIn("no unique match", reason)
        # 998 is two edits from 000, so the nearest candidate IS plausible and must be named
        self.assertIn("cand-perf-000", reason, f"the nearest candidate must be named: {reason}")


class TestAForeignBatchIdIsNotLaundered(BatchedStation):
    def test_a_sibling_batchs_exact_id_is_rejected_not_repaired(self):
        self.agent(AGENT_YAML)
        self.stub(FOREIGN_CITING_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a row naming another batch's candidate must fail the run")
        run = self.run_dir()
        reason = (run / "failure_reason.txt").read_text(encoding="utf-8")
        self.assertIn("cand-perf-006", reason, reason[:300])
        self.assertIn("not shown", reason, reason[:300])

        repairs = []
        for path in sorted(run.glob("candidate_id_repairs*.json")):
            if "_refused" in path.name:
                continue
            repairs.extend(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual([r for r in repairs if r["cited"] == "cand-perf-006"], [],
                         f"the foreign citation must not be repaired: {repairs}")


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

    def test_a_batched_failure_is_named_in_batch_vocabulary(self):
        # agents-uetmr: the fallback path used to re-classify the CONCATENATION of every batch output -
        # judging N answers as one string, writing an aggregate output_classification.json beside the
        # per-batch evidence, calling it "batch 1/1", and pointing at a model_output.txt that batching
        # renames. A batched run must keep the failing batch's own words and its own evidence file.
        self.agent(AGENT_YAML)
        self.stub(SCHEMA_BREAKING_STUB)
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0)
        run = self.run_dir()
        self.assertFalse((run / "output_classification.json").exists(),
                         "a batched run must not write an aggregate classification of the concatenation: "
                         f"{sorted(p.name for p in run.glob('output_classification*'))}")
        self.assertTrue((run / "output_classification.batch2.json").exists())
        reason = (run / "failure_reason.txt").read_text(encoding="utf-8")
        self.assertIn("batch 2/3", reason, f"the failing batch must be named: {reason}")
        self.assertNotIn("batch 1/1", reason, f"never a single-call count in a batched run: {reason}")
        self.assertIn("model_output.batch", reason, f"point at the batch answers: {reason}")
        self.assertNotIn("model_output.txt", reason,
                         f"batching renames that file, so it must not be named: {reason}")

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


# agents-tq1lt: the stations that hit the truncation (vuln-triage, docs-drift, deps-supply-chain) never
# declared a per-call bound, so they asked for up to CANDIDATE_PROMPT_SLICE rows in ONE completion. Ten
# candidates is the smallest list that shows the enforced ceiling: 8 + 2, where undeclared used to be 1.
TEN_CANDIDATE_PREPASS = PREPASS.replace("in range(8)", "in range(10)")


class TestThePerCallBoundIsPolicy(BatchedStation):
    """The bound is enforced by the dispatcher, not opted into by a station declaration."""

    def agent(self, yaml_text):  # noqa: D401 - stage ten candidates
        super().agent(yaml_text)
        (self.root / "agents" / "probe" / "scripts" / "prepass.py").write_text(
            TEN_CANDIDATE_PREPASS, encoding="utf-8")

    def test_an_undeclared_station_is_still_batched_at_the_policy_bound(self):
        self.agent(AGENT_YAML.replace("  max_candidates_per_call: 3\n", ""))
        self.stub(BATCH_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()

        prompts = sorted(run.glob("prompt.batch*.txt"))
        self.assertEqual(len(prompts), 2,
                         f"10 candidates with no declaration must be 2 calls at the policy bound of 8, "
                         f"got {[p.name for p in prompts]}")
        sizes = []
        for prompt in prompts:
            text = prompt.read_text(encoding="utf-8")
            sizes.append(len(sorted(set(__import__("re").findall(r"cand-perf-\d{3}", text)))))
        self.assertEqual(sizes, [8, 2], "the ceiling is 8 per call, and the tail is its own call")

        presented = json.loads((run / "presented_candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(presented["batch_count"], 2)
        self.assertEqual(presented["max_candidates_per_call"], 8)
        self.assertEqual(presented["presented"], 10)

        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([f["candidate_id"] for f in report["findings"]],
                         [f"cand-perf-{i:03d}" for i in range(10)],
                         "the Python-side merge accounts for every candidate across both calls")

    def test_a_declaration_above_the_ceiling_is_capped_and_says_so(self):
        self.agent(AGENT_YAML.replace("max_candidates_per_call: 3", "max_candidates_per_call: 20"))
        self.stub(BATCH_STUB)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run = self.run_dir()
        prompts = sorted(run.glob("prompt.batch*.txt"))
        self.assertEqual(len(prompts), 2,
                         f"a declared 20 must not lift the ceiling: {[p.name for p in prompts]}")
        presented = json.loads((run / "presented_candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(presented["max_candidates_per_call"], 8)
        self.assertIn("capped to the policy bound of 8", res.stdout,
                      f"the cap must be stated, not silent: {res.stdout[-400:]}")


# agents-demur: modern-web (and resilience, ui-ux-audit, memory-profile) REQUIRE `scanned_files`, and their
# pre-pass already counts the files it walked. The merge dropped it as factory-owned and nothing set it
# again, so every BATCH passed its own schema and the MERGED report failed the same schema - the whole run
# then reached nobody as a no-verdict. The pre-pass count is the truth; a batch cannot supply it.
SCANNED_FILES_PREPASS = f'''
import argparse, json
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
open(args.output, "w", encoding="utf-8").write(
    json.dumps({{"scanned_files": 137, "candidates": candidates}}))
'''

# The same schema as the probe, plus the required field modern-web declares.
SCANNED_FILES_SCHEMA = dict(SCHEMA)
SCANNED_FILES_SCHEMA["required"] = ["summary", "target", "scanned_files", "findings"]
SCANNED_FILES_SCHEMA["properties"] = dict(SCHEMA["properties"])
SCANNED_FILES_SCHEMA["properties"]["scanned_files"] = {"type": "integer"}

# Every batch INVENTS a scanned count (999) that no pre-pass ever produced: the merged report must carry
# the pre-pass's 137, not a batch's guess and not a sum.
INVENTED_SCANNED_FILES_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
prompt=$(cat)
declare -A seen=()
ids=()
for id in $(printf '%s' "$prompt" | grep -o "cand-perf-[0-9][0-9][0-9]"); do
  if [ -n "${seen[$id]:-}" ]; then continue; fi
  seen[$id]=1
  ids+=("$id")
done
out='{"summary":"batched","target":"probe-target","scanned_files":999,"findings":['
first=1
for id in "${ids[@]}"; do
  if [ $first -eq 0 ]; then out="$out,"; fi
  first=0
  out="$out{\"rule_id\":\"layout-thrashing-forced-reflow\",\"path\":\"src/$id.ts\",\"line_number\":1,\"snippet\":\"el.offsetWidth\",\"severity\":\"high\",\"title\":\"t\",\"description\":\"d\",\"remediation\":\"x\",\"candidate_id\":\"$id\"}"
done
printf '%s]}\n' "$out"
"""


class TestTheMergedReportCarriesThePrepPassCount(BatchedStation):
    """agents-demur: the merged report must satisfy the station's own schema, and its `scanned_files`
    must be the count the pre-pass actually produced."""

    def agent(self, yaml_text):  # noqa: D401 - stage the scanned-files pre-pass and schema
        super().agent(yaml_text)
        directory = self.root / "agents" / "probe"
        (directory / "report.schema.json").write_text(json.dumps(SCANNED_FILES_SCHEMA, indent=2),
                                                      encoding="utf-8")
        (directory / "scripts" / "prepass.py").write_text(SCANNED_FILES_PREPASS,
                                                          encoding="utf-8")

    def test_a_batched_run_of_a_station_requiring_scanned_files_keeps_its_verdict(self):
        self.agent(AGENT_YAML)
        self.stub(INVENTED_SCANNED_FILES_STUB)
        res = self.factory("pi")
        run = self.run_dir()
        stray = run / "merged_schema_errors.json"
        self.assertEqual(res.returncode, 0,
                         "the merged report must satisfy the schema every batch satisfied; "
                         f"merged_schema_errors={stray.read_text(encoding='utf-8') if stray.exists() else 'none'}\n"
                         + res.stdout + res.stderr)
        self.assertFalse(stray.exists(),
                         "the merge must not leave a schema violation behind")

        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["scanned_files"], 137,
                         "the pre-pass count, not a batch's invented 999 and not a per-batch sum")
        self.assertEqual([f["candidate_id"] for f in report["findings"]],
                         [f"cand-perf-{i:03d}" for i in range(CANDIDATE_COUNT)],
                         "the merge still accounts for every candidate")


if __name__ == "__main__":
    unittest.main()
