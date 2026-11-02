"""Every third-party action this repo ships or runs must be pinned to a full commit SHA.

This repo is the highest-privilege component in the system (AGENTS.md): it holds model
API keys and GitHub tokens, runs unattended on a schedule, and has write access to other
repositories. A GitHub Actions workflow or composite action that consumes a third-party
action by MUTABLE TAG (`@v4`) executes whatever that tag points to at run time, so a
compromised or coerced action repository flows straight into these runs - a supply-chain
compromise one step from every target the factory touches.

WHAT THIS GUARDS (agents-xeqg9 rework after review findings agents-6noep/agents-30rbl):
both consuming surfaces, discovered structurally rather than by filename convention -
- `.github/workflows/*.yml|yaml` (what this repo's own CI executes), and
- `action.yml|yaml` under `.github/actions/**` (composite actions; the factory action is
  the artefact docs/INTEGRATION.md tells other repos to consume, and its steps execute
  with the CALLER's token, which makes it the wider exposure of the two).

HOW: steps are collected from the PARSED document (yaml.safe_load), not a line regex -
the regex form missed three valid YAML spellings of the same mutable tag (space before
the colon, flow mappings, quoted keys; agents-30rbl). A file that does not parse fails
here rather than silently checking nothing: an unparseable workflow is unreviewable, so
that is a loud failure, not an exemption.

PINNING POLICY:
- `./` local action refs are exempt: they are this repository's own code, reviewed by
  the same diff that introduces them.
- `docker://` refs are deliberately NOT exempted: they do not match the pin regex, so a
  future docker-based step fails here loudly instead of silently bypassing pin review.
  (Digest-pinning them would be that step's own change, made with its evidence.)
- A 40-hex lowercase SHA is the strongest ref GitHub Actions accepts; a comment naming
  the upstream tag (as ci.yml, pages.yml and the factory action carry) is convention,
  not the guarantee.
- This test is the ONE holder of the invariant: the per-file guard that used to live in
  tests/test_pages_publish_scope.py was removed when this covered pages.yml too.

NOT A MACHINE-STATE TEST: only tracked files are read. Nothing is fetched, so another
lane or a network change cannot turn it red (docs/speed.md section 4 independence).
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
ACTIONS_DIR = ROOT / ".github" / "actions"

# A 40-hex lowercase SHA is the immutable pin shape GitHub Actions accepts.
_IMMUTABLE_REF = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}$")


def _candidate_files():
    """Every file that can carry step `uses:` refs: workflows plus composite actions."""
    files = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    files += sorted(ACTIONS_DIR.glob("**/action.yml"))
    files += sorted(ACTIONS_DIR.glob("**/action.yaml"))
    return files


def _steps_uses(doc):
    """Every `uses:` value in a parsed workflow or composite action document, or None
    when the document has no steps structure at all."""
    refs = []
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if isinstance(steps, list):
                refs.extend(_refs_from_steps(steps))
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if isinstance(runs, dict):
        steps = runs.get("steps")
        if isinstance(steps, list):
            refs.extend(_refs_from_steps(steps))
    return refs


def _refs_from_steps(steps):
    refs = []
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("uses"), str):
            refs.append(step["uses"])
    return refs


class TestEveryWorkflowPinsThirdPartyActions(unittest.TestCase):
    def test_the_repo_still_declares_workflow_and_action_files(self):
        """A missing or renamed consuming surface must fail here, not silently exempt everything."""
        files = _candidate_files()
        self.assertTrue(
            files,
            f"no workflow or composite-action files found under {WORKFLOW_DIR} / {ACTIONS_DIR} - "
            "if the layouts moved, update this guard; if the surfaces are gone for real, delete it",
        )

    def test_every_consumed_action_is_sha_pinned_across_every_surface(self):
        files = _candidate_files()
        all_refs = []
        for path in files:
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                self.fail(
                    f"{path.relative_to(ROOT)} does not parse as YAML ({e}); an unparseable "
                    "workflow cannot be pin-checked, so it fails here instead of passing unchecked"
                )
            refs = _steps_uses(doc)
            rel = path.relative_to(ROOT)
            if refs is not None:
                for ref in refs:
                    all_refs.append((rel, ref))
        # The invariant is vacuous if nothing consumes actions at all; assert the guard
        # still sees the surfaces it exists for, so structural drift fails loudly.
        self.assertTrue(
            all_refs,
            "no `uses:` steps found in any workflow or composite action - if this repo "
            "genuinely consumes no third-party actions any more, update this guard",
        )
        for rel, ref in all_refs:
            if ref.startswith("./"):
                continue
            with self.subTest(file=str(rel), ref=ref):
                self.assertRegex(
                    ref, _IMMUTABLE_REF,
                    f"{rel} consumes '{ref}' by a mutable ref. Pin it to the full commit SHA "
                    "its tag points at (verify with `git ls-remote <action-repo> refs/tags/<tag> "
                    "'refs/tags/<tag>^{}'`) and leave the tag name as a trailing comment.",
                )


if __name__ == "__main__":
    unittest.main()
