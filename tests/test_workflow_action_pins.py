"""Every third-party action in EVERY workflow must be pinned to a full commit SHA.

This repo is the highest-privilege component in the system (AGENTS.md): it holds model
API keys and GitHub tokens, runs unattended on a schedule, and has write access to other
repositories. A GitHub Actions workflow that consumes a third-party action by MUTABLE TAG
(`@v4`) executes whatever that tag points to at run time, so a compromised or coerced
action repository flows straight into this workflow with `contents: read` on this repo -
a supply-chain compromise one step from every target the factory touches.

agents-dikvi pinned pages.yml and added the first enforcing guard, scoped to that one
file (tests/test_pages_publish_scope.py::test_workflow_actions_use_immutable_commit_refs).
The same nightly audit kept flagging ci.yml (actions/checkout@v7, actions/setup-python@v7,
fixed here), so the invariant now lives where it covers the whole class: every workflow
file in .github/workflows/, not the one file the last audit happened to name.

NOT A MACHINE-STATE TEST: both sides are tracked files (this test and the workflows it
reads). Nothing external is fetched, so another lane or a network change cannot turn it
red (docs/speed.md section 4 independence).

Pinning policy notes:
- `./` local action refs are exempt: they are this repository's own code, reviewed by
  the same diff that introduces them.
- `docker://` refs are deliberately NOT exempted: they do not match the regex, so a
  future docker-based step fails here loudly instead of silently bypassing pin review.
  (Digest-pinning them would be that step's own change, made with its evidence.)
- A 40-hex lowercase SHA is the strongest ref GitHub Actions accepts; a comment naming
  the upstream tag (as pages.yml and ci.yml carry) is convention, not the guarantee.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# Same fail-closed shape as the pages.yml guard: owner/repo(/path)@40 hex, nothing else.
_IMMUTABLE_REF = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}$")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", flags=re.MULTILINE)


class TestEveryWorkflowPinsThirdPartyActions(unittest.TestCase):
    def test_the_repo_still_declares_workflows(self):
        """A missing or renamed workflows directory must fail here, not silently exempt everything."""
        workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
        self.assertTrue(workflows, f"no workflow files found under {WORKFLOW_DIR}")

    def test_every_third_party_action_in_every_workflow_is_sha_pinned(self):
        workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
        self.assertTrue(workflows, f"no workflow files found under {WORKFLOW_DIR}")
        for workflow in workflows:
            text = workflow.read_text(encoding="utf-8")
            refs = _USES.findall(text)
            self.assertTrue(
                refs, f"{workflow.relative_to(ROOT)} declares no actions - if actions moved "
                "elsewhere, update this guard; if the file is vestigial, delete it"
            )
            for ref in refs:
                if ref.startswith("./"):
                    continue
                with self.subTest(workflow=workflow.name, ref=ref):
                    self.assertRegex(
                        ref, _IMMUTABLE_REF,
                        f"{workflow.relative_to(ROOT)} consumes '{ref}' by a mutable ref. "
                        "Pin it to the full commit SHA its tag points at (verify with "
                        "`git ls-remote <action-repo> refs/tags/<tag> 'refs/tags/<tag>^{}'`) "
                        "and leave the tag name as a trailing comment.",
                    )


if __name__ == "__main__":
    unittest.main()
