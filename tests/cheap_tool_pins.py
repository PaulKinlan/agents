"""Stand-ins for the tools the pin generator hashes, so a test run costs seconds (agents-z3cp5).

`tools/generate-tool-pins.sh` hashes EVERY trusted tool it resolves, twice - once with sha256sum and
once with an independent `python3 -I` digest (agents-0poh) - so the cost of one run is a property of
the HOST, not of the code under test. Measured on the agents-factory VM, 2026-10-27: 73.09 s a run,
with 35 resolved entries and a 249 MB `claude` among them.

The suites that run the generator assert WHERE a pin or a hasher comes from - never how big a binary
is, and never which tools exist. So the tools an arm does not name can be tiny stand-ins. Measured
with a lookup dir of these stand-ins: 6.49 s a run, 11x cheaper, which is what makes these modules
gateable at all.

USE: pass the directory as a `--lookup-path` entry (for the CLI) or as a `lookup=` argument (in
process), APPENDED at the end so every directory the arm cares about keeps precedence:

    lookup=f"{arm_dir}:{stage_cheap_tools(tmp / 'cheap-tools')}"

THE LIST IS A CONTRACT WITH THE SCRIPT, not a memory: `drifted_tool_names()` returns the tools that
the generator declares but this set does not cover. A tool added to the script without a stand-in
here silently makes a run hash the real binary again - seconds become minutes, and the next person
to hit it sees a timeout rather than a missing stand-in. tests/test_pin_generator_hasher.py asserts
this with `TestTheCheapToolSetCoversEveryToolTheGeneratorPins`.
"""

import re
from pathlib import Path

# Sorted so the set has one spelling; every name the generator's TOOLS line carries.
CHEAP_TOOL_NAMES = ("agentapi", "bd", "bwrap", "claude", "gh", "git", "gitleaks", "node", "npm",
                    "npx", "pi", "semgrep")


def stage_cheap_tools(directory: Path, exclude=()) -> Path:
    """Tiny stand-ins for every tool the generator pins, minus `exclude`. Returns `directory`.

    `exclude` exists for the arms whose SUBJECT is a real system tool: an arm asserting "the real
    system git is still pinned, not the CWD namesake" cannot be handed a git stand-in that would
    win the lookup. Those arms still get stand-ins for the other eleven, which is where their
    minutes go - the host's 249 MB `claude` and its node/pi trees, not git.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for name in CHEAP_TOOL_NAMES:
        if name in exclude:
            # agents-90ihz: EXCLUDING IS ALSO A PROMISE THAT THE NAME IS ABSENT. Re-staging the same
            # directory with exclude=('git',) used to leave the earlier git stand-in in place, and exclude
            # exists precisely for the arms whose subject is the real binary (git, bd, gitleaks) - a stale
            # stand-in there makes the arm pass for the wrong reason, which is the failure mode these
            # stand-ins were introduced to avoid. Unlink rather than skip.
            stale = directory / name
            if stale.exists():
                stale.unlink()
            continue
        path = directory / name
        path.write_text(f'#!/bin/sh\necho "{name} stand-in"\n', encoding="utf-8")
        path.chmod(0o755)
    return directory


def declared_tool_names(generator: Path):
    """The tools the generator actually declares, or None when its TOOLS line cannot be parsed."""
    match = re.search(r'^TOOLS="([^"]*)"$', generator.read_text(encoding="utf-8"), re.M)
    if match is None:
        return None
    return sorted(match.group(1).split())


def drifted_tool_names(generator: Path):
    """Names the generator declares that have no stand-in here - the drift this contract forbids."""
    declared = declared_tool_names(generator)
    if declared is None:
        return None
    return sorted(set(declared) - set(CHEAP_TOOL_NAMES))
