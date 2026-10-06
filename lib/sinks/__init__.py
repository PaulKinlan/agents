"""Findings sink registry (fleet-km8).

Every tracker lives behind `lib.sinks.base.Sink`; this module is the only place that maps
a sink name to an adapter. Core (lib/findings.py, factory, lib/child_env.py) asks the
registry and never names a tracker. Adding Jira or Linear needs no factory change at all —
use the `command` sink — or a new module here.
"""

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from lib.sinks.base import Sink, SinkContext, new_result
from lib.sinks.beads import BeadsSink
from lib.sinks.command import CommandSink
from lib.sinks.file import FileSink
from lib.sinks.github_issues import GitHubIssuesSink

SINKS: Dict[str, Sink] = {sink.name: sink for sink in (
    FileSink(), BeadsSink(), GitHubIssuesSink(), CommandSink(),
)}

# Legacy spellings: a spec containing one of these means exactly this set (as before).
ALIASES = {"both": ("beads", "github-issues"), "all": ("beads", "github-issues")}

# Sink discovery from target guidance, in this order (AGENTS.md "Sinks").
DETECTION_ORDER = ("beads",)

__all__ = ["SINKS", "ALIASES", "Sink", "SinkContext", "new_result", "get", "expand",
           "credential_env", "detect"]


def get(name: str) -> Optional[Sink]:
    return SINKS.get(name)


def expand(spec: Optional[str]) -> List[str]:
    """`"beads,github-issues"` -> names; an alias replaces the whole list, as it always did."""
    names = [s.strip() for s in (spec or "").split(",") if s.strip()]
    for alias, members in ALIASES.items():
        if alias in names:
            return list(members)
    return names


def credential_env(spec: Optional[str], options: Optional[Mapping[str, Any]] = None) -> List[str]:
    """Env var names the findings dispatch needs for the sinks in `spec`."""
    names: List[str] = []
    for name in expand(spec):
        sink = get(name)
        if sink:
            names.extend(n for n in sink.credential_env(dict(options or {})) if n not in names)
    return names


def detect(target_dir: Path) -> Optional[str]:
    """The tracker the target repository's own guidance asks for, if any."""
    for name in DETECTION_ORDER:
        sink = get(name)
        if sink and sink.detect(target_dir):
            return name
    return None
