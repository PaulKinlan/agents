"""The one interface every findings sink implements (fleet-km8).

Core (lib/findings.py) decides *what* may leave the machine — lifecycle state, delivery
receipts, triaged false positives and the publication embargo (lib/embargo.py) — and hands
each adapter only the findings it may publish. An adapter decides *how* to deliver them and
reports what happened. Core never names a tracker; adding one is a new module here.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class SinkContext:
    """What an adapter knows about the run it is publishing for."""
    target_name: str
    target_dir: Path
    visibility: str
    agent: Optional[str] = None
    stats: Dict[str, int] = field(default_factory=dict)
    # `sink_*` settings from the target manifest (targets/<name>.yaml), e.g. sink_command.
    options: Dict[str, str] = field(default_factory=dict)


def new_result() -> Dict[str, Any]:
    """Delivery counts every adapter returns. Core adds the counts of what it withheld."""
    return {"published": 0, "failed": 0, "skipped": 0, "duplicate": 0, "note": ""}


class Sink:
    """A findings sink. Subclasses set `name` and implement `publish`."""

    name: str = ""
    # A private sink is the local evidence trail: never a publication, never embargoed. Only
    # lib/embargo.PRIVATE_SINKS decides that for routing; this flag only skips dispatch.
    private: bool = False

    def credential_env(self, options: Dict[str, Any]) -> Sequence[str]:
        """Environment variable names the findings dispatch child needs for this sink."""
        return ()

    def detect(self, target_dir: Path) -> bool:
        """Whether the target repository's own guidance asks for this tracker."""
        return False

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Deliver `findings` (already filtered and embargo-checked by core).

        Mark a delivered finding by appending `self.name` to its `dispatched_sinks`; core
        persists the receipts. Return `new_result()` filled in.
        """
        raise NotImplementedError
