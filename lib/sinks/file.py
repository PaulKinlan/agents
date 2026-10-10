"""The `file` sink: the local evidence trail.

The delta report (findings/<target>-delta.md and friends) is written by core for every run
whatever sinks are configured, because it is the complete record a responder reads — it
includes what the embargo withholds from trackers. So this adapter delivers nothing itself.
"""

from typing import Any, Dict, List

from lib.sinks.base import Sink, SinkContext, new_result


class FileSink(Sink):
    name = "file"
    private = True

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return new_result()
