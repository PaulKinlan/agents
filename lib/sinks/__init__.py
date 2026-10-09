#!/usr/bin/env python3
"""Tracker sink adapters (fleet-km8), moved out of lib/findings.py for layering.

Each adapter files findings to one destination (beads, github-issues promotion). The embargo
partition — which findings an adapter may receive — lives in lib/findings.dispatch_to_sink and
lib/embargo; adapters re-check it so a direct call stays safe. The local file/delta report is
not a tracker and stays in lib/findings.py.
"""

from lib.sinks.beads import _BEAD_EXTERNAL_REF_RE, _bd_json, _dispatch_beads
from lib.sinks.github import promote_issue

__all__ = ["_BEAD_EXTERNAL_REF_RE", "_bd_json", "_dispatch_beads", "promote_issue"]
