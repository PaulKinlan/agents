"""Hermetic test package initialization (agents-v1a2).

Establishes a deterministic test environment across all test modules:
clears ambient operator tool pins (FACTORY_TOOL_PINS) and sets the
dev/test opt-in (FACTORY_ALLOW_UNPINNED_TOOLS=1) so that tests run
against the repository tree rather than ambient host machine state.
"""

from tests import hermetic_env

hermetic_env.isolate_operator_config()
