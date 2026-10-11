# Proposal: Hermetic Test Environment Declaration (agents-v1a2)

## Context & Motivation

During incident `agents-21ap`, the deployment of a host-local tool pins file (`~/.config/factory/tools.pins.yaml` exported via `FACTORY_TOOL_PINS`) broke multiple test suites across `agents-factory`. Because the tests construct synthetic tool binaries in temporary directories on `PATH`, the presence of the operator's ambient `FACTORY_TOOL_PINS` caused tool resolution to reject synthetic binaries against host pins.

The initial fix applied in `agents-21ap` introduced `tests/hermetic_env.py` and decorated 10 test modules with `setUpModule`/`tearDownModule` pairs that called `isolate_operator_config()` and `restore_operator_config()`.

While effective as a tactical mitigation, this architecture has critical structural defects:
1. **N-copy diligence failure mode**: Every new test module that exercises tool resolution or sandbox wrappers must remember to import `hermetic_env` and implement `setUpModule`/`tearDownModule`. If any module forgets, it becomes environmentally fragile.
2. **Re-infection via tearDownModule**: Because `tearDownModule()` restored `_SAVED` ambient environment variables after each module ran, any subsequent unscrubbed module executed in a test sweep immediately inherited the dirty host environment.
3. **Layer inversion**: Test hermeticity is an infrastructural invariant of the test runner and test package, not an individual test case concern.

## Census of Affected Modules

The census measures exactly 10 test modules in `tests/` currently carrying boilerplate `setUpModule`/`tearDownModule` pairs (11 files in `tests/` including `tests/hermetic_env.py`):
1. `tests/test_adapter_auth_failure.py`
2. `tests/test_factory_core.py`
3. `tests/test_factory_truth.py`
4. `tests/test_factory_truth_2.py`
5. `tests/test_line_andon.py`
6. `tests/test_no_bwrap_guard.py`
7. `tests/test_pi_keyless_broker.py`
8. `tests/test_prompt_exposure.py`
9. `tests/test_report_schema.py`
10. `tests/test_sandbox.py`

## Architecture: Centralized Two-Tier Declaration

Instead of relying on N test files to self-scrub, the environment is declared at the two canonical entry points:

### 1. Package-Level Hermeticity (`tests/__init__.py`)
When any test is executed via `python3 -m unittest discover -s tests` or `python3 -m unittest tests.test_<name>`, Python imports the `tests` package before loading any submodule.

In `tests/__init__.py`:
```python
"""Hermetic test package initialization (agents-v1a2).

Establishes a deterministic test environment across all test modules:
clears ambient operator tool pins (FACTORY_TOOL_PINS) and sets the
dev/test opt-in (FACTORY_ALLOW_UNPINNED_TOOLS=1) so that tests run
against the repository tree rather than ambient host machine state.
"""
from tests import hermetic_env

hermetic_env.isolate_operator_config()
```
This guarantees that any test running within `tests` executes in an isolated environment by default, without needing per-module boilerplate.

### 2. Gate-Level Hermeticity (`tools/fast-gate.sh`)
At the runner level in `tools/fast-gate.sh`:
```bash
# Establish hermetic test environment: scrub ambient operator host config (agents-v1a2).
unset FACTORY_TOOL_PINS
export FACTORY_ALLOW_UNPINNED_TOOLS=1
```
All child processes and test commands dispatched by `fast-gate.sh` inherit a clean, sanitized environment.

### 3. Full-Gate Coordination (`~/.fleet/check.conf`)
Per coordinator instruction, `check.conf` is shared with `agents-j1te` and is not edited here. When `agents-j1te` coordinates `check.conf` updates, `CHECK_CMD` can be declared as:
```bash
CHECK_CMD="env -u FACTORY_TOOL_PINS FACTORY_ALLOW_UNPINNED_TOOLS=1 python3 -m unittest discover -s tests -v"
```
Because `tests/__init__.py` already isolates on import, test discovery is hermetic even prior to the `check.conf` update.

## Removal of Redundant Boilerplate

With `tests/__init__.py` and `tools/fast-gate.sh` in place, the 10 boilerplate `setUpModule`/`tearDownModule` pairs in:
- `tests/test_adapter_auth_failure.py`
- `tests/test_factory_core.py`
- `tests/test_factory_truth.py`
- `tests/test_factory_truth_2.py`
- `tests/test_line_andon.py`
- `tests/test_no_bwrap_guard.py`
- `tests/test_pi_keyless_broker.py`
- `tests/test_prompt_exposure.py`
- `tests/test_report_schema.py`
- `tests/test_sandbox.py`

become strictly redundant. They are removed to eliminate dead claims and ensure future developers follow the package-level pattern rather than copying per-module boilerplate.

## Acceptance & Verification

The acceptance test in `tests/test_hermetic_env.py` proves:
1. `tests/__init__.py` initializes the environment so that `FACTORY_TOOL_PINS` is absent and `FACTORY_ALLOW_UNPINNED_TOOLS == "1"`.
2. A new, unscrubbed test case with synthetic binaries on PATH passes under an active host pins file without needing `setUpModule`.
3. `tools/fast-gate.sh` scrubs `FACTORY_TOOL_PINS` before invoking test suites.
