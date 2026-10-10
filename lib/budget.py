#!/usr/bin/env python3
"""Station budgets: agent.yaml's budget.max_minutes, enforced.

A station is one agent run: deterministic pre-pass, engine dispatch, findings dispatch.
They share one monotonic deadline derived from the agent's declared budget, so a hung engine
cannot hold a scheduled slot forever (SF-06).

Two rules from the audit:

- Derive `timeout=` from `budget.max_minutes`; no station command runs unbounded.
- Expiry is a station failure, never a clean scan. The step's whole process *group* is killed
  (so the engine dies with the adapter shell, not only the shell), `StationTimeout` is raised,
  `run_line` records the station as ERROR, and `factory run` exits non-zero.

The budget covers the station as a whole, not each step separately: an agent that declares
5 minutes gets 5 minutes for the pre-pass, the engine and the findings dispatch together.
"""

import math
import os
import signal
import subprocess
import time
from typing import Any, Callable, Dict, Optional, Sequence

# Used only when an agent.yaml omits budget.max_minutes, or declares something that is not a
# positive finite number. Never unbounded, never zero.
DEFAULT_MAX_MINUTES = 5.0


class StationTimeout(RuntimeError):
    """A station step overran the station's declared budget.max_minutes."""


def _positive_minutes(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        minutes = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(minutes) or minutes <= 0:
        return None
    return minutes


class StationBudget:
    """One monotonic deadline for one station.

    Monotonic on purpose: a wall-clock jump (NTP, DST) must not extend or truncate a budget.
    """

    def __init__(self, max_minutes: Any, label: str = "station", clock=time.monotonic):
        self.label = label
        self.minutes = _positive_minutes(max_minutes) or DEFAULT_MAX_MINUTES
        self.max_seconds = self.minutes * 60.0
        self._clock = clock
        self._deadline = clock() + self.max_seconds

    @property
    def remaining_seconds(self) -> float:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise StationTimeout(f"{self.label}: budget of {self.minutes:g} min exhausted")
        return remaining

    def timeout_for(self, step: str) -> float:
        """Seconds left for `step`, or StationTimeout when the budget is already spent."""
        try:
            return self.remaining_seconds
        except StationTimeout:
            raise StationTimeout(
                f"{self.label}: budget of {self.minutes:g} min exhausted before {step}"
            ) from None


def budget_for(
    agent_cfg: Dict[str, Any],
    label: str = "station",
    override_minutes: Optional[Any] = None,
) -> StationBudget:
    """Build a station budget from a parsed agent.yaml mapping or explicit override.

    Order of precedence:
    1. Explicit override_minutes (from CLI, line configuration, or caller)
    2. FACTORY_BUDGET_MINUTES environment variable
    3. agent_cfg.get("budget", {}).get("max_minutes")
    4. DEFAULT_MAX_MINUTES (5.0)
    """
    minutes = None
    if override_minutes is not None:
        minutes = _positive_minutes(override_minutes)
    if minutes is None and "FACTORY_BUDGET_MINUTES" in os.environ:
        minutes = _positive_minutes(os.environ["FACTORY_BUDGET_MINUTES"])
    if minutes is None and isinstance(agent_cfg, dict):
        budget_cfg = agent_cfg.get("budget")
        if isinstance(budget_cfg, dict):
            minutes = _positive_minutes(budget_cfg.get("max_minutes"))
    return StationBudget(minutes, label=label)


def run_station_command(
    cmd: Sequence[str],
    budget: StationBudget,
    step: str,
    check: bool = False,
    kill_group_on_exit: bool = False,
    on_spawn: Optional[Callable[[subprocess.Popen], None]] = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run one station command under `budget`, killing its whole process group on expiry.

    A new session is used so the timeout reaches the engine the adapter spawned, not only the
    adapter shell. Expiry raises StationTimeout: the caller treats it as a station failure.

    `kill_group_on_exit` also kills (and waits out) whatever the command left running in its
    group when it exits normally — for a command holding delivery credentials, where a
    lingering descendant could still act after its result was recorded (command sink).

    `on_spawn` fires with the live Popen the instant the child exists — before
    communicate() blocks — for a caller that must bind something to the child's pid
    (agents-28nn round 8: the credential broker narrows its loopback peer gate to the
    engine session's own process tree, so no other descendant of the dispatcher is
    served).
    """
    timeout = budget.timeout_for(step)
    # `capture_output` and `input` are subprocess.run conveniences, not Popen arguments.
    stdin_data = kwargs.pop("input", None)
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if stdin_data is not None:
        kwargs.setdefault("stdin", subprocess.PIPE)
    proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    if on_spawn is not None:
        on_spawn(proc)
    try:
        stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:  # a child escaped the group and holds the pipes
            proc.kill()
            proc.communicate()
        _wait_for_group_exit(proc.pid)
        raise StationTimeout(
            f"{budget.label}: {step} exceeded the {budget.minutes:g} min station budget; "
            f"process group killed"
        ) from None
    if kill_group_on_exit:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # pgid == pid: the session started above
        except (ProcessLookupError, PermissionError):
            pass
        _wait_for_group_exit(proc.pid)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the session started for `proc`, falling back to the process itself."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


GROUP_EXIT_WAIT_SECONDS = 5.0


def _wait_for_group_exit(pgid: int, limit: float = GROUP_EXIT_WAIT_SECONDS) -> None:
    """Wait (bounded) until no process remains in group `pgid` after it was SIGKILLed.

    Descendants are not our children, so they cannot be waited for directly; signal 0 to the
    group reports whether any member is left.
    """
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            return
        time.sleep(0.05)
