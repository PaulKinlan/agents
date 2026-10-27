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

# A BATCHED STATION DOES N TIMES THE WORK ITS DECLARATION WAS SIZED FOR (agents-xm2xc).
# `budget.max_minutes` is written for ONE engine call, and since e5799b72 every station that presents
# candidates makes one call per bounded batch. The deadline stayed the single-call one, so on the
# reported nightly (wib2r) vuln-triage planned 7 calls of <=8 candidates against a 5-minute station
# budget and expired ON BATCH 6: five batches of finished triage were discarded, and the line skipped
# the six stations behind it. Once the call sequence is known the declaration therefore becomes a
# PER-CALL allowance and the station's deadline funds the whole sequence.
#
# Two bounds keep "fund the calls" from becoming "no bound at all": a ceiling on the station total,
# and a reserve kept out of the engine phase for the step that follows it.
#
# THE CEILING MUST STAY BELOW THE RUN-SWEEP GRACE (agents-6ep5s, review of agents-xm2xc). A run
# directory is protected from a CONCURRENT `factory` prune only by its `.active` marker's AGE
# (lib/retention.py: ACTIVE_GRACE_SECONDS_DEFAULT = 3600 s, _marker_is_active). A ceiling AT that grace
# let a batched station still be dispatching findings at 3600 s while another scheduled run swept its
# run directory out from under it - the deadline and the sweep threshold were the same number, which is
# how the first draft of this change reached 3600 s on a 12-call plan. So the ceiling is the grace
# minus a 15-minute sweep margin: 45 min, comfortably more than the measured plan that mattered (50
# candidates -> 7 calls -> 35 min at a 5-minute declaration) and provably inside the grace.
#
# lib/budget.py deliberately does NOT import lib/retention.py for this number: budget.py is copied into
# the dispatcher-runtime sandboxes of tests/test_report_schema.py and tests/test_prompt_exposure.py,
# which stage a named module set that does not include retention.py. The relationship is pinned by
# tests/test_budget.py::TestBatchedCallPlanning.test_the_ceiling_stays_inside_the_run_sweep_grace, so
# either constant moving fails the gate instead of silently reopening the hole.
STATION_DEADLINE_CEILING_MINUTES = 45.0
# The step after the engine calls is the findings dispatch - a local command, not a model call. With a
# multi-call deadline it is the step that gets squeezed: batches that each spend their full allowance
# leave it zero seconds, and the run reports a TIMEOUT over a report the model already produced.
POST_ENGINE_RESERVE_FRACTION = 0.1
POST_ENGINE_RESERVE_CEILING_SECONDS = 30.0
# Never hand a call a zero timeout. min(declared, 1 s) keeps a sub-second declared budget sub-second
# instead of rounding it up to a second it never had.
MIN_CALL_FLOOR_SECONDS = 1.0


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
        # The declaration as written, kept before plan_calls() can fund a longer deadline: a batched
        # station reports both numbers, because "5 min" and "35 min" are both true of different things.
        self.declared_minutes = self.minutes
        self.declared_seconds = self.max_seconds
        self.calls_planned = 1
        self._clock = clock
        self._started = clock()
        self._deadline = self._started + self.max_seconds

    @property
    def elapsed_seconds(self) -> float:
        """How much of the deadline the station has already spent (agents-zwq8l).

        Read-only and separate from `remaining_seconds` because it answers the question a starvation
        report has to answer: how much of the funded total the PRE-PASS took before the first engine
        call was ever offered its share. In the bug this instrument exists for, 266 s of a 45-minute
        deadline was gone before batch 1 ran, which is part of why its allowance was 171.693 s.
        """
        return self._clock() - self._started

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

    def plan_calls(self, calls: int) -> float:
        """Fund `calls` engine calls instead of the single call the declaration was sized for.

        The declaration is a PER-CALL allowance (see STATION_DEADLINE_CEILING_MINUTES): the station's
        deadline becomes `declared * calls` - never less than the declaration itself, so an agent that
        already declares more than the ceiling keeps it - measured from the moment the station started,
        so the pre-pass time already spent is still spent. Returns the funded total in seconds.

        Idempotent for reporting purposes but not cumulative: calling it twice with the same count is
        the same deadline, because the deadline is derived from the start rather than added to.
        """
        try:
            calls = int(calls)
        except (TypeError, ValueError):
            raise ValueError(f"{self.label}: call count must be an integer, got {calls!r}") from None
        if calls < 1:
            raise ValueError(f"{self.label}: call count must be at least 1, got {calls}")
        ceiling = STATION_DEADLINE_CEILING_MINUTES * 60.0
        self.calls_planned = calls
        self.max_seconds = min(self.declared_seconds * calls,
                               max(ceiling, self.declared_seconds))
        self.minutes = self.max_seconds / 60.0
        self._deadline = self._started + self.max_seconds
        return self.max_seconds

    def call_timeout(self, step: str, calls_left: int) -> float:
        """Seconds for ONE of the `calls_left` engine calls still to make (agents-xm2xc).

        The per-call allowance, reduced to a fair share of what remains once the post-engine reserve is
        set aside - which is what stops one hung batch from spending every later batch's time, and what
        keeps the findings dispatch behind them funded. Raises StationTimeout when nothing is left.
        """
        remaining = self.remaining_seconds
        reserve = min(POST_ENGINE_RESERVE_CEILING_SECONDS,
                      self.declared_seconds * POST_ENGINE_RESERVE_FRACTION)
        fair_share = max(remaining - reserve, 0.0) / max(1, int(calls_left))
        floor = min(self.declared_seconds, MIN_CALL_FLOOR_SECONDS)
        return max(floor, min(self.declared_seconds, fair_share))

    def funding_pressure(self, calls: int) -> Optional[Dict[str, Any]]:
        """The arithmetic of a plan the ceiling cannot fund at the declared allowance (agents-zwq8l).

        `plan_calls(n)` promises each of the n calls the declaration and then caps the station total at
        STATION_DEADLINE_CEILING_MINUTES. When that cap BINDS the promise is not kept: `call_timeout`
        hands every call the same fair share of the capped total, which can be a small fraction of what
        the station declared a call needs. Measured on agents-zwq8l: vuln-verify planned 14 calls of 15
        minutes against the 45-minute ceiling and each call was allowed 171.693 s - after 266 s of that
        deadline had already gone to the pre-pass, and inside the 27-135 s spread of per-call wall times
        observed across 28 real calls on this 2-vCPU host. The station then died ON BATCH 1, salvaging
        nothing, and the report named a timeout rather than the plan that could not be paid for.

        Returns the arithmetic, not a boolean: an operator told only "over budget" cannot tell WHICH
        number to change, and the two numbers that matter (what the plan asked for, what it got) are
        what distinguishes starvation from a genuinely slow call. None means the plan is affordable.

        It FUNDS the plan before judging it (`plan_calls` is idempotent by design: the deadline is
        derived from the station's start, never accumulated). That is not a convenience - read against
        an unfunded budget, three calls of a 15-minute declaration look starved (2700 s planned against
        the 900 s single-call deadline) when they are nothing of the sort, and my first draft of this
        method did exactly that.
        """
        try:
            calls = int(calls)
        except (TypeError, ValueError):
            raise ValueError(f"{self.label}: call count must be an integer, got {calls!r}") from None
        if calls < 1:
            raise ValueError(f"{self.label}: call count must be at least 1, got {calls}")
        funded = self.plan_calls(calls)
        planned = self.declared_seconds * calls
        if planned <= funded:
            return None
        return {
            "calls": calls,
            "declared_seconds": self.declared_seconds,
            "planned_seconds": planned,
            "funded_seconds": funded,
            "per_call_seconds": funded / calls,
            # How many calls the funded total would cover at the allowance the station declared.
            "calls_funded_at_declared": max(1, int(funded // self.declared_seconds)),
            # Spent before the first call was offered a share - the other half of a starved allowance.
            "elapsed_at_plan_seconds": self.elapsed_seconds,
        }


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
    timeout_seconds: Optional[float] = None,
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

    `timeout_seconds` overrides the command's share of the station budget for THIS call only. A batched
    station passes StationBudget.call_timeout, because one batch's fair share of a multi-call deadline is
    not the whole remaining budget (agents-xm2xc: the shared deadline expired on batch 6 of 7 and threw
    away five batches of finished triage).

    A hook that RAISES cannot orphan the child it was handed (agents-8z4z): the exception is
    propagated only after the session started above has been killed and reaped, because the
    alternative is a station child still running with live model credentials in its
    environment and nobody to reap it.
    """
    timeout = timeout_seconds if timeout_seconds is not None else budget.timeout_for(step)
    # `capture_output` and `input` are subprocess.run conveniences, not Popen arguments.
    stdin_data = kwargs.pop("input", None)
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if stdin_data is not None:
        kwargs.setdefault("stdin", subprocess.PIPE)
    proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    if on_spawn is not None:
        try:
            on_spawn(proc)
        except BaseException as hook_error:
            # agents-8z4z: THE HOOK MUST NOT BE ABLE TO ORPHAN THE CHILD IT WAS HANDED. The
            # call used to sit outside every cleanup path, so an exception from it (the
            # broker's registration path failing, a dead pid, a socket error) propagated
            # while the session started on the line above kept running - with live model
            # credentials in its environment, its process group unreaped, and the broker's
            # peer gate left UN-narrowed (the hook's whole purpose, factory:1835). That is
            # the one outcome this module's containment exists to prevent, and it made the
            # hook's failure mode worse than the hook's absence. BaseException, not
            # Exception: an interrupt during the hook would orphan the child just as
            # certainly, and the kill is bounded and idempotent either way.
            #
            # agents-dhk8: AND A REAP THAT ITSELF FAILS MUST NOT BE THE END OF THE STORY.
            # Measured before this change (tests/test_budget.py
            # TestRunStationCommand.test_a_failing_group_kill_still_contains_the_child):
            # with the group kill raising, the caller saw the reap's OSError INSTEAD of the
            # hook's RuntimeError - the hook's own failure silently misattributed - and the
            # child SURVIVED. So the direct child is killed when the group path is what
            # failed, and the hook's exception is then propagated, which keeps the reap's
            # error in its __context__ chain rather than letting it replace the cause.
            try:
                _kill_and_reap(proc)
            except BaseException as reap_error:
                # The reap's own failure must not vanish either: it happened WHILE HANDLING
                # the hook's error, which is the chain Python builds for a nested raise, so
                # the hook's exception stays the one reported and the reap's stays readable
                # in it. Swallowing it would be the same class of defect as the
                # misattribution above, one order smaller.
                _best_effort_kill(proc)
                hook_error.__context__ = reap_error
            raise
    try:
        stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timeout_error = StationTimeout(
            f"{budget.label}: {step} exceeded its {timeout:g}s allowance (station budget "
            f"{budget.minutes:g} min); process group killed"
        )
        # agents-0hbq: THE EXPIRY PATH NEEDS THE SAME CONTAINMENT AS THE HOOK PATH. It used to
        # call _kill_and_reap bare, so a reap that failed here did exactly what the hook path
        # was fixed for: the caller was told about the cleanup's OSError INSTEAD of the station
        # budget expiring (StationTimeout replaced by its own teardown's error), and a child
        # holding live model credentials stayed alive after the caller had been told the budget
        # was enforced. Measured before this change: OSError propagated, is StationTimeout
        # False, child alive 1 s after the caller returned. Same three pieces as the hook path -
        # keep the FIRST fault, best-effort kill the child, and leave the reap's error in the
        # chain rather than in place of the cause.
        reap_error = None
        try:
            _kill_and_reap(proc)
        except BaseException as exc:
            _best_effort_kill(proc)
            reap_error = exc
        if reap_error is not None:
            # EXPLICIT CHAINING IS REQUIRED HERE, unlike the hook path above: that path
            # RE-RAISES the same exception object, so a __context__ set by hand survives, while
            # this path raises a NEW StationTimeout from inside the handler and CPython then
            # sets its __context__ to the TimeoutExpired being handled - which silently DROPPED
            # the reap's error in my first version of this fix (the expiry-path test caught it:
            # it found the TimeoutExpired's message in the chain instead of "killpg failed").
            # `from` keeps the reap failure readable in every traceback and crash log.
            raise timeout_error from reap_error
        raise timeout_error from None
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


def _kill_and_reap(proc: subprocess.Popen) -> None:
    """End the session started for `proc`: kill its whole group, drain the pipes, wait it out.

    The single cleanup path for a child that must not outlive the call - the station budget
    expiring, and an `on_spawn` hook that raised (agents-8z4z, agents-28nn) share it, so a
    cleanup improvement lands on both rather than on whichever branch was edited last. The
    child IS our own process, so communicate() reaps it; descendants are not, which is what
    _wait_for_group_exit is for.

    BOUNDED EVEN WHEN THE DRAIN CANNOT FINISH (agents-dhk8): a descendant that escaped the
    group (its own session) still holds our stdout/stderr write end, so no communicate() can
    ever see EOF. Both waits below are therefore bounded, and the pipes are closed when the
    second one runs out: the remaining holder is neither our child nor in our group, and
    waiting for it is what made this unbounded (measured: 25.1 s against a descendant that
    slept 25 s, on the hook path and on the expiry path alike).
    """
    _kill_process_group(proc)
    try:
        # The same bound as the second wait (single-sourced, agents-dhk8): the first drain is
        # bounded by the module's group-exit wait rather than by a second literal.
        proc.communicate(timeout=GROUP_EXIT_WAIT_SECONDS)
    except subprocess.TimeoutExpired:  # a child escaped the group and holds the pipes
        proc.kill()
        try:
            proc.communicate(timeout=GROUP_EXIT_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            _close_output_pipes(proc)
    _wait_for_group_exit(proc.pid)


def _best_effort_kill(proc: subprocess.Popen) -> None:
    """Kill `proc` after the reap failed, without masking the exception being propagated.

    _kill_process_group falls back to the direct child only for ProcessLookupError and
    PermissionError, so a group kill that failed any other way left the child running. This
    retries the group path and then the direct child, swallowing everything: it runs inside
    the handler for an exception that must survive, and a second failure here belongs in
    that exception's __context__ chain rather than in place of it.
    """
    try:
        _kill_process_group(proc)
    except BaseException:
        try:
            proc.kill()
        except BaseException:
            pass


def _close_output_pipes(proc: subprocess.Popen) -> None:
    """Close the pipes no communicate() could drain, so their descriptors do not leak.

    Only reached when a process outside our group holds a write end. The station's output is
    already discarded on every path that gets here (the hook raised, or the budget expired),
    so there is nothing to read and no reader left to serve.
    """
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
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
