# ADR 0001: Fast-Gate Coverage Tiers — Tree-Property Guards vs Module- and Class-Contract Selection

- **Status:** Accepted (Adopted in `agents-dv23`, refined in `agents-pdth` and `agents-5br9`)
- **Deciders:** Software Factory Architecture, Core Coordination, Tooling Implementers
- **Context:** Bead `agents-c07o` (design), `agents-dv23` (implementation), `agents-c04d` (incident), `agents-pdth` (consumer boundary), `agents-5br9` (decoy guard tier widening)
- **Updated:** 2026-10-12

---

## 1. Context and Problem Statement

The software factory uses a selective fast gate (`tools/fast-gate.sh`) to evaluate iterative code changes in ~10–40 seconds rather than running the entire repository test suite (which requires 25–45 minutes). The fast gate determines which test suites to execute by matching changed files (`GIT_CHANGED`) against a sequential `case` statement.

### The Silent-Green Failure Mode (`agents-c04d`, `agents-9iyf`)

In incident `agents-c04d`, `TestNoUnboundedSubprocess` (which verified that every `subprocess.run` invocation across `factory` and all `lib/**/*.py` specifies an explicit `timeout=`) was located inside `tests/test_budget.py`. The fast gate only selected `tests/test_budget.py` when `lib/budget.py` or the `factory` CLI itself was modified.

When an implementer added or modified another library module that executed subprocesses without a timeout:
1. The change matched the generic `lib/*.py` arm, which ran only the module's unit contract tests.
2. `tests/test_budget.py` was not selected and ran zero times.
3. The fast gate returned `PASS` (a false green).
4. The violation was discovered 25–45 minutes later during the merger's full gate, resulting in an aborted landing, branch re-scoping, and delayed throughput.

A repo-wide sweep of tree walkers in `tests/` showed that while most scanners (e.g. agent YAML schemas, script redaction) have domains that match specific path arms, invariants asserting global repository properties have domains that strictly exceed any single file's selector.

---

## 2. Decision: Coverage Tier Classification

Test suites in `agents-factory` are categorized into three distinct coverage tiers based strictly on **Domain Resolution Asymmetry**:

> **The Criterion:** Can the domain over which an invariant asserts grow or change through a file that the fast gate resolves *without* selecting that invariant's suite?

```text
+-------------------------------------------------------------------------------+
| Fast Gate Test Execution                                                      |
+------------------------------------+------------------------------------------+
| Selective Arms                     | Always-On Tier                           |
| (Selected by GIT_CHANGED)          | (Appended to every run)                  |
|                                    |                                          |
| 1. Module-Contract Suites          | 3. Tree-Property Guards                  |
|    - Isolated unit tests           |    - Module: tests/test_tree_guards.py    |
|    - e.g. tests/test_budget.py     |    - Global repository invariants        |
|                                    |    - Checked without reference to delta  |
| 2. Class-Contract Suites           |    - Strict budget: < 0.5s per test      |
|    - Path-group domain walkers     |    - e.g. TestNoUnboundedSubprocess      |
|    - e.g. test_redaction.py        |           TestWorktreeBeadsDecoyGuard     |
+------------------------------------+------------------------------------------+
```

### Tier 1: Always-On Tree-Property Guards (`tests/test_tree_guards.py`)
- Invariants whose subject is a global property of the repository tree or filesystem state that no single file arm's trigger set comprehensively names.
- Not expressed as complex `case` statement branches or ad-hoc exceptions in `tools/fast-gate.sh`.
- Concentrated exclusively in one dedicated test module: `tests/test_tree_guards.py`.
- `tools/fast-gate.sh` appends `tests/test_tree_guards.py` unconditionally to every mapped and smoke run.
- **Two-way contract enforcement (`tests/test_fast_gate_mapping.py`):**
  1. Every mapped diff's planned test execution union MUST contain `tests/test_tree_guards.py`.
  2. `tests/test_tree_guards.py` MUST contain ONLY verified tree-property guard classes.

### Tier 2: Class-Contract Suites (Path-Group Scanners)
- Scanners whose inspection domain strictly equals the trigger set of an explicit glob arm.
- Examples (illustrative of the tier, not a uniform global pattern):
  - In individual agent arms, `agents/<agent>/scripts/*.py` triggers tests appropriate for that arm (e.g. `tests/test_redaction.py`), while directories with dedicated arms (such as `agents/docs-drift/scripts/check_docs.py`) select their own suites (e.g. `tests/test_docs_drift.py`).
  - `agents/*/agent.yaml` triggers `tests/test_containment_declarations.py`.
  - `docs/*` triggers `tests/test_docs_drift.py`.
- When a new file is added within these domains, the arm triggers automatically; no always-on execution is needed.

### Tier 3: Module-Contract Suites (Unit Tests)
- Unit and behavioral tests exercising the internal logic, functions, and state transitions of a specific source module.
- Retained in per-file or per-subsystem arms.
- When `TestNoUnboundedSubprocess` was extracted from `tests/test_budget.py`, all unit tests for `lib/budget.py` remained in `tests/test_budget.py` to ensure unit test regressions do not break unrelated lanes.

---

## 3. Qualification Criteria for Tier 1 (`test_tree_guards.py`)

A test class qualifies for `tests/test_tree_guards.py` if and only if it satisfies all of the following requirements:

1. **Repo-Wide Scope:** Asserts an invariant over the entire tree, filesystem layout, or broad multi-directory category where changes in untouched files could violate the rule.
2. **Delta-Independent:** Evaluates the state of the checkout directly; it does not take `GIT_CHANGED` as an input or rely on differential git ranges.
3. **Execution Latency Bound:** Must execute in under 0.5 seconds on warm CPU. The total execution time of all classes in `tests/test_tree_guards.py` must remain `<= 5.0s` so the fast-gate contract is not silently degraded.
4. **Hermetic & Change-Agnostic:** Does not depend on network access, live subprocess daemons, or ephemeral environment states.

### Qualifying Members (Current Roster)

1. `TestNoUnboundedSubprocess` (`agents-dv23`):
   - **Invariant:** Every `subprocess.run` across `factory` and `lib/**/*.py` must provide an explicit `timeout=` parameter.
   - **Domain:** Any Python module in `lib/` or root CLI.
   - **Cost:** Measured live on the gating union tree (`37a9671` / `beefa71c`) as ~0.30s (single wall-clock run inclusive of interpreter startup; whole `tests/test_tree_guards.py` module runs in ~0.25s). Clears the `< 0.5s` per-test bound.

2. `TestWorktreeBeadsDecoyGuard` (`agents-5br9`):
   - **Invariant:** Linked git worktrees (`[ -f "$toplevel/.git" ]`) must not contain local `.beads/embeddeddolt` or `.beads/dolt` database directories, preventing silent empty-ledger divergence and remote data overwrites.
   - **Domain:** Any linked worktree across the repository.
   - **Cost:** Measured live on the gating union tree (`37a9671` / `beefa71c`) as ~0.07s (single wall-clock run inclusive of interpreter startup). Clears the `< 0.5s` per-test bound.

---

## 4. What Does NOT Qualify (And Why)

Understanding what must be excluded from `test_tree_guards.py` is as critical as understanding what qualifies:

| Test Category | Example | Why Excluded from Tree Guards | Correct Location |
|---|---|---|---|
| **Symbol-Referenced Consumers** | `TestFastGateConsumerCoverage` (`agents-pdth`, `agents-undf`) | Asserts consumer coverage of specific symbols and fast-gate script mappings. Traces symbols, not whole-tree properties. | Dedicated always-on mapping suite (`tests/test_fast_gate_consumer_coverage.py`), appended to every run alongside the tier. |
| **Module Unit Tests** | `TestBudgetEngine` (`tests/test_budget.py`) | Tests internal methods of `lib/budget.py`. Running unit tests always-on adds 7s+ latency and breaks unrelated lanes on isolated logic changes. | Module-specific test suite triggered only by relevant file arms. |
| **Path-Bounded Walkers** | `TestRedactionRules` (`tests/test_redaction.py`) | Domain is bounded to specific script arms (e.g. `agents/*/scripts/*.py`), which match selective fast-gate arms. | Selective class-contract arm. |
| **Dynamic / End-to-End Audits** | Full factory audit pipeline (`factory run`) | Multi-minute, heavy subprocess execution requiring sandboxing and model execution. | Nightly factory runs or merger-side full gates (`fleet-check`). |
| **Documentation Format Walkers** | `check_docs.py` | Markdown link and file existence checks are already comprehensively triggered by `docs/*` and root doc arms. | Selective doc arm (`tests/test_docs_drift.py`). |

---

## 5. Architectural Invariants and Lessons Learned

### The "Criterion over Count" Principle (`agents-dv23` vs `agents-5br9`)
The fast-gate mapping test (`tests/test_fast_gate_mapping.py`) contains a pin verifying that `test_tree_guards.py` is not quietly diluted with non-tree tests (`test_tree_guard_tier_module_holds_only_tree_property_tests`).
- When `TestNoUnboundedSubprocess` was originally extracted, the pin asserted `classes == ["TestNoUnboundedSubprocess"]`.
- When `TestWorktreeBeadsDecoyGuard` was added in `agents-5br9`, the pin failed.
- **Principle:** The guard tier is defined by its *architectural criterion*, not by an immutable class count. When a new guard satisfies the repo-wide tree property criterion and respects the latency budget, the pin list is legitimately widened to include the new class.

### Separation of Symbol Consumers from Tree Invariants (`agents-pdth`, `agents-undf`)
During `agents-pdth`, `TestFastGateConsumerCoverage` was initially placed inside `tests/test_tree_guards.py`. This was an architectural defect: consumer coverage tests verify that consumers of modified functions are mapped in `tools/fast-gate.sh`. This is a symbol-referencing relationship across mapping tables, not an invariant over repo-wide files or checkout state.
However, because consumer coverage validates the fast-gate's own integrity across all changed paths, `tools/fast-gate.sh:1000-1019` appends `tests/test_fast_gate_consumer_coverage.py` to **every mapped and smoke run** alongside `tests/test_tree_guards.py`.
- **The architectural resolution:** Rather than diluting `tests/test_tree_guards.py` with symbol-referencing suites, the runner maintains two distinct always-on structural pins:
  1. `tree_guards="tests/test_tree_guards.py"` (pure tree-property invariants).
  2. `consumer_coverage="tests/test_fast_gate_consumer_coverage.py"` (mapping contract and consumer coverage).
Separating them into distinct modules preserves the purity of the tree-guard tier while ensuring both structural invariants run unconditionally on every gate execution.

### Re-entrancy Protection and Invocation Independence (`agents-q615`, `agents-dv23`)
Tests that inspect the fast-gate mapping (such as `tests/test_fast_gate_mapping.py`) must prevent recursive re-entrancy loops where the gate resolves the active diff, selects the mapping test itself, and spawns runaway child runs. In practice, invocations avoid this via two distinct mechanisms:
1. **Dry-Run Resolution:** Setting `FAST_GATE_DRY_RUN=1` resolves planned suites and exits immediately without executing runner subprocesses (used both with simulated `GIT_CHANGED` and with base ref overrides via `GIT_BASE`).
2. **Controlled Target Scoping:** Execution tests (such as terminal marker assertions in `test_fast_gate_execution_*`) set `GIT_CHANGED` to isolated probe files rather than dry-running, ensuring the gate executes the probe and always-on tiers without selecting the mapping suite.
Uncontrolled invocations of `tools/fast-gate.sh` that lack both dry-run protection and explicit target scoping are prohibited.
For the tree-guard tier (`tests/test_tree_guards.py`), the protection is even stronger: the tier module contains zero references to `tools/fast-gate.sh` and does not invoke the gate at all. It evaluates tree properties directly via the filesystem, making recursive re-entrancy impossible by construction.

---

## 6. Consequences

- **Positive:** Closes the silent-green class (`agents-c04d`) permanently. Repository-wide tree invariants are asserted on every fast-gate run.
- **Positive:** Fast-gate execution remains predictable and bounded (< 0.5s added per tree guard).
- **Positive:** Implementers and reviewers have an unambiguous, objective rule for where tests belong: if a test asserts a repo-wide invariant over an unmapped domain, it belongs in `tests/test_tree_guards.py`; if it tests a symbol, a module, or a bounded glob, it belongs in a selective arm (with the sole exception of structural runner pins like `tests/test_fast_gate_consumer_coverage.py` that guard mapping integrity across all changes).
- **Negative:** Every mapped change pays a minor (~0.2s–0.4s) baseline execution cost. Tier growth must be strictly governed by latency measurement.
