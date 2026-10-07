#!/usr/bin/env python3
"""agent.yaml's containment, capabilities and budget are read and enforced (agents-pnu, SF-02).

Three layers, each tested where it lives:

1. lib/containment.py validates every declaration, fails closed on anything it cannot honour,
   and grants the model session only the read-only tool policy.
2. Each engine adapter turns FACTORY_TOOL_POLICY into that engine's own flags, and refuses a
   policy it cannot enforce before the engine starts. A drift guard holds the adapters and
   ENGINE_TOOL_POLICIES in agreement.
3. The dispatcher refuses before any run directory exists, sets the policy explicitly (never
   from the caller's environment), and records it in policy.json.

Engines are stubs that record their argv: deterministic, no model call, no credentials.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.containment import (  # noqa: E402
    ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE, ContainmentError, banner_lines,
    budget_note, check_engine, load_policy, policy_record,
)
from lib.sandbox import sandbox_available  # noqa: E402

# Whether THIS host can run bubblewrap. The confinement acceptance test needs it; the
# fail-closed and opt-in tests simulate its absence with a broken bwrap on PATH, so they run
# anywhere (review P0, agents-9n7).
_BWRAP = sandbox_available()

_loader = importlib.machinery.SourceFileLoader("factory_cli_pnu", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_pnu", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

STUB_REPORT = "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"


def manifest(**overrides):
    cfg = {
        "name": "probe",
        "containment": "t0-readonly",
        "capabilities": {"write": False, "network": False, "browser": False, "requires": []},
        "budget": {"max_minutes": 5},
    }
    cfg.update(overrides)
    return cfg


class TestShippedManifests(unittest.TestCase):
    def test_every_shipped_agent_validates_and_gets_a_grantable_policy(self):
        agents = sorted(p for p in (ROOT / "agents").iterdir() if (p / "agent.yaml").exists())
        self.assertTrue(agents)
        for agent_dir in agents:
            with self.subTest(agent=agent_dir.name):
                cfg = factory_cli.load_yaml_simple(agent_dir / "agent.yaml")
                policy = load_policy(agent_dir.name, cfg)
                self.assertIn(policy.tool_policy, GRANTABLE_POLICIES)
                self.assertTrue(policy.tier_declared)
                # A declared write within a tier that allows it is granted as worktree-write
                # (agents-6ce); everything else stays read-only.
                self.assertEqual(policy.tool_policy,
                                 WORKTREE_WRITE if policy.declared["write"] else READ_ONLY)
                # pi and claude enforce every grantable policy; deepseek is read-only, so it
                # refuses a write agent; antigravity has no tool controls and refuses all.
                check_engine(policy, "pi")
                check_engine(policy, "claude")
                if policy.tool_policy == READ_ONLY:
                    check_engine(policy, "deepseek")
                else:
                    with self.assertRaises(ContainmentError):
                        check_engine(policy, "deepseek")
                with self.assertRaises(ContainmentError):
                    check_engine(policy, "antigravity")

    def test_declared_capabilities_are_reported_as_withheld(self):
        # write is granted via the disposable worktree (agents-6ce), so pr-fixer and
        # docs-write no longer report it as withheld; network and browser still are.
        expected = {
            "pr-fixer": set(), "docs-write": set(),
            "deps-supply-chain": {"network"}, "issue-triage": {"network"},
            "memory-profile": {"browser"}, "ui-ux-audit": {"browser"},
            "secret-scan": set(),
        }
        for name, withheld in expected.items():
            with self.subTest(agent=name):
                cfg = factory_cli.load_yaml_simple(ROOT / "agents" / name / "agent.yaml")
                self.assertEqual(set(load_policy(name, cfg).withheld), withheld)


class TestDeclarationsFailClosed(unittest.TestCase):
    INVALID = {
        "unknown tier": manifest(containment="t9-anything"),
        "misspelt tier": manifest(containment="t0-read-only"),
        "empty tier": manifest(containment=""),
        "t3 has no runner": manifest(containment="t3-sandbox"),
        "tier not a string": manifest(containment=["t0-readonly"]),
        "tier left blank in yaml": manifest(containment={}),
        "write above t0": manifest(capabilities={"write": True}),
        "network above t0": manifest(capabilities={"network": True}),
        "browser above t0": manifest(capabilities={"browser": True}),
        "write above t1": manifest(containment="t1-fetch", capabilities={"write": True}),
        "browser above t1": manifest(containment="t1-fetch", capabilities={"browser": True}),
        "network above t2": manifest(containment="t2-local", capabilities={"network": True}),
        "unknown capability": manifest(capabilities={"shell": True}),
        "misspelt capability": manifest(capabilities={"netwrok": False}),
        "string, not bool": manifest(capabilities={"write": "no"}),
        "int, not bool": manifest(capabilities={"write": 0}),
        "capabilities not a mapping": manifest(capabilities=["write"]),
        "requires not a list": manifest(capabilities={"requires": "gh"}),
        "requires holds a non-string": manifest(capabilities={"requires": [1]}),
        "gh at t0, which forbids network": manifest(capabilities={"requires": ["gh"]}),
        "gh without declared network": manifest(containment="t1-fetch",
                                                 capabilities={"requires": ["gh"]}),
        "gh at t2, which forbids network": manifest(containment="t2-local",
                                                    capabilities={"requires": ["gh"]}),
        "unknown budget key": manifest(budget={"max_minute": 5}),
        "budget not a mapping": manifest(budget=5),
        "zero minutes": manifest(budget={"max_minutes": 0}),
        "negative dollars": manifest(budget={"max_usd": -1}),
        "non-numeric minutes": manifest(budget={"max_minutes": "soon"}),
        "boolean minutes": manifest(budget={"max_minutes": True}),
        "nan minutes": manifest(budget={"max_minutes": float("nan")}),
        "manifest not a mapping": ["containment", "t0-readonly"],
    }

    def test_each_invalid_declaration_is_refused(self):
        for label, cfg in self.INVALID.items():
            with self.subTest(case=label):
                with self.assertRaises(ContainmentError):
                    load_policy("probe", cfg)

    def test_yaml_one_one_booleans_are_refused_not_guessed(self):
        """The factory's YAML reader keeps `yes` as a string; the validator refuses it rather
        than guess which way it was meant."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "agent.yaml"
            path.write_text("name: probe\ncontainment: t2-local\ncapabilities:\n  write: yes\n",
                            encoding="utf-8")
            with self.assertRaises(ContainmentError):
                load_policy("probe", factory_cli.load_yaml_simple(path))

    def test_an_absent_tier_gets_the_strictest_ceiling(self):
        cfg = manifest()
        del cfg["containment"]
        policy = load_policy("probe", cfg)
        self.assertEqual(policy.tier, "t0-readonly")
        self.assertFalse(policy.tier_declared)
        cfg["capabilities"] = {"write": True}
        with self.assertRaises(ContainmentError):
            load_policy("probe", cfg)

    def test_each_tier_accepts_its_ceiling_and_grants_the_policy(self):
        # tier -> (declared caps, expected tool_policy, expected withheld flags)
        cases = {
            "t0-readonly": ({}, READ_ONLY, set()),
            "t1-fetch": ({"network": True}, READ_ONLY, {"network"}),
            # write is granted via the disposable worktree (agents-6ce), so it is not
            # withheld; browser still is (no localhost-only browser mechanism yet).
            "t2-local": ({"write": True, "browser": True}, WORKTREE_WRITE, {"browser"}),
        }
        for tier, (caps, tool_policy, withheld) in cases.items():
            with self.subTest(tier=tier):
                policy = load_policy("probe", manifest(containment=tier, capabilities=caps))
                self.assertEqual(policy.tool_policy, tool_policy)
                self.assertEqual(set(policy.withheld), withheld)

    def test_budget_values_parse_like_lib_budget(self):
        policy = load_policy("probe", manifest(budget={"max_minutes": "15", "max_usd": 0.5}))
        self.assertEqual(policy.max_minutes, 15.0)
        self.assertEqual(policy.max_usd, 0.5)
        policy = load_policy("probe", manifest(budget=None))
        self.assertIsNone(policy.max_minutes)
        self.assertIsNone(policy.max_usd)

    def test_an_engine_without_enforcement_is_refused(self):
        policy = load_policy("probe", manifest())
        for engine in ("antigravity", "codex", ""):
            with self.subTest(engine=engine):
                with self.assertRaises(ContainmentError):
                    check_engine(policy, engine)


    def test_a_network_credential_needs_declared_network(self):
        """requires [gh] brings the pre-pass a GitHub token, so it needs network: true at a
        tier that allows it: issue-triage's shape (agents-05h)."""
        policy = load_policy("probe", manifest(containment="t1-fetch",
                                               capabilities={"network": True, "requires": ["gh"]}))
        self.assertEqual(policy.requires, ("gh",))

    def test_the_credential_list_matches_the_pre_pass_grant(self):
        """Drift guard: the pre-pass receives a credential for exactly the requirements that
        lib/child_env.py lists, so the validator and the grant cannot disagree."""
        from lib.child_env import BASE_ALLOW, NETWORK_CREDENTIAL_REQUIREMENTS, prepass_environment
        parent = {"PATH": "/bin", "GH_TOKEN": "t", "GITHUB_TOKEN": "t", "NPM_TOKEN": "t"}
        tools = set(NETWORK_CREDENTIAL_REQUIREMENTS) | {"npm", "curl"}
        for agent_yaml in (ROOT / "agents").glob("*/agent.yaml"):
            caps = factory_cli.load_yaml_simple(agent_yaml).get("capabilities") or {}
            tools.update(caps.get("requires") or [])
        for tool in sorted(tools):
            with self.subTest(requires=tool):
                env = prepass_environment({"capabilities": {"requires": [tool]}}, parent=parent)
                granted = set(env) - set(BASE_ALLOW)
                self.assertEqual(bool(granted), tool in NETWORK_CREDENTIAL_REQUIREMENTS, granted)


class TestBannerAndRecord(unittest.TestCase):
    def test_the_banner_says_what_is_enforced_and_what_is_not(self):
        # A declared write at t2-local is granted via the disposable worktree (agents-6ce):
        # the banner says worktree-write and does NOT list write as withheld. Declare browser
        # too so the banner still shows what is NOT enforced.
        policy = load_policy("pr-fixer", manifest(containment="t2-local",
                                                  capabilities={"write": True, "browser": True}))
        pi_banner = "\n".join(banner_lines(policy, "pi"))
        self.assertIn("worktree-write, enforced by the pi adapter", pi_banner)
        self.assertIn("edit,write", pi_banner)
        self.assertNotIn("Withheld:    write", pi_banner)
        self.assertIn("Withheld:    browser", pi_banner)
        self.assertIn("Sandbox:     NOT enforced", pi_banner)
        self.assertIn("NOT confined", pi_banner)
        self.assertIn("confined to the target directory",
                      "\n".join(banner_lines(policy, "claude")))

    def test_the_record_lists_what_is_not_enforced(self):
        policy = load_policy("probe", manifest(budget={"max_minutes": 5, "max_usd": 0.5}))
        record = policy_record(policy, "pi")
        json.dumps(record)
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["not_enforced"], ["os-sandbox", "read-scope", "budget.max_usd"])
        # agents-js7: the claude adapter enforces a declared cap via --max-budget-usd.
        self.assertEqual(policy_record(policy, "claude")["not_enforced"],
                         ["os-sandbox"])

    def test_the_budget_line_names_the_enforcement_state_per_engine(self):
        policy = load_policy("probe", manifest(budget={"max_minutes": 5, "max_usd": 0.5}))
        self.assertIn("$0.50 enforced by the claude adapter (--max-budget-usd)",
                      budget_note(policy, "claude"))
        self.assertIn("$0.50 declared, NOT enforced (the pi adapter has no per-run budget flag)",
                      budget_note(policy, "pi"))
        no_cap = load_policy("probe", manifest(budget={"max_minutes": 5}))
        self.assertEqual(budget_note(no_cap, "claude"), "")


class TestAdapters(unittest.TestCase):
    ENGINE_BINARY = {"pi": "pi", "claude": "claude", "antigravity": "agentapi", "deepseek": "deepseek"}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-pnu-adapter-")
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.argv_log = self.tmp / "engine-argv.log"
        for binary in set(self.ENGINE_BINARY.values()):
            stub = self.bin / binary
            stub.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > '{self.argv_log}'\n"
                "cat >/dev/null\n" + STUB_REPORT,
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.skill = self.tmp / "skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("# Probe skill\n", encoding="utf-8")
        self.target = self.tmp / "target"
        self.target.mkdir()
        self.home = self.tmp / "home"
        self.home.mkdir()

    def run_adapter(self, engine, policy=None, skill_dir=None, budget_usd=None):
        if self.argv_log.exists():
            self.argv_log.unlink()
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.home),
               "ANTHROPIC_API_KEY": "stub-key"}
        if policy is not None:
            env["FACTORY_TOOL_POLICY"] = policy
        if budget_usd is not None:
            env["FACTORY_MAX_BUDGET_USD"] = budget_usd
        res = subprocess.run(
            ["bash", str(ROOT / "lib" / "adapters" / f"{engine}.sh"), "probe", str(self.target),
             str(skill_dir or self.skill), str(self.tmp / "run")],
            input="the prompt", capture_output=True, text=True, env=env, timeout=60,
        )
        argv = self.argv_log.read_text(encoding="utf-8").splitlines() if self.argv_log.exists() else None
        return res, argv

    def test_pi_gets_the_read_only_flags(self):
        for policy in ("read-only", None):
            with self.subTest(policy=policy):
                res, argv = self.run_adapter("pi", policy)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(argv[argv.index("--tools") + 1], "read,grep,find,ls")
                self.assertIn("--no-extensions", argv)
                self.assertIn("--no-approve", argv)
                self.assertIn("Tool policy: read-only", res.stdout)

    def test_claude_gets_the_read_only_flags_and_the_skill_as_a_file(self):
        for policy in ("read-only", None):
            with self.subTest(policy=policy):
                res, argv = self.run_adapter("claude", policy)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertIn("--restricted", argv)
                self.assertEqual(argv[argv.index("--tools") + 1], "Read,Grep,Glob")
                self.assertIn("--strict-mcp-config", argv)
                self.assertEqual(argv[argv.index("--append-system-prompt-file") + 1],
                                 str(self.skill / "SKILL.md"))
                self.assertNotIn("--plugin-dir", argv)

    def test_claude_enforces_a_declared_usd_cap(self):
        """agents-js7: budget.max_usd reaches the engine as --max-budget-usd."""
        res, argv = self.run_adapter("claude", budget_usd="0.50")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(argv[argv.index("--max-budget-usd") + 1], "0.50")
        self.assertIn("Budget cap: $0.50", res.stdout)

    def test_claude_without_a_cap_runs_uncapped_but_only_then(self):
        res, argv = self.run_adapter("claude")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("--max-budget-usd", argv)

    def test_claude_refuses_a_malformed_cap(self):
        """A malformed cap would otherwise run uncapped while the record says enforced."""
        res, argv = self.run_adapter("claude", budget_usd="abc")
        self.assertEqual(res.returncode, 3, res.stderr)
        self.assertIn("not a positive dollar amount", res.stderr)
        self.assertIsNone(argv, "the engine must not run")

    def test_pi_reports_a_declared_cap_as_not_enforced(self):
        """pi has no per-run budget flag: the run proceeds, and the log says so."""
        res, argv = self.run_adapter("pi", budget_usd="0.50")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("--max-budget-usd", argv or [])
        self.assertIn("NOT enforced", res.stdout)

    def test_claude_without_a_skill_file_warns_and_still_runs_restricted(self):
        bare = self.tmp / "bare"
        bare.mkdir()
        res, argv = self.run_adapter("claude", "read-only", skill_dir=bare)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("no SKILL.md", res.stderr)
        self.assertIn("--restricted", argv)
        self.assertNotIn("--append-system-prompt-file", argv)

    def test_an_unenforceable_policy_is_refused_before_the_engine_starts(self):
        for engine in self.ENGINE_BINARY:
            for policy in ("unrestricted", "read-write", "READ-ONLY", " read-only"):
                with self.subTest(engine=engine, policy=policy):
                    res, argv = self.run_adapter(engine, policy)
                    self.assertEqual(res.returncode, 3, res.stderr)
                    self.assertIn("Refusing", res.stderr)
                    self.assertIsNone(argv, "the engine must not start")
                    self.assertFalse((self.tmp / "run" / "model_output.txt").exists())

    def test_the_adapters_agree_with_the_policy_table(self):
        """Drift guard: an adapter runs exactly the policies ENGINE_TOOL_POLICIES says it
        enforces, and every adapter on disk is in the table."""
        on_disk = {p.stem for p in (ROOT / "lib" / "adapters").glob("*.sh")}
        self.assertEqual(on_disk, set(ENGINE_TOOL_POLICIES))
        for engine, supported in ENGINE_TOOL_POLICIES.items():
            for policy in GRANTABLE_POLICIES:
                with self.subTest(engine=engine, policy=policy):
                    res, argv = self.run_adapter(engine, policy)
                    if policy in supported:
                        self.assertEqual(res.returncode, 0, res.stderr)
                        self.assertIsNotNone(argv)
                    else:
                        self.assertEqual(res.returncode, 3, res.stderr)
                        self.assertIsNone(argv)


class TestDispatcher(unittest.TestCase):
    """The real `factory run` CLI, from a sandbox copy, against a stub `pi`.

    The stub reports through its stdout, which the adapter captures into the run
    directory's model_output.txt — the only place an engine can write, because the OS
    sandbox (agents-9n7) makes the factory root read-only and the run directory writable.
    extract_json_from_output tolerates the marker lines around the JSON report.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-pnu-dispatch-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copyfile(ROOT / "factory", self.root / "factory")
        shutil.copytree(ROOT / "lib", self.root / "lib",
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.target = self.root / "target"
        self.target.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"ARGV:$*\"\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"BUDGET:${FACTORY_MAX_BUDGET_USD:-unset}\"\n"
            # The canary's *path* arrives through a file inside the target (the adapter
            # cds there); env would not reach the engine — child_environment is an
            # allowlist, which is exactly the point.
            "CANARY_PATH=$(cat canary-path.txt 2>/dev/null || echo /nonexistent)\n"
            "echo \"CANARY:$(cat \"$CANARY_PATH\" 2>&1 | head -1)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def stub_lines(self):
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1, "expected exactly one run directory")
        output = (runs[0] / "model_output.txt").read_text(encoding="utf-8")
        return output.splitlines()

    def stub_line(self, prefix):
        for line in self.stub_lines():
            if line.startswith(prefix):
                return line[len(prefix):]
        self.fail(f"no {prefix} line in the stub's output")

    def agent(self, yaml_text):
        directory = self.root / "agents" / "probe"
        directory.mkdir(parents=True)
        (directory / "agent.yaml").write_text(yaml_text, encoding="utf-8")
        (directory / "SKILL.md").write_text("# Probe\n", encoding="utf-8")

    def factory(self, engine, extra_env=None):
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.root)}
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(self.root / "factory"), "run", "probe", "--target",
             str(self.target), "--engine", engine, "--sink", "file"],
            cwd=str(self.root), env=env, capture_output=True, text=True, timeout=120,
        )

    def run_dirs(self):
        runs = self.root / "runs"
        return sorted(runs.glob("probe-*")) if runs.exists() else []

    def test_an_engine_that_cannot_enforce_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("antigravity")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("cannot enforce", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_a_declaration_above_its_ceiling_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("exceeds the t0-readonly ceiling", res.stderr)
        self.assertEqual(self.run_dirs(), [], "the engine must not start")

    def test_the_policy_is_set_explicitly_enforced_and_recorded(self):
        """A FACTORY_TOOL_POLICY in the caller's environment never reaches the adapter."""
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_TOOL_POLICY": "unrestricted",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        argv = self.stub_line("ARGV:").split()
        self.assertEqual(argv[argv.index("--tools") + 1], "read,grep,find,ls")
        self.assertIn("Withheld:    write", res.stdout)
        self.assertIn("[pi adapter] Tool policy: read-only", res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["declared"]["containment"], "t2-local")
        self.assertEqual(set(record["withheld"]), {"write"})

    def test_a_declared_usd_cap_reaches_the_adapter_only_from_the_dispatcher(self):
        """agents-js7: the declared cap is set explicitly on the adapter environment; an
        ambient FACTORY_MAX_BUDGET_USD in the operator's shell never reaches the adapter."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1, max_usd: 0.5}\n")
        res = self.factory("pi", {"FACTORY_MAX_BUDGET_USD": "999",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("BUDGET:"), "0.5", "the declared cap, not the ambient one")
        self.assertIn("NOT enforced (the pi adapter has no per-run budget flag)", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("budget.max_usd", record["not_enforced"])

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_engine_cannot_read_outside_the_target(self):
        """agents-9n7 acceptance, end to end (the agents-pnu probe): with the sandbox up, a
        pi factory run cannot read a canary that sits outside the target. This PROVES
        confinement — it does not tolerate the sandbox's absence (review P0)."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-9N7", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        line = self.stub_line("CANARY:")
        self.assertNotIn("CANARY-SECRET-9N7", line)
        self.assertIn("No such file", line)
        self.assertNotIn("CANARY-SECRET-9N7", res.stdout + res.stderr)
        self.assertIn("confined by the OS sandbox to the target", record["granted"]["read_scope"])
        self.assertNotIn("read-scope", record["not_enforced"])
        self.assertNotIn("os-sandbox", record["not_enforced"])
        self.assertIn("network-egress", record["not_enforced"])
        self.assertIn("Sandbox:     enforced", res.stdout)

    @unittest.skipUnless(shutil.which("node"),
                         "needs a real node to prove a node-shebang engine runs confined")
    def test_a_node_shebang_engine_runs_confined(self):
        """review P1 (agents-9n7): the real pi is `#!/usr/bin/env node`, so the sandbox must
        bind node or the engine dies with 'env: node: No such file or directory'. This runs a
        REAL node program as the engine (not a bash stub) and asserts it both executes inside
        the sandbox AND cannot read a canary outside the target — proving node is bound and
        the boundary still holds for a node engine."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-node-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-NODE", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        node_script = r'''#!/usr/bin/env node
const fs = require('fs');
let p = '/nonexistent';
try { p = fs.readFileSync('canary-path.txt', 'utf8').trim(); } catch (e) {}
let r;
try { r = fs.readFileSync(p, 'utf8').split('\n')[0]; } catch (e) { r = e.message; }
process.stdout.write('CANARY:' + r + '\n');
process.stdout.write('NODE-ENGINE-OK\n');
let inp = '';
process.stdin.on('data', d => { inp += d; });
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({summary: 'node probe', scanned_files: 1, findings: []}) + '\n');
});
'''
        node_pi = self.bin / "pi"
        node_pi.write_text(node_script, encoding="utf-8")
        node_pi.chmod(node_pi.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        # node must be on the subprocess PATH so the engine wrap resolves and binds it.
        node_dir = str(Path(shutil.which("node")).parent)
        res = self.factory("pi", {"PATH": f"{self.bin}{os.pathsep}{node_dir}{os.pathsep}/usr/bin:/bin"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        lines = "\n".join(self.stub_lines())
        self.assertIn("NODE-ENGINE-OK", lines,
                      "the node engine must actually execute inside the sandbox (node bound)")
        canary_line = self.stub_line("CANARY:")
        self.assertNotIn("CANARY-SECRET-NODE", canary_line)
        self.assertTrue("ENOENT" in canary_line or "No such file" in canary_line, canary_line)

    def test_a_pi_run_is_refused_when_the_sandbox_cannot_run(self):
        """review P0 (agents-9n7): pi's read scope is confined ONLY by the OS sandbox. If
        bubblewrap cannot run on the host, the dispatcher must REFUSE — never silently fall
        back to an unsandboxed run where a prompt-injected model reads any file the operator
        can. A broken bwrap on PATH simulates a host where the real probe fails."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-9N7", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin"})
        self.assertNotEqual(res.returncode, 0, "an unsandboxed pi run must be refused")
        self.assertIn("OS filesystem sandbox", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_unsandboxed_run_requires_an_explicit_opt_in(self):
        """The only unsandboxed path is the explicit FACTORY_ALLOW_UNSANDBOXED opt-in for a
        TRUSTED target (THREAT_MODEL.md section 7). It must run and say NOT confined,
        proving the refusal above is the default and this is a deliberate, honest exception
        rather than a silent fallback."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("NOT confined", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("os-sandbox", record["not_enforced"])
        self.assertIn("read-scope", record["not_enforced"])

    # --- agents-6ce: the disposable per-session worktree -------------------------------

    def _git_init_target(self):
        """Make self.target a git repo with one committed file, so a write grant can create a
        disposable worktree of its HEAD."""
        subprocess.run(["git", "init", "-q", str(self.target)], check=True, capture_output=True)
        (self.target / "fixme.txt").write_text("original line\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.target), "add", "-A"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.target), "-c", "user.email=factory@test",
                        "-c", "user.name=factory", "commit", "-qm", "initial"], check=True,
                       capture_output=True)

    def _editing_stub(self):
        """Overwrite the stub pi with one that records its policy/cwd and makes an edit
        (modify a tracked file + add a new one) so the session diff is non-empty."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "printf '// proposed fix\\n' >> fixme.txt\n"
            "printf 'brand new file\\n' > proposed.txt\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def test_a_write_agent_edits_a_disposable_worktree_and_leaves_the_target_untouched(self):
        """agents-6ce acceptance: a granted write runs in a disposable git worktree. The engine
        edits files there, the dispatcher collects the session diff as the proposal, the
        worktree is discarded, and the target checkout is never modified."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The grant is worktree-write and the engine ran inside the worktree, not the target.
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        self.assertIn("Tool policy: worktree-write", res.stdout)
        self.assertTrue(self.stub_line("CWD:").endswith("/worktree"), self.stub_line("CWD:"))
        # The session diff was collected as the proposal (both the edit and the new file).
        run_dir = self.run_dirs()[0]
        patch = run_dir / "session.patch"
        self.assertTrue(patch.exists(), "session.patch must be collected")
        patch_text = patch.read_text(encoding="utf-8")
        self.assertIn("proposed fix", patch_text)
        self.assertIn("proposed.txt", patch_text)
        # The worktree was discarded ...
        self.assertFalse((run_dir / "worktree").exists(), "the worktree must be removed")
        # ... and the target checkout was never modified.
        status = subprocess.run(["git", "-C", str(self.target), "status", "--porcelain"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(status.stdout.strip(), "",
                         "the target must be clean, got: " + status.stdout)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_worktree_is_writable_inside_the_sandbox(self):
        """End-to-end: under the enforced OS sandbox the worktree (under the read-write-bound
        run directory) is writable, so the engine's edits are collected and the target stays
        read-only and unmodified. No FACTORY_ALLOW_UNSANDBOXED here — the sandbox is enforced."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        patch = self.run_dirs()[0] / "session.patch"
        self.assertTrue(patch.exists(), "the sandboxed engine's edits must be collected")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))
        status = subprocess.run(["git", "-C", str(self.target), "status", "--porcelain"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(status.stdout.strip(), "",
                         "the target must be clean, got: " + status.stdout)

    def test_a_write_agent_on_a_non_git_target_downgrades_to_read_only(self):
        """agents-6ce: the worktree grant needs a git repo. A non-git target downgrades to
        read-only and re-withholds write with the specific reason, so the banner and policy
        stay honest and no worktree/session.patch is produced."""
        # self.target is a plain directory (not git) from setUp.
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("Tool policy: read-only", res.stdout)
        self.assertIn("not a git repository", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])


if __name__ == "__main__":
    unittest.main()
