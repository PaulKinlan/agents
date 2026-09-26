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
    ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, ContainmentError, banner_lines,
    check_engine, load_policy, policy_record,
)

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
    def test_every_shipped_agent_validates_and_gets_read_only(self):
        agents = sorted(p for p in (ROOT / "agents").iterdir() if (p / "agent.yaml").exists())
        self.assertTrue(agents)
        for agent_dir in agents:
            with self.subTest(agent=agent_dir.name):
                cfg = factory_cli.load_yaml_simple(agent_dir / "agent.yaml")
                policy = load_policy(agent_dir.name, cfg)
                self.assertEqual(policy.tool_policy, READ_ONLY)
                self.assertTrue(policy.tier_declared)
                check_engine(policy, "pi")
                check_engine(policy, "claude")
                with self.assertRaises(ContainmentError):
                    check_engine(policy, "antigravity")

    def test_declared_capabilities_are_reported_as_withheld(self):
        expected = {
            "pr-fixer": {"write"}, "docs-write": {"write"},
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

    def test_each_tier_accepts_its_ceiling_and_grants_read_only(self):
        cases = {
            "t0-readonly": {},
            "t1-fetch": {"network": True},
            "t2-local": {"write": True, "browser": True},
        }
        for tier, caps in cases.items():
            with self.subTest(tier=tier):
                policy = load_policy("probe", manifest(containment=tier, capabilities=caps))
                self.assertEqual(policy.tool_policy, READ_ONLY)
                self.assertEqual(set(policy.withheld), set(caps))

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


class TestBannerAndRecord(unittest.TestCase):
    def test_the_banner_says_what_is_enforced_and_what_is_not(self):
        policy = load_policy("pr-fixer", manifest(containment="t2-local",
                                                  capabilities={"write": True}))
        pi_banner = "\n".join(banner_lines(policy, "pi"))
        self.assertIn("read-only, enforced by the pi adapter", pi_banner)
        self.assertIn("Withheld:    write", pi_banner)
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
        self.assertEqual(policy_record(policy, "claude")["not_enforced"],
                         ["os-sandbox", "budget.max_usd"])


class TestAdapters(unittest.TestCase):
    ENGINE_BINARY = {"pi": "pi", "claude": "claude", "antigravity": "agentapi"}

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

    def run_adapter(self, engine, policy=None, skill_dir=None):
        if self.argv_log.exists():
            self.argv_log.unlink()
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.home),
               "ANTHROPIC_API_KEY": "stub-key"}
        if policy is not None:
            env["FACTORY_TOOL_POLICY"] = policy
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
    """The real `factory run` CLI, from a sandbox copy, against a stub `pi`."""

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
        self.argv_log = self.root / "engine-argv.log"
        self.policy_log = self.root / "engine-policy.log"
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' \"$@\" > '{self.argv_log}'\n"
            f"printf '%s' \"${{FACTORY_TOOL_POLICY:-unset}}\" > '{self.policy_log}'\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

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
        self.assertFalse(self.argv_log.exists(), "the engine must not start")
        self.assertEqual(self.run_dirs(), [])

    def test_the_policy_is_set_explicitly_enforced_and_recorded(self):
        """A FACTORY_TOOL_POLICY in the caller's environment never reaches the adapter."""
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_TOOL_POLICY": "unrestricted"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.policy_log.read_text(encoding="utf-8"), READ_ONLY)
        argv = self.argv_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(argv[argv.index("--tools") + 1], "read,grep,find,ls")
        self.assertIn("Withheld:    write", res.stdout)
        self.assertIn("[pi adapter] Tool policy: read-only", res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["declared"]["containment"], "t2-local")
        self.assertEqual(set(record["withheld"]), {"write"})


if __name__ == "__main__":
    unittest.main()
