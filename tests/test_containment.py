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

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.containment import (  # noqa: E402
    ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE, ContainmentError, banner_lines,
    budget_note, check_engine, downgrade_network_to_withheld, egress_allowlist, load_policy,
    policy_record,
)
from lib.sandbox import sandbox_available, sandbox_command  # noqa: E402
from lib.credential_broker import PLACEHOLDER_KEY  # noqa: E402
from lib import egress_proxy  # noqa: E402
from lib.egress_proxy import EgressProxy  # noqa: E402

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
                # A declared write is granted as worktree-write ONLY for class `proposer`
                # (its output is a patch); an optimizer (perf-hillclimb) stays read-only
                # because its driver applies structured steps in its own worktree, and any
                # other/unknown class is not granted it — fail closed (agents-6ce, review P2).
                expected = (WORKTREE_WRITE
                            if policy.declared["write"] and cfg.get("class") == "proposer"
                            else READ_ONLY)
                self.assertEqual(policy.tool_policy, expected)
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
        # docs-write no longer report it as withheld; network is granted via the
        # egress-allowlist proxy (agents-2x6 — run_agent re-withholds it per run when the
        # proxy cannot be active); browser still is.
        expected = {
            "pr-fixer": set(), "docs-write": set(),
            "deps-supply-chain": set(), "issue-triage": set(),
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
            "t1-fetch": ({"network": True}, READ_ONLY, set()),
            # write is granted via the disposable worktree (agents-6ce), so it is not
            # withheld; browser still is (no localhost-only browser mechanism yet). network
            # is granted via the egress-allowlist proxy (agents-2x6) and re-withheld at run
            # time only when this run cannot isolate the netns.
            "t2-local": ({"write": True, "browser": True}, WORKTREE_WRITE, {"browser"}),
        }
        for tier, (caps, tool_policy, withheld) in cases.items():
            with self.subTest(tier=tier):
                # class=proposer so a t2-local write declaration is grantable (the gate is
                # fail-closed on class == proposer, review P2).
                policy = load_policy("probe", manifest(containment=tier, capabilities=caps,
                                                       **{"class": "proposer"}))
                self.assertEqual(policy.tool_policy, tool_policy)
                self.assertEqual(set(policy.withheld), withheld)

    def test_the_egress_allowlist_derives_from_the_agents_own_requires(self):
        """agents-2x6: the per-run allowlist is configuration data — the union of the hosts
        each DECLARED requires tool fetches from — never a hardcoded global list. A tool that
        is absent or unknown (git: audited to be local-only) contributes nothing."""
        self.assertEqual(egress_allowlist(("gh",)), ("api.github.com",))
        self.assertEqual(egress_allowlist(("gh", "npm", "npx")),
                         ("api.github.com", "registry.npmjs.org"))
        self.assertEqual(egress_allowlist(("git",)), ())
        self.assertEqual(egress_allowlist(()), ())
        self.assertEqual(egress_allowlist(("curl", "make")), ())

    def test_a_declared_network_is_rewithheld_only_when_declared(self):
        """agents-2x6: load_policy grants a declared network optimistically (the
        egress-allowlist proxy can hold it to the tier's hosts); the run-time downgrade
        re-withholds it with the reason that names the mechanism. Idempotent, and a policy
        that never declared network is returned untouched."""
        net = load_policy("probe", manifest(containment="t1-fetch",
                                             capabilities={"network": True}))
        self.assertNotIn("network", net.withheld)
        downgraded = downgrade_network_to_withheld(net)
        self.assertIn("network", downgraded.withheld)
        self.assertIn("egress-allowlist proxy", downgraded.withheld["network"])
        # Idempotent, and an undeclared network is untouched.
        self.assertIs(downgrade_network_to_withheld(downgraded), downgraded)
        plain = load_policy("probe", manifest())
        self.assertIs(downgrade_network_to_withheld(plain), plain)

    def test_a_proposer_gets_the_worktree_but_an_optimizer_session_stays_read_only(self):
        """agents-6ce: the session worktree is for a proposer whose output IS a patch. An
        optimizer (perf-hillclimb) returns structured steps its driver applies in its own
        measure-change-remeasure worktree, so its model session stays read-only — which also
        keeps a read-only engine (deepseek) usable for it, while a proposer's worktree-write
        needs an engine that enforces edit/write (pi, claude)."""
        proposer = load_policy("pr-fixer", manifest(containment="t2-local",
                                                    capabilities={"write": True},
                                                    **{"class": "proposer"}))
        self.assertEqual(proposer.tool_policy, WORKTREE_WRITE)
        self.assertNotIn("write", proposer.withheld)
        optimizer = load_policy("perf-hillclimb", manifest(containment="t2-local",
                                                           capabilities={"write": True},
                                                           **{"class": "optimizer"}))
        self.assertEqual(optimizer.tool_policy, READ_ONLY)
        self.assertIn("write", optimizer.withheld)
        self.assertIn("optimizer", optimizer.withheld["write"])
        check_engine(optimizer, "deepseek")  # read-only is enforceable everywhere
        with self.assertRaises(ContainmentError):
            check_engine(proposer, "deepseek")  # worktree-write is not

    def test_a_non_proposer_class_is_not_granted_write(self):
        """Review P2 (agents-6ce): the write gate is fail-closed on class == proposer. An
        observer, or any unknown/mis-typed class, that declares write is NOT granted
        worktree-write — it stays read-only with write withheld. (Before the fix the gate was
        `!= optimizer`, which granted a write primitive to any class nobody had vetted.)"""
        for klass in ("observer", "totally-unknown-class"):
            with self.subTest(klass=klass):
                policy = load_policy("probe", manifest(containment="t2-local",
                                                       capabilities={"write": True},
                                                       **{"class": klass}))
                self.assertEqual(policy.tool_policy, READ_ONLY)
                self.assertIn("write", policy.withheld)
        # The positive case is unchanged: a proposer IS granted it.
        proposer = load_policy("probe", manifest(containment="t2-local",
                                                 capabilities={"write": True},
                                                 **{"class": "proposer"}))
        self.assertEqual(proposer.tool_policy, WORKTREE_WRITE)

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
                                                  capabilities={"write": True, "browser": True},
                                                  **{"class": "proposer"}))
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
        # agents-2x6: egress control is active on a sandboxed run (netns isolated, only the
        # broker + allowlist proxy reachable), so network-egress is no longer honestly
        # listed as not enforced — the record now says the egress IS filtered.
        self.assertNotIn("network-egress", record["not_enforced"])
        self.assertTrue(record["granted"]["os_sandbox"]["network_egress_filtered"])
        self.assertIn("egress filtered", res.stdout)
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

    def _target_fingerprint(self):
        """A byte-level fingerprint of the target checkout: its HEAD commit plus a sha256 of
        every working-tree file's relative path and content (.git internals excluded). Equal
        fingerprints before and after a run prove the checkout is byte-identical — the explicit
        hard requirement, stronger than `git status` alone."""
        head = subprocess.run(["git", "-C", str(self.target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        digest = hashlib.sha256(head.encode("utf-8"))
        for path in sorted(p for p in self.target.rglob("*")
                           if p.is_file() and ".git" not in p.relative_to(self.target).parts):
            digest.update(str(path.relative_to(self.target)).encode("utf-8"))
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def _assert_no_leaked_worktree(self):
        """No disposable session worktree may survive a run (coord hard requirement): neither
        the directory under the run dir nor a registration in the target's .git/worktrees."""
        for run_dir in self.run_dirs():
            self.assertFalse((run_dir / "worktree").exists(),
                             f"leaked worktree directory in {run_dir}")
        listing = subprocess.run(
            ["git", "-C", str(self.target), "worktree", "list", "--porcelain"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("/worktree", listing, "leaked worktree registration: " + listing)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_write_agent_edits_a_disposable_worktree_and_leaves_the_target_untouched(self):
        """agents-6ce acceptance: a granted write runs in a disposable git worktree. The engine
        edits files there, the dispatcher collects the session diff as the proposal, the
        worktree is discarded, and the target checkout is never modified. Gated on bwrap: since
        review P1-2 pi gets worktree-write ONLY when engine_sandboxed, so this mechanism is
        reachable only under a real OS sandbox; on a bwrap-less host it downgrades to read-only
        (test_an_unsandboxed_pi_write_agent_downgrades_to_read_only)."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
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
        # No worktree leaked, and the target checkout is byte-identical (coord hard
        # requirement: prove a write run never touched the operator's checkout).
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical after a write run")
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
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        patch = self.run_dirs()[0] / "session.patch"
        self.assertTrue(patch.exists(), "the sandboxed engine's edits must be collected")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical after a sandboxed write run")
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

    def test_an_unsandboxed_pi_write_agent_downgrades_to_read_only(self):
        """Review P1-2 (agents-6ce): the OS sandbox is the ONLY boundary that ro-binds the
        target — pi's tools are not path-confined by its flags. On a bwrap-less host (a broken
        bwrap on PATH simulates it) under the explicit FACTORY_ALLOW_UNSANDBOXED opt-in, a pi
        write agent must NOT get worktree-write: that would hand a prompt-injected session an
        unconfined write primitive over the operator's tree. It downgrades to read-only (the
        pre-6ce behaviour for this mode); no worktree or session.patch is produced."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        bwrap = broken / "bwrap"
        bwrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        bwrap.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("Tool policy: read-only", res.stdout)
        self.assertIn("will not run inside the OS sandbox", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_a_claude_write_agent_downgrades_to_read_only(self):
        """Review P1-2 (agents-6ce): claude is NOT in SANDBOXED_ENGINES (its adapter is not
        sandbox-verified), so engine_sandboxed('claude') is False on EVERY host — claude never
        gets the OS sandbox that ro-binds the target. Its --restricted is claude's own
        confinement, not a kernel boundary, so a claude write agent downgrades to read-only
        anywhere. No broken bwrap needed here: claude is never engine_sandboxed."""
        self._git_init_target()
        stub = self.bin / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        # ANTHROPIC_API_KEY satisfies claude.sh's deterministic auth gate (a presence check);
        # the stub never calls the real API.
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("will not run inside the OS sandbox", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_collect_session_diff_raises_on_a_stale_index_lock(self):
        """Review P1-1 (agents-6ce): if a crashed run left a stale index.lock, `git add -A`
        exits non-zero (128) while the following `git diff --cached` returns an empty rc0 diff.
        _collect_session_diff must RAISE, not return None — returning None would print 'no file
        edits (empty proposal)' and exit 0, silently discarding the engine's proposal. Uses a
        real linked worktree (round 2) so the .git marker and admin gitdir match production."""
        target = self.root / "lock-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "lock-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The session "edited" a file, then a crashed run left a stale lock in the admin gitdir.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        lock = gitdir / "index.lock"
        lock.write_text("", encoding="utf-8")
        run_dir = self.root / "lock-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a failed stage must not produce a patch")
        finally:
            lock.unlink(missing_ok=True)
            factory_cli._remove_session_worktree(target, wt)

    def test_a_redirected_worktree_git_marker_is_refused_not_followed(self):
        """Review P1-1 round 2 (agents-6ce): the worktree's .git marker is a FILE inside the
        writable run_dir, so a write-enabled model can replace `gitdir: <target>/.git/worktrees/
        <name>` with `gitdir: <target>/.git`. An unpinned host-side `git add -A` would then run
        against the operator's real repo and STAGE THE OPERATOR'S uncommitted target edits.
        _collect_session_diff must validate the marker against the admin gitdir captured at
        creation and REFUSE; its --git-dir/--work-tree pinning is the second layer that makes
        the redirect ineffective regardless. The operator's target index must be untouched."""
        target = self.root / "redirect-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "committed.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        # An operator edit sitting UNSTAGED in the target's own checkout — exactly what the
        # attack would stage into the target's index if host-side git followed the marker.
        (target / "committed.txt").write_text("base\nOPERATOR UNCOMMITTED WORK\n", encoding="utf-8")
        index_before = (target / ".git" / "index").read_bytes()

        wt = self.root / "redirect-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The model edits its worktree, then repoints the .git marker at the target's real .git.
        (wt / "committed.txt").write_text("base\nmodel edit\n", encoding="utf-8")
        (wt / ".git").write_text(f"gitdir: {target / '.git'}\n", encoding="utf-8")

        run_dir = self.root / "redirect-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a refused marker redirect must not produce a patch")
            self.assertEqual((target / ".git" / "index").read_bytes(), index_before,
                             "the redirected marker must never stage the operator's target index")
        finally:
            factory_cli._remove_session_worktree(target, wt)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_worktree_is_removed_even_when_the_engine_fails(self):
        """agents-6ce hard requirement: no leaked worktrees. An engine that edits the worktree
        and then FAILS must still have its disposable worktree discarded by the finally block,
        and the target checkout must stay byte-identical. Gated on bwrap and asserting the
        worktree-write policy + a /worktree cwd FIRST (review P1-2 round 2): without a real OS
        sandbox the run downgrades to read-only, no worktree is created, and the cleanup
        assertions below would pass vacuously — proving nothing about worktree cleanup."""
        self._git_init_target()
        # A stub that records its policy/cwd, edits a file inside the worktree, then fails
        # (non-zero, no report). The adapter propagates the failure (pi.sh: `pi ... || exit 1`),
        # so run_agent raises StationError only AFTER the finally has removed the worktree.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "printf '// edited then crashed\\n' >> fixme.txt\n"
            "cat >/dev/null\n"
            "exit 7\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a failed engine must fail the run")
        # Prove the worktree path was actually taken (review P1-2 round 2): the grant was
        # worktree-write and the engine ran inside the disposable worktree, not the target.
        # Without this the cleanup assertions below could pass on a downgraded read-only run.
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        self.assertTrue(self.stub_line("CWD:").endswith("/worktree"), self.stub_line("CWD:"))
        # No worktree leaked despite the failure, and the target is byte-identical.
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical even when the engine fails")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_engine_gets_a_broker_placeholder_not_the_real_key(self):
        """agents-8h4 acceptance: a sandboxed engine must not carry the operator's real API key.
        With a real key in the dispatcher's environment, run_agent starts the localhost
        credential broker and hands the engine a PLACEHOLDER + the broker base URL instead, so
        the engine's own /proc/self/environ — the leak vector THREAT_MODEL §6.1 names — holds no
        credential shape, while the broker (host side) still injects the real key upstream. This
        proves the key is stripped inside the REAL bwrap sandbox and that the engine can reach
        the broker through the sandbox's shared host network. Gated on bwrap: brokering applies
        only to an engine_sandboxed run."""
        real_key = "sk-ant-REALKEY-do-not-leak"
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"ENVKEY:${ANTHROPIC_API_KEY:-unset}\"\n"
            "echo \"ENVBASE:${ANTHROPIC_BASE_URL:-unset}\"\n"
            # The leak vector: grep the engine's OWN /proc/self/environ for the real key.
            "if tr '\\0' '\\n' < /proc/self/environ | grep -qF '" + real_key + "'; then\n"
            "  echo PROCENV:LEAKED\n"
            "else\n"
            "  echo PROCENV:CLEAN\n"
            "fi\n"
            # Reach the broker over loopback; the root path 404s BEFORE any upstream hop, so
            # this needs no real provider network.
            "PORT=${ANTHROPIC_BASE_URL#http://127.0.0.1:}; PORT=${PORT%%/*}\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf 'GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' >&3\n"
            "  read -r LINE <&3 && echo \"BROKERLINE:$LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo BROKERLINE:UNREACHABLE\n"
            "fi\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        # A read-only observer: brokering applies to any sandboxed engine, no write grant needed.
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"ANTHROPIC_API_KEY": real_key})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The engine's environ holds the placeholder, never the real key.
        self.assertEqual(self.stub_line("ENVKEY:"), PLACEHOLDER_KEY)
        self.assertEqual(self.stub_line("PROCENV:"), "CLEAN",
                         "the real key must not appear in the sandboxed engine's /proc/self/environ")
        base = self.stub_line("ENVBASE:")
        self.assertTrue(base.startswith("http://127.0.0.1:") and base.endswith("/proxy/anthropic"),
                        f"the engine must be pointed at the localhost broker, got {base!r}")
        # And it can actually reach the broker through the sandbox network: a 404 on the root
        # path proves the listener answered (no upstream hop involved).
        self.assertIn("404", self.stub_line("BROKERLINE:"),
                      "the sandboxed engine must reach the broker over loopback")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_engine_has_no_route_off_its_netns(self):
        """agents-2x6 acceptance: with egress control active the engine runs under
        --unshare-net, so a dial off the sandbox must genuinely fail at the kernel, not by
        convention. The allowlisted path — the credential broker through the net_forward
        relay — is proven end to end by the 8h4 acceptance test above, which now runs through
        that relay (the engine dials 127.0.0.1:8384 and the broker answers). This is the
        complement: everything ELSE is unreachable, and no resolver is available either."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "python3 - <<'PYEOF'\n"
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('93.184.216.34', 443), timeout=3).close()\n"
            "    print('DIRECT:REACHED')\n"
            "except OSError:\n"
            "    print('DIRECT:UNREACHABLE')\n"
            "try:\n"
            "    socket.gethostbyname('api.github.com')\n"
            "    print('DNS:RESOLVED')\n"
            "except OSError:\n"
            "    print('DNS:BLOCKED')\n"
            "PYEOF\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("DIRECT:"), "UNREACHABLE",
                         "under --unshare-net a dial off the netns must fail at the kernel")
        self.assertEqual(self.stub_line("DNS:"), "BLOCKED",
                         "no resolver may be reachable from the isolated netns")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_prepass_egress_is_held_to_its_own_allowlist(self):
        """agents-2x6 acceptance: the pre-pass runs under --unshare-net with the egress
        proxy as its only route off the netns (HTTP_PROXY points at the in-sandbox relay),
        and the allowlist is derived from the agent's OWN requires — here [gh] →
        api.github.com — so a fetch of any other host is refused by the proxy itself (403).
        The refusal is decided before any upstream dial, so this needs no live network."""
        self.agent("name: probe\nclass: observer\ncontainment: t1-fetch\n"
                   "capabilities:\n  network: true\n  requires: [gh]\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, os, sys, urllib.error, urllib.request\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "try:\n"
            "    urllib.request.urlopen('http://registry.npmjs.org/-/ping', timeout=5)\n"
            "    verdict = 'reached'\n"
            "except urllib.error.HTTPError as e:\n"
            "    verdict = f'http-{e.code}'\n"
            "except OSError as e:\n"
            "    verdict = f'os-{type(e).__name__}'\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'egress': verdict, 'proxy': os.environ.get('HTTP_PROXY')}, fh)\n",
            encoding="utf-8",
        )
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        payload = json.loads((self.run_dirs()[0] / "candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["proxy"], "http://127.0.0.1:8385",
                         "the pre-pass must be pointed at the in-sandbox egress proxy")
        self.assertEqual(payload["egress"], "http-403",
                         "a host outside the agent's own requires allowlist must be refused")


def _mock_http_upstream(port_holder, ready, stop):
    """A plain-HTTP mock upstream for the agents-2x6 end-to-end test: answers every
    request with `200 mock-upstream-ok` on an ephemeral loopback port (host side; the
    sandboxed client never dials it directly — only the egress proxy does)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    try:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(3)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    body = b"mock-upstream-ok"
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                                 + str(len(body)).encode()
                                 + b"\r\nConnection: close\r\n\r\n" + body)
                except OSError:
                    pass
    finally:
        srv.close()


# Runs INSIDE the sandboxed engine (under --unshare-net): every network act goes through
# the in-sandbox relay (127.0.0.1:8385) or fails at the kernel. Note the client resolves
# no hostname at all — with a proxy set, urllib/http.client send the absolute URI to the
# numeric loopback relay — which is itself the design property under test (DNS is blocked
# in the netns and nothing legitimate needs it).
_E2E_PROBE_SCRIPT = r"""
import http.client, json, socket, sys, urllib.error, urllib.request

port = int(sys.argv[1])
results = {}

def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=6) as r:
            return "ok-{}-{}".format(r.status, r.read().decode())
    except urllib.error.HTTPError as e:
        return "http-{}".format(e.code)
    except OSError as e:
        return "os-{}:{}".format(type(e).__name__, getattr(e, "reason", e))

# (a) allowlisted host: relay -> proxy -> mock upstream.
results["allowlisted"] = fetch("http://allowlisted.test:{}/fetch".format(port))
# (b) non-allowlisted host: the proxy must refuse it, never dial it.
results["forbidden"] = fetch("http://forbidden.test:{}/fetch".format(port))

# (c) coercion 1: absolute-URI target forbidden, forged Host header allowlisted. The
# proxy's decision must come from the request line, never the header.
conn = http.client.HTTPConnection("127.0.0.1", 8385, timeout=6)
try:
    conn.request("GET", "http://forbidden.test:{}/smuggle".format(port),
                 headers={"Host": "allowlisted.test:{}".format(port)})
    results["coerce_host_header"] = "http-{}".format(conn.getresponse().status)
except OSError as e:
    results["coerce_host_header"] = "os-{}".format(type(e).__name__)
finally:
    conn.close()

# (c) coercion 2: a direct CONNECT to a non-allowlisted host.
line = "no-response"
s = socket.create_connection(("127.0.0.1", 8385), timeout=6)
try:
    s.sendall(("CONNECT forbidden.test:{0} HTTP/1.1\r\nHost: forbidden.test:{0}\r\n\r\n"
               .format(port)).encode())
    data = s.recv(4096)
    if data:
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
finally:
    s.close()
results["coerce_connect"] = line

# The kernel property, in the same sandboxed run: no route off the netns at all.
try:
    socket.create_connection(("93.184.216.34", 443), timeout=3).close()
    results["direct"] = "REACHED"
except OSError:
    results["direct"] = "UNREACHABLE"

print("EGRESS:" + json.dumps(results, sort_keys=True))
"""


class TestEgressEndToEnd(unittest.TestCase):
    """agents-2x6 named end-to-end acceptance (coord guardrails), all in ONE sandboxed
    run: from INSIDE a real --unshare-net bubblewrap engine, through the net_forward relay
    and the egress proxy, (a) an allowlisted host succeeds against a mock upstream,
    (b) a non-allowlisted host genuinely fails (403 from the proxy, ENETUNREACH from the
    kernel for anything off the netns), and (c) the proxy cannot be coerced into reaching
    a non-allowlisted host via the request — the dial target is taken from the request
    line and checked against the run's own allowlist, never trusted from a header. The
    mock upstream is loopback, so the SSRF guard is patched to treat it as public (the
    established pattern from tests/test_egress_proxy.py); bwrap, --unshare-net, the relay
    and the proxy's allowlist decision are all the real mechanism."""

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_allowlisted_egress_works_and_everything_else_genuinely_fails(self):
        with tempfile.TemporaryDirectory(prefix="factory-2x6-e2e-") as tmpdir:
            root = Path(tmpdir)
            target = root / "target"
            target.mkdir()
            run_dir = root / "runs" / "probe-e2e"
            run_dir.mkdir(parents=True)

            port_holder, upstream_ready, upstream_stop = [], threading.Event(), threading.Event()
            threading.Thread(target=_mock_http_upstream,
                             args=(port_holder, upstream_ready, upstream_stop),
                             daemon=True).start()
            self.assertTrue(upstream_ready.wait(5))
            upstream_port = port_holder[0]

            probe = run_dir / "probe.py"
            probe.write_text(_E2E_PROBE_SCRIPT, encoding="utf-8")

            proxy = EgressProxy(["allowlisted.test"], str(run_dir / "egress-proxy.sock"))
            proxy.start()
            child_env = {"PATH": "/usr/bin:/bin",
                         "HTTP_PROXY": "http://127.0.0.1:8385",
                         "HTTPS_PROXY": "http://127.0.0.1:8385",
                         "NO_PROXY": "localhost,127.0.0.1"}
            try:
                with mock.patch.object(egress_proxy, "_public_addresses",
                                       return_value=["127.0.0.1"]):
                    wrapped = sandbox_command(
                        [sys.executable, str(probe), str(upstream_port)],
                        target_dir=target, factory_root=ROOT, run_dir=run_dir,
                        env=child_env,
                        executables=(sys.executable,),
                        egress_forwards=[(8385, str(run_dir / "egress-proxy.sock"))])
                    res = subprocess.run(wrapped, capture_output=True, text=True,
                                         timeout=120, env=child_env)
            finally:
                proxy.stop()
                upstream_stop.set()

            line = next((l for l in res.stdout.splitlines() if l.startswith("EGRESS:")), None)
            self.assertIsNotNone(
                line, "the sandboxed probe produced no verdict:\n" + res.stdout + res.stderr)
            results = json.loads(line[len("EGRESS:"):])

            # (a) the allowlisted host is reachable through relay + proxy + mock upstream.
            self.assertEqual(results["allowlisted"], "ok-200-mock-upstream-ok", results)
            # (b) a non-allowlisted host genuinely fails: refused by the proxy (403) ...
            self.assertEqual(results["forbidden"], "http-403", results)
            # ... and a dial off the netns fails at the kernel, not by convention.
            self.assertEqual(results["direct"], "UNREACHABLE", results)
            # (c) coercion: the Host header cannot smuggle a non-allowlisted target ...
            self.assertEqual(results["coerce_host_header"], "http-403", results)
            # ... and a direct CONNECT to a non-allowlisted host is refused too.
            self.assertIn("403", results["coerce_connect"], results)


if __name__ == "__main__":
    unittest.main()
