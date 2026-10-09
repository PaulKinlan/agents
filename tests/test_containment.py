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
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
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
from lib.child_env import child_environment  # noqa: E402
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
        observer that declares write is NOT granted worktree-write — it stays read-only
        with write withheld. (Before the fix the gate was `!= optimizer`, which granted a
        write primitive to any class nobody had vetted.) agents-7ik tightened the tail:
        an unknown/mis-typed class no longer slips through as a silent read-only run — it
        REFUSES, like an unknown tier."""
        policy = load_policy("probe", manifest(containment="t2-local",
                                               capabilities={"write": True},
                                               **{"class": "observer"}))
        self.assertEqual(policy.tool_policy, READ_ONLY)
        self.assertIn("write", policy.withheld)
        with self.assertRaises(ContainmentError):
            load_policy("probe", manifest(containment="t2-local",
                                           capabilities={"write": True},
                                           **{"class": "totally-unknown-class"}))
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

    def test_the_record_documents_the_transport_trust_assumption(self):
        # agents-5d9: policy.json records the previously-invisible ambient proxy/CA
        # passthrough — the operator CA bundle is never forwarded, and the operator proxy
        # reaches only unsandboxed children.
        record = policy_record(load_policy("probe", manifest()), "pi")
        self.assertIn("network_transport", record)
        self.assertIn("CA bundle not forwarded", record["network_transport"]["ca_bundle"])
        self.assertIn("only to unsandboxed children", record["network_transport"]["proxy"])

    def test_only_an_exercised_brokered_engine_drops_the_env_credential_residual(self):
        """Fail-on-revert: the old unconditional append falsified sandboxed broker runs."""
        policy = load_policy("probe", manifest())
        sandbox = {"engine_sandboxed": True, "network_egress_filtered": True,
                   "engine_read_scope": "OS sandbox"}
        parent = {"ANTHROPIC_API_KEY": "not-a-real-provider-key"}
        engine_env = child_environment(engine="pi", parent=parent, broker_urls={
            "anthropic": "http://127.0.0.1:8384/proxy/anthropic"})
        kwargs = {"sandbox": sandbox, "brokered_providers": ("anthropic",),
                  "engine_env": engine_env}
        record = policy_record(policy, "pi", **kwargs)
        self.assertNotIn("env-credentials", record["not_enforced"])
        self.assertEqual(record["granted"]["credential_broker"]["providers"], ["anthropic"])
        self.assertNotIn("not-a-real-provider-key", json.dumps(record))
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, engine_env=engine_env)["not_enforced"],
            "a placeholder without an actually running broker is not enforcement")
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=child_environment(engine="pi", parent=parent))["not_enforced"],
            "a provider name without apply_broker_urls must not upgrade policy.json")
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=dict(engine_env, ANTHROPIC_BASE_URL="http://[invalid"))[
                "not_enforced"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=dict(engine_env, OPENAI_API_KEY="unbrokered"))["not_enforced"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=dict(engine_env, HTTPS_PROXY="http://user:pass@proxy.test"))[
                "not_enforced"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox={**sandbox, "engine_sandboxed": False},
            brokered_providers=("anthropic",), engine_env=engine_env)["not_enforced"],
            "a sandboxed pre-pass cannot attest to the engine env")
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=(),
            engine_env=child_environment(engine="pi", parent={}))["not_enforced"],
            "no credentials means no broker was started; keep the conservative residual")

    def test_an_unsandboxed_opt_in_is_surfaced_prominently(self):
        # agents-bp0: a run that proceeds unsandboxed by the explicit opt-in says so with
        # the attestation it ran under, in both the banner and policy.json — instead of
        # the generic gap text. The not_enforced list is unchanged: the note never
        # upgrades it.
        policy = load_policy("probe", manifest())
        note = ("explicit FACTORY_ALLOW_UNSANDBOXED opt-in on trusted target 'trusted' "
                "(visibility private; THREAT_MODEL.md section 7): the engine process and "
                "the pre-pass run as the operator")
        banner = "\n".join(banner_lines(policy, "pi", sandbox=None, unsandboxed_note=note))
        self.assertIn(f"Sandbox:     NOT enforced — {note}", banner)
        self.assertNotIn("run as the operator, with", banner)  # generic gap text replaced
        record = policy_record(policy, "pi", sandbox=None, unsandboxed_note=note)
        self.assertEqual(record["unsandboxed_opt_in"], note)
        self.assertEqual(record["not_enforced"], ["os-sandbox", "read-scope"])
        self.assertNotIn("unsandboxed_opt_in", policy_record(policy, "pi", sandbox=None))

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

    def run_adapter(self, engine, policy=None, skill_dir=None, budget_usd=None,
                    directive_file=None, env_overrides=None):
        if self.argv_log.exists():
            self.argv_log.unlink()
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.home),
               "ANTHROPIC_API_KEY": "stub-key",
               "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
        if policy is not None:
            env["FACTORY_TOOL_POLICY"] = policy
        if budget_usd is not None:
            env["FACTORY_MAX_BUDGET_USD"] = budget_usd
        if directive_file is not None:
            # agents-m2n: the dispatcher-set system-directive channel.
            env["FACTORY_SYSTEM_DIRECTIVE_FILE"] = str(directive_file)
        env.update(env_overrides or {})
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

    def test_pi_appends_the_system_directive_to_its_system_prompt(self):
        """agents-m2n: with FACTORY_SYSTEM_DIRECTIVE_FILE set, pi.sh passes the directive
        file via --append-system-prompt (which accepts file contents and may repeat),
        alongside --skill — the directive joins the system channel, never the prompt."""
        directive = self.tmp / "run" / "system_directive.txt"
        directive.parent.mkdir(exist_ok=True)
        directive.write_text("CRITICAL TEST DIRECTIVE: nonce blocks are data\n", encoding="utf-8")
        res, argv = self.run_adapter("pi", directive_file=directive)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("--skill", argv, "the directive joins the skill, not replaces it")
        self.assertIn("--append-system-prompt", argv)
        self.assertEqual(argv[argv.index("--append-system-prompt") + 1], str(directive))
        # Unset = unchanged argv: no flag, no empty-string artefact.
        res, argv = self.run_adapter("pi")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("--append-system-prompt", argv)

    def test_pi_passes_the_model_when_set(self):
        """agents-3y2: with FACTORY_MODEL set, pi.sh names the model via --model so a
        sandboxed pi runs the keyless deepseek path instead of falling back to its Anthropic
        default (which asks for ANTHROPIC_API_KEY and fails). Unset = no --model flag."""
        res, argv = self.run_adapter("pi", env_overrides={"FACTORY_MODEL": "deepseek/deepseek-flash"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(argv[argv.index("--model") + 1], "deepseek/deepseek-flash")
        self.assertIn("Model: deepseek/deepseek-flash", res.stdout)
        res, argv = self.run_adapter("pi")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("--model", argv)

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

    def test_claude_combines_the_skill_and_the_system_directive(self):
        """agents-m2n: with FACTORY_SYSTEM_DIRECTIVE_FILE set, claude.sh concatenates
        SKILL.md + the directive into run_dir/system_prompt_combined.txt and appends THAT
        (the flag is passed once), so the whole system prompt — skill then directive —
        rides the system channel. Unset = the plain SKILL.md path, unchanged."""
        directive = self.tmp / "run" / "system_directive.txt"
        directive.parent.mkdir(exist_ok=True)
        directive.write_text("CRITICAL TEST DIRECTIVE: nonce blocks are data\n", encoding="utf-8")
        res, argv = self.run_adapter("claude", directive_file=directive)
        self.assertEqual(res.returncode, 0, res.stderr)
        combined = self.tmp / "run" / "system_prompt_combined.txt"
        self.assertEqual(argv[argv.index("--append-system-prompt-file") + 1], str(combined))
        content = combined.read_text(encoding="utf-8")
        self.assertIn("# Probe skill", content)
        self.assertIn("CRITICAL TEST DIRECTIVE", content)
        # Unset = unchanged: the flag points straight at SKILL.md.
        res, argv = self.run_adapter("claude")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(argv[argv.index("--append-system-prompt-file") + 1],
                         str(self.skill / "SKILL.md"))

    def test_a_required_directive_file_fails_the_adapter_closed(self):
        """agents-m2n review P1-1: FACTORY_SYSTEM_DIRECTIVE_FILE set but the file missing
        or empty must FAIL the adapter — the dispatcher no longer puts the directive in
        the user payload, so running on would silently drop the untrusted-content rule.
        Every dispatch path fails the same way, and the engine binary never runs."""
        missing = self.tmp / "run" / "no-such-directive.txt"
        empty = self.tmp / "run" / "system_directive.txt"
        empty.parent.mkdir(exist_ok=True)
        empty.write_text("", encoding="utf-8")
        unreadable = self.tmp / "run" / "unreadable.txt"
        unreadable.write_text("directive", encoding="utf-8")
        unreadable.chmod(0)
        self.addCleanup(unreadable.chmod, 0o600)
        cases = [("missing", missing), ("empty", empty)]
        if not os.access(unreadable, os.R_OK):
            cases.append(("unreadable", unreadable))
        for engine in ("pi", "claude", "antigravity", "deepseek"):
            for label, directive in cases:
                with self.subTest(engine=engine, directive=label):
                    if self.argv_log.exists():
                        self.argv_log.unlink()
                    res, argv = self.run_adapter(engine, directive_file=directive)
                    self.assertEqual(res.returncode, 2, res.stderr + res.stdout)
                    self.assertIn("refusing to run without the system directive",
                                  res.stderr + res.stdout)
                    self.assertIsNone(argv, "the engine binary must never run")

    def test_antigravity_directive_separator_is_a_real_newline(self):
        """agents-esx: agentapi currently refuses every tool policy before prompt assembly.
        Exercise the adapter's actual assignment in isolation to pin the separator; a
        literal backslash-n in double quotes must not replace the two real newlines."""
        directive = self.tmp / "run" / "system_directive.txt"
        directive.parent.mkdir(exist_ok=True)
        directive.write_text("DIRECTIVE\n", encoding="utf-8")
        source = (ROOT / "lib" / "adapters" / "antigravity.sh").read_text(encoding="utf-8")
        assignment = next(line for line in source.splitlines()
                          if line.strip().startswith('PROMPT="$(cat "$FACTORY_SYSTEM_DIRECTIVE_FILE")'))
        res = subprocess.run(["bash", "-c", f'PROMPT="Scanner Data"\n{assignment}\nprintf "%s" "$PROMPT"'],
                             env={"PATH": "/usr/bin:/bin",
                                  "FACTORY_SYSTEM_DIRECTIVE_FILE": str(directive),
                                  "FACTORY_ALLOW_UNPINNED_TOOLS": "1"},
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout, "DIRECTIVE\n\nScanner Data")

    def test_deepseek_python_path_fails_closed_on_empty_and_read_errors(self):
        """agents-esx: exercise the Python API path, not the CLI refusal. A nonempty
        whitespace-only file passes bash's -s but fails Python's .strip() check; a
        directory passes bash's -r/-s but Python cannot read it as a file. Both must
        fail before any network request, with the exact Python error in model_output."""
        (self.bin / "deepseek").unlink()
        whitespace = self.tmp / "run" / "whitespace.txt"
        whitespace.parent.mkdir(exist_ok=True)
        whitespace.write_text("  \n", encoding="utf-8")
        for label, directive, message in (("empty", whitespace, "directive file is empty"),
                                           ("read-error", self.skill, "cannot read the system directive file")):
            with self.subTest(case=label):
                res, argv = self.run_adapter("deepseek", directive_file=directive,
                                             env_overrides={"DEEPSEEK_API_KEY": "dummy-key"})
                self.assertNotEqual(res.returncode, 0)
                self.assertIn(message, res.stderr)
                self.assertIsNone(argv)
                self.assertNotIn("API Request Error", res.stderr)

    def test_deepseek_python_path_sends_the_prompt_in_the_user_message(self):
        """agents-w8z: the heredoc owns the Python process's stdin (it IS the program), so
        sys.stdin.read() was always empty and every deepseek run sent an empty user
        message — a schema-valid false-clean report with zero findings. The prompt must
        ride PROMPT in the environment and reach the outgoing user message."""
        import http.server
        (self.bin / "deepseek").unlink()  # force the Python API path, not the CLI stub
        captured = {}

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server hook
                length = int(self.headers.get("Content-Length", "0"))
                captured["body"] = self.rfile.read(length)
                reply = json.dumps({"choices": [{"message": {"content":
                    json.dumps({"summary": "stub", "findings": []})}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):  # noqa: N802 - silence request logging
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        res, argv = self.run_adapter(
            "deepseek",
            env_overrides={"DEEPSEEK_API_KEY": "dummy-key",
                           "DEEPSEEK_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}"},
        )
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn("body", captured, "the adapter must actually issue the API request")
        payload = json.loads(captured["body"])
        self.assertEqual(payload["messages"][1]["content"], "the prompt",
                         "the prompt must reach the outgoing user message")

    def test_deepseek_python_path_is_keyless_without_a_key(self):
        """agents-3y2: with NO DEEPSEEK_API_KEY, the adapter still issues the request keylessly
        (no Authorization header) and uses the managed endpoint's provider-prefixed model id by
        default, so the exe.dev BYOK endpoint authenticates server-side."""
        import http.server
        (self.bin / "deepseek").unlink()  # force the Python API path, not the CLI stub
        captured = {}

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server hook
                length = int(self.headers.get("Content-Length", "0"))
                captured["body"] = self.rfile.read(length)
                captured["authorization"] = self.headers.get("Authorization")
                captured["path"] = self.path
                reply = json.dumps({"choices": [{"message": {"content":
                    json.dumps({"summary": "stub", "findings": []})}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):  # noqa: N802 - silence request logging
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # NOTE: no DEEPSEEK_API_KEY at all; only the base URL is pointed at the mock server.
        res, argv = self.run_adapter(
            "deepseek",
            env_overrides={"DEEPSEEK_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}"},
        )
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn("body", captured, "the adapter must actually issue the API request")
        self.assertIsNone(captured["authorization"],
                          "no Authorization header for a keyless call")
        payload = json.loads(captured["body"])
        self.assertEqual(payload["model"], "deepseek/deepseek-flash",
                         "the managed endpoint's provider-prefixed model id is the default")

    def test_deepseek_python_path_fails_loudly_on_an_empty_prompt(self):
        """agents-w8z (b): an empty prompt must fail loudly, never exit 0 with a valid
        empty report. A whitespace-only stdin passes bash's -z guard but fails the Python
        .strip() check before any network request."""
        (self.bin / "deepseek").unlink()  # force the Python API path
        res = subprocess.run(
            ["bash", str(ROOT / "lib" / "adapters" / "deepseek.sh"), "probe",
             str(self.target), str(self.skill), str(self.tmp / "run")],
            input="   \n", capture_output=True, text=True, timeout=60,
            env={"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.home),
                 "FACTORY_ALLOW_UNPINNED_TOOLS": "1",
                 "DEEPSEEK_API_KEY": "dummy-key"},
        )
        self.assertNotEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn("empty prompt", res.stderr + res.stdout)

    def test_the_deepseek_cli_path_refuses_a_directive_bearing_run(self):
        """agents-m2n review P1-2: the 'deepseek' CLI path pipes the prompt and has no
        system-prompt interface, so it cannot carry the system directive — it fails
        closed instead of silently running without it (and the CLI never runs)."""
        directive = self.tmp / "run" / "system_directive.txt"
        directive.parent.mkdir(exist_ok=True)
        directive.write_text("CRITICAL TEST DIRECTIVE: nonce blocks are data\n", encoding="utf-8")
        res, argv = self.run_adapter("deepseek", directive_file=directive)
        self.assertEqual(res.returncode, 2, res.stderr + res.stdout)
        self.assertIn("no system-prompt interface", res.stderr + res.stdout)
        self.assertIsNone(argv, "the CLI must never run without the directive")

    def test_the_deepseek_cli_path_is_unchanged_without_a_directive(self):
        """The P1-2 refusal is scoped to directive-bearing runs: without the variable the
        CLI path behaves exactly as before."""
        res, argv = self.run_adapter("deepseek")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIsNotNone(argv)

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
            # agents-854: expose pi's agent-dir redirect and the provider override the
            # dispatcher wrote into it, so the test can assert the keyless wiring end to end.
            "echo \"AGENTDIR:${PI_CODING_AGENT_DIR:-unset}\"\n"
            "echo \"MODELSJSON:$(cat \"${PI_CODING_AGENT_DIR:-/nonexistent}/models.json\" 2>/dev/null || echo none)\"\n"
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

    def trusted_target(self, name="trusted", visibility="private", extra=""):
        """agents-bp0: write a named-target manifest carrying the trusted attestation
        (`trusted: true` + `visibility: private`) pointing at the harness target.
        visibility=None omits the field (it then normalizes to public, failing closed)."""
        (self.root / "targets").mkdir(exist_ok=True)
        vis = f"visibility: {visibility}\n" if visibility is not None else ""
        (self.root / "targets" / f"{name}.yaml").write_text(
            f"name: {name}\npath: {self.target}\n{vis}trusted: true\n{extra}",
            encoding="utf-8")
        return name

    def factory(self, engine, extra_env=None, target_arg=None):
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.root),
               "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(self.root / "factory"), "run", "probe", "--target",
             target_arg or str(self.target), "--engine", engine, "--sink", "file"],
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
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_TOOL_POLICY": "unrestricted",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
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
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_MAX_BUDGET_USD": "999",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
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
        # agents-3y2: the keyless BYOK broker starts even with no real key present, so the
        # credential residual is covered (placeholders only), not recorded as not enforced.
        self.assertNotIn("env-credentials", record["not_enforced"])
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

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
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

    def test_an_exec_time_wrap_failure_leaves_no_enforced_record(self):
        """agents-kwi (agents-9n7 probe #2 A2): a bwrap that passes the availability probe but
        cannot start the child must not leave the run recorded as sandboxed. The wrap is
        exercised before the banner is printed and before policy.json is written, so the
        station fails with nothing that claims `Sandbox: enforced` / engine_sandboxed: true,
        and the engine never starts (so it can never run unsandboxed either)."""
        outside = tempfile.TemporaryDirectory(prefix="factory-kwi-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-KWI", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "execfailbin"
        broken.mkdir()
        stub = broken / "bwrap"
        # Green for the bare availability probe (a plan ending in /bin/true), dead for every
        # real wrap: exactly the situation agents-kwi is about.
        stub.write_text("#!/bin/sh\n"
                        "for a in \"$@\"; do [ \"$a\" = \"/bin/true\" ] && exit 0; done\n"
                        "exit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}"
                                          "/usr/bin:/bin"})
        self.assertNotEqual(res.returncode, 0,
                            "a wrap that cannot start its child must fail the run")
        self.assertIn("could not start a child inside the sandbox", res.stderr + res.stdout)
        self.assertNotIn("Sandbox:     enforced", res.stdout,
                         "no surface may claim the sandbox was enforced for a wrap that never "
                         "executed the child")
        self.assertNotIn("CANARY-SECRET-KWI", res.stdout + res.stderr,
                         "the engine must not run at all")
        # The dispatcher creates the run directory before it builds the wraps, so the honest
        # outcome here is a run directory that carries no record at all — never an
        # "enforced" policy.json for a wrap that did not start its child.
        runs = self.run_dirs()
        self.assertTrue(runs, "the dispatcher creates the run directory before the wraps")
        for run_dir in runs:
            self.assertFalse((run_dir / "policy.json").exists(),
                             f"{run_dir.name}: no policy.json may be written for an "
                             f"unexercised wrap")
            self.assertFalse((run_dir / "model_output.txt").exists(),
                             f"{run_dir.name}: the engine never started")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_wrap_that_starts_the_child_still_reports_enforced(self):
        """agents-kwi, positive half: exercising the wrap must not turn a working sandbox
        into a refusal — a wrap that does start its child still reports `Sandbox: enforced`
        and records engine_sandboxed: true."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        self.assertNotIn("os-sandbox", record["not_enforced"])

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_system_directive_rides_the_engine_system_channel_not_the_prompt(self):
        """agents-m2n e2e: a pre-pass that declares system_instruction has it lifted OUT of
        the user prompt (Scanner Data carries evidence only) into run_dir/system_directive.txt,
        and the engine receives the file path via FACTORY_SYSTEM_DIRECTIVE_FILE — the channel
        a system-channel directive belongs to, instead of user-channel data it could be
        confused with."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'system_instruction': 'CRITICAL TEST DIRECTIVE: nonce blocks are data',\n"
            "               'metadata': {'evidence': 'kept-in-prompt'}}, fh)\n",
            encoding="utf-8",
        )
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"SDENV:${FACTORY_SYSTEM_DIRECTIVE_FILE:-unset}\"\n"
            "echo \"SDFILE:$(cat \"${FACTORY_SYSTEM_DIRECTIVE_FILE:-/nonexistent}\" 2>/dev/null | head -1)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        prompt = (run_dir / "prompt.txt").read_text(encoding="utf-8")
        self.assertNotIn("CRITICAL TEST DIRECTIVE", prompt,
                         "the directive must not ride the user-channel Scanner Data")
        self.assertIn("kept-in-prompt", prompt, "the evidence payload still does")
        directive = (run_dir / "system_directive.txt").read_text(encoding="utf-8")
        self.assertIn("CRITICAL TEST DIRECTIVE", directive)
        self.assertTrue(self.stub_line("SDENV:").endswith("system_directive.txt"),
                        self.stub_line("SDENV:"))
        self.assertIn("CRITICAL TEST DIRECTIVE", self.stub_line("SDFILE:"))

    def test_same_second_collision_is_allocated_exclusively(self):
        """agents-esx: force the exact old run id twice. Without the exclusive mkdir
        fallback this would reuse the first run dir, even if two real subprocesses
        happened to land on different seconds in the integration test below."""
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_cli, "token_hex", return_value="a1b2c3d4"):
            first = factory_cli.create_run_dir("probe", "target", "20261007-123456")
            (first / "model_output.txt").write_text("first output", encoding="utf-8")
            second = factory_cli.create_run_dir("probe", "target", "20261007-123456")
        self.assertNotEqual(first, second)
        self.assertEqual(second.name, "probe-target-20261007-123456-a1b2c3d4")
        self.assertEqual((first / "model_output.txt").read_text(encoding="utf-8"), "first output")
        self.assertEqual(second.stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_two_runs_never_share_a_run_directory(self):
        """agents-m2n review P2 (same class as agents-30q): run ids resolve to the second,
        and two runs in one second must still get distinct, exclusively-created run
        directories — the egress sockets, prompt, policy.json and session.patch all live
        there."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        for _ in range(2):
            res = self.factory("pi")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 2, "both runs must complete")
        self.assertEqual(len({r.name for r in runs}), 2,
                         "consecutive runs must never share a run directory")

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
        """agents-bp0 acceptance: the ambient FACTORY_ALLOW_UNSANDBOXED opt-in alone must
        NOT unlock an unsandboxed run. The attestation lives in the TARGET's own manifest
        (targets/<name>.yaml `trusted: true` + `visibility: private`), because anything
        able to set an environment variable — a compromised schedule entry, a malicious CI
        step, a wrapper script, a command a doc tells a developer to run — must not be able
        to make the operator's filesystem the read scope. A raw --target path carries no
        manifest at all, so it refuses exactly like the no-opt-in case above."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertNotEqual(res.returncode, 0, "an untrusted target must refuse the opt-in")
        self.assertIn("trusted attestation", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_a_trusted_but_public_target_still_refuses_the_opt_in(self):
        """agents-bp0: `trusted: true` is necessary but not sufficient — a target whose
        visibility is public (or undeclared, which normalizes to public) never qualifies:
        THREAT_MODEL.md section 7's precondition is a trusted AND non-public target."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        env = {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
               "FACTORY_ALLOW_UNSANDBOXED": "1",
               "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
        for name, visibility in (("pub", "public"), ("unsetvis", None)):
            with self.subTest(target=name):
                self.trusted_target(name, visibility=visibility)
                res = self.factory("pi", env, target_arg=name)
                self.assertNotEqual(res.returncode, 0,
                                    f"{name} must refuse the opt-in")
                self.assertIn("trusted attestation", res.stderr + res.stdout)
                self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_an_absolute_target_path_never_loads_a_planted_manifest(self):
        """review P1 (agents-bp0): pathlib's absolute-join DISCARD made
        FACTORY_ROOT/'targets'/f'{target_arg}.yaml' load a manifest from ANYWHERE, so an
        argv+env-controlling adversary could plant trusted:true + visibility:private +
        path:<operator home> beside any directory and get an attested unsandboxed run
        from `--target <dir>`. Only a bare name may load a manifest; an absolute path is
        a raw target and must refuse the opt-in exactly like any other untrusted one."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        # The planted manifest sits beside the target directory: with the absolute-join
        # bug, --target <self.root>/target resolved to it and the run would be attested.
        (self.root / "target.yaml").write_text(
            f"name: planted\npath: {self.root}\nvisibility: private\ntrusted: true\n",
            encoding="utf-8")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertNotEqual(res.returncode, 0,
                            "an absolute --target must not load a planted manifest")
        self.assertIn("trusted attestation", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_the_opt_in_runs_only_for_a_trusted_private_target(self):
        """The only unsandboxed path is the explicit FACTORY_ALLOW_UNSANDBOXED opt-in for a
        TRUSTED target (THREAT_MODEL.md section 7) — a real precondition since agents-bp0,
        not just an honour-system docstring. It must run and say NOT enforced with the
        opt-in named prominently, proving the refusals above are the default and this is a
        deliberate, attested exception rather than a silent fallback."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        self.trusted_target("trusted")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     NOT enforced — explicit FACTORY_ALLOW_UNSANDBOXED opt-in "
                      "on trusted target 'trusted'", res.stdout)
        self.assertIn("run as the operator", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("os-sandbox", record["not_enforced"])
        self.assertIn("read-scope", record["not_enforced"])
        self.assertIn("explicit FACTORY_ALLOW_UNSANDBOXED opt-in on trusted target 'trusted'",
                      record["unsandboxed_opt_in"])

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
        # self.target is a plain directory (not git) from setUp; the trusted manifest
        # points at it, so the run proceeds on any host (review P2: the old raw-path +
        # opt-in form only worked where bubblewrap exists).
        self.trusted_target("trusted")
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
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
        self.trusted_target("trusted")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
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
        anywhere. No broken bwrap needed here: claude is never engine_sandboxed. agents-ejm:
        claude also needs the trusted-private target attestation, so this runs against one."""
        self._git_init_target()
        self.trusted_target("trusted")
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
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("will not run inside the OS sandbox", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_a_claude_run_against_a_public_target_is_refused(self):
        """agents-ejm: claude runs without the OS sandbox (--restricted only, not a kernel
        boundary) and with unbrokered credentials, so it is refused against any target whose
        manifest does not declare the trusted-private attestation — a raw --target path carries
        no manifest at all and refuses, fail-closed, before any run directory exists."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        # The stub is never reached — the refusal is before the adapter — but it proves a
        # reverted check would run claude to a clean exit 0, not an adapter-not-found failure.
        stub = self.bin / "claude"
        stub.write_text("#!/usr/bin/env bash\ncat >/dev/null\n" + STUB_REPORT, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"})
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("claude", res.stderr)
        self.assertIn("trusted: true", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused claude run must leave no run directory")

    def test_a_claude_run_against_a_public_named_target_is_refused(self):
        """agents-ejm: the attestation is the manifest's `trusted: true` + `visibility: private`,
        so a NAMED target that declares visibility: public (even with a trusted field absent)
        refuses a claude run — the public sink is exactly what a no-kernel-boundary engine must
        not reach."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        stub = self.bin / "claude"
        stub.write_text("#!/usr/bin/env bash\ncat >/dev/null\n" + STUB_REPORT, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        (self.root / "targets").mkdir(exist_ok=True)
        (self.root / "targets" / "public.yaml").write_text(
            f"name: public\npath: {self.target}\nvisibility: public\n", encoding="utf-8")
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="public")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("trusted: true", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused claude run must leave no run directory")

    def test_a_claude_read_only_run_against_a_trusted_private_target_proceeds(self):
        """agents-ejm positive control: a claude run against a manifest declaring trusted: true +
        visibility: private is allowed (read-only, unsandboxed) — the restriction must not
        over-block the one target class claude is permitted on."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        stub = self.bin / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("os-sandbox", record["not_enforced"])

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

    def test_second_collection_write_failure_keeps_the_first_patch_intact(self):
        """agents-nei P1-2 (round 4): each kept win re-collects session.patch in place, so a
        failure during a LATER collection's write (disk full) could truncate the earlier good
        patch and strand an already-durable KEPT row. The write must go to a sibling temp file
        and be atomically os.replace()'d only after it completes."""
        target = self.root / "atomic-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "atomic-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        run_dir = self.root / "atomic-run"
        run_dir.mkdir()

        # First collection succeeds and writes the first accumulated proposal.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        factory_cli._collect_session_diff(wt, run_dir, gitdir)
        patch_file = run_dir / "session.patch"
        first_patch = patch_file.read_bytes()
        self.assertIn(b"two", first_patch)
        self.assertNotIn(b"three", first_patch)

        # A second accumulated edit is re-collected, but its write fails (disk full) only
        # AFTER the target file has been truncated and a partial prefix written — the exact
        # failure the temp-file+replace path must survive. The earlier patch must remain
        # byte-for-byte intact (a), so the already-durable KEPT row's proposal still matches
        # what is on disk (b), and the failed temp file must be cleaned up.
        (wt / "f.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")

        def write_prefix_then_fail(path, data, encoding="utf-8"):
            # In-place implementations truncate the write target and write a prefix before the
            # error. Here the prefix lands in whatever file _collect_session_diff is writing;
            # the assertions below prove that file is a throwaway temp, not session.patch.
            path.write_bytes(data[:12].encode(encoding))
            raise OSError("disk full")

        with mock.patch.object(Path, "write_text", write_prefix_then_fail):
            with self.assertRaises(OSError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)

        self.assertEqual(patch_file.read_bytes(), first_patch)  # (a) byte-for-byte intact
        self.assertIn(b"two", patch_file.read_bytes())          # (b) kept proposal still on disk
        self.assertNotIn(b"three", patch_file.read_bytes())
        self.assertFalse((run_dir / "session.patch.tmp").exists(),
                         "a failed write must not leak the temp file")

    def test_a_non_utf8_worktree_marker_fails_closed(self):
        """agents-7ik (4): a binary .git marker raises UnicodeDecodeError (a ValueError,
        not an OSError) — it must surface as a clean StationError, never an unhandled
        traceback. Fail-closed: host-side git is refused against the marker."""
        target = self.root / "bin-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "bin-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / ".git").write_bytes(b"\xff\xfe\x00not-a-gitdir-pointer")
        with self.assertRaises(factory_cli.StationError) as ctx:
            factory_cli._validate_worktree_marker(wt, gitdir)
        self.assertIn("not UTF-8", str(ctx.exception))
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
        # agents-7ik (d): a failed session's partial edits are NOT collected as a proposal.
        self.assertIn("discarding its partial edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a failed session must not leave a proposal patch")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_session_patch_carries_a_base_commit_and_applies_cleanly(self):
        """agents-7ik (b): session.patch begins with a `base-commit:` trailer naming the
        base HEAD, so a proposal can never be applied blind against a moved HEAD — and
        git apply skips the trailer (verified here by applying the whole marked patch to a
        fresh clone of the same base)."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch_text = (run_dir / "session.patch").read_text(encoding="utf-8")
        head = subprocess.run(["git", "-C", str(self.target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertTrue(patch_text.startswith(f"base-commit: {head}\n"),
                        patch_text[:120])
        clone = self.root / "apply-clone"
        subprocess.run(["git", "clone", "-q", str(self.target), str(clone)],
                       check=True, capture_output=True)
        applied = subprocess.run(["git", "-C", str(clone), "apply",
                                  str(run_dir / "session.patch")],
                                 capture_output=True, text=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertTrue((clone / "proposed.txt").exists(),
                        "the proposal's new file must apply")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_tampered_candidates_json_fails_closed(self):
        """agents-5bn: candidates.json is the scanner's ground truth (agents-nha) that binds
        the model's rule_id/path at findings dispatch, which runs AFTER the session. The run
        dir is rw-bound inside the sandbox, so a write-granted session can overwrite it. The
        dispatcher snapshots the trusted bytes before the session and must REFUSE the dispatch
        (station failure) when the session changed them — never book findings against forged
        ground truth."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        # A write-granted session that overwrites the scanner ground truth from inside its
        # worktree (the run dir is the worktree's parent): ../candidates.json.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'FORGED' > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json changed during the engine session", res.stderr)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_an_untampered_write_session_with_candidates_dispatches(self):
        """agents-5bn positive control: a write-granted session that leaves candidates.json
        alone still dispatches normally — the snapshot verification must not false-positive on
        the honest path (a pre-pass that produces candidates, then a normal editing session)."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        self._editing_stub()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch = run_dir / "session.patch"
        self.assertTrue(patch.exists(), "the honest editing session must still collect a patch")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_preplaced_session_patch_is_discarded_when_no_edits_are_made(self):
        """agents-5bn: a write-granted session runs with the run dir rw-bound, so it can write
        run_dir/session.patch directly and be credited with a proposal it never made in the
        worktree. When the session makes no trackable edits, _collect_session_diff returns None
        and the dispatcher must discard any session.patch left in the run dir — only a collected
        patch is a real proposal."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'forged proposal' > ../session.patch\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a forged pre-placed session.patch must not survive a no-edit session")

    def test_a_planted_session_patch_tmp_symlink_is_not_followed(self):
        """agents-5bn: the run dir is rw-bound inside the sandbox, so a write-granted session
        could plant a symlink at session.patch.tmp pointing at an arbitrary operator-writable
        host file; host-side collection writing the temp file must not follow it. Unlink the name
        before writing so the planted target is never overwritten."""
        target = self.root / "symlink-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "symlink-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        run_dir = self.root / "symlink-run"
        run_dir.mkdir()
        canary = self.root / "canary.txt"
        canary.write_text("DO NOT OVERWRITE", encoding="utf-8")
        # A planted symlink at the temp-file path, as a write-granted session could leave.
        (run_dir / "session.patch.tmp").symlink_to(canary)
        try:
            patch_file = factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertIsNotNone(patch_file)
            self.assertEqual(canary.read_text(encoding="utf-8"), "DO NOT OVERWRITE",
                             "the planted symlink must never redirect the temp write at its target")
            self.assertIn("two", (run_dir / "session.patch").read_text(encoding="utf-8"))
        finally:
            factory_cli._remove_session_worktree(target, wt)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_forged_candidates_json_without_a_prepass_fails_closed(self):
        """agents-5bn: even a write-granted agent with no deterministic pre-pass must not be
        able to mint its own candidates.json — it has no trusted origin. The dispatcher refuses
        findings dispatch when candidates.json exists but no pre-pass produced it."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf '{\"candidates\":[{\"rule_id\":\"forged\",\"path\":\"forged.py\"}]}'"
            " > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json appeared during the engine session", res.stderr)

    def test_write_run_artifact_does_not_follow_a_planted_symlink(self):
        """agents-5bn P0: a write-granted session can plant a symlink at any run-dir path; the
        helper must unlink it first so the write never follows it to an arbitrary host file."""
        run_dir = self.root / "symlink-artifact-run"
        run_dir.mkdir()
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        target = run_dir / "report.json"
        target.symlink_to(canary)
        factory_cli._write_run_artifact(target, '{"summary": "clean"}')
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the write must not follow the planted symlink")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"summary": "clean"}',
                         "the artifact must be a fresh regular file")

    def test_write_run_artifact_fails_closed_on_a_planted_directory(self):
        """agents-5bn P0: a session could plant a directory at an artifact path; unlink on a
        directory raises, so the write fails closed rather than erroring into a bad state."""
        run_dir = self.root / "symlink-dir-run"
        run_dir.mkdir()
        target = run_dir / "report.json"
        target.mkdir()
        with self.assertRaises(factory_cli.StationError):
            factory_cli._write_run_artifact(target, "x")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_planted_report_json_symlink_is_not_followed(self):
        """agents-5bn P0 end-to-end: a write-granted session plants a symlink at
        run_dir/report.json pointing at a host canary; the post-session report.json write must
        unlink it first, so the canary is untouched and the real report is written."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"ln -s {canary} ../report.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the post-session report.json write must not follow the planted symlink")
        report = json.loads((self.run_dirs()[0] / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report.get("summary"), "stub", "the real report.json must be written")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_staging_writes_no_content_blobs_into_the_shared_object_store(self):
        """agents-7ik (c): intent-to-add staging must not litter the target's shared
        .git/objects with unreferenced content blobs (a plain `git add -A` wrote one per
        new/modified file every run). At most the canonical empty blob (size 0) may
        appear, once; never the session's content."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        objects = self.target / ".git" / "objects"
        before = {p for p in objects.rglob("*") if p.is_file()}
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        after = {p for p in objects.rglob("*") if p.is_file()}
        new_objects = after - before
        self.assertLessEqual(len(new_objects), 1,
                             f"staging wrote {len(new_objects)} objects: {new_objects}")
        for obj in new_objects:
            sha = f"{obj.parent.name}{obj.name}"
            size = subprocess.run(["git", "-C", str(self.target), "cat-file", "-s", sha],
                                  capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(size, "0", "the only allowed new object is the empty blob")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_gitignored_edits_are_reported_honestly(self):
        """agents-7ik (a): a session whose only edits land in gitignored paths must not
        be reported as 'no file edits' — the files exist on disk — but as ignored edits,
        honestly not representable as a patch proposal."""
        self._git_init_target()
        (self.target / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.target), "add", ".gitignore"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.target), "-c", "user.email=factory@test",
                        "-c", "user.name=factory", "commit", "-qm", "gitignore"],
                       check=True, capture_output=True)
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "mkdir -p ignored && printf 'junk\\n' > ignored/x.txt\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("gitignored files", res.stdout)
        self.assertIn("not representable as a patch proposal", res.stdout)
        self.assertNotIn("no file edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists())

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_session_cannot_tamper_with_its_own_policy_record(self):
        """agents-7ik (2): run_dir is the read-write bind, so a granted-write session can
        reach its own policy.json — but whatever it writes there does not survive it: the
        dispatcher rewrites the record from its captured bytes after the session closes."""
        self._git_init_target()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            # The tamper: overwrite the containment record mid-session.
            "printf '%s' '{\"tampered\": true, \"granted\": {\"tool_policy\": \"unrestricted\"}}' "
            "> ../policy.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE,
                         "sanity: this really was a granted-write session")
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertNotIn("tampered", record)
        self.assertEqual(record["granted"]["tool_policy"], WORKTREE_WRITE,
                         "the post-session rewrite must restore the dispatcher's record")

    def test_an_unknown_agent_class_refuses_before_any_run(self):
        """An unknown class fails closed on every host, including without bubblewrap."""
        self.agent("name: probe\nclass: writer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unknown agent class", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_missing_agent_class_defaults_to_observer(self):
        """A missing class runs as an observer when the OS sandbox is runnable."""
        self.agent("name: probe\ncontainment: t0-readonly\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)

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
        res = self.factory("pi", {"ANTHROPIC_API_KEY": real_key,
                                  "FACTORY_MODEL": "anthropic/claude-3-5-sonnet"})
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
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        self.assertNotIn("env-credentials", record["not_enforced"],
                         "the actual brokered engine env must update the trusted record")
        # agents-3z8: policy.json lists ONLY the run's effective model provider (anthropic),
        # not an unrestricted fail-open list of all host credentials.
        self.assertEqual(record["granted"]["credential_broker"]["providers"],
                         ["anthropic"])
        self.assertNotIn(real_key, json.dumps(record))

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_default_pi_run_brokers_only_effective_model_provider(self):
        """agents-3z8: a default pi run's policy.json lists ONLY the effective model's provider
        (deepseek), not an unrestricted allowlist of all host credentials."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {
            "ANTHROPIC_API_KEY": "sk-ant-secret",
            "OPENAI_API_KEY": "sk-openai-secret",
            "GEMINI_API_KEY": "gem-secret",
        })
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        # Only deepseek (the DEFAULT_PI_MODEL provider) must be brokered, never all host credentials!
        self.assertEqual(record["granted"]["credential_broker"]["providers"], ["deepseek"])

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_sandboxed_engine_cross_provider_request_returns_403(self):
        """agents-3z8 [P2]: a sandboxed engine attempting cross-provider egress through
        the credential broker receives HTTP 403 Forbidden inside real bubblewrap sandbox."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "PORT=${ANTHROPIC_BASE_URL#http://127.0.0.1:}; PORT=${PORT%%/*}\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf 'POST /proxy/openai/v1/chat/completions HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Length: 2\\r\\n\\r\\n{}' >&3\n"
            "  read -r STATUS_LINE <&3\n"
            "  echo \"RESP_STATUS:$STATUS_LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo RESP_STATUS:UNREACHABLE\n"
            "fi\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-openai-secret",
            "FACTORY_MODEL": "anthropic/claude-3-5-sonnet",
        })
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        resp_line = self.stub_line("RESP_STATUS:")
        self.assertIn("403", resp_line,
                      f"cross-provider broker request inside sandbox must be 403 Forbidden, got {resp_line!r}")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_pi_engine_gets_the_keyless_broker_provider_config(self):
        """agents-854: pi ignores *_BASE_URL env, so the keyless broker routing must reach it as
        a models.json in its (redirected) agent directory, bound writable into the sandbox. The
        dispatcher wires PI_CODING_AGENT_DIR + FACTORY_MODEL and writes the provider override."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The adapter names the keyless model explicitly (not pi's Anthropic default).
        argv = self.stub_line("ARGV:").split()
        self.assertIn("--model", argv)
        self.assertEqual(argv[argv.index("--model") + 1], "deepseek/deepseek-flash")
        # The agent directory is redirected to a per-run config dir…
        agent_dir = self.stub_line("AGENTDIR:")
        self.assertTrue(agent_dir.startswith("/tmp/factory-pi-"), agent_dir)
        # …which holds the broker-routed provider override, readable inside the sandbox.
        models = self.stub_line("MODELSJSON:")
        self.assertIn("proxy/deepseek", models)
        self.assertIn("factory-broker-placeholder", models)
        self.assertIn("openai-completions", models)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_keyless_pi_wiring_is_provider_agnostic(self):
        """agents-854/agents-0ld: the keyless wiring is not deepseek-specific. Selecting a
        different keyless provider (kimi, an Anthropic-style managed endpoint) must wire THAT
        provider's broker route, api type AND model ids, so `--model kimi/k3` resolves even
        though pi's bundled registry has no provider named `kimi` (it is `kimi-coding`)."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_MODEL": "kimi/k3"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        argv = self.stub_line("ARGV:").split()
        self.assertEqual(argv[argv.index("--model") + 1], "kimi/k3")
        models = self.stub_line("MODELSJSON:")
        self.assertIn("proxy/kimi", models)
        self.assertIn("anthropic-messages", models)
        self.assertNotIn("deepseek", models)
        self.assertIn('"models"', models)
        self.assertIn('"k3"', models)
        self.assertIn('"k3-256k"', models)
        self.assertIn('"kimi-for-coding"', models)

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

            # The mock upstream listens on a random (non-standard) port, so pin it in the
            # allowlist entry (agents-cn3: a bare host permits only the standard web ports).
            proxy = EgressProxy([f"allowlisted.test:{upstream_port}"],
                                str(run_dir / "egress-proxy.sock"))
            proxy.start()
            child_env = {"PATH": "/usr/bin:/bin",
                         "HTTP_PROXY": "http://127.0.0.1:8385",
                         "HTTPS_PROXY": "http://127.0.0.1:8385",
                         "NO_PROXY": "localhost,127.0.0.1",
                         "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
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
