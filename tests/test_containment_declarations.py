"""Containment: declarations, shipped manifests and the run record.

Split from tests/test_containment.py (agents-3iog) so the fast-gate arms that
consume a declaration-level path (`agents/*/agent.yaml`) can run THIS file
instead of the whole dispatcher suite: these are the no-sandbox assertions, and
TestDeclarationsFailClosed's credential-grant drift guard is what a station
manifest can regress (it globs agents/*/agent.yaml).
"""

import hashlib
import http.server
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
    ENGINE_READ_SCOPE, ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE,
    WORKTREE_WRITE_UNVERIFIED_ENGINES, ContainmentError, banner_lines,
    budget_note, check_engine, downgrade_network_to_withheld, egress_allowlist, load_policy,
    policy_record,
)
from lib.sandbox import SANDBOXED_ENGINES, sandbox_available, sandbox_command  # noqa: E402
from lib.credential_broker import PLACEHOLDER_PREFIX  # noqa: E402
from lib.child_env import child_environment  # noqa: E402
from lib import egress_proxy  # noqa: E402
from lib import containment as containment_module  # noqa: E402
from lib import sandbox as sandbox_module  # noqa: E402
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

from tests import containment_harness as harness

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
        self.assertIn("NOT kernel-confined",
                      "\n".join(banner_lines(policy, "claude")))

    def test_the_sandboxed_banner_truthfully_states_read_scope_and_mounts(self):
        """[agents-wqy] The enforced sandbox banner truthfully states factory repo and system dirs read-only."""
        policy = load_policy("probe", manifest())
        lines = banner_lines(policy, "pi", sandbox={
            "tool": "bubblewrap",
            "engine_sandboxed": True,
            "engine_read_scope": "confined by the OS sandbox to the target (read-only)...",
            "network_egress_filtered": True,
        })
        text = "\n".join(lines)
        self.assertIn("factory repo and system dirs read-only", text)
        self.assertNotIn("everything else invisible", text)

    def test_the_record_lists_what_is_not_enforced(self):
        policy = load_policy("probe", manifest(budget={"max_minutes": 5, "max_usd": 0.5}))
        record = policy_record(policy, "pi")
        json.dumps(record)
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["not_enforced"], ["os-sandbox", "read-scope", "budget.max_usd"])

    def test_the_unsandboxed_engine_read_scope_is_plainly_not_kernel_confined(self):
        """agents-nq7: engines outside SANDBOXED_ENGINES must say plainly that they are NOT
        kernel-confined — never claim "confined" as if the OS sandbox held them."""
        policy = load_policy("probe", manifest())
        for engine in ("claude", "antigravity", "deepseek"):
            with self.subTest(engine=engine):
                record = policy_record(policy, engine)
                scope = record["granted"]["read_scope"]
                self.assertIn("NOT kernel-confined", scope)
                self.assertNotIn("confined to", scope)  # never claim the sandbox held it
                self.assertIn("os-sandbox", record["not_enforced"])
        # agents-js7: the claude adapter enforces a declared cap via --max-budget-usd.
        self.assertEqual(policy_record(policy, "claude")["not_enforced"],
                         ["os-sandbox"])

    def test_every_write_capable_engine_is_sandbox_verified_or_named_unverified(self):
        """agents-dpbc: pin the CLAIM of the ENGINE_TOOL_POLICIES worktree-write rows, not
        their text. The runtime delivers a write grant only when engine_sandboxed(engine)
        holds (factory downgrades to read-only otherwise), and engine_sandboxed is decided
        by lib/sandbox.py SANDBOXED_ENGINES. So an engine whose row grants WORKTREE_WRITE
        must be in that runtime-verified set, or be named in
        WORKTREE_WRITE_UNVERIFIED_ENGINES — the explicit list of engines whose adapter
        implements the flags but which never receive the grant. Adding the next engine to
        a worktree-write row without sandbox verification fails this test unless its
        author names it unverified, in code.

        The relation is a SUBSET, not an equality (agents-dpbc review P1): being
        sandbox-verified does not imply being write-capable, so a purely read-only
        OS-sandboxed engine is legitimate — under strict equality the only way to keep
        such an engine passing would be to FORGE a WORKTREE_WRITE row for an engine that
        does not have the capability, and a guard that can only be satisfied by a false
        claim is worse than no guard. The reviewer's counterexample is pinned as a
        permanent accepted case in
        test_a_read_only_sandboxed_engine_needs_no_write_row below."""
        write_capable = {e for e, policies in ENGINE_TOOL_POLICIES.items()
                         if WORKTREE_WRITE in policies}
        self.assertLessEqual(write_capable,
                             set(SANDBOXED_ENGINES) | set(WORKTREE_WRITE_UNVERIFIED_ENGINES),
                             "a worktree-write row is a write grant the runtime can deliver "
                             "only to a SANDBOXED_ENGINES engine; any other engine with the "
                             "row must be named in WORKTREE_WRITE_UNVERIFIED_ENGINES. This "
                             "is deliberately a subset: a sandboxed engine is not required "
                             "to be write-capable")
        # The two sets stay disjoint: no engine is both verified and named unverified.
        self.assertFalse(set(SANDBOXED_ENGINES) & set(WORKTREE_WRITE_UNVERIFIED_ENGINES))
        # Every sandbox-verified engine is a known engine in the table.
        self.assertLessEqual(set(SANDBOXED_ENGINES), set(ENGINE_TOOL_POLICIES))
        # Every engine named unverified really does carry the row it is excused for, and
        # is really absent from the runtime's verified set (host-independent: membership,
        # not engine_sandboxed(), which also depends on this host having bubblewrap).
        for engine in WORKTREE_WRITE_UNVERIFIED_ENGINES:
            with self.subTest(engine=engine):
                self.assertIn(WORKTREE_WRITE, ENGINE_TOOL_POLICIES.get(engine, frozenset()))
                self.assertNotIn(engine, SANDBOXED_ENGINES)
        # And every table engine the OS sandbox does not cover must already say plainly,
        # in its read-scope claim, that it is NOT confined.
        for engine in set(ENGINE_TOOL_POLICIES) - set(SANDBOXED_ENGINES):
            with self.subTest(read_scope=engine):
                self.assertIn("NOT", ENGINE_READ_SCOPE.get(engine, ""),
                              f"{engine} is not in SANDBOXED_ENGINES, so its "
                              f"ENGINE_READ_SCOPE entry must say plainly that it is not "
                              f"kernel-confined")

    def test_a_read_only_sandboxed_engine_needs_no_write_row(self):
        """agents-dpbc review P1, the counterexample as a permanent ACCEPTED case: an
        engine that is in SANDBOXED_ENGINES but has NO worktree-write row (a purely
        read-only OS-sandboxed engine) must satisfy the write-capable claim guard above.
        Sandbox verification does not imply write capability, so the guard must not force
        a forged WORKTREE_WRITE row onto such an engine. The tables are monkeypatched —
        the engine never enters the real sets — so this proves the guard's shape, not the
        current table contents."""
        read_only_engine = "readonly-sandboxed"
        patched_policies = dict(ENGINE_TOOL_POLICIES)
        patched_policies[read_only_engine] = frozenset({READ_ONLY})
        patched_sandboxed = set(SANDBOXED_ENGINES) | {read_only_engine}
        with mock.patch.object(containment_module, "ENGINE_TOOL_POLICIES",
                               patched_policies), \
                mock.patch.object(sandbox_module, "SANDBOXED_ENGINES",
                                  patched_sandboxed):
            # The guard's own computation, against the patched tables: the read-only
            # sandboxed engine adds nothing to write_capable, and the subset holds.
            write_capable = {e for e, policies in
                             containment_module.ENGINE_TOOL_POLICIES.items()
                             if WORKTREE_WRITE in policies}
            self.assertNotIn(read_only_engine, write_capable)
            self.assertLessEqual(
                write_capable,
                set(sandbox_module.SANDBOXED_ENGINES) | set(WORKTREE_WRITE_UNVERIFIED_ENGINES),
                "a read-only sandboxed engine must be ACCEPTED: the guard is a subset, "
                "not an equality that would force a forged write row")

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
        # agents-28nn round 7: the record only drops the residual when the env holds the
        # RUNNING broker's per-run placeholder (any other value — including a retired
        # static placeholder — is not evidence of a broker that will answer).
        run_placeholder = "factory-broker-the-run-placeholder"
        engine_env = child_environment(engine="pi", parent=parent, broker_urls={
            "anthropic": "http://127.0.0.1:8384/proxy/anthropic"},
            broker_placeholder=run_placeholder)
        kwargs = {"sandbox": sandbox, "brokered_providers": ("anthropic",),
                  "engine_env": engine_env, "expected_placeholder": run_placeholder}
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
            engine_env=dict(engine_env, ANTHROPIC_BASE_URL="http://[invalid"),
            expected_placeholder=run_placeholder)["not_enforced"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=dict(engine_env, OPENAI_API_KEY="unbrokered"),
            expected_placeholder=run_placeholder)["not_enforced"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=sandbox, brokered_providers=("anthropic",),
            engine_env=dict(engine_env, HTTPS_PROXY="http://user:pass@proxy.test"),
            expected_placeholder=run_placeholder)["not_enforced"])
        # agents-28nn round 7: a placeholder that is NOT the running broker's per-run
        # secret is not evidence of enforcement either.
        self.assertIn("env-credentials", policy_record(
            policy, "pi", **{**kwargs, "expected_placeholder": "factory-broker-other-run"})[
                "not_enforced"])
        # agents-28nn round 6: the broker is no longer sandbox-gated, so a verified
        # placeholder env drops the residual on EITHER path — _broker_covers_engine_env
        # inspects the engine env itself (placeholders + loopback broker URL, no surviving
        # credential), which is direct evidence, not an attestation by the sandbox.
        self.assertNotIn("env-credentials", policy_record(
            policy, "pi", sandbox={**sandbox, "engine_sandboxed": False},
            brokered_providers=("anthropic",), engine_env=engine_env,
            expected_placeholder=run_placeholder)["not_enforced"],
            "a brokered unsandboxed engine's env holds placeholders only — verified directly")
        # And with NO sandbox record at all (a sandbox-less host): a started broker whose
        # swap verified drops the residual and records the grant; one whose swap did NOT
        # take keeps it.
        none_record = policy_record(policy, "pi", sandbox=None,
                                    brokered_providers=("anthropic",), engine_env=engine_env,
                                    expected_placeholder=run_placeholder)
        self.assertNotIn("env-credentials", none_record["not_enforced"])
        self.assertEqual(none_record["granted"]["credential_broker"]["providers"],
                         ["anthropic"])
        self.assertIn("env-credentials", policy_record(
            policy, "pi", sandbox=None, brokered_providers=("anthropic",),
            engine_env=child_environment(engine="pi", parent=parent))["not_enforced"],
            "a broker that did not take (real key survives) is recorded, sandbox or none")
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

    def test_an_unpinned_tools_opt_in_run_records_its_waiver(self):
        """agents-onf6: when FACTORY_ALLOW_UNPINNED_TOOLS waives content verification for
        trusted tools, the banner and policy.json must record the explicit opt-in text
        and include 'trusted-tool-pins' in not_enforced, so an unpinned run is auditable."""
        policy = load_policy("probe", manifest())
        note = ("explicit FACTORY_ALLOW_UNPINNED_TOOLS=1 dev/test opt-in active: "
                "trusted tools resolved by PATH order without sha256 verification")
        banner = "\n".join(banner_lines(policy, "pi", sandbox=None, unpinned_note=note))
        self.assertIn(f"Tool pins:   NOT enforced — {note}", banner)
        record = policy_record(policy, "pi", sandbox=None, unpinned_note=note)
        self.assertEqual(record["unpinned_tools_opt_in"], note)
        self.assertIn("trusted-tool-pins", record["not_enforced"])

        # When tool pins are enforced (unpinned_note=None), the waiver is absent
        # and the banner states that tool pins are enforced.
        normal_banner = "\n".join(banner_lines(policy, "pi", sandbox=None))
        self.assertIn("Tool pins:   enforced (tools.yaml / --tool-pins)", normal_banner)
        normal_record = policy_record(policy, "pi", sandbox=None)
        self.assertNotIn("unpinned_tools_opt_in", normal_record)
        self.assertNotIn("trusted-tool-pins", normal_record["not_enforced"])

    def test_the_budget_line_names_the_enforcement_state_per_engine(self):
        policy = load_policy("probe", manifest(budget={"max_minutes": 5, "max_usd": 0.5}))
        self.assertIn("$0.50 enforced by the claude adapter (--max-budget-usd)",
                      budget_note(policy, "claude"))
        self.assertIn("$0.50 declared, NOT enforced (the pi adapter has no per-run budget flag)",
                      budget_note(policy, "pi"))
        no_cap = load_policy("probe", manifest(budget={"max_minutes": 5}))
        self.assertEqual(budget_note(no_cap, "claude"), "")

if __name__ == "__main__":
    unittest.main()
