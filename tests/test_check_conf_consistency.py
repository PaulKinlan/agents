"""agents-ia3p: assert the gate's command lives in a TRACKED file, and CI agrees with it.

WHY THIS FILE EXISTS: the -t . hermeticity fix lived ONLY in an untracked per-VM
check.conf while deployed CI ran package-blind discovery without -t ., bypassing
tests/__init__.py and failing to run the hermetic test environment declaration (P1).

This test proves:
1. tools/check.conf exists and defines the package-aware discovery command.
2. .github/workflows/ci.yml runs the exact same flags (the drift guard).
3. tools/check-cmd.sh resolves the tracked command as default and refuses on missing/empty config.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
TRACKED = ROOT / "tools" / "check.conf"


def _tracked_fields(text: str | None = None) -> dict:
    """Parse NAME=value lines from the tracked config, or from `text` when one is supplied.

    The optional argument exists so a test can drive the REAL parser with a sample
    (agents-4eg2): the pinning test used to re-implement this loop with a verbatim copy of the
    regex, which meant no change to this function - the parser the check actually depends on -
    could ever make that test fail.
    """
    fields = {}
    source = TRACKED.read_text(encoding="utf-8") if text is None else text
    for line in source.splitlines():
        m = re.match(r'^([A-Z_]+)=(?:"(.*)"|(\S+))\s*$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


def _discovery_commands() -> list[str]:
    """Every `unittest discover` invocation in the deployed CI workflow, regardless of interpreter variant."""
    commands = []
    for line in CI_YML.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if "unittest discover" in stripped:
            if stripped.startswith("run:"):
                stripped = stripped[4:].strip()
            commands.append(stripped)
    return commands


def _parse_discovery_args(cmd: str) -> dict:
    """Parse unittest discover arguments (-s, -t, -p, -k, etc., short/long/attached forms) from a command string."""
    tokens = cmd.split()
    args = {"start": None, "top": None, "pattern": None, "filters": [], "verbose": False}
    if "discover" in tokens:
        idx = tokens.index("discover") + 1
        i = idx
        while i < len(tokens):
            t = tokens[i]
            if t == "-s" or t == "--start-directory":
                if i + 1 < len(tokens):
                    args["start"] = tokens[i + 1].strip("'\"")
                    i += 2
                else:
                    i += 1
            elif t.startswith("--start-directory="):
                args["start"] = t.split("=", 1)[1].strip("'\"")
                i += 1
            elif t.startswith("-s") and len(t) > 2:
                val = t[2:]
                if val.startswith("="):
                    val = val[1:]
                args["start"] = val.strip("'\"")
                i += 1
            elif t == "-t" or t == "--top-level-directory":
                if i + 1 < len(tokens):
                    args["top"] = tokens[i + 1].strip("'\"")
                    i += 2
                else:
                    i += 1
            elif t.startswith("--top-level-directory="):
                args["top"] = t.split("=", 1)[1].strip("'\"")
                i += 1
            elif t.startswith("-t") and len(t) > 2:
                val = t[2:]
                if val.startswith("="):
                    val = val[1:]
                args["top"] = val.strip("'\"")
                i += 1
            elif t == "-p" or t == "--pattern":
                if i + 1 < len(tokens):
                    args["pattern"] = tokens[i + 1].strip("'\"")
                    i += 2
                else:
                    i += 1
            elif t.startswith("--pattern="):
                args["pattern"] = t.split("=", 1)[1].strip("'\"")
                i += 1
            elif t.startswith("-p") and len(t) > 2:
                val = t[2:]
                if val.startswith("="):
                    val = val[1:]
                args["pattern"] = val.strip("'\"")
                i += 1
            elif t == "-k":
                if i + 1 < len(tokens):
                    args["filters"].append(tokens[i + 1].strip("'\""))
                    i += 2
                else:
                    i += 1
            elif t.startswith("-k") and len(t) > 2:
                val = t[2:]
                if val.startswith("="):
                    val = val[1:]
                args["filters"].append(val.strip("'\""))
                i += 1
            elif t in ("-v", "--verbose"):
                args["verbose"] = True
                i += 1
            else:
                i += 1
    return args


def check_ci_and_tracked_config_consistency(ci_commands: list[str], tracked_cmd: str) -> None:
    """Assert that CI discovery commands and tracked CHECK_CMD agree on hermeticity and test selection."""
    if not ci_commands:
        raise AssertionError("expected at least one discovery invocation in ci.yml")

    tracked_args = _parse_discovery_args(tracked_cmd)

    # 1. EVERY discovery command in CI must carry -t . (package-aware) and -s tests
    for cmd in ci_commands:
        cmd_args = _parse_discovery_args(cmd)
        if cmd_args["top"] != ".":
            raise AssertionError(f"the CI invocation lost top-level directory -t .: {cmd!r}")
        if cmd_args["start"] != "tests":
            raise AssertionError(f"the CI invocation lost start directory -s tests: {cmd!r}")

    # 2. Tracked CHECK_CMD must carry -t . and -s tests
    if tracked_args["top"] != ".":
        raise AssertionError(f"the tracked CHECK_CMD lost top-level directory -t .: {tracked_cmd!r}")
    if tracked_args["start"] != "tests":
        raise AssertionError(f"the tracked CHECK_CMD lost start directory -s tests: {tracked_cmd!r}")

    # 3. Tracked CHECK_CMD must be UN-NARROWED (agents-h4tg). The full gate selects the complete suite.
    if tracked_args["pattern"] is not None:
        raise AssertionError(
            f"the tracked CHECK_CMD must not carry a pattern filter (-p/--pattern); "
            f"the full gate selects the complete suite: {tracked_cmd!r}"
        )
    if tracked_args["filters"]:
        raise AssertionError(
            f"the tracked CHECK_CMD must not carry a test name filter (-k); "
            f"the full gate selects the complete suite: {tracked_cmd!r}"
        )

    # 4. Core CI suite must agree with tracked CHECK_CMD on discovery arguments and test selection.
    # Neither side may acquire a pattern (-p/--pattern), filter (-k), or directory (-s, -t) flag the other lacks (agents-z9aa, agents-h4tg).
    core_ci_cmd = ci_commands[0]
    core_ci_args = _parse_discovery_args(core_ci_cmd)

    if core_ci_args["start"] != tracked_args["start"]:
        raise AssertionError(
            f"CI core discovery start dir ({core_ci_args['start']!r}) "
            f"diverges from tracked CHECK_CMD ({tracked_args['start']!r})"
        )
    if core_ci_args["top"] != tracked_args["top"]:
        raise AssertionError(
            f"CI core discovery top dir ({core_ci_args['top']!r}) "
            f"diverges from tracked CHECK_CMD ({tracked_args['top']!r})"
        )
    if core_ci_args["pattern"] != tracked_args["pattern"]:
        raise AssertionError(
            f"CI core discovery pattern ({core_ci_args['pattern']!r}) "
            f"diverges from tracked CHECK_CMD ({tracked_args['pattern']!r}); "
            f"core CI must not narrow or alter test selection"
        )
    if core_ci_args["filters"] != tracked_args["filters"]:
        raise AssertionError(
            f"CI core discovery filter ({core_ci_args['filters']!r}) "
            f"diverges from tracked CHECK_CMD ({tracked_args['filters']!r}); "
            f"core CI must not filter test names"
        )


class TestTrackedCheckConfig(unittest.TestCase):
    """The acceptance: tools/check.conf is tracked and specifies package-aware discovery."""

    def test_tracked_config_file_exists(self):
        self.assertTrue(TRACKED.is_file(),
                        f"tracked gate config missing: {TRACKED} - a fresh VM gets no "
                        f"default without it, which was the original P1")

    def test_tracked_config_defines_the_hermetic_full_gate(self):
        fields = _tracked_fields()
        for required in ("CHECK_CMD", "CHECK_FAST_CMD", "CHECK_TIMEOUT", "CHECK_FAST_TIMEOUT"):
            self.assertIn(required, fields, f"missing required field: {required}")

        cmd = fields["CHECK_CMD"]
        self.assertIn("discover", cmd, f"CHECK_CMD is not a discovery command: {cmd!r}")
        self.assertRegex(cmd, r"(^|\s)-t\s+\.",
                         f"CHECK_CMD must carry `-t .` or the hermetic declaration never "
                         f"runs: {cmd!r}")

    def test_tracked_fields_parser_accepts_inner_quotes_and_unquoted_values(self):
        """The parser must accept escaped inner quotes (e.g. bash -c commands) and unquoted values."""
        sample = (
            'CHECK_CMD="bash -c \'echo \\"inner quotes\\" && python3 -m unittest discover -s tests -t . -v\'"\n'
            'CHECK_FAST_CMD="bash tools/fast-gate.sh"\n'
            'CHECK_TIMEOUT=2400\n'
            'CHECK_FAST_TIMEOUT=180\n'
        )
        # agents-4eg2: drive the REAL parser through its optional argument. This used to
        # re-implement the loop above with a verbatim copy of the regex, so a regression in
        # _tracked_fields - the parser tools/check.conf is actually read with - left this test
        # green while only other tests in this module caught it by accident.
        fields = _tracked_fields(sample)
        self.assertIn("CHECK_CMD", fields)
        self.assertIn('echo \\"inner quotes\\"', fields["CHECK_CMD"])
        self.assertEqual(fields["CHECK_TIMEOUT"], "2400")
        self.assertEqual(fields["CHECK_FAST_TIMEOUT"], "180")

    def test_every_parser_of_the_tracked_file_agrees_on_its_fields(self):
        """agents-1i7v: two test modules parse tools/check.conf; they must not disagree silently.

        tests/test_gate_entrypoint_config.py parsed only NAME="value", so on the real file it
        returned the two command fields and silently dropped the two unquoted bound fields. No
        assertion noticed, because its callers read CHECK_CMD only - so any future pin built on
        that parser would have been blind to a field the file defines, and 'which fields exist'
        depended on which module you asked. The grammars are unified now, and this test fails if
        they diverge again, which is what makes the drop impossible rather than merely fixed.
        """
        from tests.test_gate_entrypoint_config import _tracked_fields as parsed_there

        here, there = _tracked_fields(), parsed_there()
        # agents-ju3g: compare the WHOLE dicts, not just the key sets. The keys-only form was
        # green while the two copies returned DIFFERENT VALUES for the same file - the review
        # measured CHECK_TIMEOUT 2400 vs 24000 with this test passing - so it pinned half of
        # what the docstring above claims and a value-semantics drift stayed invisible. The
        # commands have another consumer (tests/test_gate_entrypoint_config.py compares
        # CHECK_CMD against the installed config); the BOUNDS parsed by that copy have none,
        # so nothing else would have caught the drift either.
        self.assertEqual(
            there, here,
            "the two parsers of tools/check.conf disagree about its fields or their values",
        )
        # The value forms the shared grammar exists to accept: bounds are bare integers, and the
        # command fields stay quoted single strings (agents-j1te keeps them one string per line).
        for bound in ("CHECK_TIMEOUT", "CHECK_FAST_TIMEOUT"):
            self.assertIn(bound, here, f"the tracked config lost {bound}")
            self.assertTrue(here[bound].isdigit(), f"{bound} must be a bare integer: {here[bound]!r}")
        # The one relation between the two bounds that is a contract rather than a tuning
        # choice: the fast gate must be bounded tighter than the full gate.
        self.assertLess(int(here["CHECK_FAST_TIMEOUT"]), int(here["CHECK_TIMEOUT"]),
                        "the fast gate must be bounded tighter than the full gate")
        raw = TRACKED.read_text(encoding="utf-8")
        for cmd in ("CHECK_CMD", "CHECK_FAST_CMD"):
            self.assertRegex(
                raw, re.compile(rf'^{cmd}="', re.M),
                f"{cmd} must stay a quoted single string",
            )
        # The field SET is the contract too: tools/check-cmd.sh supports exactly these four
        # (its usage line and its --install printf both name them), so a field that appears or
        # disappears has to be a deliberate edit with this tuple updated, never a silent one.
        self.assertEqual(
            sorted(here),
            ["CHECK_CMD", "CHECK_FAST_CMD", "CHECK_FAST_TIMEOUT", "CHECK_TIMEOUT"],
            "the tracked config's field set changed: update this pin deliberately",
        )

    def test_every_discovery_in_ci_carries_the_same_top_level_flag(self):
        """EVERY invocation, not just the first - the second line initially lacked it."""
        commands = _discovery_commands()
        self.assertTrue(commands, "expected at least one discovery invocation in ci.yml")
        for cmd in commands:
            with self.subTest(command=cmd):
                self.assertRegex(cmd, r"(^|\s)-t\s+\.",
                                 f"ci.yml runs package-blind discovery, so the hermetic "
                                 f"declaration does not run there and CI's result is not "
                                 f"the result we measured: {cmd!r}")

    def test_ci_and_the_tracked_config_agree_on_the_hermeticity_flags(self):
        """The drift guard. A future edit to one without the other fails HERE.

        Both sides must be package-aware, and neither may acquire a discovery flag the
        other lacks. This is the assertion that makes the fix a property rather than an
        edit: it compares the two, so it fails whichever side changes alone.
        """
        tracked = _tracked_fields()["CHECK_CMD"]
        commands = _discovery_commands()
        check_ci_and_tracked_config_consistency(commands, tracked)

    def test_divergent_ci_test_selection_fails_consistency_check(self):
        """agents-z9aa: assert that when CI's core test command narrows or alters test selection
        (e.g. adding -p, -pVAL, --pattern, --pattern=, -k, or -kVAL), the consistency check FAILS."""
        tracked = _tracked_fields()["CHECK_CMD"]
        divergent_variants = [
            "python3 -m unittest discover -s tests -t . -p test_no_bwrap_guard.py -v",
            "python3 -m unittest discover -s tests -t . -p 'test_no_bwrap_guard.py' -v",
            "python3 -m unittest discover -s tests -t . -ptest_no_bwrap_guard.py -v",
            "python3 -m unittest discover -s tests -t . --pattern test_no_bwrap_guard.py -v",
            "python3 -m unittest discover -s tests -t . --pattern='test_no_bwrap_guard.py' -v",
            "python3 -m unittest discover -s tests -t . -k test_no_bwrap -v",
            "python3 -m unittest discover -s tests -t . -ktest_no_bwrap -v",
        ]
        for divergent_cmd in divergent_variants:
            with self.subTest(variant=divergent_cmd):
                with self.assertRaises(AssertionError) as cm:
                    check_ci_and_tracked_config_consistency([divergent_cmd], tracked)
                self.assertIn("diverges from tracked CHECK_CMD", str(cm.exception))

    def test_divergent_start_dir_fails_consistency_check(self):
        """agents-z9aa: assert that a divergent start directory fails consistency check."""
        tracked = _tracked_fields()["CHECK_CMD"]
        divergent_commands = [
            "python3 -m unittest discover -s other_tests -t . -v",
        ]
        with self.assertRaises(AssertionError) as cm:
            check_ci_and_tracked_config_consistency(divergent_commands, tracked)
        self.assertIn("tests", str(cm.exception))

    def test_narrowed_tracked_check_cmd_fails_consistency_check(self):
        """agents-h4tg: assert that tracked CHECK_CMD carrying -p or -k fails consistency check.
        The full gate command in tools/check.conf must select the complete test suite."""
        commands = _discovery_commands()
        narrowed_tracked_cmds = [
            "python3 -m unittest discover -s tests -t . -v -p test_no_bwrap_guard.py",
            "python3 -m unittest discover -s tests -t . -v --pattern=test_no_bwrap_guard.py",
            "python3 -m unittest discover -s tests -t . -v -k test_no_bwrap",
            "python3 -m unittest discover -s tests -t . -v -ktest_no_bwrap",
        ]
        for narrowed_cmd in narrowed_tracked_cmds:
            with self.subTest(narrowed_cmd=narrowed_cmd):
                with self.assertRaises(AssertionError) as cm:
                    check_ci_and_tracked_config_consistency(commands, narrowed_cmd)
                self.assertIn("the tracked CHECK_CMD must not carry", str(cm.exception))

    def test_mutual_narrowing_fails_consistency_check(self):
        """agents-h4tg: assert that mutual narrowing (identical -p or -k on both CI and tracked config)
        fails consistency check because tracked CHECK_CMD must select the complete suite."""
        mutual_pairs = [
            (
                ["python3 -m unittest discover -s tests -t . -v -p test_no_bwrap_guard.py"],
                "python3 -m unittest discover -s tests -t . -v -p test_no_bwrap_guard.py",
            ),
            (
                ["python3 -m unittest discover -s tests -t . -v -k test_no_bwrap"],
                "python3 -m unittest discover -s tests -t . -v -k test_no_bwrap",
            ),
        ]
        for ci_cmds, tracked_cmd in mutual_pairs:
            with self.subTest(ci_cmds=ci_cmds, tracked_cmd=tracked_cmd):
                with self.assertRaises(AssertionError) as cm:
                    check_ci_and_tracked_config_consistency(ci_cmds, tracked_cmd)
                self.assertIn("the tracked CHECK_CMD must not carry", str(cm.exception))

    def test_repeated_k_flag_difference_fails_consistency_check(self):
        """agents-h4tg: assert that repeated -k flags on CI are collected into a list rather than
        overwriting with last-wins semantics, and diverge from tracked un-narrowed command."""
        parsed = _parse_discovery_args("python3 -m unittest discover -s tests -t . -v -k foo -k bar")
        self.assertEqual(parsed["filters"], ["foo", "bar"],
                         "repeated -k flags must be collected in order rather than keeping last-wins")

        parsed_attached = _parse_discovery_args("python3 -m unittest discover -s tests -t . -v -kfoo -k=bar")
        self.assertEqual(parsed_attached, {"start": "tests", "top": ".", "pattern": None,
                                           "filters": ["foo", "bar"], "verbose": True})

        tracked = _tracked_fields()["CHECK_CMD"]
        ci_cmds = ["python3 -m unittest discover -s tests -t . -v -k foo -k bar"]
        with self.assertRaises(AssertionError) as cm:
            check_ci_and_tracked_config_consistency(ci_cmds, tracked)
        self.assertIn("['foo', 'bar']", str(cm.exception))
        self.assertIn("diverges from tracked CHECK_CMD", str(cm.exception))


class TestConfigIsResolvedLoudly(unittest.TestCase):
    """The resolver must REFUSE rather than silently substitute a default (agents-5o5q, agents-g2n4)."""

    def test_missing_tracked_config_fails_loudly_naming_file(self):
        """Shape (a): a missing TRACKED config (tools/check.conf) must exit 2 loudly naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_tools = Path(tmp) / "tools"
            tmp_tools.mkdir(parents=True)
            symlink_resolver = tmp_tools / "check-cmd.sh"
            os.symlink(resolver, symlink_resolver)

            res = subprocess.run(["bash", str(symlink_resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 2, f"missing tracked config must exit 2: {res.stderr}")
            self.assertIn("the TRACKED gate config is missing", res.stderr,
                          "refusal must report missing tracked configuration")
            self.assertIn(str(tmp_tools / "check.conf"), res.stderr,
                          "refusal must name the exact missing file path (agents-g2n4)")

    def test_empty_or_unset_check_cmd_is_refused_loudly(self):
        """Shape (b): an override that unsets or empties CHECK_CMD must be refused loudly naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "empty.conf"
            conf.write_text('CHECK_CMD=""\n', encoding="utf-8")
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = str(conf)
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(res.returncode, 0, "empty CHECK_CMD must fail non-zero")
            self.assertIn("CHECK_CMD is unset or empty", res.stderr,
                          "refusal must report empty/unset CHECK_CMD")
            self.assertIn(str(conf), res.stderr,
                          "refusal must name the offending configuration file (agents-g2n4)")

    def test_syntax_error_in_config_fails_loudly_under_set_e(self):
        """Shape (c): syntax errors in sourced config must be fatal under set -e naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "broken.conf"
            conf.write_text('CHECK_CMD="unterminated\n', encoding="utf-8")
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = str(conf)
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(res.returncode, 0, "syntax error must fail non-zero")
            self.assertRegex(res.stderr, r"unexpected EOF|syntax error")
            self.assertIn(str(conf), res.stderr,
                          "refusal must name the syntax-error configuration file (agents-g2n4)")

    def test_missing_override_is_tolerated_and_uses_tracked_defaults(self):
        """A missing override file is tolerated and falls back to tracked defaults."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = os.path.join(tmp, "does-not-exist.conf")
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(res.returncode, 0, f"a missing OVERRIDE is fine: {res.stderr}")
            self.assertIn("-t .", res.stdout,
                          "the resolved command must come from the tracked config")

    def test_install_honors_fleet_check_conf_destination_and_docs_agree(self):
        """tools/check-cmd.sh --install respects FLEET_CHECK_CONF and docs describe it (agents-80go)."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        conf_doc = ROOT / "tools" / "check.conf"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        self.assertTrue(conf_doc.is_file(), "tools/check.conf must exist")

        # 1. Behavior: FLEET_CHECK_CONF redirects the install destination
        with tempfile.TemporaryDirectory() as tmp_home, tempfile.TemporaryDirectory() as tmp_dest:
            redirected = Path(tmp_dest) / "redirected.conf"
            env = dict(os.environ)
            env["HOME"] = tmp_home
            env["FLEET_CHECK_CONF"] = str(redirected)
            res = subprocess.run(["bash", str(resolver), "--install"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(res.returncode, 0, f"--install failed: {res.stderr}")
            self.assertTrue(redirected.is_file(), f"redirected config must be written to {redirected}")
            self.assertFalse((Path(tmp_home) / ".fleet" / "check.conf").exists(),
                             "HOME/.fleet/check.conf must NOT be created when FLEET_CHECK_CONF is set")
            self.assertIn(str(redirected), res.stdout,
                          "install output must report the actual destination written")

        # 2. Docs agreement: both tools/check.conf and tools/check-cmd.sh must document
        # the FLEET_CHECK_CONF override destination rather than claiming ~/.fleet/check.conf unconditionally.
        # Scoped strictly to the leading documentation headers so code occurrences cannot satisfy the check (agents-0fne).
        def _leading_comment_header(path: Path) -> str:
            lines = []
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    lines.append(line)
                else:
                    break
            return "\n".join(lines)

        conf_header = _leading_comment_header(conf_doc)
        cmd_header = _leading_comment_header(resolver)
        self.assertIn("FLEET_CHECK_CONF", conf_header,
                      "tools/check.conf header must document FLEET_CHECK_CONF override destination")
        self.assertIn("FLEET_CHECK_CONF", cmd_header,
                      "tools/check-cmd.sh header must document FLEET_CHECK_CONF override destination")
        self.assertNotIn("sources ONLY $HOME/.fleet/check.conf", conf_header,
                         "tools/check.conf header must not claim fleet-check sources ONLY $HOME/.fleet/check.conf")
        self.assertNotIn("sources ONLY $HOME/.fleet/check.conf", cmd_header,
                         "tools/check-cmd.sh header must not claim fleet-check sources ONLY $HOME/.fleet/check.conf")


if __name__ == "__main__":
    unittest.main()
