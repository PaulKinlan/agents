"""agents-oc3q: the pin generator's HASHER must come from the system dirs, not operator dirs.

THE HOLE THIS PINS, FOUND BY MUTATION RATHER THAN BY READING. `resolve_in_lookup` walked
$PIN_LOOKUP_PATH, and --lookup-path PREPENDS operator dirs to it. The script's own comment
says the plumbing and "the hasher" must keep resolving from the system dirs, and the file's
header says "the hash this script writes IS the vouch for the binary" - but the code passed
$PIN_LOOKUP_PATH for the hasher too, so `--lookup-path /attacker` put a planted sha256sum
FIRST. MEASURED before the fix: every line of the generated pins carried `sha256: 0000...`.
So a caller-supplied directory could supply the pin's own reference value, which makes every
pin worthless and AUTHORITATIVE at once - the same shape as the tool lookup it was already
careful about, one level up.

THE TEST IS BEHAVIOURAL, NOT A GREP: it plants a fake hasher in a temp dir, passes that dir
via --lookup-path, and asserts the generated file carries NO hash the fake produced. A test
that only checked for the string "command -v" would pass while the hole was open.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "tools" / "generate-tool-pins.sh"
FAKE_HASH = "0" * 64

# A HANG GUARD, NOT A MEASUREMENT (agents-h71zr's rule, RE-DERIVED here by agents-fzcs6). Six arms in
# this module run the REAL generator, and every one of them used a literal 120 s. ONE run costs 73.09 s
# on this VM (measured 2026-10-27: 35 tools resolved, each hashed twice - sha256sum plus an independent
# `python3 -I` digest (agents-0poh) - at load 4.66), so 120 s was 1.6x a single run; inside the fast
# gate, which runs four modules at once, the arms ERRORED with subprocess.TimeoutExpired. That is the
# same defect agents-h71zr fixed for tests/test_tool_pins.py, in a DIFFERENT file that runs the same
# expensive generator - which is why this number now lives in a named constant instead of a literal.
# Not a skip: dropping these arms would drop the hasher contract on exactly the hosts where it matters.
# 600 s is ~8x the measured cost and still bounds a wedged script. Re-measure before replacing it.
_GENERATOR_GUARD_S = 600

# WHY THESE ARMS WERE MINUTES LONG (agents-z3cp5). The generator hashes EVERY trusted tool it
# resolves, twice, and it resolves them from the host. On this VM that is 73.09 s a run (measured
# 2026-10-27) because the host carries a 249 MB `claude` and a full node/pi tree, and this module
# runs the real script six times. Nothing here asserts how BIG a binary is or which tools exist -
# every arm asserts where a HASHER, or a pin's reference value, may come from - so the tools each arm
# does not name can be tiny stand-ins. Measured with the stand-ins in the lookup: 6.49 s a run
# (11x cheaper), which is what makes this module gateable at all.
CHEAP_TOOL_NAMES = ("agentapi", "bd", "bwrap", "claude", "gh", "git", "gitleaks", "node", "npm",
                    "npx", "pi", "semgrep")


def stage_cheap_tools(directory):
    """Tiny stand-ins for every tool the generator pins, so a run costs seconds, not minutes."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in CHEAP_TOOL_NAMES:
        path = directory / name
        path.write_text(f'#!/bin/sh\necho "{name} stand-in"\n', encoding="utf-8")
        path.chmod(0o755)
    return directory


@unittest.skipUnless(GENERATOR.exists(), "generator not present")
class TestPinGeneratorHasherIsNotCallerSupplied(unittest.TestCase):

    def _run_with_planted_hasher(self, tmp):
        planted = Path(tmp) / "planted"
        out = Path(tmp) / "out"
        planted.mkdir()
        out.mkdir()
        # The exact attack: a hasher that answers a constant, so any pin it feeds is forged.
        fake = planted / "sha256sum"
        fake.write_text(f'#!/bin/sh\necho "{FAKE_HASH}  $1"\n', encoding="utf-8")
        fake.chmod(0o755)
        # and a planted tool, so the run has something to hash
        tool = planted / "git"
        tool.write_text("#!/bin/sh\necho PWNED\n", encoding="utf-8")
        tool.chmod(0o755)
        # agents-z3cp5: the cheap tool set is appended AFTER the plant, so the planted `git` above is
        # still the one this arm pins; the other eleven tools are stand-ins instead of real binaries.
        cheap = stage_cheap_tools(Path(tmp) / "cheap-tools")
        subprocess.run(
            ["bash", str(GENERATOR), str(out / "pins.yaml"), "--lookup-path",
             f"{planted}:{cheap}"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
            env={"PATH": f"{planted}:/usr/bin:/bin", "HOME": tmp},
        )
        return (out / "pins.yaml")

    def test_a_planted_hasher_cannot_supply_the_pin_reference_value(self):
        with tempfile.TemporaryDirectory(prefix="oc3q-") as tmp:
            pins = self._run_with_planted_hasher(tmp)
            text = pins.read_text(encoding="utf-8")
            hashes = re.findall(r"^\s+sha256: ([0-9a-f]{64})$", text, re.M)
            self.assertTrue(hashes, f"expected at least one pin, got:\n{text}")
            self.assertNotIn(
                FAKE_HASH, hashes,
                "the hasher came from the OPERATOR-SUPPLIED dir: a caller-supplied directory "
                "supplied the pin's own reference value, which makes every pin worthless and "
                "authoritative at once (agents-oc3q)")

    def test_an_operator_dir_still_extends_the_TOOL_lookup(self):
        """The other direction, and it must be a real assertion: the fix narrows ONLY the
        hasher and the plumbing. --lookup-path's documented purpose is to let the operator
        pass dirs where TOOLS live (engines install outside the system dirs), so a planted
        tool THERE must still be found, hashed with the REAL hasher, and pinned."""
        with tempfile.TemporaryDirectory(prefix="oc3q-") as tmp:
            pins = self._run_with_planted_hasher(tmp)
            text = pins.read_text(encoding="utf-8")
            planted_git = str(Path(tmp) / "planted" / "git")
            self.assertIn(
                planted_git, text,
                "an operator-supplied dir must still extend the TOOL lookup - the fix "
                "narrows the hasher and the plumbing, not --lookup-path's purpose")
            # and the hash written for it must be the REAL one, not the fake's constant
            block = text[text.index(planted_git):].split("sha256: ", 1)
            written = block[1][:64]
            # Assert a REAL sha256 rather than merely "not the fake's constant" (review P2):
            # `!= FAKE_HASH` also holds for an empty or garbage 64-char value, so it is the
            # weaker of the two assertions and arm 1 is what makes the pair sound.
            self.assertRegex(written, r"^[0-9a-f]{64}$",
                             "the planted tool's pin must carry a real lowercase hex sha256")
            self.assertNotEqual(written, FAKE_HASH,
                                "the planted tool was hashed by the planted hasher: the fix "
                                "narrowed the tool lookup too, or not at all")


@unittest.skipUnless(GENERATOR.exists(), "generator not present")
class TestLookupPathCannotInjectAPin(unittest.TestCase):
    """agents-oc3q: no CALLER-SUPPLIED DIRECTORY may supply the pin's reference value.

    THE ROUTE THIS PINS, AND WHY THE FIRST ATTEMPT AT IT WAS NOT ENOUGH. --lookup-path's
    value is interpolated into the emitted file's header comment, so a directory name
    carrying a LINE BREAK breaks out of that comment and injects a complete pin - path AND
    sha256 - which lib/tool_pins.py then accepts.

      Round 1 fix rejected \\n \\r \\t. THAT IS THE YAML LINE-BREAK SET AND THIS FILE IS NOT
      PARSED AS YAML: lib/tool_pins.py:318 uses text.splitlines() on a decoded string, which
      ALSO breaks on \\v \\f \\x1c \\x1d \\x1e \\x85 U+2028 U+2029. The reviewer constructed
      the surviving \\v route end to end and resolve_tool() returned the attacker's binary.
      So the first fix closed THE DELIMITER I WAS SHOWN rather than THE CLASS, and this test
      is written over the LOADER'S boundary set rather than a remembered list.

      Multi-byte characters U+0085, U+2028, U+2029: bash ANSI-C quoting $'\\u0085' expands to
      literal "\\u0085" in non-Unicode locales (C / POSIX), failing to match incoming UTF-8
      bytes. Exact hex byte escapes ($'\\xc2\\x85', $'\\xe2\\x80\\xa8', $'\\xe2\\x80\\xa9')
      match the loader's line break bytes across all host and runner locales.

    THE TEST IS BEHAVIOURAL AND ASSERTED AGAINST THE GENERATOR'S REFUSAL: for every
    character str.splitlines() breaks on it builds the injection, runs the generator, and
    asserts the generator refuses with exit 2 and writes nothing.
    """

    LINE_BREAKS = {
        "LF": "\n", "CR": "\r", "VT": "\v", "FF": "\f",
        "FS": "\x1c", "GS": "\x1d", "RS": "\x1e",
        "NEL": "\u0085", "LS": "\u2028", "PS": "\u2029",
    }

    def _run_injection(self, tmp, evil, flag_style="separate"):
        out = Path(tmp) / "out"
        out.mkdir(exist_ok=True)
        pins_file = out / "pins.yaml"
        cmd = ["bash", str(GENERATOR), str(pins_file)]
        if flag_style == "separate":
            cmd.extend(["--lookup-path", evil])
        else:
            cmd.append(f"--lookup-path={evil}")
        proc = subprocess.run(
            cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
            env={"PATH": "/usr/bin:/bin", "HOME": tmp},
        )
        return proc, pins_file

    def test_no_line_break_character_in_lookup_path_can_inject_a_pin(self):
        for label, char in self.LINE_BREAKS.items():
            for flag_style in ("separate", "equals"):
                with self.subTest(char=label, flag_style=flag_style), tempfile.TemporaryDirectory(prefix="oc3q-inj-") as tmp:
                    tmpd = Path(tmp)
                    fake = tmpd / "fakesemgrep"
                    fake.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
                    fake.chmod(0o755)
                    fake_hash = hashlib.sha256(fake.read_bytes()).hexdigest()
                    evil = (f"{tmpd}/P{char}semgrep:{char}  path: {fake}{char}"
                            f"  sha256: {fake_hash} #")
                    proc, pins_file = self._run_injection(tmp, evil, flag_style=flag_style)
                    self.assertEqual(proc.returncode, 2,
                                     f"{label} ({flag_style}): expected generator exit 2, got {proc.returncode}")
                    self.assertIn("error: --lookup-path must not contain", proc.stderr,
                                  f"{label} ({flag_style}): expected rejection on stderr")
                    self.assertFalse(pins_file.exists(),
                                     f"{label} ({flag_style}): pins file should not be created on rejection")

    def test_a_legitimate_lookup_path_is_still_accepted(self):
        """The other direction: the fix must not reject ordinary operator directories, which
        are the flag's documented purpose (engines install outside the system dirs)."""
        with tempfile.TemporaryDirectory(prefix="oc3q-ok-") as tmp:
            tmpd = Path(tmp)
            out = tmpd / "out"
            out.mkdir()
            os.makedirs(tmpd / "operator bin", exist_ok=True)
            # agents-z3cp5: the two operator dirs keep their precedence; the cheap tool set is appended
            # so the remaining tools are stand-ins.
            cheap = stage_cheap_tools(tmpd / "cheap-tools")
            proc = subprocess.run(
                ["bash", str(GENERATOR), str(out / "pins.yaml"),
                 "--lookup-path", f"{tmpd}/operator bin:{tmpd}:{cheap}"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
                env={"PATH": "/usr/bin:/bin", "HOME": tmp},
            )
            self.assertEqual(proc.returncode, 0,
                             f"a legitimate --lookup-path was rejected: {proc.stderr}")
            self.assertTrue((out / "pins.yaml").exists())


@unittest.skipUnless(GENERATOR.exists(), "generator not present")
class TestTheCheapToolSetCoversEveryToolTheGeneratorPins(unittest.TestCase):
    """agents-z3cp5: the stand-ins must stay IN STEP with the generator's own tool list.

    The arms above are only cheap while every tool the generator resolves has a stand-in. A tool
    added to the script without a stand-in here silently makes a run hash the real binary again -
    seconds become minutes, and the next person to hit it sees a timeout rather than a missing
    stand-in. So the list is a CONTRACT with the script, asserted rather than remembered.
    """

    def test_the_stand_ins_cover_exactly_the_tools_the_generator_pins(self):
        text = GENERATOR.read_text(encoding="utf-8")
        declared = re.search(r'^TOOLS="([^"]*)"$', text, re.M)
        self.assertIsNotNone(declared, "the generator's TOOLS line must stay parseable by this contract")
        self.assertEqual(sorted(declared.group(1).split()), sorted(CHEAP_TOOL_NAMES),
                         "the stand-in set and the generator's tool list have drifted apart")


@unittest.skipUnless(GENERATOR.exists(), "generator not present")
class TestTheIndependentDigestMustAgree(unittest.TestCase):
    """agents-0poh: the digest is computed twice, by two different implementations, and they
    must AGREE. A substituted external hasher can no longer choose the pin's reference value -
    it must also substitute the interpreter, a different binary in a different implementation.

    THE ATTACK THIS CLOSES IS NOT THE ONE ABOVE. The wrong-PATH arm plants a hasher in an
    OPERATOR dir; this arm plants a wrong-DIGEST hasher that the confined lookup would ACCEPT,
    and the confinement alone cannot catch it, because a compromised hasher in a system dir is
    inside the confinement by definition. That is why it needs the second implementation.
    """

    def _copy_with_confined_lookup(self, tmp, planted_dir):
        """A test-local copy whose confined lookup includes `planted_dir`.

        The generator's lookup string is a CONSTANT, so a system-dir plant cannot be reached
        from a test; rewriting that one line is what makes the arm reachable. It changes the
        LOOKUP LIST only - the resolution logic, the cross-check and the emit path are the
        generator's own bytes, so this discharges the arm's reachability rather than stubbing
        the behaviour under test.
        """
        text = GENERATOR.read_text(encoding="utf-8")
        new, n = re.subn(
            r'^SYSTEM_LOOKUP_PATH="[^"]*"$',
            f'SYSTEM_LOOKUP_PATH="{planted_dir}:{stage_cheap_tools(Path(tmp) / "cheap-tools")}'
            f':/usr/local/bin:/usr/bin:/bin"',
            text, count=1, flags=re.M)
        self.assertEqual(n, 1, "the confined lookup line must exist to be rewritten")
        self.assertNotIn(str(planted_dir), text, "the rewrite must be the only change")
        copy = Path(tmp) / "generate-tool-pins.sh"
        copy.write_text(new, encoding="utf-8")
        return copy

    def _run(self, tmp, copy):
        out = Path(tmp) / "out"
        out.mkdir()
        return subprocess.run(
            ["bash", str(copy), str(out / "pins.yaml")],
            cwd=str(ROOT), capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tmp})

    def test_a_wrong_digest_hasher_is_refused_rather_than_trusted(self):
        with tempfile.TemporaryDirectory(prefix="0poh-") as tmp:
            binp = Path(tmp) / "bin"
            binp.mkdir()
            fake = binp / "sha256sum"
            fake.write_text(f'#!/bin/sh\necho "{FAKE_HASH}  $2"\n', encoding="utf-8")
            fake.chmod(0o755)
            # ASSERT THE PLANT LANDED BEFORE READING ANY RESULT: a plant that never existed
            # reads exactly like a control that passed (the oc3q probe, 2026-10-11).
            ran = subprocess.run(["bash", str(fake), "/etc/hostname"],
                                 capture_output=True, text=True, timeout=30)
            self.assertIn(FAKE_HASH, ran.stdout, "the planted hasher must be the one on the path")
            res = self._run(tmp, self._copy_with_confined_lookup(tmp, binp))
            self.assertEqual(res.returncode, 2,
                             f"a wrong DIGEST must be refused, not emitted: {res.stdout}{res.stderr}")
            self.assertIn("digest disagreement", res.stderr,
                          "the refusal must SAY the two hashers disagreed, so the operator knows "
                          "which of the two is not trustworthy")
            self.assertNotIn(FAKE_HASH, (Path(tmp) / "out" / "pins.yaml").read_text(
                encoding="utf-8") if (Path(tmp) / "out" / "pins.yaml").exists() else "",
                "no pin may carry a value one of the two hashers contradicted")

    def test_the_same_copy_without_the_plant_still_generates(self):
        """THE CONTROL: identical code path, no plant - so the refusal above is attributable to
        the hasher and not to the copy."""
        with tempfile.TemporaryDirectory(prefix="0poh-ctl-") as tmp:
            empty = Path(tmp) / "bin"
            empty.mkdir()
            res = self._run(tmp, self._copy_with_confined_lookup(tmp, empty))
            self.assertEqual(res.returncode, 0, f"no plant, so nothing to disagree: {res.stderr}")
            self.assertIn("sha256: ", (Path(tmp) / "out" / "pins.yaml").read_text(encoding="utf-8"))

@unittest.skipUnless(GENERATOR.exists(), "generator not present")
class TestTheIndependentDigestCannotBeShadowed(unittest.TestCase):
    """agents-lm6r: 'an independent implementation' is not enough if the DEFENDED PARTY CAN SHADOW
    IT. hashlib is reachable AS A FILE - a hashlib.py on PYTHONPATH or in the generator's CWD
    shadows stdlib - so the independent digest could itself be supplied by the party the pin
    defends against, and the cross-check would compare the attacker against the attacker.

    THE SAME RULE ONE LEVEL DEEPER than agents-aeav: there the anchor was text a comment could
    impersonate; here the reference value is code a FILE can impersonate. The remedy is python3
    -I, isolated mode: PYTHONPATH is dropped and the CWD is kept off sys.path.

    WHAT THIS ASSERTS AND WHY IT IS NOT 'REFUSES': with -I the shadow is INVISIBLE, so there is
    nothing to disagree with and the run SUCCEEDS WITH CORRECT HASHES. Asserting a refusal here
    would be asserting the wrong outcome. The shadow is detected by its ABSENCE FROM THE OUTPUT -
    if the planted digest appears in any pin, the shadow won.
    """

    SHADOW = ("def sha256(data):\n"
              "    class _R:\n"
              "        def hexdigest(self):\n"
              "            return '0' * 64\n"
              "    return _R()\n")

    def test_a_hashlib_py_on_pythonpath_cannot_supply_the_digest(self):
        with tempfile.TemporaryDirectory(prefix="lm6r-path-") as tmp:
            shadow = Path(tmp) / "shadow"
            shadow.mkdir()
            (shadow / "hashlib.py").write_text(self.SHADOW, encoding="utf-8")
            # ASSERT THE PLANT SHADOWS BEFORE READING ANY RESULT (the oc3q-probe lesson).
            probe = subprocess.run(
                ["python3", "-c", "import hashlib;print(hashlib.sha256(b'x').hexdigest())"],
                capture_output=True, text=True, timeout=60,
                env={"PYTHONPATH": str(shadow), "PATH": "/usr/local/bin:/usr/bin:/bin"})
            self.assertEqual(probe.stdout.strip(), "0" * 64,
                             "the plant must actually shadow stdlib, or this test proves nothing")
            out = Path(tmp) / "out"
            out.mkdir()
            # agents-z3cp5: --lookup-path is unrelated to this arm's subject (which python digest
            # supplies the reference value); it is here so the twelve tools are stand-ins.
            res = subprocess.run(
                ["bash", str(GENERATOR), str(out / "pins.yaml"),
                 "--lookup-path", str(stage_cheap_tools(Path(tmp) / "cheap-tools"))],
                cwd=str(ROOT), capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
                env={"PYTHONPATH": str(shadow), "PATH": "/usr/local/bin:/usr/bin:/bin",
                     "HOME": tmp})
            self.assertEqual(res.returncode, 0,
                             f"with -I the shadow is invisible, so generation must succeed: {res.stderr}")
            text = (out / "pins.yaml").read_text(encoding="utf-8")
            hashes = re.findall(r"^\s+sha256: ([0-9a-f]{64})$", text, re.M)
            self.assertTrue(hashes, f"expected pins, got:\n{text}")
            self.assertNotIn("0" * 64, hashes,
                             "a hashlib.py on PYTHONPATH supplied the digest:' python3 -I is what "
                             "keeps the reference value out of the defended party's hands "
                             "(agents-lm6r)")

    def test_a_hashlib_py_in_the_cwd_cannot_supply_the_digest(self):
        """The SECOND channel - the generator's own working directory - closed by the same flag.

        WHAT THIS ARM IS AND IS NOT, STATED HERE RATHER THAN LEFT AS A WEAKNESS (agents-lm6r):
        the PYTHONPATH arm above REPRODUCES an exploit - it plants a shadow, proves the shadow is
        reached, and shows -I is what stops it. THIS arm asserts a GUARANTEE: that -I keeps the CWD
        off sys.path. It does not reproduce a shadow REACHING the generator's digest through the
        cwd, so it is A GUARD AGAINST REGRESSION, NOT A DEMONSTRATED EXPLOIT. Two different jobs,
        and the weaker one says so rather than borrowing the stronger one's evidence.
        agents-yuk9: the generator below now runs with the shadow in ITS OWN working
        directory, so this arm can fail for the regression it names - reverting -I turns it
        red (measured). It still runs no mutant itself, which is what keeps it a GUARD rather
        than a reproduction.
        """
        with tempfile.TemporaryDirectory(prefix="lm6r-cwd-") as tmp:
            (Path(tmp) / "hashlib.py").write_text(self.SHADOW, encoding="utf-8")
            probe = subprocess.run(
                ["python3", "-c", "import hashlib;print(hashlib.sha256(b'x').hexdigest())"],
                cwd=tmp, capture_output=True, text=True, timeout=60,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin"})
            self.assertEqual(probe.stdout.strip(), "0" * 64,
                             "the CWD plant must shadow stdlib before this test means anything")
            out = Path(tmp) / "out"
            out.mkdir()
            res = subprocess.run(
                ["bash", str(GENERATOR), str(out / "pins.yaml"),
                 # agents-z3cp5: stand-ins for the twelve tools, so this arm costs seconds.
                 "--lookup-path", str(stage_cheap_tools(Path(tmp) / "cheap-tools"))],
                # agents-yuk9: the shadow lives HERE, so this arm can actually fail.
                cwd=tmp, capture_output=True, text=True, timeout=_GENERATOR_GUARD_S,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tmp})
            self.assertEqual(res.returncode, 0, f"generation must succeed: {res.stderr}")
            hashes = re.findall(r"^\s+sha256: ([0-9a-f]{64})$",
                                (out / "pins.yaml").read_text(encoding="utf-8"), re.M)
            self.assertNotIn("0" * 64, hashes,
                             "a hashlib.py in the CWD supplied the digest (agents-lm6r)")


if __name__ == "__main__":
    unittest.main()

