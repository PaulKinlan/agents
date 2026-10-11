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

from lib.tool_pins import load_tool_pins

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "tools" / "generate-tool-pins.sh"
FAKE_HASH = "0" * 64


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
        subprocess.run(
            ["bash", str(GENERATOR), str(out / "pins.yaml"), "--lookup-path", str(planted)],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120,
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

    THE TEST IS BEHAVIOURAL AND ASSERTED AGAINST THE PARSER, not against the shell: for every
    character str.splitlines() breaks on it builds the injection, runs the generator, and
    asserts (a) the generator refuses and writes nothing, and (b) if a file WERE produced,
    this repo's own parser would not find the injected path in it.
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
            cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=120,
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
                    if pins_file.exists():
                        parsed = load_tool_pins(pins_file)
                        entry = parsed.get("semgrep") or {}
                        self.assertNotEqual(
                            entry.get("path"), str(fake),
                            f"{label} ({flag_style}): injected semgrep pin accepted by loader")

    def test_a_legitimate_lookup_path_is_still_accepted(self):
        """The other direction: the fix must not reject ordinary operator directories, which
        are the flag's documented purpose (engines install outside the system dirs)."""
        with tempfile.TemporaryDirectory(prefix="oc3q-ok-") as tmp:
            tmpd = Path(tmp)
            out = tmpd / "out"
            out.mkdir()
            os.makedirs(tmpd / "operator bin", exist_ok=True)
            proc = subprocess.run(
                ["bash", str(GENERATOR), str(out / "pins.yaml"),
                 "--lookup-path", f"{tmpd}/operator bin:{tmpd}"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=120,
                env={"PATH": "/usr/bin:/bin", "HOME": tmp},
            )
            self.assertEqual(proc.returncode, 0,
                             f"a legitimate --lookup-path was rejected: {proc.stderr}")
            self.assertTrue((out / "pins.yaml").exists())


if __name__ == "__main__":
    unittest.main()
