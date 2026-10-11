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

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
