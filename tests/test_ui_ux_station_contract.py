"""The ui-ux-audit station must NAME the route for the font-size gap its own rule documents.

agents-txhd. The rule reads DECLARATIONS (simple px, rem, pt, zero), so it cannot decide a case that turns
on the cascade, a media query, an inherited root font-size or a UA default - and the SKILL says so itself in
the bullet that reports font_size_values_unparsed: "A zero-candidate result with a nonzero unparsed count is
not proof that all font sizes are legible." The station already runs a browser for rendered layout, and the
rendered sweep exists (tools/docs-text-floor.sh, landed in agents-ssyq), so that gap has a route. This
asserts the route is written down WITH the gap - not merely that both facts exist somewhere in the file -
and that the tool it names is really there, so the pointer cannot rot into a name with no file behind it.

Measured red-first: with the bullet as it stood before this change (no tool named) the first test below
fails; naming the sweep turns it green.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "agents" / "ui-ux-audit" / "SKILL.md"
TOOL = "tools/docs-text-floor.sh"
GAP_MARKER = "font_size_values_unparsed"


def bullets(text: str):
    """The SKILL's bullet blocks: a line opening with '- ' plus its continuation lines."""
    out, cur = [], None
    for line in text.splitlines():
        if line.lstrip().startswith("- "):
            if cur:
                out.append(cur)
            cur = [line]
        elif cur is not None and line.strip():
            cur.append(line)
        elif cur is not None:
            out.append(cur)
            cur = None
    if cur:
        out.append(cur)
    return ["\n".join(b) for b in out]


class TestTheStationNamesTheRouteForItsOwnDocumentedGap(unittest.TestCase):
    def setUp(self):
        self.text = SKILL.read_text()

    def the_bullet_that_reports_the_gap(self):
        hits = [b for b in bullets(self.text) if GAP_MARKER in b]
        self.assertEqual(
            len(hits), 1,
            "expected exactly one bullet to report %s; found %d" % (GAP_MARKER, len(hits)))
        return hits[0]

    def test_the_gap_bullet_names_the_rendered_sweep(self):
        # RED WITHOUT THE WIRING: before agents-txhd this bullet conceded the gap and named no tool.
        self.assertIn(
            TOOL, self.the_bullet_that_reports_the_gap(),
            "the bullet reporting %s must name %s as the route for the case it cannot decide"
            % (GAP_MARKER, TOOL))

    def test_the_named_route_is_a_file_that_exists(self):
        p = ROOT / TOOL
        self.assertTrue(p.is_file(), "%s is named as the route but is not a file" % TOOL)
        self.assertGreater(p.stat().st_size, 0, "%s is empty" % TOOL)

    def test_the_guard_can_go_red(self):
        # THE CONTROL: the assertion above proves nothing unless it fails on a SKILL that names no route.
        stripped = self.text.replace(TOOL, "<no route named>")
        self.assertNotEqual(stripped, self.text, "expected %s to read %s" % (SKILL.name, TOOL))
        stripped_hits = [b for b in bullets(stripped) if GAP_MARKER in b]
        self.assertEqual(len(stripped_hits), 1, "the control must strip the same single bullet")
        self.assertNotIn(TOOL, stripped_hits[0])


if __name__ == "__main__":
    unittest.main()
