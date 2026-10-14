"""Static Pages snapshot contract, independent of the future generator."""

from collections import Counter
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PAGES = ("index.html", "install.html", "use.html", "stations.html", "lines.html", "help.html")
MARKERS = {
    "index.html": ("quickstart",),
    "install.html": ("install-prerequisites", "install-local", "install-auth", "install-action", "install-extras"),
    "use.html": ("cli-reference",),
    "stations.html": ("stations",),
    "lines.html": ("lines",),
}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.links = []
        self.headings = []
        self.landmarks = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "a" or tag == "link":
            self.links.append(attributes.get("href", ""))
        if tag in ("h1", "h2", "h3"):
            self.headings.append(tag)
        if tag in ("header", "main", "footer"):
            self.landmarks.append(tag)


def parse(path):
    parser = PageParser()
    parser.feed(path.read_text())
    return parser


def code_vertical_align_rules(css):
    """Find declarations on pre's code descendants, including rules nested in at-rules.

    This is a narrow structural guard, not a general CSS cascade implementation: a
    competing declaration must be reviewed with the browser layout before acceptance.
    """
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    stack = []
    rules = []
    cursor = 0
    for brace in re.finditer(r"[{}]", css):
        if brace.group() == "{":
            stack.append((css[cursor:brace.start()].strip(), brace.end()))
        else:
            if not stack:
                raise ValueError("unbalanced CSS closing brace")
            selector, start = stack.pop()
            body = css[start:brace.start()]
            # A leaf is a style rule; an enclosing @layer/@media/@supports body
            # contains nested braces and is not a declaration block itself.
            if "{" not in body and re.search(r"(?<![\w-])pre(?:\s*>\s*|\s+)code\b", selector):
                contexts = tuple(name for name, _ in stack if name.startswith("@"))
                for declaration in body.split(";"):
                    property_name, separator, value = declaration.partition(":")
                    if separator and property_name.strip().lower() == "vertical-align":
                        rules.append((selector, value.strip(), contexts))
        cursor = brace.end()
    if stack:
        raise ValueError("unbalanced CSS opening brace")
    return rules


class DocsDesignTest(unittest.TestCase):
    def test_pages_have_landmarks_and_working_local_links(self):
        for filename in PAGES:
            with self.subTest(page=filename):
                page = DOCS / filename
                parsed = parse(page)
                self.assertEqual(parsed.headings.count("h1"), 1)
                self.assertEqual(parsed.landmarks, ["header", "main", "footer"])
                self.assertEqual(len(parsed.ids), len(set(parsed.ids)))
                for link in parsed.links:
                    if re.match(r"^(https?://|mailto:)", link):
                        continue
                    destination, _, fragment = link.partition("#")
                    target = DOCS / destination if destination else page
                    self.assertTrue(target.is_file(), (filename, link))
                    if fragment:
                        self.assertIn(fragment, parse(target).ids, (filename, link))
                    self.assertFalse(link.startswith("/"), (filename, link))

    def test_generated_region_snapshot_matches_public_declarations(self):
        for filename, markers in MARKERS.items():
            text = (DOCS / filename).read_text()
            for marker in markers:
                self.assertEqual(text.count(f"<!-- BEGIN GENERATED:{marker} -->"), 1)
                self.assertEqual(text.count(f"<!-- END GENERATED:{marker} -->"), 1)
        station_ids = [value.removeprefix("station-") for value in parse(DOCS / "stations.html").ids if value.startswith("station-")]
        line_ids = [value.removeprefix("line-") for value in parse(DOCS / "lines.html").ids if value.startswith("line-")]
        command_ids = [value.removeprefix("cmd-") for value in parse(DOCS / "use.html").ids if value.startswith("cmd-")]
        self.assertEqual(set(station_ids), {path.parent.name for path in (ROOT / "agents").glob("*/agent.yaml")})
        self.assertEqual(set(line_ids), {path.stem for path in (ROOT / "lines").glob("*.yaml")})
        self.assertEqual(Counter(command_ids), Counter("integrate list promote run line hillclimb hook skills schedule".split()))

    def test_code_scroll_hints_query_descendants_and_keep_fallback(self):
        """The committed hints style code descendants without dropping the gradient fallback."""
        css = (DOCS / "css" / "factory.css").read_text(encoding="utf-8")
        self.assertIn("pre:has(> code) { container-type: scroll-state; }", css)
        self.assertIn("pre > code { display: inline-grid; vertical-align: top;", css,
                      "inline-grid must not add a baseline descender gap to every code block")
        for direction, indicator in (("inline-start", "before"), ("inline-end", "after")):
            self.assertIn(f"@container scroll-state(scrollable: {direction}) "
                          f"{{ pre > code::{indicator} {{ opacity: 1; }} }}", css)
        self.assertIn("no-repeat local", css, "keep the gradient fallback for unsupported browsers")
        self.assertIn("Chrome 155.0.8059.39 the <code> descendant indicators match", css,
                      "do not reinstate the falsified browser-support claim")
        self.assertNotIn("parsed the native rules without ever matching them", css)
        self.assertNotIn("the earlier failed probe", css,
                         "the historical cause was not established by the browser measurement")
        self.assertNotIn("a scroller cannot query its own scroll state", css,
                         "the scroller's pseudo-elements can match even though the element itself cannot")

    def assert_code_scroll_alignment(self, css):
        # A later unlayered or more-specific rule can beat the inline-grid rule
        # while the old substring assertion still passes. Pin the ONE declaration
        # and its wide-screen feature context; a new competing rule needs review.
        self.assertEqual(code_vertical_align_rules(css), [
            ("pre > code", "top", ("@layer components", "@supports (container-type: scroll-state)",
                                   "@media (min-width: 48.001rem)")),
        ], "competing vertical-align declaration affecting pre code")

    def test_code_scroll_alignment_has_no_competing_declaration(self):
        css = (DOCS / "css" / "factory.css").read_text(encoding="utf-8")
        self.assert_code_scroll_alignment(css)

    def test_code_scroll_alignment_guard_rejects_higher_priority_mutant(self):
        css = (DOCS / "css" / "factory.css").read_text(encoding="utf-8")
        # Unlayered and later: this beats the @layer components declaration at
        # 900px and recreates the measured 6.0625px descender gap.
        mutant = css + "\n@media (min-width: 48.001rem) { html pre > code { vertical-align: baseline; } }\n"
        self.assertIn("pre > code { display: inline-grid; vertical-align: top;", mutant)
        with self.assertRaisesRegex(AssertionError, "competing vertical-align declaration affecting pre code"):
            self.assert_code_scroll_alignment(mutant)

    def test_pages_have_valid_speculation_rules(self):
        """All public documentation pages must carry moderate-eagerness speculation rules (agents-74qx et al)."""
        for filename in PAGES:
            with self.subTest(page=filename):
                page = DOCS / filename
                content = page.read_text(encoding="utf-8")
                self.assertIn('<script type="speculationrules">', content)
                match = re.search(r'<script type="speculationrules">\s*(\{.*?\})\s*</script>', content, re.DOTALL)
                self.assertIsNotNone(match, f"Missing or malformed speculationrules block in {filename}")
                rules = json.loads(match.group(1))
                self.assertIn("prerender", rules)
                self.assertEqual(len(rules["prerender"]), 1)
                self.assertEqual(rules["prerender"][0]["where"], {"href_matches": "/*"})
                self.assertEqual(rules["prerender"][0]["eagerness"], "moderate")


if __name__ == "__main__":
    unittest.main()
