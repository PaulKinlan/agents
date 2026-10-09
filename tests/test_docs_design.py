"""Static Pages snapshot contract, independent of the future generator."""

from collections import Counter
from html.parser import HTMLParser
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


if __name__ == "__main__":
    unittest.main()
