"""Tests for tools/gen_site.py (site generator and contract checks)."""

import html
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import tempfile
import unittest

from tools.gen_site import (
    ROOT,
    DOCS,
    PAGE_MARKERS,
    generate_all,
    get_agents,
    get_lines,
    get_cli_commands,
    replace_region,
    validate_safety,
)


class SimpleHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.links = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "a" or tag == "link":
            if "href" in attributes:
                self.links.append(attributes["href"])


def parse_page(html_text: str) -> SimpleHTMLParser:
    p = SimpleHTMLParser()
    p.feed(html_text)
    return p


class GenSiteTest(unittest.TestCase):
    def test_idempotence(self):
        """Generation must be deterministic: second run produces byte-identical output."""
        first_run = generate_all(ROOT, DOCS)
        second_run = generate_all(ROOT, DOCS)
        self.assertEqual(set(first_run.keys()), set(second_run.keys()))
        for filename in first_run:
            self.assertEqual(
                first_run[filename],
                second_run[filename],
                f"Page {filename} differs between successive generator runs",
            )

    def test_fails_closed_on_missing_or_duplicate_markers(self):
        """Generator must refuse and fail closed on missing, duplicate, or reversed markers."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_docs = Path(tmp_dir) / "docs"
            shutil.copytree(DOCS, tmp_docs)

            # 1. Missing BEGIN marker
            sample_file = tmp_docs / "index.html"
            original = sample_file.read_text(encoding="utf-8")
            missing_begin = original.replace("<!-- BEGIN GENERATED:quickstart -->", "")
            sample_file.write_text(missing_begin, encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                generate_all(ROOT, tmp_docs)
            self.assertIn("Marker count error", str(ctx.exception))

            # 2. Missing END marker
            sample_file.write_text(original.replace("<!-- END GENERATED:quickstart -->", ""), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                generate_all(ROOT, tmp_docs)
            self.assertIn("Marker count error", str(ctx.exception))

            # 3. Duplicate BEGIN marker
            dup_begin = original.replace(
                "<!-- BEGIN GENERATED:quickstart -->",
                "<!-- BEGIN GENERATED:quickstart -->\n<!-- BEGIN GENERATED:quickstart -->",
            )
            sample_file.write_text(dup_begin, encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                generate_all(ROOT, tmp_docs)
            self.assertIn("Marker count error", str(ctx.exception))

            # 4. Reversed markers (END before BEGIN)
            reversed_markers = original.replace(
                "<!-- BEGIN GENERATED:quickstart -->", "<!-- TEMP_MARKER -->"
            ).replace(
                "<!-- END GENERATED:quickstart -->", "<!-- BEGIN GENERATED:quickstart -->"
            ).replace(
                "<!-- TEMP_MARKER -->", "<!-- END GENERATED:quickstart -->"
            )
            sample_file.write_text(reversed_markers, encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                generate_all(ROOT, tmp_docs)
            self.assertIn("Malformed markers", str(ctx.exception))

    def test_station_count_and_id_parity(self):
        """Stations in stations.html must match agents/*/agent.yaml count, IDs, and be sorted."""
        agents = get_agents(ROOT)
        expected_names = [a["name"] for a in agents]
        self.assertGreater(len(expected_names), 0)
        self.assertEqual(expected_names, sorted(expected_names), "Agents must be sorted by name")

        pages = generate_all(ROOT, DOCS)
        parsed = parse_page(pages["stations.html"])
        station_ids = [val.removeprefix("station-") for val in parsed.ids if val.startswith("station-")]

        self.assertEqual(station_ids, expected_names)
        self.assertEqual(len(station_ids), len(set(station_ids)), "Station IDs must be unique")

    def test_line_station_order_preserved(self):
        """Lines must preserve declared station order and not alphabetize them."""
        agents = get_agents(ROOT)
        agent_names = {a["name"] for a in agents}
        lines = get_lines(ROOT, agent_names)

        pages = generate_all(ROOT, DOCS)
        lines_html = pages["lines.html"]

        for line in lines:
            line_id = f"line-{line['name']}"
            self.assertIn(f'id="{line_id}"', lines_html)
            # Find the section for this line card
            card_start = lines_html.index(f'id="{line_id}"')
            card_end = lines_html.find("</article>", card_start)
            card_text = lines_html[card_start:card_end]

            # Verify station links appear in the exact order declared in lines/*.yaml
            last_pos = -1
            for station in line["stations"]:
                target_href = f'href="stations.html#station-{station}"'
                pos = card_text.find(target_href)
                self.assertNotEqual(pos, -1, f"Station {station} not found in line {line['name']}")
                self.assertGreater(pos, last_pos, f"Station {station} out of order in line {line['name']}")
                last_pos = pos

    def test_editorial_text_outside_markers_untouched(self):
        """Text outside markers is human-owned and must never be altered by the generator."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_docs = Path(tmp_dir) / "docs"
            shutil.copytree(DOCS, tmp_docs)

            index_path = tmp_docs / "index.html"
            content = index_path.read_text(encoding="utf-8")
            custom_editorial_sentinel = '<p class="lede">UNIQUE_HUMAN_EDITORIAL_TEXT_12345</p>'
            modified_content = re.sub(r'<p class="lede">.*?</p>', custom_editorial_sentinel, content, count=1)
            index_path.write_text(modified_content, encoding="utf-8")

            pages = generate_all(ROOT, tmp_docs)
            self.assertIn(
                custom_editorial_sentinel,
                pages["index.html"],
                "Generator modified or destroyed human editorial text outside markers",
            )

    def test_no_html_injection_from_hostile_input(self):
        """Hostile strings in manifests must be properly escaped and never injected as raw HTML."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_root = Path(tmp_dir) / "repo"
            shutil.copytree(ROOT, fake_root, ignore=shutil.ignore_patterns(".git", "runs", "findings"))

            # Create a mock agent with hostile characters in its summary
            if (ROOT / ".git").is_file():
                shutil.copy2(ROOT / ".git", fake_root / ".git")
            elif (ROOT / ".git").is_dir():
                shutil.copytree(ROOT / ".git", fake_root / ".git")

            hostile_agent_dir = fake_root / "agents" / "xss-test-agent"
            hostile_agent_dir.mkdir(parents=True, exist_ok=True)
            hostile_summary = 'Audit <script>alert("xss")</script> & "quotes" and \'single\'.'
            (hostile_agent_dir / "agent.yaml").write_text(
                f"""name: xss-test-agent
class: observer
plane: [local]
containment: t0-readonly
summary: {hostile_summary}
capabilities:
  write: false
  network: false
  browser: false
  requires: []
""",
                encoding="utf-8",
            )

            pages = generate_all(fake_root, fake_root / "docs")
            stations_html = pages["stations.html"]

            # Must NOT contain raw script tag or unescaped HTML tag
            self.assertNotIn("<script>", stations_html)
            self.assertNotIn("</script>", stations_html)
            parsed = parse_page(stations_html)
            self.assertNotIn("script", parsed.tags, "DOM contains injected <script> tag!")

            # Must contain escaped text
            self.assertIn("&lt;script&gt;", stations_html)
            self.assertIn("&amp; &quot;quotes&quot;", stations_html)

    def test_safety_check_detects_forbidden_patterns(self):
        """Generator must fail closed if host paths, secrets or internal paths are rendered."""
        with self.assertRaises(ValueError) as ctx:
            validate_safety("Something pointing to /home/developer/secret.txt in docs", "test.html")
        self.assertIn("Host /home filesystem path", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            validate_safety("Something referencing findings/target.json in docs", "test.html")
        self.assertIn("Internal findings store file path", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            validate_safety("API token sk-1234567890abcdef1234567890abcdef in docs", "test.html")
        self.assertIn("API secret token", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
