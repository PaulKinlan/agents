"""The Pages artifact must contain the site and nothing else (agents-36z).

`docs/` is a working directory that also holds internal material (PLAN.md,
DESIGN.md, INTEGRATION.md, audits/). The Pages workflow used to upload `docs/`
wholesale, which published that material. These tests pin the narrowed publish
scope: the workflow uploads a staged directory; the staged set is derived from
the pages; and every path in it passes `guard()` - a publishable extension, no
`audits/` component (compared case-insensitively), no escape from the site root
and no symlink. The negative tests run against throwaway fixtures so they prove
the tool refuses bad input rather than describing today's tree.
"""

import os
from pathlib import Path
import tempfile
import unittest

from tools.stage_site import (
    PAGES,
    PUBLISH_EXTENSIONS,
    StagingError,
    _HREF,
    _local_reference,
    guard,
    plan,
    stage,
)


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
WORKFLOW = ROOT / ".github" / "workflows" / "pages.yml"

#: Material that lives in docs/ but must never be served.
INTERNAL_FILES = ("PLAN.md", "DESIGN.md", "INTEGRATION.md")

PAGE_TEMPLATE = """<!doctype html>
<html lang="en"><head><title>t</title><link rel="stylesheet" href="css/factory.css"></head>
<body><h1>t</h1><img src="factory-cli.png" alt=""><a href="{link}">x</a></body></html>
"""


def make_site(root: Path, link: str = "index.html", page_body: str | None = None) -> Path:
    """Build a minimal six-page site under `root`; `page_body` replaces index.html if given."""
    (root / "css").mkdir(parents=True, exist_ok=True)
    (root / "css" / "factory.css").write_text("body { color: black }", encoding="utf-8")
    (root / "factory-cli.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    for page in PAGES:
        if page == "index.html" and page_body is not None:
            (root / page).write_text(page_body, encoding="utf-8")
        else:
            (root / page).write_text(PAGE_TEMPLATE.format(link=link), encoding="utf-8")
    return root


class PagesPublishScopeTest(unittest.TestCase):
    # --- the real tree -----------------------------------------------------------------

    def test_internal_material_exists_in_docs_but_is_not_published(self):
        for name in INTERNAL_FILES:
            self.assertTrue((DOCS / name).is_file(), f"{name} should still live in docs/")
        audit_notes = sorted((DOCS / "audits").glob("*.md"))
        self.assertTrue(audit_notes, "docs/audits/ should still hold the internal audit notes")

        published = plan(DOCS)
        for rel in published:
            self.assertFalse(rel.endswith(".md"), f"{rel} is markdown and must not be published")
            self.assertNotIn("audits", Path(rel).parts, f"{rel} is under audits/ and must not be published")
            self.assertIn(Path(rel).suffix.lower(), PUBLISH_EXTENSIONS, rel)
        for name in INTERNAL_FILES:
            self.assertNotIn(name, published)
        for note in audit_notes:
            self.assertNotIn(f"audits/{note.name}", published)

    def test_the_six_pages_and_their_assets_are_published(self):
        published = set(plan(DOCS))
        self.assertEqual(set(PAGES) - published, set(), "every page must be published")
        for asset in ("css/factory.css", "css/product.css", "css/projects.css", "factory-cli.png"):
            self.assertIn(asset, published, f"{asset} is referenced by a page and must be published")

    def test_every_local_reference_in_the_real_pages_resolves_to_a_published_file(self):
        """Raw references are re-extracted here, not taken from the plan, so a broken asset is caught."""
        published = set(plan(DOCS))
        for page in PAGES:
            for raw in _HREF.findall((DOCS / page).read_text(encoding="utf-8")):
                target = _local_reference(page, raw)
                if target is None:
                    continue
                with self.subTest(page=page, reference=raw):
                    self.assertTrue((DOCS / target).is_file(), f"{page} references missing {target}")
                    self.assertIn(target, published, f"{page} references {target}, which is not published")

    def test_staging_copies_exactly_the_planned_files(self):
        planned = plan(DOCS)
        with tempfile.TemporaryDirectory() as tmp:
            written = stage(DOCS, Path(tmp))
            self.assertEqual(sorted(written), planned)
            on_disk = sorted(
                path.relative_to(tmp).as_posix() for path in Path(tmp).rglob("*") if path.is_file()
            )
            self.assertEqual(on_disk, planned)
            for rel in on_disk:
                self.assertFalse(rel.endswith(".md"), rel)
                self.assertNotIn("audits", Path(rel).parts, rel)

    def test_staging_replaces_a_stale_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "_site"
            out.mkdir()
            (out / "audits").mkdir()
            (out / "audits" / "engine-auth-parity.md").write_text("stale internal note", encoding="utf-8")
            (out / "PLAN.md").write_text("stale plan", encoding="utf-8")
            stage(DOCS, out)
            self.assertEqual(
                sorted(path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()),
                plan(DOCS),
            )

    # --- refusals (fixtures, so these fail for the right reason) -----------------------

    def test_guard_refuses_internal_material_including_a_case_difference(self):
        for rel in (
            "PLAN.md",
            "DESIGN.md",
            "INTEGRATION.md",
            "audits/engine-auth-parity.md",
            "audits/report.html",
            "Audits/report.html",
            "AUDITS/report.html",
            "css/../PLAN.md",
        ):
            with self.subTest(rel=rel):
                with self.assertRaises(StagingError):
                    guard(rel)
        for rel in ("index.html", "css/factory.css", "factory-cli.png"):
            self.assertEqual(guard(rel), rel)

    def test_a_reference_to_internal_markdown_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link="PLAN.md"))
            (site / "PLAN.md").write_text("# internal", encoding="utf-8")
            with self.assertRaises(StagingError):
                plan(site)

    def test_a_reference_escaping_the_site_root_is_refused(self):
        for link in ("../outside.png", "../../escape.html", "css/../../outside.png", "/../outside.png"):
            with self.subTest(link=link):
                with tempfile.TemporaryDirectory() as tmp:
                    site = make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link=link))
                    (Path(tmp) / "outside.png").write_bytes(b"\x89PNG\r\n\x1a\n")
                    with self.assertRaises(StagingError):
                        plan(site)

    def test_an_escaping_reference_inside_css_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp))
            (site / "css" / "factory.css").write_text("body { background: url(../../outside.png) }", encoding="utf-8")
            (Path(tmp) / "outside.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with self.assertRaises(StagingError):
                plan(site)

    def test_a_symlinked_asset_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp))
            outside = Path(tmp) / "outside.png"
            outside.write_bytes(b"\x89PNG\r\n\x1a\n")
            try:
                os.symlink(outside, site / "linked.png")
            except (OSError, NotImplementedError) as error:  # e.g. unprivileged Windows
                self.skipTest(f"symlinks unavailable: {error}")
            (site / "index.html").write_text(PAGE_TEMPLATE.format(link="linked.png"), encoding="utf-8")
            with self.assertRaises(StagingError):
                plan(site)

    def test_a_directory_symlink_aliasing_an_internal_directory_is_refused(self):
        """docs/pub -> docs/audits must not become a way to publish audits/ under another name."""
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp))
            (site / "audits").mkdir()
            (site / "audits" / "report.html").write_text("<html><body>internal</body></html>", encoding="utf-8")
            try:
                os.symlink(site / "audits", site / "pub")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            (site / "index.html").write_text(PAGE_TEMPLATE.format(link="pub/report.html"), encoding="utf-8")
            with self.assertRaises(StagingError):
                plan(site)

    def test_a_missing_reference_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link="nope.css"))
            with self.assertRaises(StagingError):
                plan(site)

    def test_a_query_or_fragment_reference_resolves_to_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link="stations.html?x=1#y"))
            published = plan(site)
            self.assertIn("stations.html", published)

    def test_external_references_are_not_resolved(self):
        baseline = None
        with tempfile.TemporaryDirectory() as tmp:
            baseline = plan(make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link="index.html")))
        for reference in ("https://example.com/x.png", "//example.com/x.png", "mailto:a@b.c", "#top", "?q=1"):
            with self.subTest(reference=reference):
                with tempfile.TemporaryDirectory() as tmp:
                    site = make_site(Path(tmp), page_body=PAGE_TEMPLATE.format(link=reference))
                    self.assertEqual(plan(site), baseline)

    def test_stage_refuses_to_write_outside_the_output_directory(self):
        from tools import stage_site as module

        original = module.plan
        module.plan = lambda source=None: ["../escaped.html"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(StagingError):
                    module.stage(DOCS, Path(tmp) / "_site")
        finally:
            module.plan = original

    # --- the workflow ------------------------------------------------------------------

    def test_workflow_uploads_the_staged_directory_and_keeps_the_freshness_guard(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("gen_site.py", text, "the regenerate-and-diff freshness guard must stay")
        self.assertIn("stage_site.py", text, "the workflow must stage the site instead of uploading docs/")
        self.assertNotIn("path: docs/", text, "the workflow must not upload the whole docs/ tree")
        upload = text.split("upload-pages-artifact", 1)[1]
        self.assertIn("path: _site", upload, "the uploaded artifact must be the staged directory")

    def test_workflow_fetches_full_history(self):
        """The freshness step verifies a pinned commit with `git cat-file`, which a depth-1 clone lacks."""
        text = WORKFLOW.read_text(encoding="utf-8")
        checkout = text.split("actions/checkout", 1)[1].split("- name:", 1)[0]
        self.assertIn("fetch-depth: 0", checkout, "the checkout must fetch full history for the pin check")


if __name__ == "__main__":
    unittest.main()
