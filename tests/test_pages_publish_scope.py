"""The Pages artifact must contain the site and nothing else (agents-36z).

`docs/` is a working directory that also holds internal material (PLAN.md,
DESIGN.md, INTEGRATION.md, audits/). The Pages workflow used to upload `docs/`
wholesale, which published that material. These tests pin the narrowed publish
scope: the workflow uploads a staged directory, and the staged set is derived
from the pages and can only contain publishable site assets.
"""

from pathlib import Path
import tempfile
import unittest

from tools.stage_site import (
    PAGES,
    PUBLISH_EXTENSIONS,
    StagingError,
    guard,
    plan,
    stage,
)


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
WORKFLOW = ROOT / ".github" / "workflows" / "pages.yml"

#: Material that lives in docs/ but must never be served.
INTERNAL_FILES = ("PLAN.md", "DESIGN.md", "INTEGRATION.md")


class PagesPublishScopeTest(unittest.TestCase):
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

    def test_guard_refuses_internal_material(self):
        for rel in ("PLAN.md", "DESIGN.md", "INTEGRATION.md", "audits/engine-auth-parity.md"):
            with self.subTest(rel=rel):
                with self.assertRaises(StagingError):
                    guard(rel)
        for rel in ("index.html", "css/factory.css", "factory-cli.png"):
            self.assertEqual(guard(rel), rel)

    def test_the_six_pages_and_their_assets_are_published(self):
        published = set(plan(DOCS))
        self.assertEqual(set(PAGES) - published, set(), "every page must be published")
        for asset in ("css/factory.css", "css/product.css", "css/projects.css", "factory-cli.png"):
            self.assertIn(asset, published, f"{asset} is referenced by a page and must be published")

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
            self.assertEqual(sorted(path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()), plan(DOCS))

    def test_every_local_reference_of_a_published_file_is_published(self):
        """A page that links a local file must have that file in the artifact."""
        from tools.stage_site import _local_reference, _references  # noqa: WPS437 (test-only)

        published = set(plan(DOCS))
        for rel in sorted(published):
            for target in _references(DOCS, rel):
                with self.subTest(source=rel, target=target):
                    self.assertIn(target, published)
                    self.assertIsNotNone(_local_reference(rel, target))

    def test_workflow_uploads_the_staged_directory_and_keeps_the_freshness_guard(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("gen_site.py", text, "the regenerate-and-diff freshness guard must stay")
        self.assertIn("stage_site.py", text, "the workflow must stage the site instead of uploading docs/")
        self.assertNotIn("path: docs/", text, "the workflow must not upload the whole docs/ tree")
        upload = text.split("upload-pages-artifact", 1)[1]
        self.assertIn("path: _site", upload, "the uploaded artifact must be the staged directory")


if __name__ == "__main__":
    unittest.main()
