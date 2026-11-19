"""Unit and integration tests for scraper, downloader, reporter, and main CLI."""

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from foca_core.downloader import DocumentDownloader
from foca_core.models import DocumentTarget, ExtractedMetadata, OrganizationFingerprint
from foca_core.reporter import FocaReporter
from foca_core.scraper import DocumentScraper


class TestScraper(unittest.TestCase):
    """Test scraper discovery mechanisms."""

    def setUp(self) -> None:
        self.scraper = DocumentScraper(request_delay=0.01, timeout=2)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_local_directory_scanning(self) -> None:
        dir_path = Path(self.temp_dir.name)
        (dir_path / "report1.pdf").write_bytes(b"%PDF-1.4 test")
        (dir_path / "notes.docx").write_bytes(b"PK\x03\x04 test")
        (dir_path / "ignored.txt").write_text("ignore this")

        targets = self.scraper.scan_local_directory(
            str(dir_path),
            file_types=["pdf", "docx"],
        )
        self.assertEqual(len(targets), 2)
        filenames = {t.filename for t in targets}
        self.assertIn("report1.pdf", filenames)
        self.assertIn("notes.docx", filenames)
        for t in targets:
            self.assertEqual(t.source_engine, "local")
            self.assertEqual(t.status, "discovered")
            self.assertTrue(t.local_path and os.path.exists(t.local_path))

    @patch("requests.Session.post")
    def test_duckduckgo_parsing(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            '<html><body>'
            '<a class="result__url" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdocs%2Fannual_report.pdf&rut=1">Link</a>'
            '<a class="result__snippet" href="https://example.com/files/plan.pdf">Direct</a>'
            '</body></html>'
        )
        mock_post.return_value = mock_response

        targets = self.scraper.search_duckduckgo("example.com", ["pdf"], max_results=5)
        self.assertEqual(len(targets), 2)
        urls = {t.url for t in targets}
        self.assertIn("https://example.com/docs/annual_report.pdf", urls)
        self.assertIn("https://example.com/files/plan.pdf", urls)
        self.assertEqual(targets[0].file_type, "pdf")

    @patch("requests.Session.get")
    def test_spider_domain_crawling(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_response.text = (
            '<html><body>'
            '<a href="/downloads/whitepaper.pdf">PDF</a>'
            '<a href="/team">Team</a>'
            '<a href="https://external.com/file.pdf">External</a>'
            '</body></html>'
        )
        mock_get.return_value = mock_response

        targets = self.scraper.spider_domain("example.com", ["pdf"], max_results=5, max_pages=1)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "https://example.com/downloads/whitepaper.pdf")
        self.assertEqual(targets[0].source_engine, "spider")


class TestDownloader(unittest.TestCase):
    """Test streaming downloader, bounding limits, and content verification."""

    def setUp(self) -> None:
        self.downloader = DocumentDownloader(timeout=2)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_cached_file_skip(self) -> None:
        cache_dir = Path(self.temp_dir.name)
        domain_dir = cache_dir / "example.com"
        domain_dir.mkdir(parents=True)
        cached_file = domain_dir / "doc.pdf"
        cached_file.write_bytes(b"%PDF-1.5 existing")

        target = DocumentTarget(
            url="https://example.com/doc.pdf",
            filename="doc.pdf",
            file_type="pdf",
        )
        result = self.downloader.download_target(target, output_cache_dir=str(cache_dir))
        self.assertEqual(result.status, "cached")
        self.assertEqual(result.local_path, str(cached_file.resolve()))

    @patch("requests.Session.get")
    def test_streaming_and_magic_verification(self, mock_get: MagicMock) -> None:
        cache_dir = self.temp_dir.name

        # Test valid PDF stream
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Length": "100"}
        mock_resp.iter_content.return_value = [b"%PDF-1.4 header", b" body content"]
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_get.return_value = mock_resp

        target = DocumentTarget(
            url="https://example.com/test.pdf",
            filename="test.pdf",
            file_type="pdf",
        )
        res = self.downloader.download_target(target, output_cache_dir=cache_dir)
        self.assertEqual(res.status, "downloaded")
        self.assertTrue(res.local_path and os.path.exists(res.local_path))

    @patch("requests.Session.get")
    def test_reject_html_error_page(self, mock_get: MagicMock) -> None:
        cache_dir = self.temp_dir.name

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.iter_content.return_value = [b"<!DOCTYPE html><html><body>Error 404</body></html>"]
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_get.return_value = mock_resp

        target = DocumentTarget(
            url="https://example.com/broken.pdf",
            filename="broken.pdf",
            file_type="pdf",
        )
        res = self.downloader.download_target(target, output_cache_dir=cache_dir)
        self.assertIn("invalid MIME", res.status)


class TestReporter(unittest.TestCase):
    """Test Rich terminal reporter formatting and exports."""

    def setUp(self) -> None:
        self.reporter = FocaReporter()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_export_json_and_csv(self) -> None:
        meta = ExtractedMetadata(
            file_path="C:/docs/spec.pdf",
            file_type="pdf",
            author="jsmith",
            creator_tool="Adobe InDesign",
            producer="macOS Quartz",
            extracted_users=["jsmith", "admin"],
            extracted_paths=["C:\\Users\\jsmith\\Desktop"],
            extracted_printers=["HP LaserJet 4000"],
            extracted_emails=["jsmith@corp.internal"],
        )
        fingerprint = OrganizationFingerprint(
            domain="corp.internal",
            total_files_analyzed=1,
            discovered_users=["jsmith"],
            discovered_software={"Adobe InDesign": 1},
            discovered_operating_systems={"Windows": 1},
            discovered_printers=["HP LaserJet 4000"],
            discovered_paths=["C:\\Users\\jsmith\\Desktop"],
            discovered_emails=["jsmith@corp.internal"],
            documents=[meta],
        )

        json_path = os.path.join(self.temp_dir.name, "report.json")
        csv_path = os.path.join(self.temp_dir.name, "report.csv")

        self.reporter.export_json(fingerprint, json_path)
        self.reporter.export_csv(fingerprint, csv_path)

        self.assertTrue(os.path.isfile(json_path))
        self.assertTrue(os.path.isfile(csv_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["domain"], "corp.internal")
            self.assertIn("jsmith", data["discovered_users"])

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)  # Header + 1 row
            self.assertIn("spec.pdf", rows[1][0])
            self.assertIn("jsmith", rows[1][3])


class TestEndToEndCLI(unittest.TestCase):
    """Integration test running main.py on local files."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_cli_local_scan_and_json(self) -> None:
        doc_dir = Path(self.temp_dir.name) / "docs"
        out_dir = Path(self.temp_dir.name) / "out"
        doc_dir.mkdir()

        # Create a small valid test PDF with PyMuPDF
        import fitz
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 72), "Confidential Blueprint for Acme Corp")
        doc.set_metadata({
            "author": "Alice Montgomery",
            "creator": "Adobe Acrobat 2024",
            "producer": "macOS PDF",
        })
        pdf_path = doc_dir / "blueprint.pdf"
        doc.save(str(pdf_path))
        doc.close()

        # Run main.py with --json flag
        cmd = [
            sys.executable,
            "main.py",
            "-l", str(doc_dir),
            "-o", str(out_dir),
            "--json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        self.assertEqual(data["total_files_analyzed"], 1)
        self.assertIn("alice montgomery", [u.lower() for u in data["discovered_users"]])
        self.assertTrue((out_dir / f"foca_fingerprint_{doc_dir.name}.json").exists())
        self.assertTrue((out_dir / f"foca_metadata_{doc_dir.name}.csv").exists())


if __name__ == "__main__":
    unittest.main()
