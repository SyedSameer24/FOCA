"""Unit and integration tests for DeepCrawler, ArchiveDigger, reporter export_all, and CLI pipeline."""

import csv
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests
from rich.console import Console

from foca_core.archive_digger import ArchiveDigger
from foca_core.deep_crawler import DeepCrawler
from foca_core.models import (
    DNSAuditResult,
    DocumentTarget,
    ExtractedMetadata,
    OrganizationFingerprint,
    SubdomainResult,
    TechStackResult,
    WhoisResult,
)
from foca_core.reporter import FocaReporter
import main


class TestDeepCrawler(unittest.TestCase):
    """Test suite for DeepCrawler functionality."""

    def setUp(self) -> None:
        self.crawler = DeepCrawler(max_pages=5, max_depth=2, timeout=5)

    def test_clean_domain(self) -> None:
        self.assertEqual(self.crawler._clean_domain("https://example.com/test"), "example.com")
        self.assertEqual(self.crawler._clean_domain("http://sub.example.com:8080/"), "sub.example.com")
        self.assertEqual(self.crawler._clean_domain("example.org"), "example.org")

    def test_extract_emails_filtering(self) -> None:
        raw_text = (
            "Contact us at alice.smith@enterprise.org or bob-dev@company.co.uk. "
            "Ignore dummy info@example.com and test@test.com and user@sample.com. "
            "Also ignore graphic assets like logo@2x.png or banner@3x.jpg."
        )
        emails = self.crawler._extract_emails(raw_text)
        self.assertIn("alice.smith@enterprise.org", emails)
        self.assertIn("bob-dev@company.co.uk", emails)
        self.assertNotIn("info@example.com", emails)
        self.assertNotIn("test@test.com", emails)
        self.assertNotIn("user@sample.com", emails)
        self.assertNotIn("logo@2x.png", emails)
        self.assertNotIn("banner@3x.jpg", emails)

    def test_extract_cloud_buckets(self) -> None:
        text = (
            "Static assets hosted on https://mybucket.s3.us-west-2.amazonaws.com/files "
            "and backup at s3.amazonaws.com/corp-archive-data "
            "along with Azure blob storage at securelogs.blob.core.windows.net "
            "and GCP bucket at storage.googleapis.com/company-assets-prod."
        )
        buckets = self.crawler._extract_cloud_buckets(text)
        self.assertTrue(any("mybucket.s3" in b for b in buckets))
        self.assertTrue(any("s3.amazonaws.com/corp-archive-data" in b for b in buckets))
        self.assertTrue(any("securelogs.blob.core.windows.net" in b for b in buckets))
        self.assertTrue(any("storage.googleapis.com/company-assets-prod" in b for b in buckets))

    def test_extract_internal_ips_from_comments_and_scripts(self) -> None:
        html = """
        <html>
        <head>
            <!-- Deploy server: 192.168.1.55 on node 10.0.12.3 -->
            <!-- Invalid IP: 10.300.1.1 and 192.168.1.999 -->
        </head>
        <body>
            <p>Public text with 8.8.8.8 should not be matched as internal</p>
            <script>
                const internalGateway = "172.20.10.4";
                const apiHost = "10.254.1.100";
            </script>
        </body>
        </html>
        """
        ips = self.crawler._extract_internal_ips(html)
        self.assertIn("192.168.1.55", ips)
        self.assertIn("10.0.12.3", ips)
        self.assertIn("172.20.10.4", ips)
        self.assertIn("10.254.1.100", ips)
        self.assertNotIn("8.8.8.8", ips)
        self.assertNotIn("10.300.1.1", ips)

    def test_fetch_robots_txt(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /confidential/q4_report.pdf\n"
            "Allow: /public/\n"
            "Sitemap: https://target.com/custom_sitemap.xml\n"
        )
        mock_session.get.return_value = mock_resp
        crawler = DeepCrawler(session=mock_session)

        sitemaps, paths = crawler._fetch_robots_txt("https://target.com")
        self.assertIn("https://target.com/custom_sitemap.xml", sitemaps)
        self.assertIn("/admin/", paths)
        self.assertIn("/confidential/q4_report.pdf", paths)

    def test_fetch_sitemaps(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://target.com/about</loc>
            </url>
            <url>
                <loc>https://target.com/docs/annual_report_2025.pdf</loc>
            </url>
            <url>
                <loc>https://target.com/data/export.xlsx</loc>
            </url>
        </urlset>
        """
        mock_session.get.return_value = mock_resp
        crawler = DeepCrawler(session=mock_session)

        target_exts = {"pdf", "xlsx", "docx"}
        discovered_docs, web_urls = crawler._fetch_sitemaps(
            ["https://target.com/sitemap.xml"], "target.com", target_exts
        )

        self.assertEqual(len(discovered_docs), 2)
        urls = [doc.url for doc in discovered_docs]
        self.assertIn("https://target.com/docs/annual_report_2025.pdf", urls)
        self.assertIn("https://target.com/data/export.xlsx", urls)
        self.assertIn("https://target.com/about", web_urls)

    def test_crawl_end_to_end_and_callback(self) -> None:
        mock_session = MagicMock()

        def mock_get(url: str, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.url = url

            if "robots.txt" in url:
                resp.text = "Sitemap: https://target.com/sitemap.xml\nDisallow: /secret/audit.docx"
                resp.content = resp.text.encode("utf-8")
                resp.headers = {"Content-Type": "text/plain"}
            elif "sitemap.xml" in url:
                resp.content = b"""<?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                    <url><loc>https://target.com/team</loc></url>
                </urlset>"""
                resp.text = resp.content.decode("utf-8")
                resp.headers = {"Content-Type": "application/xml"}
            elif "team" in url:
                resp.text = """
                <html>
                <body>
                    <!-- Internal node: 10.10.10.20 -->
                    <h1>Team</h1>
                    <p>Contact engineer: jane.doe@target.com</p>
                    <a href="/downloads/spec.pdf">Download Spec</a>
                    <a href="https://target.com/cloud">Cloud</a>
                </body>
                </html>
                """
                resp.content = resp.text.encode("utf-8")
                resp.headers = {"Content-Type": "text/html"}
            elif "cloud" in url:
                resp.text = """
                <html>
                <body>
                    <script>var s3 = "target-data.s3.amazonaws.com";</script>
                    <a href="https://target.com/docs/overview.pptx">Presentation</a>
                </body>
                </html>
                """
                resp.content = resp.text.encode("utf-8")
                resp.headers = {"Content-Type": "text/html"}
            else:
                resp.text = """
                <html>
                <body>
                    <a href="https://target.com/team">Our Team</a>
                </body>
                </html>
                """
                resp.content = resp.text.encode("utf-8")
                resp.headers = {"Content-Type": "text/html"}
            return resp

        mock_session.get.side_effect = mock_get
        crawler = DeepCrawler(max_pages=5, max_depth=2, timeout=5, session=mock_session)

        logs = []
        result = crawler.crawl(
            "target.com",
            file_types=["pdf", "docx", "pptx"],
            log_callback=lambda msg: logs.append(msg),
        )

        self.assertIn("document_targets", result)
        self.assertIn("emails", result)
        self.assertIn("cloud_buckets", result)
        self.assertIn("internal_ips", result)
        self.assertIn("crawled_urls", result)

        self.assertIn("jane.doe@target.com", result["emails"])
        self.assertIn("10.10.10.20", result["internal_ips"])
        self.assertTrue(any("target-data.s3.amazonaws.com" in b for b in result["cloud_buckets"]))

        doc_urls = [d.url for d in result["document_targets"]]
        self.assertTrue(any("audit.docx" in u for u in doc_urls))
        self.assertTrue(any("spec.pdf" in u for u in doc_urls))
        self.assertTrue(len(logs) > 0)
        self.assertTrue(any("Visiting:" in l for l in logs))


class TestArchiveDigger(unittest.TestCase):
    """Test suite for ArchiveDigger Wayback Machine integration."""

    def setUp(self) -> None:
        self.digger = ArchiveDigger(timeout=5)

    def test_clean_domain_and_filename(self) -> None:
        self.assertEqual(self.digger._clean_domain("https://example.com/path"), "example.com")
        self.assertEqual(self.digger._extract_filename("http://example.com/doc.pdf", "pdf"), "doc.pdf")
        self.assertEqual(self.digger._extract_filename("http://example.com/get?file=123", "pdf"), "get.pdf")

    def test_dig_historical_documents(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            ["original"],
            ["https://target.com/archive/q1_report.pdf"],
            ["https://target.com/archive/contracts.docx"],
            ["https://target.com/index.html"],
            ["https://target.com/archive/q1_report.pdf"],  # Duplicate
        ]
        mock_session.get.return_value = mock_resp
        digger = ArchiveDigger(session=mock_session)

        results = digger.dig_historical_documents("target.com", ["pdf", "docx"], limit=10)
        self.assertEqual(len(results), 2)
        urls = [r.url for r in results]
        self.assertIn("https://target.com/archive/q1_report.pdf", urls)
        self.assertIn("https://target.com/archive/contracts.docx", urls)
        self.assertEqual(results[0].source_engine, "wayback_archive")


class TestReporterExportAll(unittest.TestCase):
    """Test suite for FocaReporter export_all generating all 8 output files."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.reporter = FocaReporter(console=Console(record=True, width=120))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_export_all_creates_all_8_files(self) -> None:
        """Verify export_all writes all 8 files into the target folder."""
        fingerprint = OrganizationFingerprint(
            domain="acme.corp",
            scan_timestamp="2026-11-15T00:00:00Z",
            total_files_analyzed=1,
            discovered_users=["admin_jdoe", "alice"],
            discovered_software={"Microsoft Word 2019": 1},
            discovered_operating_systems={"Windows 10": 1},
            discovered_paths=[r"C:\Users\jdoe\Documents\budget.docx"],
            discovered_printers=["\\\\printserver\\PRINTER-HP400"],
            discovered_emails=["jdoe@acme.corp"],
            documents=[
                ExtractedMetadata(
                    file_path="/tmp/budget.docx",
                    file_type="docx",
                    author="John Doe",
                    company="ACME Corp",
                    extracted_users=["admin_jdoe"],
                    extracted_emails=["jdoe@acme.corp"],
                    extracted_paths=[r"C:\Users\jdoe\Documents\budget.docx"],
                    extracted_printers=["\\\\printserver\\PRINTER-HP400"],
                )
            ],
            dns_audit=DNSAuditResult(
                domain="acme.corp",
                a_records=["192.0.2.1"],
                mx_records=[{"exchange": "mail.acme.corp", "preference": 10}],
                spf_record="v=spf1 include:_spf.google.com ~all",
                dmarc_record="v=DMARC1; p=reject",
                mail_provider="Google",
            ),
            subdomain_audit=SubdomainResult(
                domain="acme.corp",
                total_found=2,
                subdomains=["vpn.acme.corp", "mail.acme.corp"],
            ),
            tech_stack=TechStackResult(
                domain="acme.corp",
                server_banner="nginx/1.24.0",
                security_headers={"Strict-Transport-Security": True, "Content-Security-Policy": False},
                detected_technologies=["Nginx", "React"],
            ),
            whois_info=WhoisResult(
                domain="acme.corp",
                registrar="MarkMonitor Inc.",
                creation_date="2010-05-01",
                expiration_date="2030-05-01",
            ),
            crawled_emails=["support@acme.corp", "dev@acme.corp"],
            cloud_buckets=["acme-data-store.s3.amazonaws.com", "acmelogs.blob.core.windows.net"],
            internal_ips=["10.0.4.15", "192.168.1.100"],
            crawled_urls=["https://acme.corp/", "https://acme.corp/about"],
            archive_documents=["https://web.archive.org/web/acme.corp/legacy.pdf"],
        )

        output_paths = self.reporter.export_all(
            fingerprint=fingerprint,
            target_identity="https://acme.corp/",
            output_base_dir=self.temp_dir.name,
            print_box=True,
        )

        target_dir = Path(self.temp_dir.name) / "acme.corp"
        self.assertTrue(target_dir.is_dir())

        # Verify all 8 files exist
        expected_files = [
            "full_report.json",
            "metadata_catalog.csv",
            "emails.txt",
            "subdomains.txt",
            "cloud_buckets.txt",
            "internal_network_leaks.txt",
            "crawled_urls.txt",
            "summary.txt",
        ]
        for fname in expected_files:
            file_p = target_dir / fname
            self.assertTrue(file_p.exists(), f"Expected {fname} to exist at {file_p}")
            self.assertIn(fname, output_paths)

        # 1. Check full_report.json
        with open(target_dir / "full_report.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["domain"], "acme.corp")
            self.assertIn("support@acme.corp", data["crawled_emails"])
            self.assertIn("10.0.4.15", data["internal_ips"])

        # 2. Check metadata_catalog.csv
        with open(target_dir / "metadata_catalog.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            self.assertGreaterEqual(len(rows), 2)
            self.assertIn("John Doe", rows[1])

        # 3. Check emails.txt (sorted unique union of doc emails + crawled emails)
        with open(target_dir / "emails.txt", "r", encoding="utf-8") as f:
            emails_lines = [line.strip() for line in f if line.strip()]
            self.assertEqual(emails_lines, ["dev@acme.corp", "jdoe@acme.corp", "support@acme.corp"])

        # 4. Check subdomains.txt
        with open(target_dir / "subdomains.txt", "r", encoding="utf-8") as f:
            sub_lines = [line.strip() for line in f if line.strip()]
            self.assertEqual(sub_lines, ["mail.acme.corp", "vpn.acme.corp"])

        # 5. Check cloud_buckets.txt
        with open(target_dir / "cloud_buckets.txt", "r", encoding="utf-8") as f:
            bucket_lines = [line.strip() for line in f if line.strip()]
            self.assertEqual(
                bucket_lines,
                ["acme-data-store.s3.amazonaws.com", "acmelogs.blob.core.windows.net"],
            )

        # 6. Check internal_network_leaks.txt
        with open(target_dir / "internal_network_leaks.txt", "r", encoding="utf-8") as f:
            leak_lines = [line.strip() for line in f if line.strip()]
            self.assertIn("10.0.4.15", leak_lines)
            self.assertIn("192.168.1.100", leak_lines)
            self.assertIn(r"C:\Users\jdoe\Documents\budget.docx", leak_lines)
            self.assertIn(r"\\printserver\PRINTER-HP400", leak_lines)

        # 7. Check crawled_urls.txt
        with open(target_dir / "crawled_urls.txt", "r", encoding="utf-8") as f:
            url_lines = [line.strip() for line in f if line.strip()]
            self.assertEqual(url_lines, ["https://acme.corp/", "https://acme.corp/about"])

        # 8. Check summary.txt
        with open(target_dir / "summary.txt", "r", encoding="utf-8") as f:
            summary_content = f.read()
            self.assertIn("Target Identifier       : https://acme.corp/", summary_content)
            self.assertIn("DISCOVERED USERS & DOCUMENT AUTHORS", summary_content)
            self.assertIn("admin_jdoe", summary_content)
            self.assertIn("DISCOVERED EMAIL ADDRESSES", summary_content)
            self.assertIn("dev@acme.corp", summary_content)
            self.assertIn("EXPOSED CLOUD STORAGE BUCKETS", summary_content)
            self.assertIn("acme-data-store.s3.amazonaws.com", summary_content)
            self.assertIn("INTERNAL NETWORK & PATH LEAKS", summary_content)
            self.assertIn("10.0.4.15", summary_content)
            self.assertIn("DNS & MAIL INFRASTRUCTURE", summary_content)
            self.assertIn("Mail Provider : Google", summary_content)
            self.assertIn("WEB TECHNOLOGY & SECURITY HEADERS", summary_content)
            self.assertIn("Web Server    : nginx/1.24.0", summary_content)

    def test_dashboard_renders_email_and_leak_tables_no_emojis(self) -> None:
        """Verify render_dashboard displays Discovered Employee Emails and Exposed Leaks without emojis."""
        fingerprint = OrganizationFingerprint(
            domain="bank.org",
            crawled_emails=["ceo@bank.org"],
            cloud_buckets=["bank-vault.s3.amazonaws.com"],
            internal_ips=["10.50.1.1"],
        )

        test_console = Console(record=True, width=120)
        reporter = FocaReporter(console=test_console)
        reporter.render_dashboard(fingerprint)
        rendered = test_console.export_text()

        self.assertIn("Discovered Employee Emails", rendered)
        self.assertIn("ceo@bank.org", rendered)
        self.assertIn("Exposed Cloud Storage & Network Leaks", rendered)
        self.assertIn("AWS S3 Bucket", rendered)
        self.assertIn("bank-vault.s3.amazonaws.com", rendered)
        self.assertIn("Private Internal IP", rendered)
        self.assertIn("10.50.1.1", rendered)

        # Ensure no forbidden emojis
        forbidden = ["🚀", "✅", "💡", "📁", "📄", "🔒", "✨"]
        for emoji in forbidden:
            self.assertNotIn(emoji, rendered)


class TestMainPipelineIntegration(unittest.TestCase):
    """Test suite for main pipeline deep crawling, target merging, and complete export."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @patch("foca_core.downloader.DocumentDownloader.download_targets")
    @patch("foca_core.deep_crawler.DeepCrawler.crawl")
    @patch("foca_core.archive_digger.ArchiveDigger.dig_historical_documents")
    @patch("foca_core.scraper.DocumentScraper.discover")
    def test_pipeline_deep_and_archive_merging(
        self,
        mock_dork: MagicMock,
        mock_archive: MagicMock,
        mock_crawl: MagicMock,
        mock_download: MagicMock,
    ) -> None:
        """Verify targets from DeepCrawler, ArchiveDigger, and dorking are merged and exported."""
        mock_crawl.return_value = {
            "document_targets": [
                DocumentTarget(url="https://cybercorp.io/deep.pdf", filename="deep.pdf", file_type="pdf")
            ],
            "emails": ["crawler@cybercorp.io"],
            "cloud_buckets": ["cyber-data.s3.amazonaws.com"],
            "internal_ips": ["192.168.10.5"],
            "crawled_urls": ["https://cybercorp.io/page1"],
        }
        mock_archive.return_value = [
            DocumentTarget(url="https://cybercorp.io/wayback.pdf", filename="wayback.pdf", file_type="pdf")
        ]
        mock_dork.return_value = [
            DocumentTarget(url="https://cybercorp.io/dork.pdf", filename="dork.pdf", file_type="pdf")
        ]
        mock_download.return_value = []

        exit_code = main.run_pipeline(
            domain="cybercorp.io",
            output_dir_str=self.temp_dir.name,
            deep=True,
            no_archive=False,
            run_documents=True,
            no_download=False,
            json_mode=True,
        )

        self.assertEqual(exit_code, 0)
        mock_crawl.assert_called_once()
        mock_archive.assert_called_once()
        mock_dork.assert_called_once()

        # Check export directory
        export_folder = Path(self.temp_dir.name) / "cybercorp.io"
        self.assertTrue(export_folder.is_dir())
        self.assertTrue((export_folder / "emails.txt").exists())
        self.assertTrue((export_folder / "cloud_buckets.txt").exists())
        self.assertTrue((export_folder / "internal_network_leaks.txt").exists())
        self.assertTrue((export_folder / "crawled_urls.txt").exists())
        self.assertTrue((export_folder / "summary.txt").exists())

        # Check legacy files for backward compatibility
        self.assertTrue((Path(self.temp_dir.name) / "foca_fingerprint_cybercorp.io.json").exists())

    def test_cli_deep_and_no_archive_flags(self) -> None:
        """Verify --deep and --no-archive CLI argument parsing."""
        test_args = ["main.py", "-d", "testdomain.com", "--deep", "--no-archive"]
        with patch.object(main.sys, "argv", test_args):
            args = main.parse_arguments()
            self.assertEqual(args.domain, "testdomain.com")
            self.assertTrue(args.deep)
            self.assertTrue(args.no_archive)


if __name__ == "__main__":
    unittest.main()
