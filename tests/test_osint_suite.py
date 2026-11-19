"""Comprehensive unit and integration test suite for FOCA OSINT modules and reporter."""

import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rich.console import Console

from foca_core.dns_audit import DNSAuditor
from foca_core.models import (
    DNSAuditResult,
    DocumentTarget,
    ExtractedMetadata,
    OrganizationFingerprint,
    SocialProfileResult,
    SubdomainResult,
    TechStackResult,
    WhoisResult,
)
from foca_core.reporter import FocaReporter
from foca_core.social_finder import SocialFinder
from foca_core.subdomains import SubdomainFinder
from foca_core.tech_stack import TechStackAnalyzer
from foca_core.whois_lookup import WhoisLookup
import main


class TestDNSAuditor(unittest.TestCase):
    """Test DNS enumeration, mail provider identification, SPF and DMARC extraction."""

    def setUp(self) -> None:
        self.auditor = DNSAuditor()

    @patch("dns.resolver.Resolver.resolve")
    def test_dns_audit_success(self, mock_resolve: MagicMock) -> None:
        """Verify successful query and parsing of A, AAAA, MX, NS, TXT, SPF, DMARC records."""
        def resolve_side_effect(qname, rtype):
            mock_ans = MagicMock()
            q_str = str(qname).lower()
            if rtype == "A":
                mock_ans.__iter__.return_value = ["93.184.216.34"]
            elif rtype == "AAAA":
                mock_ans.__iter__.return_value = ["2606:2800:220:1:248:1893:25c8:1946"]
            elif rtype == "MX":
                mx_record = MagicMock()
                mx_record.exchange = "aspmx.l.google.com."
                mx_record.preference = 10
                mock_ans.__iter__.return_value = [mx_record]
            elif rtype == "NS":
                mock_ans.__iter__.return_value = ["ns1.example.com.", "ns2.example.com."]
            elif rtype == "TXT":
                if "_dmarc" in q_str:
                    mock_rdata = MagicMock()
                    mock_rdata.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
                    mock_ans.__iter__.return_value = [mock_rdata]
                else:
                    mock_rdata = MagicMock()
                    mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]
                    mock_ans.__iter__.return_value = [mock_rdata]
            else:
                mock_ans.__iter__.return_value = []
            return mock_ans

        mock_resolve.side_effect = resolve_side_effect

        result = self.auditor.audit("https://example.com/docs")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.a_records, ["93.184.216.34"])
        self.assertEqual(result.aaaa_records, ["2606:2800:220:1:248:1893:25c8:1946"])
        self.assertEqual(len(result.mx_records), 1)
        self.assertEqual(result.mx_records[0]["host"], "aspmx.l.google.com")
        self.assertEqual(result.mx_records[0]["priority"], 10)
        self.assertEqual(result.mail_provider, "Google")
        self.assertIn("v=spf1 include:_spf.google.com ~all", result.spf_record)
        self.assertIn("v=DMARC1", result.dmarc_record)
        self.assertIn("ns1.example.com", result.ns_records)

    @patch("dns.resolver.Resolver.resolve")
    def test_dns_audit_missing_records(self, mock_resolve: MagicMock) -> None:
        """Verify graceful fallback when DNS records are missing or NXDOMAIN."""
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        result = self.auditor.audit("nonexistent.invalid")
        self.assertEqual(result.domain, "nonexistent.invalid")
        self.assertEqual(result.a_records, [])
        self.assertEqual(result.mx_records, [])
        self.assertIsNone(result.spf_record)
        self.assertIsNone(result.dmarc_record)
        self.assertIsNone(result.mail_provider)


class TestSubdomainFinder(unittest.TestCase):
    """Test crt.sh Certificate Transparency parsing, sanitization, and deduplication."""

    def setUp(self) -> None:
        self.finder = SubdomainFinder()

    @patch("requests.get")
    def test_subdomain_discovery_success(self, mock_get: MagicMock) -> None:
        """Verify parsing and normalization of crt.sh JSON certificates."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "api.example.com\nmail.example.com", "common_name": "example.com"},
            {"name_value": "*.dev.example.com", "common_name": "*.dev.example.com"},
            {"name_value": "admin.example.com", "common_name": "admin.example.com"},
            {"name_value": "unrelated.other.com", "common_name": "other.com"},
        ]
        mock_get.return_value = mock_response

        result = self.finder.discover("example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertIn("api.example.com", result.subdomains)
        self.assertIn("mail.example.com", result.subdomains)
        self.assertIn("dev.example.com", result.subdomains)
        self.assertIn("admin.example.com", result.subdomains)
        self.assertNotIn("unrelated.other.com", result.subdomains)
        self.assertEqual(result.total_found, len(result.subdomains))

    @patch("requests.get")
    def test_subdomain_discovery_network_failure(self, mock_get: MagicMock) -> None:
        """Verify resilient error handling when crt.sh is unreachable or returns error."""
        import requests
        mock_get.side_effect = requests.RequestException("Connection timeout")

        result = self.finder.discover("example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.total_found, 0)
        self.assertEqual(result.subdomains, [])


class TestTechStackAnalyzer(unittest.TestCase):
    """Test HTTP header inspection, web technology detection, and security header audit."""

    def setUp(self) -> None:
        self.analyzer = TechStackAnalyzer()

    @patch("requests.get")
    def test_tech_stack_detection(self, mock_get: MagicMock) -> None:
        """Verify detection of Server, Powered-By, and security headers."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.1",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "CF-Ray": "8932402139412-IAD",
        }
        mock_resp.text = "<html><body>Welcome to site</body></html>"
        mock_resp.cookies = {}
        mock_get.return_value = mock_resp

        result = self.analyzer.analyze("example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.server_banner, "nginx/1.24.0")
        self.assertEqual(result.powered_by, "PHP/8.2.1")
        self.assertTrue(result.security_headers["Strict-Transport-Security"])
        self.assertTrue(result.security_headers["X-Frame-Options"])
        self.assertTrue(result.security_headers["X-Content-Type-Options"])
        self.assertFalse(result.security_headers["Content-Security-Policy"])
        self.assertFalse(result.security_headers["Referrer-Policy"])
        self.assertIn("Nginx", result.detected_technologies)
        self.assertIn("PHP", result.detected_technologies)
        self.assertIn("Cloudflare", result.detected_technologies)

    @patch("requests.get")
    def test_tech_stack_network_failure(self, mock_get: MagicMock) -> None:
        """Verify graceful fallback on request failure."""
        import requests
        mock_get.side_effect = requests.ConnectionError("Connection refused")

        result = self.analyzer.analyze("unreachable.test")
        self.assertEqual(result.domain, "unreachable.test")
        self.assertEqual(result.status_code, 0)
        self.assertIsNone(result.server_banner)
        self.assertFalse(result.security_headers["Strict-Transport-Security"])


class TestWhoisLookup(unittest.TestCase):
    """Test RDAP whois lookup and registrar information parsing."""

    def setUp(self) -> None:
        self.whois = WhoisLookup()

    @patch("requests.get")
    def test_whois_rdap_success(self, mock_get: MagicMock) -> None:
        """Verify parsing of registrar, creation date, expiry date, and nameservers."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "MarkMonitor, Inc."],
                        ],
                    ],
                }
            ],
            "events": [
                {"eventAction": "registration", "eventDate": "1995-09-04T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-09-13T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2023-08-01T12:00:00Z"},
            ],
            "nameservers": [
                {"ldhName": "ns1.markmonitor.com"},
                {"ldhName": "ns2.markmonitor.com"},
            ],
            "status": ["clientTransferProhibited", "serverDeleteProhibited"],
        }
        mock_get.return_value = mock_resp

        result = self.whois.lookup("example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.registrar, "MarkMonitor, Inc.")
        self.assertEqual(result.creation_date, "1995-09-04T00:00:00Z")
        self.assertEqual(result.expiration_date, "2028-09-13T04:00:00Z")
        self.assertEqual(result.updated_date, "2023-08-01T12:00:00Z")
        self.assertIn("ns1.markmonitor.com", result.nameservers)
        self.assertIn("clientTransferProhibited", result.status)

    @patch("requests.get")
    def test_whois_rdap_404(self, mock_get: MagicMock) -> None:
        """Verify handling of 404 or missing RDAP entity."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = self.whois.lookup("notfound.example")
        self.assertEqual(result.domain, "notfound.example")
        self.assertIsNone(result.registrar)
        self.assertEqual(result.nameservers, [])


class TestSocialFinder(unittest.TestCase):
    """Test public social profile link discovery and extraction from homepage HTML."""

    def setUp(self) -> None:
        self.finder = SocialFinder()

    @patch("requests.get")
    def test_social_finder_success(self, mock_get: MagicMock) -> None:
        """Verify extraction of legitimate social profiles and exclusion of share links."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            '<html><body>'
            '<a href="https://twitter.com/acmecorp">Twitter</a>'
            '<a href="https://linkedin.com/company/acmecorp">LinkedIn</a>'
            '<a href="https://github.com/acme-org">GitHub</a>'
            '<a href="https://twitter.com/intent/tweet?text=CheckThis">Share Tweet</a>'
            '<a href="https://facebook.com/acmebrand">Facebook</a>'
            '</body></html>'
        )
        mock_get.return_value = mock_resp

        result = self.finder.find_profiles("acme.com")
        self.assertEqual(result.domain, "acme.com")
        self.assertIn("twitter", result.profiles)
        self.assertEqual(result.profiles["twitter"], "https://x.com/acmecorp")
        self.assertIn("linkedin", result.profiles)
        self.assertEqual(result.profiles["linkedin"], "https://www.linkedin.com/company/acmecorp")
        self.assertIn("github", result.profiles)
        self.assertEqual(result.profiles["github"], "https://github.com/acme-org")
        self.assertIn("facebook", result.profiles)


class TestReporterOSINT(unittest.TestCase):
    """Test Rich terminal rendering and JSON/CSV exports for all OSINT modules."""

    def setUp(self) -> None:
        self.console = Console(record=True, width=120)
        self.reporter = FocaReporter(console=self.console)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_render_all_osint_tables(self) -> None:
        """Verify each OSINT table renders without error and contains zero emojis."""
        # 1. DNS Audit Result
        dns_res = DNSAuditResult(
            domain="target.corp",
            a_records=["10.0.0.1"],
            aaaa_records=["2001:db8::1"],
            mx_records=[{"host": "mail.target.corp", "priority": 10}],
            ns_records=["ns1.target.corp"],
            txt_records=["v=spf1 ip4:10.0.0.0/24 -all"],
            spf_record="v=spf1 ip4:10.0.0.0/24 -all",
            dmarc_record="v=DMARC1; p=reject",
            mail_provider="Microsoft",
        )
        self.reporter.render_dns_audit(dns_res)

        # 2. Subdomain Result
        sub_res = SubdomainResult(
            domain="target.corp",
            total_found=2,
            subdomains=["vpn.target.corp", "portal.target.corp"],
        )
        self.reporter.render_subdomains(sub_res)

        # 3. Tech Stack Result
        tech_res = TechStackResult(
            domain="target.corp",
            server_banner="nginx",
            powered_by="Express",
            status_code=200,
            security_headers={
                "Strict-Transport-Security": True,
                "Content-Security-Policy": False,
                "X-Frame-Options": True,
                "X-Content-Type-Options": False,
                "Referrer-Policy": True,
            },
            detected_technologies=["Nginx", "Node.js"],
        )
        self.reporter.render_tech_stack(tech_res)

        # 4. Whois Result
        whois_res = WhoisResult(
            domain="target.corp",
            registrar="NameCheap",
            creation_date="2020-01-01",
            expiration_date="2027-01-01",
            updated_date="2024-01-01",
            nameservers=["ns1.target.corp", "ns2.target.corp"],
            status=["active"],
        )
        self.reporter.render_whois(whois_res)

        # 5. Social Profile Result
        social_res = SocialProfileResult(
            domain="target.corp",
            profiles={
                "github": "https://github.com/targetcorp",
                "linkedin": "https://linkedin.com/company/targetcorp",
            },
        )
        self.reporter.render_social_profiles(social_res)

        output_text = self.console.export_text()
        self.assertIn("target.corp", output_text)
        self.assertIn("Microsoft", output_text)
        self.assertIn("vpn.target.corp", output_text)
        self.assertIn("Strict-Transport-Security", output_text)
        self.assertIn("NameCheap", output_text)
        self.assertIn("https://github.com/targetcorp", output_text)

        # Assert zero emojis in the output text
        emoji_pattern = re.compile(
            "[\U00010000-\U0010ffff\U00002600-\U000027bf\U0000fe00-\U0000fe0f\U0000200d]"
        )
        self.assertFalse(
            bool(emoji_pattern.search(output_text)),
            "Found forbidden emoji in reporter output!",
        )

    def test_dashboard_and_export_with_osint(self) -> None:
        """Verify full dashboard synthesis, JSON serialization, and CSV generation."""
        meta = ExtractedMetadata(
            file_path="C:/docs/annual_review.pdf",
            file_type="pdf",
            author="Executive Alice",
            extracted_users=["Executive Alice"],
        )
        fingerprint = OrganizationFingerprint(
            domain="enterprise.com",
            total_files_analyzed=1,
            discovered_users=["Executive Alice"],
            documents=[meta],
            dns_audit=DNSAuditResult(domain="enterprise.com", mail_provider="Google"),
            subdomain_audit=SubdomainResult(domain="enterprise.com", total_found=1, subdomains=["vpn.enterprise.com"]),
            tech_stack=TechStackResult(domain="enterprise.com", server_banner="Apache"),
            whois_info=WhoisResult(domain="enterprise.com", registrar="GoDaddy"),
            social_profiles=SocialProfileResult(domain="enterprise.com", profiles={"twitter": "https://x.com/enterprise"}),
        )

        self.reporter.render_dashboard(fingerprint)
        rendered = self.console.export_text()
        self.assertIn("enterprise.com", rendered)
        self.assertIn("Google", rendered)
        self.assertIn("vpn.enterprise.com", rendered)

        json_out = Path(self.temp_dir.name) / "fingerprint.json"
        csv_out = Path(self.temp_dir.name) / "metadata.csv"

        self.reporter.export_json(fingerprint, str(json_out))
        self.reporter.export_csv(fingerprint, str(csv_out))

        self.assertTrue(json_out.exists())
        self.assertTrue(csv_out.exists())

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["domain"], "enterprise.com")
            self.assertEqual(data["dns_audit"]["mail_provider"], "Google")
            self.assertEqual(data["subdomain_audit"]["total_found"], 1)
            self.assertEqual(data["tech_stack"]["server_banner"], "Apache")
            self.assertEqual(data["whois_info"]["registrar"], "GoDaddy")
            self.assertEqual(data["social_profiles"]["profiles"]["twitter"], "https://x.com/enterprise")


class TestMainPipelineOSINTFlags(unittest.TestCase):
    """Test CLI arguments and execution of pipeline with OSINT modules."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @patch("foca_core.dns_audit.DNSAuditor.audit")
    def test_run_pipeline_dns_only(self, mock_dns: MagicMock) -> None:
        """Verify pipeline executes DNS audit and skips document scraping."""
        mock_dns.return_value = DNSAuditResult(domain="example.com", mail_provider="Proton")
        out_dir = self.temp_dir.name

        exit_code = main.run_pipeline(
            domain="example.com",
            output_dir_str=out_dir,
            run_dns=True,
            run_documents=False,
            json_mode=True,
        )
        self.assertEqual(exit_code, 0)
        mock_dns.assert_called_once_with("example.com")

        # Verify JSON file written
        json_file = Path(out_dir) / "foca_fingerprint_example.com.json"
        self.assertTrue(json_file.exists())
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["dns_audit"]["mail_provider"], "Proton")
            self.assertEqual(data["total_files_analyzed"], 0)

    @patch("foca_core.social_finder.SocialFinder.find_profiles")
    @patch("foca_core.whois_lookup.WhoisLookup.lookup")
    @patch("foca_core.tech_stack.TechStackAnalyzer.analyze")
    @patch("foca_core.subdomains.SubdomainFinder.discover")
    @patch("foca_core.dns_audit.DNSAuditor.audit")
    @patch("foca_core.scraper.DocumentScraper.discover")
    def test_run_pipeline_all_modules(
        self,
        mock_scrape: MagicMock,
        mock_dns: MagicMock,
        mock_sub: MagicMock,
        mock_tech: MagicMock,
        mock_whois: MagicMock,
        mock_social: MagicMock,
    ) -> None:
        """Verify --all runs all OSINT modules and document scraper."""
        mock_scrape.return_value = []
        mock_dns.return_value = DNSAuditResult(domain="corp.com")
        mock_sub.return_value = SubdomainResult(domain="corp.com")
        mock_tech.return_value = TechStackResult(domain="corp.com")
        mock_whois.return_value = WhoisResult(domain="corp.com")
        mock_social.return_value = SocialProfileResult(domain="corp.com")

        exit_code = main.run_pipeline(
            domain="corp.com",
            output_dir_str=self.temp_dir.name,
            run_dns=True,
            run_subdomains=True,
            run_tech=True,
            run_whois=True,
            run_social=True,
            run_documents=True,
            json_mode=True,
        )
        self.assertEqual(exit_code, 0)
        mock_dns.assert_called_once()
        mock_sub.assert_called_once()
        mock_tech.assert_called_once()
        mock_whois.assert_called_once()
        mock_social.assert_called_once()
        mock_scrape.assert_called_once()

    def test_cli_argument_parsing(self) -> None:
        """Test parse_arguments parses all new OSINT flags."""
        test_args = [
            "main.py",
            "-d", "example.com",
            "--dns",
            "--subdomains",
            "--tech",
            "--whois",
            "--social",
            "--all",
        ]
        with patch.object(sys, "argv", test_args):
            args = main.parse_arguments()
            self.assertEqual(args.domain, "example.com")
            self.assertTrue(args.dns)
            self.assertTrue(args.subdomains)
            self.assertTrue(args.tech)
            self.assertTrue(args.whois)
            self.assertTrue(args.social)
            self.assertTrue(args.all)


if __name__ == "__main__":
    unittest.main()
