"""Unit tests for FOCA OSINT modules: DNSAudit, Subdomains, TechStack, Whois, and SocialFinder."""

import unittest
from unittest.mock import MagicMock, patch

from foca_core import (
    DNSAuditResult,
    DNSAuditor,
    OrganizationFingerprint,
    SocialFinder,
    SocialProfileResult,
    SubdomainFinder,
    SubdomainResult,
    TechStackAnalyzer,
    TechStackResult,
    WhoisLookup,
    WhoisResult,
)


class TestOSINTModels(unittest.TestCase):
    """Test Pydantic model definitions, validations, and serialization."""

    def test_dns_audit_result_defaults(self) -> None:
        result = DNSAuditResult(domain="example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.a_records, [])
        self.assertEqual(result.mx_records, [])
        self.assertIsNone(result.spf_record)
        self.assertIsNone(result.mail_provider)

    def test_subdomain_result_model(self) -> None:
        result = SubdomainResult(
            domain="example.com",
            total_found=2,
            subdomains=["a.example.com", "b.example.com"],
        )
        self.assertEqual(result.total_found, 2)
        self.assertEqual(len(result.subdomains), 2)

    def test_tech_stack_result_model(self) -> None:
        result = TechStackResult(
            domain="example.com",
            server_banner="nginx/1.18.0",
            status_code=200,
            security_headers={"Strict-Transport-Security": True},
            detected_technologies=["Nginx"],
        )
        self.assertEqual(result.server_banner, "nginx/1.18.0")
        self.assertTrue(result.security_headers["Strict-Transport-Security"])
        self.assertIn("Nginx", result.detected_technologies)

    def test_whois_result_model(self) -> None:
        result = WhoisResult(
            domain="example.com",
            registrar="MarkMonitor",
            status=["clientTransferProhibited"],
        )
        self.assertEqual(result.registrar, "MarkMonitor")
        self.assertEqual(result.status, ["clientTransferProhibited"])

    def test_social_profile_result_model(self) -> None:
        result = SocialProfileResult(
            domain="example.com",
            profiles={"twitter": "https://x.com/example"},
        )
        self.assertEqual(result.profiles["twitter"], "https://x.com/example")

    def test_organization_fingerprint_with_osint_fields(self) -> None:
        fingerprint = OrganizationFingerprint(
            domain="example.com",
            dns_audit=DNSAuditResult(domain="example.com", mail_provider="Google"),
            subdomain_audit=SubdomainResult(domain="example.com", total_found=1, subdomains=["mail.example.com"]),
            tech_stack=TechStackResult(domain="example.com", status_code=200),
            whois_info=WhoisResult(domain="example.com", registrar="Example Registrar"),
            social_profiles=SocialProfileResult(domain="example.com", profiles={"github": "https://github.com/example"}),
        )
        data = fingerprint.to_dict()
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["dns_audit"]["mail_provider"], "Google")
        self.assertEqual(data["subdomain_audit"]["total_found"], 1)
        self.assertEqual(data["tech_stack"]["status_code"], 200)
        self.assertEqual(data["whois_info"]["registrar"], "Example Registrar")
        self.assertEqual(data["social_profiles"]["profiles"]["github"], "https://github.com/example")

        json_str = fingerprint.to_json()
        self.assertIn("Example Registrar", json_str)


class TestDNSAuditor(unittest.TestCase):
    """Test DNSAuditor querying and parsing logic."""

    def test_normalize_domain(self) -> None:
        auditor = DNSAuditor()
        self.assertEqual(auditor._normalize_domain("https://example.com/test"), "example.com")
        self.assertEqual(auditor._normalize_domain("HTTP://SUB.EXAMPLE.COM:8080/"), "sub.example.com")
        self.assertEqual(auditor._normalize_domain("example.com."), "example.com")

    def test_mail_provider_detection(self) -> None:
        auditor = DNSAuditor()
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "aspmx.l.google.com", "priority": 1}]),
            "Google",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "company-com.mail.protection.outlook.com", "priority": 10}]),
            "Microsoft",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "mail.protonmail.ch", "priority": 10}]),
            "Proton",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "mx.zoho.com", "priority": 10}]),
            "Zoho",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "mail.messagingengine.com", "priority": 10}]),
            "Fastmail",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "inbound-smtp.us-east-1.amazonaws.com", "priority": 10}]),
            "AWS",
        )
        self.assertEqual(
            auditor._detect_mail_provider([{"host": "mail.internalcorp.local", "priority": 10}]),
            "Private",
        )
        self.assertIsNone(auditor._detect_mail_provider([]))

    def test_extract_spf(self) -> None:
        auditor = DNSAuditor()
        records = ["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"]
        self.assertEqual(auditor._extract_spf(records), "v=spf1 include:_spf.google.com ~all")
        self.assertIsNone(auditor._extract_spf(["random text"]))

    @patch("dns.resolver.Resolver.resolve")
    def test_audit_mocked(self, mock_resolve: MagicMock) -> None:
        def side_effect(qname: str, rtype: str) -> Any:
            mock_answer = MagicMock()
            if rtype == "A":
                mock_item = MagicMock()
                mock_item.__str__.return_value = "93.184.216.34"
                mock_answer.__iter__.return_value = [mock_item]
                return mock_answer
            elif rtype == "MX":
                mock_item = MagicMock()
                mock_item.exchange = "mail.protection.outlook.com."
                mock_item.preference = 10
                mock_answer.__iter__.return_value = [mock_item]
                return mock_answer
            elif rtype == "TXT":
                mock_item = MagicMock()
                mock_item.strings = [b"v=spf1 -all"]
                mock_answer.__iter__.return_value = [mock_item]
                return mock_answer
            raise Exception("No record")

        mock_resolve.side_effect = side_effect

        auditor = DNSAuditor()
        res = auditor.audit("example.com")
        self.assertEqual(res.domain, "example.com")
        self.assertEqual(res.a_records, ["93.184.216.34"])
        self.assertEqual(res.mail_provider, "Microsoft")
        self.assertEqual(res.spf_record, "v=spf1 -all")


class TestSubdomainFinder(unittest.TestCase):
    """Test SubdomainFinder extraction and network error handling."""

    def test_extract_from_field(self) -> None:
        finder = SubdomainFinder()
        collected: set[str] = set()

        raw_text = "*.dev.example.com\napi.example.com\nexample.com\nattacker.otherdomain.com"
        finder._extract_from_field(raw_text, "example.com", collected)

        self.assertIn("dev.example.com", collected)
        self.assertIn("api.example.com", collected)
        self.assertIn("example.com", collected)
        self.assertNotIn("attacker.otherdomain.com", collected)

    @patch("requests.get")
    def test_discover_mocked_success(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "portal.example.com\n*.vpn.example.com", "common_name": "example.com"},
            {"name_value": "mail.example.com", "common_name": "mail.example.com"},
        ]
        mock_get.return_value = mock_response

        finder = SubdomainFinder()
        res = finder.discover("example.com")
        self.assertEqual(res.domain, "example.com")
        self.assertEqual(res.total_found, 4)
        self.assertEqual(res.subdomains, ["example.com", "mail.example.com", "portal.example.com", "vpn.example.com"])

    @patch("requests.get", side_effect=Exception("Network down"))
    def test_discover_resilience_on_failure(self, mock_get: MagicMock) -> None:
        finder = SubdomainFinder()
        res = finder.discover("example.com")
        self.assertEqual(res.domain, "example.com")
        self.assertEqual(res.total_found, 0)
        self.assertEqual(res.subdomains, [])


class TestTechStackAnalyzer(unittest.TestCase):
    """Test TechStackAnalyzer headers and technology detection."""

    def test_detect_technologies(self) -> None:
        analyzer = TechStackAnalyzer()
        cookies = MagicMock()
        cookies.__iter__.return_value = []

        headers = {
            "server": "cloudflare",
            "cf-ray": "12345678",
            "strict-transport-security": "max-age=31536000",
        }
        techs = analyzer._detect_technologies("cloudflare", None, headers, cookies)
        self.assertIn("Cloudflare", techs)

        # Microsoft IIS + ASP.NET
        techs_ms = analyzer._detect_technologies("Microsoft-IIS/10.0", "ASP.NET", {"x-aspnet-version": "4.0"}, cookies)
        self.assertIn("IIS", techs_ms)
        self.assertIn("ASP.NET", techs_ms)

        # LiteSpeed
        techs_ls = analyzer._detect_technologies("LiteSpeed", None, {}, cookies)
        self.assertIn("LiteSpeed", techs_ls)

        # Vercel
        techs_vercel = analyzer._detect_technologies("Vercel", None, {"x-vercel-id": "xyz"}, cookies)
        self.assertIn("Vercel", techs_vercel)

        # Netlify
        techs_netlify = analyzer._detect_technologies("Netlify", None, {"x-nf-request-id": "abc"}, cookies)
        self.assertIn("Netlify", techs_netlify)

    @patch("requests.get")
    def test_analyze_mocked(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "nginx/1.21",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        mock_response.cookies = MagicMock()
        mock_response.cookies.__iter__.return_value = []
        mock_get.return_value = mock_response

        analyzer = TechStackAnalyzer()
        res = analyzer.analyze("example.com")

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.server_banner, "nginx/1.21")
        self.assertTrue(res.security_headers["Strict-Transport-Security"])
        self.assertTrue(res.security_headers["X-Frame-Options"])
        self.assertTrue(res.security_headers["X-Content-Type-Options"])
        self.assertFalse(res.security_headers["Content-Security-Policy"])
        self.assertIn("Nginx", res.detected_technologies)


class TestWhoisLookup(unittest.TestCase):
    """Test WhoisLookup RDAP parsing and resilience."""

    def test_parse_rdap_response(self) -> None:
        lookup = WhoisLookup()
        data = {
            "status": ["active", "clientTransferProhibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
            ],
            "nameservers": [
                {"ldhName": "ns1.example.com"},
                {"ldhName": "ns2.example.com"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Top Level Registrar, Inc."],
                        ],
                    ],
                }
            ],
        }

        res = lookup._parse_rdap_response("example.com", data)
        self.assertEqual(res.domain, "example.com")
        self.assertEqual(res.registrar, "Top Level Registrar, Inc.")
        self.assertEqual(res.creation_date, "2010-01-01T00:00:00Z")
        self.assertEqual(res.expiration_date, "2030-01-01T00:00:00Z")
        self.assertEqual(res.updated_date, "2024-01-01T00:00:00Z")
        self.assertEqual(res.nameservers, ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(res.status, ["active", "clientTransferProhibited"])

    @patch("requests.get", side_effect=Exception("Timeout"))
    def test_lookup_resilience_on_error(self, mock_get: MagicMock) -> None:
        lookup = WhoisLookup()
        res = lookup.lookup("example.com")
        self.assertEqual(res.domain, "example.com")
        self.assertIsNone(res.registrar)
        self.assertEqual(res.nameservers, [])


class TestSocialFinder(unittest.TestCase):
    """Test SocialFinder link extraction and share-url filtering."""

    def test_extract_social_links(self) -> None:
        finder = SocialFinder()
        html = """
        <html>
        <body>
            <a href="https://twitter.com/intent/tweet?text=Share+This">Tweet</a>
            <a href="https://twitter.com/SecurityFOCA">Official Twitter</a>
            <a href="https://www.linkedin.com/sharing/share-offsite/?url=http://example.com">Share</a>
            <a href="https://linkedin.com/company/foca-project/">LinkedIn Page</a>
            <a href="https://github.com/FOCA-Sec">GitHub Org</a>
            <a href="https://github.com/pricing">Pricing (Ignored)</a>
            <a href="https://youtube.com/@FOCAChannel">YouTube Channel</a>
            <a href="https://facebook.com/sharer.php?u=example.com">FB Share</a>
            <a href="https://www.facebook.com/FOCASecurity">FB Page</a>
            <a href="https://www.instagram.com/foca_sec/">IG Page</a>
        </body>
        </html>
        """
        profiles = finder._extract_social_links(html)
        self.assertEqual(profiles["twitter"], "https://x.com/SecurityFOCA")
        self.assertEqual(profiles["linkedin"], "https://www.linkedin.com/company/foca-project")
        self.assertEqual(profiles["github"], "https://github.com/FOCA-Sec")
        self.assertEqual(profiles["youtube"], "https://www.youtube.com/@FOCAChannel")
        self.assertEqual(profiles["facebook"], "https://www.facebook.com/FOCASecurity")
        self.assertEqual(profiles["instagram"], "https://www.instagram.com/foca_sec")

    @patch("requests.get", side_effect=Exception("Failed"))
    def test_find_profiles_resilience_on_failure(self, mock_get: MagicMock) -> None:
        finder = SocialFinder()
        res = finder.find_profiles("example.com")
        self.assertEqual(res.domain, "example.com")
        self.assertEqual(res.profiles, {})


if __name__ == "__main__":
    unittest.main()
