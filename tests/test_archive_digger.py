"""Unit tests for ArchiveDigger historical document extraction."""

import unittest
from unittest.mock import MagicMock, patch
import requests

from foca_core.archive_digger import ArchiveDigger
from foca_core.models import DocumentTarget


class TestArchiveDigger(unittest.TestCase):
    """Test suite for ArchiveDigger historical Wayback search."""

    def setUp(self) -> None:
        self.digger = ArchiveDigger(timeout=5)

    def test_clean_domain(self) -> None:
        self.assertEqual(self.digger._clean_domain("https://testcorp.com/path"), "testcorp.com")
        self.assertEqual(self.digger._clean_domain("http://sub.testcorp.com:443"), "sub.testcorp.com")
        self.assertEqual(self.digger._clean_domain("testcorp.com"), "testcorp.com")
        self.assertEqual(self.digger._clean_domain(""), "")

    def test_extract_filename(self) -> None:
        url1 = "https://web.archive.org/web/http://corp.com/docs/Annual%20Report.pdf"
        self.assertEqual(self.digger._extract_filename(url1, "pdf"), "Annual Report.pdf")

        url2 = "https://corp.com/download?id=123"
        self.assertEqual(self.digger._extract_filename(url2, "xlsx"), "download.xlsx")

    def test_dig_historical_documents_success(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            ["original"],
            ["http://testcorp.com/files/quarterly_results.pdf"],
            ["https://testcorp.com/assets/presentation.pptx"],
            ["https://testcorp.com/index.html"],
            ["http://testcorp.com/images/banner.png"],
            ["https://testcorp.com/data/roster.xlsx"],
            ["http://testcorp.com/files/quarterly_results.pdf"],  # Duplicate
        ]
        mock_session.get.return_value = mock_resp
        digger = ArchiveDigger(session=mock_session)

        file_types = ["pdf", "pptx", "xlsx"]
        results = digger.dig_historical_documents("testcorp.com", file_types, limit=10)

        self.assertEqual(len(results), 3)
        self.assertIsInstance(results[0], DocumentTarget)
        urls = [r.url for r in results]
        self.assertIn("http://testcorp.com/files/quarterly_results.pdf", urls)
        self.assertIn("https://testcorp.com/assets/presentation.pptx", urls)
        self.assertIn("https://testcorp.com/data/roster.xlsx", urls)
        self.assertNotIn("https://testcorp.com/index.html", urls)
        self.assertNotIn("http://testcorp.com/images/banner.png", urls)

        for target in results:
            self.assertEqual(target.source_engine, "wayback_archive")

    def test_dig_historical_documents_limit(self) -> None:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            ["original"],
            ["http://testcorp.com/doc1.pdf"],
            ["http://testcorp.com/doc2.pdf"],
            ["http://testcorp.com/doc3.pdf"],
            ["http://testcorp.com/doc4.pdf"],
        ]
        mock_session.get.return_value = mock_resp
        digger = ArchiveDigger(session=mock_session)

        results = digger.dig_historical_documents("testcorp.com", ["pdf"], limit=2)
        self.assertEqual(len(results), 2)

    def test_dig_historical_documents_empty_or_error(self) -> None:
        mock_session = MagicMock()

        # Test HTTP error status
        mock_resp_err = MagicMock()
        mock_resp_err.status_code = 503
        mock_session.get.return_value = mock_resp_err
        digger = ArchiveDigger(session=mock_session)
        self.assertEqual(digger.dig_historical_documents("testcorp.com", ["pdf"]), [])

        # Test Connection Exception
        mock_session.get.side_effect = requests.ConnectionError("Connection aborted")
        self.assertEqual(digger.dig_historical_documents("testcorp.com", ["pdf"]), [])

        # Test Invalid JSON
        mock_session.get.side_effect = None
        mock_resp_bad = MagicMock()
        mock_resp_bad.status_code = 200
        mock_resp_bad.json.side_effect = ValueError("Invalid JSON")
        mock_session.get.return_value = mock_resp_bad
        self.assertEqual(digger.dig_historical_documents("testcorp.com", ["pdf"]), [])


if __name__ == "__main__":
    unittest.main()
