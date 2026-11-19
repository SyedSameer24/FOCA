"""Unit tests for FOCA core models, extractor, and fingerprint analyzer using standard unittest."""

from pathlib import Path
import tempfile
import unittest
import zipfile

import fitz  # PyMuPDF
from PIL import Image

from foca_core.analyzer import FingerprintAnalyzer
from foca_core.extractor import MetadataExtractor
from foca_core.models import (
    DocumentTarget,
    ExtractedMetadata,
    OrganizationFingerprint,
)


class TestFocaCore(unittest.TestCase):
    """Test suite for FOCA models, metadata extractor, and fingerprint analyzer."""

    def test_models_validation_and_serialization(self):
        """Verify models instantiate correctly and coerce sets to sorted lists."""
        target = DocumentTarget(
            url="https://example.com/files/doc.pdf",
            filename="doc.pdf",
            file_type="pdf",
            source_engine="google",
            local_path="/tmp/doc.pdf",
            size_bytes=1024,
            status="downloaded",
        )
        self.assertEqual(target.filename, "doc.pdf")
        self.assertEqual(target.status, "downloaded")

        meta = ExtractedMetadata(
            file_path="/tmp/test.docx",
            file_type="docx",
            author="Alice Smith",
            extracted_users={"asmith", "alice"},  # passing set
            extracted_emails={"alice@example.com"},
            extracted_paths={"C:\\Users\\asmith\\report.docx"},
            extracted_printers={"HP LaserJet Pro"},
        )
        self.assertIsInstance(meta.extracted_users, list)
        self.assertEqual(meta.extracted_users, ["alice", "asmith"])
        self.assertEqual(meta.extracted_emails, ["alice@example.com"])

        fingerprint = OrganizationFingerprint(
            domain="example.com",
            discovered_users={"asmith", "bjones", "asmith"},
            discovered_printers={"HP LaserJet Pro"},
            discovered_paths={"C:\\Users\\asmith"},
            discovered_emails={"asmith@example.com"},
            documents=[meta],
        )
        self.assertEqual(fingerprint.discovered_users, ["asmith", "bjones"])
        data = fingerprint.to_dict()
        self.assertIsInstance(data["discovered_users"], list)
        self.assertEqual(data["discovered_users"], ["asmith", "bjones"])
        json_str = fingerprint.to_json()
        self.assertIn("example.com", json_str)
        self.assertIn("asmith", json_str)

    def test_pdf_extraction(self):
        """Verify PDF extraction extracts title, author, producer, creator using PyMuPDF."""
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "sample.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((50, 72), "Confidential corporate report.")
            doc.set_metadata({
                "title": "Quarterly Financial Analysis",
                "author": "Marcus Aurelius",
                "creator": "Adobe InDesign 18.0",
                "producer": "Adobe PDF Library 15.0",
                "subject": "Financials",
                "keywords": "finance, audit, Q3",
            })
            doc.save(str(pdf_path))
            doc.close()

            extractor = MetadataExtractor()
            meta = extractor.extract(str(pdf_path))

            self.assertEqual(meta.file_type, "pdf")
            self.assertEqual(meta.title, "Quarterly Financial Analysis")
            self.assertEqual(meta.author, "Marcus Aurelius")
            self.assertEqual(meta.creator_tool, "Adobe InDesign 18.0")
            self.assertEqual(meta.producer, "Adobe PDF Library 15.0")
            self.assertEqual(meta.raw_properties.get("subject"), "Financials")
            self.assertEqual(meta.raw_properties.get("pdf_engine"), "PyMuPDF")

    def test_pdf_pypdf2_fallback(self):
        """Verify fallback to PyPDF2 when PyMuPDF open fails."""
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "sample_fallback.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((50, 72), "Fallback test content.")
            doc.set_metadata({
                "title": "Fallback Title",
                "author": "Fallback Author",
                "creator": "Fallback Creator",
            })
            doc.save(str(pdf_path))
            doc.close()

            with patch("fitz.open", side_effect=RuntimeError("Simulated fitz failure")):
                extractor = MetadataExtractor()
                meta = extractor.extract(str(pdf_path))
                self.assertEqual(meta.file_type, "pdf")
                self.assertEqual(meta.raw_properties.get("pdf_engine"), "PyPDF2")
                self.assertEqual(meta.author, "Fallback Author")

    def test_ooxml_extraction(self):
        """Verify OOXML extraction safely inspects docProps/core.xml and app.xml."""
        with tempfile.TemporaryDirectory() as temp_dir:
            docx_path = Path(temp_dir) / "sample.docx"

            core_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                               xmlns:dc="http://purl.org/dc/elements/1.1/"
                               xmlns:dcterms="http://purl.org/dc/terms/">
                <dc:title>Internal Network Architecture</dc:title>
                <dc:creator>John Doe</dc:creator>
                <cp:lastModifiedBy>Jane Admin</cp:lastModifiedBy>
                <dcterms:created>2026-03-01T10:00:00Z</dcterms:created>
                <dcterms:modified>2026-03-02T15:30:00Z</dcterms:modified>
                <dc:subject>Engineering Guidelines</dc:subject>
            </cp:coreProperties>"""

            app_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
                <Application>Microsoft Office Word</Application>
                <AppVersion>16.0000</AppVersion>
                <Company>Acme Corporation</Company>
                <Manager>Director Bob</Manager>
                <Template>Normal.dotm</Template>
                <TotalTime>45</TotalTime>
            </Properties>"""

            with zipfile.ZipFile(docx_path, "w") as zf:
                zf.writestr("docProps/core.xml", core_xml)
                zf.writestr("docProps/app.xml", app_xml)
                zf.writestr("word/document.xml", b"<w:document/>")

            extractor = MetadataExtractor()
            meta = extractor.extract(str(docx_path))

            self.assertEqual(meta.file_type, "docx")
            self.assertEqual(meta.title, "Internal Network Architecture")
            self.assertEqual(meta.author, "John Doe")
            self.assertEqual(meta.creator_tool, "Microsoft Office Word")
            self.assertEqual(meta.company, "Acme Corporation")
            self.assertEqual(meta.creation_date, "2026-03-01T10:00:00Z")
            self.assertEqual(meta.modification_date, "2026-03-02T15:30:00Z")
            self.assertEqual(meta.raw_properties.get("last_modified_by"), "Jane Admin")
            self.assertEqual(meta.raw_properties.get("manager"), "Director Bob")
            self.assertEqual(meta.raw_properties.get("app_version"), "16.0000")

    def test_image_exif_extraction(self):
        """Verify Image EXIF extraction works for tags like Software, Artist, Make, Model."""
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = Path(temp_dir) / "photo.jpg"
            img = Image.new("RGB", (100, 100), color="blue")
            exif = img.getexif()
            exif[0x0131] = "Adobe Photoshop 24.1"  # Software
            exif[0x013B] = "Sarah Connor"  # Artist
            exif[0x010F] = "Canon"  # Make
            exif[0x0110] = "Canon EOS 5D"  # Model
            exif[0x0132] = "2026:01:15 14:22:10"  # DateTime
            img.save(str(img_path), exif=exif)

            extractor = MetadataExtractor()
            meta = extractor.extract(str(img_path))

            self.assertEqual(meta.file_type, "jpg")
            self.assertEqual(meta.author, "Sarah Connor")
            self.assertEqual(meta.creator_tool, "Adobe Photoshop 24.1")
            self.assertEqual(meta.creation_date, "2026:01:15 14:22:10")
            self.assertEqual(meta.raw_properties.get("camera_make"), "Canon")
            self.assertEqual(meta.raw_properties.get("camera_model"), "Canon EOS 5D")

    def test_extractor_error_handling(self):
        """Verify defensive handling of missing or corrupted files."""
        extractor = MetadataExtractor()

        # Missing file
        meta_missing = extractor.extract("non_existent_file.pdf")
        self.assertIn("error", meta_missing.raw_properties)

        # Corrupt zip/docx
        with tempfile.TemporaryDirectory() as temp_dir:
            corrupt_docx = Path(temp_dir) / "corrupt.docx"
            corrupt_docx.write_bytes(b"NOT A REAL ZIP FILE CONTENT")
            meta_corrupt = extractor.extract(str(corrupt_docx))
            self.assertIn("error", meta_corrupt.raw_properties)

    def test_analyzer_session_heuristics(self):
        """Verify analyzer extracts users, paths, operating systems, printers, and emails."""
        meta1 = ExtractedMetadata(
            file_path="C:\\Reports\\Doc1.docx",
            file_type="docx",
            author="Johnathan Doe",
            creator_tool="Microsoft Office Word 2016 for Windows",
            company="Initech Global",
            raw_properties={
                "last_modified_by": "Bill Lumbergh",
                "manager": "Peter Gibbons",
                "path_notes": "Saved at C:\\Users\\jdoe\\Documents\\TPS_Reports\\report.docx",
                "printer": "Printed via \\\\print01.initech.local\\hplaserjet_exec",
                "notes": "Sent from pgibbons@initech.com to jdoe@initech.com",
            },
        )

        meta2 = ExtractedMetadata(
            file_path="/opt/data/mac_doc.pdf",
            file_type="pdf",
            author="Milton Waddams",
            creator_tool="Pages for Mac",
            producer="macOS Quartz PDFContext",
            raw_properties={
                "local_path": "/Users/miltonw/Library/Documents/stapler.pdf",
                "email_footer": "support@initech.com",
                "driver": "PScript5.dll Version 5.2.2",
                "hardware": "Canon imageRUNNER 3245",
            },
        )

        meta3 = ExtractedMetadata(
            file_path="/var/www/linux_report.pdf",
            file_type="pdf",
            author="Linux Admin",
            creator_tool="CUPS 2.4.2",
            producer="GPL Ghostscript 9.55",
            raw_properties={
                "source_dir": "/home/sysadmin/scripts/generate.sh",
            },
        )

        analyzer = FingerprintAnalyzer()
        fingerprint = analyzer.analyze_session(
            domain="initech.com",
            metadata_list=[meta1, meta2, meta3],
        )

        self.assertEqual(fingerprint.domain, "initech.com")
        self.assertEqual(fingerprint.total_files_analyzed, 3)

        # Check discovered users
        users = fingerprint.discovered_users
        self.assertTrue("Johnathan Doe" in users or "jdoe" in users)
        self.assertIn("Bill Lumbergh", users)
        self.assertTrue("Peter Gibbons" in users or "pgibbons" in users)
        self.assertTrue("Milton Waddams" in users or "miltonw" in users)
        self.assertIn("sysadmin", users)
        # Filtered usernames should NOT be present
        self.assertNotIn("administrator", [u.lower() for u in users])
        self.assertNotIn("admin", [u.lower() for u in users])

        # Check operating systems
        os_detected = fingerprint.discovered_operating_systems
        self.assertIn("Windows", os_detected)
        self.assertIn("macOS", os_detected)
        self.assertIn("Linux", os_detected)

        # Check emails
        emails = fingerprint.discovered_emails
        self.assertIn("jdoe@initech.com", emails)
        self.assertIn("pgibbons@initech.com", emails)
        self.assertIn("support@initech.com", emails)

        # Check printers
        printers = fingerprint.discovered_printers
        self.assertTrue(any("print01" in p or "laserjet" in p.lower() for p in printers))
        self.assertTrue(any("pscript5" in p.lower() for p in printers))
        self.assertTrue(any("canon" in p.lower() for p in printers))

        # Check discovered paths
        paths = fingerprint.discovered_paths
        self.assertTrue(any("C:\\Users\\jdoe" in p for p in paths))
        self.assertTrue(any("/Users/miltonw" in p for p in paths))
        self.assertTrue(any("/home/sysadmin" in p for p in paths))


if __name__ == "__main__":
    unittest.main()
