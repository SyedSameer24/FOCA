"""Metadata extraction engine for PDF, OOXML documents, and image formats."""

import os
from pathlib import Path
from typing import Any, Optional
import zipfile

import defusedxml.ElementTree as ET
from PIL import ExifTags, Image

from foca_core.models import ExtractedMetadata

# Maximum bounds for OOXML zip inspection to mitigate zip bombs / malicious archives
MAX_OOXML_FILE_SIZE = 100 * 1024 * 1024  # 100 MB on disk
MAX_OOXML_UNCOMPRESSED_SIZE = 250 * 1024 * 1024  # 250 MB total extracted size
MAX_OOXML_MEMBER_COUNT = 5000


class MetadataExtractor:
    """Unified metadata extraction engine with defensive format dispatchers."""

    PDF_EXTENSIONS = {".pdf"}
    OOXML_EXTENSIONS = {
        ".docx",
        ".docm",
        ".dotx",
        ".dotm",
        ".xlsx",
        ".xlsm",
        ".xltx",
        ".xltm",
        ".pptx",
        ".pptm",
        ".potx",
        ".potm",
    }
    IMAGE_EXTENSIONS = {
        ".jpg",
        ".jpeg",
        ".png",
        ".tiff",
        ".tif",
        ".webp",
    }

    def __init__(self, max_file_size_bytes: int = MAX_OOXML_FILE_SIZE) -> None:
        self.max_file_size_bytes = max_file_size_bytes

    def extract(self, file_path: str) -> ExtractedMetadata:
        """Extract metadata from the target file, safely handling errors and missing fields.

        Args:
            file_path: Absolute or relative filesystem path to the target document.

        Returns:
            ExtractedMetadata object containing normalized attributes and raw properties.
        """
        path = Path(file_path).resolve()
        ext = path.suffix.lower()

        if not path.is_file():
            return ExtractedMetadata(
                file_path=str(path),
                file_type=ext.lstrip(".") or "unknown",
                raw_properties={"error": f"File does not exist or is not a regular file: {path}"},
            )

        try:
            file_size = path.stat().st_size
        except OSError as e:
            return ExtractedMetadata(
                file_path=str(path),
                file_type=ext.lstrip(".") or "unknown",
                raw_properties={"error": f"Failed to read file stats: {e}"},
            )

        if file_size > self.max_file_size_bytes:
            return ExtractedMetadata(
                file_path=str(path),
                file_type=ext.lstrip(".") or "unknown",
                raw_properties={
                    "error": (
                        f"File size {file_size} bytes exceeds maximum limit "
                        f"{self.max_file_size_bytes} bytes."
                    )
                },
            )

        try:
            if ext in self.PDF_EXTENSIONS:
                return self._extract_pdf(path, ext)
            elif ext in self.OOXML_EXTENSIONS:
                return self._extract_ooxml(path, ext)
            elif ext in self.IMAGE_EXTENSIONS:
                return self._extract_image(path, ext)
            else:
                return self._extract_generic(path, ext)
        except Exception as e:
            return ExtractedMetadata(
                file_path=str(path),
                file_type=ext.lstrip(".") or "unknown",
                raw_properties={"error": f"Unhandled extraction exception: {type(e).__name__}: {e}"},
            )

    def _extract_pdf(self, path: Path, ext: str) -> ExtractedMetadata:
        """Extract metadata from PDF files using PyMuPDF (fitz) with PyPDF2 fallback."""
        raw_props: dict[str, Any] = {"file_size_bytes": path.stat().st_size}
        author: Optional[str] = None
        creator: Optional[str] = None
        producer: Optional[str] = None
        creation_date: Optional[str] = None
        mod_date: Optional[str] = None
        title: Optional[str] = None
        company: Optional[str] = None

        fitz_available = False
        try:
            import fitz  # PyMuPDF

            fitz_available = True
            doc = fitz.open(str(path))
            meta = doc.metadata or {}
            raw_props["pdf_engine"] = "PyMuPDF"
            raw_props["format"] = meta.get("format")
            raw_props["subject"] = meta.get("subject")
            raw_props["keywords"] = meta.get("keywords")
            raw_props["page_count"] = doc.page_count

            title = meta.get("title") or None
            author = meta.get("author") or None
            creator = meta.get("creator") or None
            producer = meta.get("producer") or None
            creation_date = meta.get("creationDate") or None
            mod_date = meta.get("modDate") or None

            # Attempt to extract XML/XMP metadata if available
            try:
                xmp_data = doc.get_xml_metadata()
                if xmp_data:
                    raw_props["xmp_metadata_bytes"] = len(xmp_data)
                    self._parse_pdf_xmp(xmp_data, raw_props)
            except Exception as xmp_err:
                raw_props["xmp_parse_error"] = str(xmp_err)

            doc.close()
        except Exception as fitz_err:
            raw_props["fitz_error"] = str(fitz_err)

        if not fitz_available or raw_props.get("fitz_error"):
            # Fallback to PyPDF2
            try:
                from PyPDF2 import PdfReader

                reader = PdfReader(str(path))
                raw_props["pdf_engine"] = "PyPDF2"
                raw_props["page_count"] = len(reader.pages)
                info = reader.metadata
                if info:
                    title = title or getattr(info, "title", None) or info.get("/Title")
                    author = author or getattr(info, "author", None) or info.get("/Author")
                    creator = creator or getattr(info, "creator", None) or info.get("/Creator")
                    producer = producer or getattr(info, "producer", None) or info.get("/Producer")
                    creation_date = (
                        creation_date
                        or getattr(info, "creation_date", None)
                        or info.get("/CreationDate")
                    )
                    mod_date = (
                        mod_date
                        or getattr(info, "modification_date", None)
                        or info.get("/ModDate")
                    )
                    company = company or info.get("/Company")
                    raw_props["subject"] = raw_props.get("subject") or info.get("/Subject")
                    raw_props["keywords"] = raw_props.get("keywords") or info.get("/Keywords")
                    for k, v in info.items():
                        if str(k).startswith("/") and str(k) not in raw_props:
                            raw_props[f"pypdf_{k.lstrip('/')}"] = str(v)
            except Exception as pypdf_err:
                raw_props["pypdf_error"] = str(pypdf_err)

        return ExtractedMetadata(
            file_path=str(path),
            file_type="pdf",
            author=author,
            creator_tool=creator,
            producer=producer,
            creation_date=str(creation_date) if creation_date else None,
            modification_date=str(mod_date) if mod_date else None,
            company=company,
            title=title,
            raw_properties=raw_props,
        )

    def _parse_pdf_xmp(self, xmp_str: str, raw_props: dict[str, Any]) -> None:
        """Safely parse XMP XML packet and extract known organizational properties."""
        try:
            root = ET.fromstring(xmp_str)
            for elem in root.iter():
                tag_local = elem.tag.split("}")[-1].lower()
                text = (elem.text or "").strip()
                if not text:
                    continue
                if tag_local in {"company", "organization"}:
                    raw_props["xmp_company"] = text
                elif tag_local in {"creator", "author"}:
                    raw_props["xmp_creator"] = text
                elif tag_local in {"creatortool", "software"}:
                    raw_props["xmp_creator_tool"] = text
                elif tag_local in {"producer"}:
                    raw_props["xmp_producer"] = text
                elif tag_local in {"modifydate"}:
                    raw_props["xmp_modify_date"] = text
                elif tag_local in {"createdate"}:
                    raw_props["xmp_create_date"] = text
        except Exception as e:
            raw_props["xmp_xml_error"] = str(e)

    def _extract_ooxml(self, path: Path, ext: str) -> ExtractedMetadata:
        """Safely inspect OOXML archive without disk extraction and parse docProps."""
        raw_props: dict[str, Any] = {"file_size_bytes": path.stat().st_size}
        author: Optional[str] = None
        creator_tool: Optional[str] = None
        producer: Optional[str] = None
        creation_date: Optional[str] = None
        mod_date: Optional[str] = None
        company: Optional[str] = None
        title: Optional[str] = None

        try:
            if not zipfile.is_zipfile(path):
                raw_props["error"] = "Invalid ZIP/OOXML container structure"
                return ExtractedMetadata(
                    file_path=str(path),
                    file_type=ext.lstrip("."),
                    raw_properties=raw_props,
                )

            with zipfile.ZipFile(path, mode="r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_OOXML_MEMBER_COUNT:
                    raw_props["error"] = f"Archive member count {len(infolist)} exceeds threshold"
                    return ExtractedMetadata(
                        file_path=str(path),
                        file_type=ext.lstrip("."),
                        raw_properties=raw_props,
                    )

                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > MAX_OOXML_UNCOMPRESSED_SIZE:
                    raw_props["error"] = (
                        f"Uncompressed archive size {total_uncompressed} bytes "
                        f"exceeds limit {MAX_OOXML_UNCOMPRESSED_SIZE}"
                    )
                    return ExtractedMetadata(
                        file_path=str(path),
                        file_type=ext.lstrip("."),
                        raw_properties=raw_props,
                    )

                namelist = set(zf.namelist())

                # Parse docProps/core.xml
                core_file = next(
                    (name for name in namelist if name.lower() == "docprops/core.xml"),
                    None,
                )
                if core_file:
                    try:
                        core_data = zf.read(core_file)
                        root = ET.fromstring(core_data)
                        for elem in root.iter():
                            tag = elem.tag.split("}")[-1]
                            val = (elem.text or "").strip()
                            if not val:
                                continue
                            if tag == "creator":
                                author = val
                            elif tag == "lastModifiedBy":
                                raw_props["last_modified_by"] = val
                            elif tag == "created":
                                creation_date = val
                            elif tag == "modified":
                                mod_date = val
                            elif tag == "title":
                                title = val
                            elif tag == "subject":
                                raw_props["subject"] = val
                            elif tag == "description":
                                raw_props["description"] = val
                            elif tag == "keywords":
                                raw_props["keywords"] = val
                            elif tag == "revision":
                                raw_props["revision"] = val
                    except Exception as err:
                        raw_props["core_xml_error"] = str(err)

                # Parse docProps/app.xml
                app_file = next(
                    (name for name in namelist if name.lower() == "docprops/app.xml"),
                    None,
                )
                if app_file:
                    try:
                        app_data = zf.read(app_file)
                        root = ET.fromstring(app_data)
                        for elem in root.iter():
                            tag = elem.tag.split("}")[-1]
                            val = (elem.text or "").strip()
                            if not val:
                                continue
                            if tag == "Application":
                                creator_tool = val
                            elif tag == "AppVersion":
                                raw_props["app_version"] = val
                            elif tag == "Company":
                                company = val
                            elif tag == "Manager":
                                raw_props["manager"] = val
                            elif tag == "Template":
                                raw_props["template"] = val
                            elif tag == "TotalTime":
                                raw_props["total_time_minutes"] = val
                    except Exception as err:
                        raw_props["app_xml_error"] = str(err)

                # Parse docProps/custom.xml if available
                custom_file = next(
                    (name for name in namelist if name.lower() == "docprops/custom.xml"),
                    None,
                )
                if custom_file:
                    try:
                        custom_data = zf.read(custom_file)
                        root = ET.fromstring(custom_data)
                        custom_props: dict[str, str] = {}
                        for prop in root.iter():
                            name = prop.attrib.get("name")
                            if name:
                                val = "".join(prop.itertext()).strip()
                                if val:
                                    custom_props[name] = val
                        if custom_props:
                            raw_props["custom_properties"] = custom_props
                    except Exception as err:
                        raw_props["custom_xml_error"] = str(err)

        except zipfile.BadZipFile as bzf:
            raw_props["error"] = f"Corrupted or invalid zip file: {bzf}"
        except Exception as e:
            raw_props["error"] = f"OOXML extraction failure: {e}"

        return ExtractedMetadata(
            file_path=str(path),
            file_type=ext.lstrip("."),
            author=author,
            creator_tool=creator_tool,
            producer=producer,
            creation_date=creation_date,
            modification_date=mod_date,
            company=company,
            title=title,
            raw_properties=raw_props,
        )

    def _extract_image(self, path: Path, ext: str) -> ExtractedMetadata:
        """Extract EXIF, software, and device parameters from supported image formats."""
        raw_props: dict[str, Any] = {"file_size_bytes": path.stat().st_size}
        author: Optional[str] = None
        creator_tool: Optional[str] = None
        creation_date: Optional[str] = None
        mod_date: Optional[str] = None
        title: Optional[str] = None

        try:
            with Image.open(path) as img:
                raw_props["image_format"] = img.format
                raw_props["image_mode"] = img.mode
                raw_props["image_dimensions"] = f"{img.width}x{img.height}"

                exif_data = img.getexif()
                if exif_data:
                    for tag_id, val in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        if isinstance(val, bytes):
                            try:
                                val = val.decode("utf-8", errors="ignore").strip("\x00")
                            except Exception:
                                val = repr(val)
                        if isinstance(val, (int, float, str)):
                            raw_props[f"exif_{tag_name}"] = val

                        tag_lower = tag_name.lower()
                        if tag_lower in {"artist", "author"}:
                            author = str(val).strip()
                        elif tag_lower in {"software", "processingsoftware"}:
                            creator_tool = str(val).strip()
                        elif tag_lower in {"datetime", "datetimeoriginal"}:
                            creation_date = str(val).strip()
                        elif tag_lower in {"datetimedigitized"}:
                            mod_date = str(val).strip()
                        elif tag_lower in {"imagedescription", "documentname"}:
                            title = str(val).strip()
                        elif tag_lower in {"make"}:
                            raw_props["camera_make"] = str(val).strip()
                        elif tag_lower in {"model"}:
                            raw_props["camera_model"] = str(val).strip()
                        elif tag_lower in {"hostcomputer"}:
                            raw_props["host_computer"] = str(val).strip()

                    # Check GPS IFD if present
                    try:
                        gps_ifd = exif_data.get_ifd(ExifTags.IFD.GPSInfo)
                        if gps_ifd:
                            gps_decoded: dict[str, Any] = {}
                            for gps_tag_id, gps_val in gps_ifd.items():
                                gps_tag_name = ExifTags.GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                                if isinstance(gps_val, (int, float, str, tuple)):
                                    gps_decoded[gps_tag_name] = str(gps_val)
                            if gps_decoded:
                                raw_props["gps_info"] = gps_decoded
                    except Exception as gps_err:
                        raw_props["gps_error"] = str(gps_err)

                # Check image.info for any embedded software/creator hints (PNG, TIFF)
                for info_key in ("Software", "Author", "Title", "Comment", "Copyright"):
                    if info_key in img.info:
                        raw_props[f"info_{info_key.lower()}"] = str(img.info[info_key])
                        if info_key == "Software" and not creator_tool:
                            creator_tool = str(img.info[info_key])
                        elif info_key == "Author" and not author:
                            author = str(img.info[info_key])
                        elif info_key == "Title" and not title:
                            title = str(img.info[info_key])

        except Exception as img_err:
            raw_props["error"] = f"Image metadata extraction failed: {img_err}"

        return ExtractedMetadata(
            file_path=str(path),
            file_type=ext.lstrip("."),
            author=author,
            creator_tool=creator_tool,
            producer=None,
            creation_date=creation_date,
            modification_date=mod_date,
            company=None,
            title=title,
            raw_properties=raw_props,
        )

    def _extract_generic(self, path: Path, ext: str) -> ExtractedMetadata:
        """Handle unsupported or generic files defensively recording file attributes."""
        raw_props: dict[str, Any] = {
            "file_size_bytes": path.stat().st_size,
            "notice": f"Generic parser fallback for extension {ext}",
        }
        return ExtractedMetadata(
            file_path=str(path),
            file_type=ext.lstrip(".") or "unknown",
            raw_properties=raw_props,
        )
