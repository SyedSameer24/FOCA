"""Fingerprint analysis engine for extracting organizational intelligence from document metadata."""

import re
from typing import Any, Iterable, Optional

from foca_core.models import ExtractedMetadata, OrganizationFingerprint

# Common system or non-person accounts to filter out from user discovery
FILTERED_USERNAMES = {
    "administrator",
    "admin",
    "all users",
    "anonymous",
    "author",
    "creator",
    "default",
    "default user",
    "guest",
    "local service",
    "network service",
    "nobody",
    "none",
    "null",
    "owner",
    "public",
    "root",
    "system",
    "user",
    "users",
    "unknown",
}

# Software/application names that might appear as author but are actually software
SOFTWARE_AUTHORS = {
    "acrobat distiller",
    "apache fop",
    "canva",
    "ghostscript",
    "gpl ghostscript",
    "imagemagick",
    "libreoffice",
    "microsoft office",
    "microsoft word",
    "openoffice",
    "pdfcreator",
    "pymupdf",
    "pypdf",
    "pypdf2",
    "reportlab",
    "wkhtmltopdf",
}

EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

WINDOWS_USER_PATH_REGEX = re.compile(
    r"(?:[a-zA-Z]:|\\[a-zA-Z0-9._-]+)\\(?:Users|Documents and Settings)\\([^\s\\/:\*?\"<>|]+)",
    re.IGNORECASE,
)

UNIX_USER_PATH_REGEX = re.compile(
    r"/(?:home|Users)/([a-zA-Z0-9._-]+)",
    re.IGNORECASE,
)

GENERAL_WINDOWS_PATH_REGEX = re.compile(
    r"(?:[a-zA-Z]:\\[^<>\":|?*\n\r\t]+|\\\\[a-zA-Z0-9._-]+\\[^<>\":|?*\n\r\t]+)",
    re.IGNORECASE,
)

GENERAL_UNIX_PATH_REGEX = re.compile(
    r"/(?:home|Users|var|tmp|etc|usr|opt|Library|Applications|Volumes)/[^\s<>\":|?*\n\r\t]+",
    re.IGNORECASE,
)

PRINTER_DRIVER_REGEX = re.compile(
    r"(?:PScript5\.dll(?:\s*Version\s*[\d\.]+)?|Acrobat Distiller(?:\s*[\d\.]+)?|"
    r"PDFCreator|CutePDF|PrimoPDF|Bullzip|doPDF|Foxit PDF Creator|Microsoft Print to PDF|"
    r"CUPS(?:\s*[\d\.]+)?|GPL Ghostscript|AFPL Ghostscript)",
    re.IGNORECASE,
)

PRINTER_UNC_REGEX = re.compile(
    r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]*(?:prn|print|laser|jet|xerox|canon|ricoh|plotter|sharp)[a-zA-Z0-9._-]*",
    re.IGNORECASE,
)

PRINTER_HARDWARE_REGEX = re.compile(
    r"\b(?:HP\s+(?:LaserJet|DeskJet|OfficeJet|PageWide)|Canon\s+(?:iR|imageRUNNER|LBP|PIXMA)[A-Za-z0-9-]*|"
    r"Xerox\s+(?:WorkCentre|Phaser|AltaLink|VersaLink)[A-Za-z0-9-]*|"
    r"RICOH\s+(?:Aficio|MP|SP|IM)[A-Za-z0-9-]*|"
    r"Konica\s+Minolta\s+[A-Za-z0-9-]+|Brother\s+[A-Za-z0-9-]+|"
    r"Kyocera\s+(?:TASKalfa|ECOSYS)[A-Za-z0-9-]*|Sharp\s+MX-[A-Za-z0-9-]+)\b",
    re.IGNORECASE,
)


class FingerprintAnalyzer:
    """Analyzes document metadata to reconstruct organizational infrastructure and identities."""

    def analyze_session(
        self,
        domain: str,
        metadata_list: list[ExtractedMetadata],
    ) -> OrganizationFingerprint:
        """Analyze a collection of extracted document metadata to build an organizational fingerprint.

        Args:
            domain: Target domain or organizational identifier.
            metadata_list: List of ExtractedMetadata objects to analyze.

        Returns:
            OrganizationFingerprint containing aggregated users, software, OS, printers, paths, and emails.
        """
        all_users: set[str] = set()
        all_software: dict[str, int] = {}
        all_operating_systems: dict[str, int] = {}
        all_printers: set[str] = set()
        all_paths: set[str] = set()
        all_emails: set[str] = set()

        for meta in metadata_list:
            doc_users: set[str] = set()
            doc_printers: set[str] = set()
            doc_paths: set[str] = set()
            doc_emails: set[str] = set()
            doc_os_hits: set[str] = set()

            all_text_values = self._collect_text_values(meta)

            # 1. Email extraction across all text metadata
            for text in all_text_values:
                for match in EMAIL_REGEX.finditer(text):
                    email = match.group(0).strip().lower()
                    doc_emails.add(email)
                    all_emails.add(email)
                    # Infer username from email prefix if domain matches or plausible
                    prefix = email.split("@")[0]
                    clean_user = self._clean_username(prefix)
                    if clean_user:
                        doc_users.add(clean_user)
                        all_users.add(clean_user)

            # 2. File path extraction & OS heuristic
            for text in all_text_values:
                # Windows path detection
                for match in GENERAL_WINDOWS_PATH_REGEX.finditer(text):
                    cleaned_path = match.group(0).strip()
                    doc_paths.add(cleaned_path)
                    all_paths.add(cleaned_path)
                    doc_os_hits.add("Windows")

                for match in WINDOWS_USER_PATH_REGEX.finditer(text):
                    raw_user = match.group(1).strip()
                    clean_user = self._clean_username(raw_user)
                    if clean_user:
                        doc_users.add(clean_user)
                        all_users.add(clean_user)

                # Unix / macOS path detection
                for match in GENERAL_UNIX_PATH_REGEX.finditer(text):
                    cleaned_path = match.group(0).strip()
                    doc_paths.add(cleaned_path)
                    all_paths.add(cleaned_path)
                    if cleaned_path.startswith("/Users") or cleaned_path.startswith("/Library"):
                        doc_os_hits.add("macOS")
                    else:
                        doc_os_hits.add("Linux")

                for match in UNIX_USER_PATH_REGEX.finditer(text):
                    raw_user = match.group(1).strip()
                    clean_user = self._clean_username(raw_user)
                    if clean_user:
                        doc_users.add(clean_user)
                        all_users.add(clean_user)

            # 3. Direct user / author inspection
            if meta.author:
                candidate_authors = [meta.author]
                if ";" in meta.author:
                    candidate_authors = [a.strip() for a in meta.author.split(";")]
                elif "," in meta.author and not any(title_word in meta.author.lower() for title_word in ["llc", "inc", "corp"]):
                    candidate_authors = [a.strip() for a in meta.author.split(",")]

                for author_cand in candidate_authors:
                    clean_author = self._clean_username(author_cand)
                    if clean_author:
                        doc_users.add(clean_author)
                        all_users.add(clean_author)

            # Check lastModifiedBy in raw properties
            last_mod = meta.raw_properties.get("last_modified_by")
            if isinstance(last_mod, str):
                clean_last_mod = self._clean_username(last_mod)
                if clean_last_mod:
                    doc_users.add(clean_last_mod)
                    all_users.add(clean_last_mod)

            # Check manager in raw properties
            manager = meta.raw_properties.get("manager")
            if isinstance(manager, str):
                clean_manager = self._clean_username(manager)
                if clean_manager:
                    doc_users.add(clean_manager)
                    all_users.add(clean_manager)

            # 4. Software extraction & OS detection from tools
            software_candidates: list[str] = []
            if meta.creator_tool:
                software_candidates.append(meta.creator_tool)
            if meta.producer:
                software_candidates.append(meta.producer)
            if "app_version" in meta.raw_properties:
                app_ver = str(meta.raw_properties["app_version"]).strip()
                if meta.creator_tool:
                    software_candidates.append(f"{meta.creator_tool} {app_ver}")
                else:
                    software_candidates.append(app_ver)
            if "camera_make" in meta.raw_properties:
                cam = f"{meta.raw_properties.get('camera_make', '')} {meta.raw_properties.get('camera_model', '')}".strip()
                if cam:
                    software_candidates.append(cam)

            for soft in software_candidates:
                cleaned_soft = soft.strip()
                if cleaned_soft:
                    all_software[cleaned_soft] = all_software.get(cleaned_soft, 0) + 1
                    inferred_os = self._detect_os_from_string(cleaned_soft)
                    if inferred_os:
                        doc_os_hits.add(inferred_os)

            # Check operating system clues in other raw fields
            for text in all_text_values:
                inferred_os = self._detect_os_from_string(text)
                if inferred_os:
                    doc_os_hits.add(inferred_os)

            for os_name in doc_os_hits:
                all_operating_systems[os_name] = all_operating_systems.get(os_name, 0) + 1

            # 5. Printer detection
            for text in all_text_values:
                for match in PRINTER_DRIVER_REGEX.finditer(text):
                    printer_match = match.group(0).strip()
                    doc_printers.add(printer_match)
                    all_printers.add(printer_match)

                for match in PRINTER_UNC_REGEX.finditer(text):
                    printer_match = match.group(0).strip()
                    doc_printers.add(printer_match)
                    all_printers.add(printer_match)

                for match in PRINTER_HARDWARE_REGEX.finditer(text):
                    printer_match = match.group(0).strip()
                    doc_printers.add(printer_match)
                    all_printers.add(printer_match)

            # Update document's own extracted collections
            meta.extracted_users = sorted(doc_users)
            meta.extracted_printers = sorted(doc_printers)
            meta.extracted_paths = sorted(doc_paths)
            meta.extracted_emails = sorted(doc_emails)

        return OrganizationFingerprint(
            domain=domain,
            total_files_analyzed=len(metadata_list),
            discovered_users=sorted(all_users),
            discovered_software=dict(sorted(all_software.items(), key=lambda item: (-item[1], item[0]))),
            discovered_operating_systems=dict(
                sorted(all_operating_systems.items(), key=lambda item: (-item[1], item[0]))
            ),
            discovered_printers=sorted(all_printers),
            discovered_paths=sorted(all_paths),
            discovered_emails=sorted(all_emails),
            documents=metadata_list,
        )

    def _collect_text_values(self, meta: ExtractedMetadata) -> list[str]:
        """Flatten and extract all string attributes from an ExtractedMetadata record."""
        values: list[str] = []
        for attr in (meta.author, meta.creator_tool, meta.producer, meta.company, meta.title):
            if attr and isinstance(attr, str):
                values.append(attr)

        def _traverse(obj: Any) -> None:
            if isinstance(obj, str):
                values.append(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(k, str):
                        values.append(k)
                    _traverse(v)
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    _traverse(item)

        _traverse(meta.raw_properties)
        return values

    def _clean_username(self, candidate: str) -> Optional[str]:
        """Validate and clean username candidate string."""
        if not candidate:
            return None
        text = candidate.strip()

        # Handle DOMAIN\user or user@domain.com
        if "\\" in text:
            parts = text.split("\\")
            text = parts[-1].strip()
        if "@" in text:
            text = text.split("@")[0].strip()

        # Remove surrounding quotes, brackets
        text = text.strip("'\"`()[]{}<> ")

        if len(text) < 2 or len(text) > 64:
            return None

        lower = text.lower()
        if lower in FILTERED_USERNAMES:
            return None
        if lower in SOFTWARE_AUTHORS:
            return None

        # Filter out pure numbers or paths or URLs
        if text.isdigit() or text.startswith("http") or "/" in text or "\\" in text:
            return None

        return text

    def _detect_os_from_string(self, text: str) -> Optional[str]:
        """Detect operating system indicators from text."""
        lower = text.lower()

        # High priority Windows detections
        if any(w in lower for w in ("windows", "win32", "win64", "winnt", "microsoft word for windows")):
            return "Windows"

        # macOS detections
        if any(w in lower for w in ("macintosh", "mac os", "macos", "darwin", "os x", "quartz pdfcontext", "word for mac")):
            return "macOS"

        # Linux detections
        if any(w in lower for w in ("ubuntu", "debian", "red hat", "centos", "fedora", "suse", "linux", "cups")):
            return "Linux"

        # Mobile OS detections
        if any(w in lower for w in ("ios", "iphone", "ipad")):
            return "iOS"
        if "android" in lower:
            return "Android"

        return None
