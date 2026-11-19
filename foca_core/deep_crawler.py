"""Deep web crawler and OSINT asset extractor for target domains."""

from collections import deque
import ipaddress
import logging
import os
import re
from typing import Any, Callable, Optional, Set
import urllib.parse

import defusedxml.ElementTree as ET
import requests

from foca_core.models import DocumentTarget

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Common non-HTML static extensions to skip during link discovery
STATIC_EXTENSIONS: set[str] = {
    ".css",
    ".js",
    ".json",
    ".xml",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".tiff",
}

# Dummy emails and domains to filter out
DUMMY_DOMAINS: set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "sample.com",
    "placeholder.com",
    "domain.com",
    "email.com",
    "yourdomain.com",
    "yoursite.com",
}

DUMMY_LOCAL_PARTS: set[str] = {
    "user",
    "test",
    "email",
    "example",
    "dummy",
    "someone",
    "name",
    "username",
    "admin",
    "sample",
}

# Image extensions that mistakenly get matched by naive email regexes (e.g. logo@2x.png)
EMAIL_IMAGE_EXTENSIONS: set[str] = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "bmp",
    "tif",
    "tiff",
    "css",
    "js",
    "woff",
    "woff2",
    "ttf",
}

# Regex definitions
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE,
)

S3_REGEX = re.compile(
    r"(?:https?://)?(?:[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com|s3\.amazonaws\.com/[a-zA-Z0-9._-]+)",
    re.IGNORECASE,
)
AZURE_REGEX = re.compile(
    r"(?:https?://)?[a-zA-Z0-9.-]+\.blob\.core\.windows\.net",
    re.IGNORECASE,
)
GCP_REGEX = re.compile(
    r"(?:https?://)?storage\.googleapis\.com/[a-zA-Z0-9._-]+",
    re.IGNORECASE,
)

HTML_COMMENT_REGEX = re.compile(r"<!--(.*?)-->", re.DOTALL)
SCRIPT_TAG_REGEX = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
HREF_SRC_REGEX = re.compile(r'(?:href|src)=["\']([^"\'\s>]+)["\']', re.IGNORECASE)

INTERNAL_IP_PATTERNS = [
    re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    re.compile(r"\b(192\.168\.\d{1,3}\.\d{1,3})\b"),
    re.compile(r"\b(172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b"),
]


class DeepCrawler:
    """Deep crawler and OSINT asset extractor for target domains."""

    def __init__(
        self,
        max_pages: int = 50,
        max_depth: int = 3,
        timeout: int = 8,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Initialize the crawler with limits, timeouts, and session configuration."""
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.session = session or requests.Session()

    def _get_headers(self) -> dict[str, str]:
        """Construct standard browser headers."""
        return {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _clean_domain(self, domain_or_url: str) -> str:
        """Extract clean hostname from domain or URL string."""
        raw = domain_or_url.strip().lower()
        if "://" in raw:
            parsed = urllib.parse.urlparse(raw)
            return parsed.netloc.split(":")[0]
        return raw.split("/")[0].split(":")[0]

    def _discover_base_url(self, clean_domain: str) -> str:
        """Determine whether HTTPS or HTTP is available for the base domain."""
        https_url = f"https://{clean_domain}"
        http_url = f"http://{clean_domain}"

        try:
            resp = self.session.get(
                https_url,
                headers=self._get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
            return f"{resp.url.split('?')[0].rstrip('/')}"
        except requests.RequestException:
            pass

        try:
            resp = self.session.get(
                http_url,
                headers=self._get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
            return f"{resp.url.split('?')[0].rstrip('/')}"
        except requests.RequestException:
            return https_url

    def _fetch_robots_txt(
        self, base_url: str
    ) -> tuple[list[str], list[str]]:
        """Fetch robots.txt and parse sitemaps and allow/disallow paths."""
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        sitemaps: list[str] = []
        paths: list[str] = []

        try:
            resp = self.session.get(
                robots_url,
                headers=self._get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200 and resp.text:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("sitemap:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            sitemaps.append(parts[1].strip())
                    elif line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            paths.append(parts[1].strip())
        except requests.RequestException as e:
            logger.debug("Failed fetching robots.txt from %s: %s", robots_url, e)

        return sitemaps, paths

    def _fetch_sitemaps(
        self, sitemap_urls: list[str], clean_domain: str, target_exts: set[str]
    ) -> tuple[list[DocumentTarget], list[str]]:
        """Safely fetch and parse XML sitemaps using defusedxml."""
        discovered_docs: list[DocumentTarget] = []
        discovered_urls: list[str] = []
        seen_sitemaps: set[str] = set()

        sitemap_queue = list(sitemap_urls)

        while sitemap_queue and len(seen_sitemaps) < 10:
            current_sitemap = sitemap_queue.pop(0)
            if current_sitemap in seen_sitemaps:
                continue
            seen_sitemaps.add(current_sitemap)

            try:
                resp = self.session.get(
                    current_sitemap,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                )
                if resp.status_code != 200 or not resp.content:
                    continue

                root = ET.fromstring(resp.content)
                for elem in root.iter():
                    if elem.tag.endswith("loc") and elem.text:
                        loc = elem.text.strip()
                        if not loc:
                            continue

                        parsed = urllib.parse.urlparse(loc)
                        path_lower = parsed.path.lower()

                        if loc.endswith(".xml") or loc.endswith(".xml.gz"):
                            if loc not in seen_sitemaps:
                                sitemap_queue.append(loc)
                            continue

                        ext = os.path.splitext(path_lower)[1].lstrip(".")
                        if ext in target_exts:
                            filename = os.path.basename(parsed.path) or f"document.{ext}"
                            discovered_docs.append(
                                DocumentTarget(
                                    url=loc,
                                    filename=filename,
                                    file_type=ext,
                                    source_engine="sitemap",
                                )
                            )
                        else:
                            host = parsed.netloc.lower().split(":")[0]
                            if host == clean_domain or host.endswith(f".{clean_domain}"):
                                discovered_urls.append(loc)
            except Exception as e:
                logger.debug("Error parsing sitemap %s: %s", current_sitemap, e)

        return discovered_docs, discovered_urls

    def _extract_emails(self, text: str) -> list[str]:
        """Extract and sanitize valid employee emails from text."""
        raw_matches = EMAIL_REGEX.findall(text)
        valid_emails: list[str] = []

        for email in raw_matches:
            email_clean = email.strip().strip(".>,;\"'").lower()
            if not email_clean or "@" not in email_clean:
                continue

            local_part, domain_part = email_clean.split("@", 1)
            if not local_part or not domain_part or "." not in domain_part:
                continue

            # Skip dummy domain names
            if domain_part in DUMMY_DOMAINS:
                continue

            # Skip dummy local parts
            if local_part in DUMMY_LOCAL_PARTS:
                continue

            # Skip fake emails from image assets like logo@2x.png
            ext = domain_part.split(".")[-1].lower()
            if ext in EMAIL_IMAGE_EXTENSIONS:
                continue

            valid_emails.append(email_clean)

        return valid_emails

    def _extract_cloud_buckets(self, text: str) -> list[str]:
        """Extract cloud storage buckets for S3, Azure, and Google Cloud."""
        buckets: list[str] = []

        for regex in (S3_REGEX, AZURE_REGEX, GCP_REGEX):
            for match in regex.findall(text):
                cleaned = match.strip().rstrip("/>\"';,")
                if cleaned:
                    buckets.append(cleaned)

        return buckets

    def _extract_internal_ips(self, html: str) -> list[str]:
        """Extract and validate RFC1918 private IPv4 addresses from HTML comments and scripts."""
        comments = HTML_COMMENT_REGEX.findall(html)
        scripts = SCRIPT_TAG_REGEX.findall(html)

        extracted_text = " \n ".join(comments + scripts)
        discovered_ips: list[str] = []

        for pattern in INTERNAL_IP_PATTERNS:
            matches = pattern.findall(extracted_text)
            for ip_str in matches:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private and not ip_obj.is_loopback:
                        discovered_ips.append(ip_str)
                except ValueError:
                    continue

        return discovered_ips

    def crawl(
        self,
        domain: str,
        file_types: list[str],
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> dict[str, Any]:
        """Perform deep crawl across target domain searching for assets and documents."""
        clean_domain = self._clean_domain(domain)
        target_exts = {ext.strip().lstrip(".").lower() for ext in file_types if ext.strip()}

        base_url = self._discover_base_url(clean_domain)
        logger.info("Base URL discovered: %s", base_url)

        # 1. Fetch robots.txt
        sitemap_links, robot_paths = self._fetch_robots_txt(base_url)

        # Default sitemap locations
        default_sitemaps = [
            f"{base_url.rstrip('/')}/sitemap.xml",
            f"{base_url.rstrip('/')}/sitemap_index.xml",
        ]
        all_sitemaps = list(dict.fromkeys(sitemap_links + default_sitemaps))

        # 2. Fetch sitemaps
        sitemap_docs, sitemap_web_urls = self._fetch_sitemaps(
            all_sitemaps, clean_domain, target_exts
        )

        # State tracking
        seen_targets: set[str] = set()
        document_targets: list[DocumentTarget] = []
        for doc in sitemap_docs:
            if doc.url not in seen_targets:
                seen_targets.add(doc.url)
                document_targets.append(doc)

        crawled_emails: set[str] = set()
        cloud_buckets: set[str] = set()
        internal_ips: set[str] = set()
        visited_urls: set[str] = set()
        enqueued_urls: set[str] = set()

        # Check robot paths for documents or queue candidates
        for path in robot_paths:
            full_path_url = urllib.parse.urljoin(base_url, path)
            parsed_path = urllib.parse.urlparse(full_path_url)
            ext = os.path.splitext(parsed_path.path.lower())[1].lstrip(".")
            if ext in target_exts and full_path_url not in seen_targets:
                seen_targets.add(full_path_url)
                document_targets.append(
                    DocumentTarget(
                        url=full_path_url,
                        filename=os.path.basename(parsed_path.path) or f"document.{ext}",
                        file_type=ext,
                        source_engine="robots.txt",
                    )
                )

        # 3. Breadth-first crawl setup
        queue: deque[tuple[str, int]] = deque()
        queue.append((base_url, 0))
        enqueued_urls.add(base_url.rstrip("/"))

        # Seed candidate pages from sitemap
        for url in sitemap_web_urls[: self.max_pages]:
            norm = url.split("#")[0].rstrip("/")
            if norm not in enqueued_urls:
                queue.append((url, 1))
                enqueued_urls.add(norm)

        # 4. Execute breadth-first crawl
        while queue and len(visited_urls) < self.max_pages:
            current_url, depth = queue.popleft()
            norm_url = current_url.split("#")[0].rstrip("/")
            if norm_url in visited_urls:
                continue
            visited_urls.add(norm_url)

            docs_found_on_page = 0
            emails_found_on_page = 0

            try:
                resp = self.session.get(
                    current_url,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    # If direct document link encountered
                    parsed_curr = urllib.parse.urlparse(current_url)
                    curr_ext = os.path.splitext(parsed_curr.path.lower())[1].lstrip(".")
                    if curr_ext in target_exts and current_url not in seen_targets:
                        seen_targets.add(current_url)
                        document_targets.append(
                            DocumentTarget(
                                url=current_url,
                                filename=os.path.basename(parsed_curr.path) or f"doc.{curr_ext}",
                                file_type=curr_ext,
                                source_engine="crawler",
                            )
                        )
                        docs_found_on_page += 1
                    continue

                html = resp.text

                # Extract emails
                page_emails = self._extract_emails(html)
                for email in page_emails:
                    if email not in crawled_emails:
                        crawled_emails.add(email)
                        emails_found_on_page += 1

                # Extract cloud storage buckets
                page_buckets = self._extract_cloud_buckets(html)
                for bucket in page_buckets:
                    cloud_buckets.add(bucket)

                # Extract private internal IPs from comments and scripts
                page_ips = self._extract_internal_ips(html)
                for ip in page_ips:
                    internal_ips.add(ip)

                # Extract links
                link_matches = HREF_SRC_REGEX.findall(html)
                for raw_link in link_matches:
                    clean_link = raw_link.strip().split("#")[0]
                    if not clean_link or clean_link.startswith(
                        ("javascript:", "mailto:", "tel:", "data:")
                    ):
                        continue

                    abs_url = urllib.parse.urljoin(current_url, clean_link)
                    parsed_abs = urllib.parse.urlparse(abs_url)

                    if parsed_abs.scheme not in ("http", "https"):
                        continue

                    netloc = parsed_abs.netloc.lower().split(":")[0]
                    if not (netloc == clean_domain or netloc.endswith(f".{clean_domain}")):
                        continue

                    path_lower = parsed_abs.path.lower()
                    path_ext = os.path.splitext(path_lower)[1].lstrip(".")

                    # Target document check
                    if path_ext in target_exts:
                        if abs_url not in seen_targets:
                            seen_targets.add(abs_url)
                            fname = os.path.basename(parsed_abs.path) or f"doc.{path_ext}"
                            document_targets.append(
                                DocumentTarget(
                                    url=abs_url,
                                    filename=fname,
                                    file_type=path_ext,
                                    source_engine="crawler",
                                )
                            )
                            docs_found_on_page += 1
                    else:
                        # Internal page check for queueing
                        if (
                            depth < self.max_depth
                            and len(enqueued_urls) < self.max_pages * 3
                        ):
                            if os.path.splitext(path_lower)[1] not in STATIC_EXTENSIONS:
                                norm_abs = abs_url.split("#")[0].rstrip("/")
                                if norm_abs not in enqueued_urls and norm_abs not in visited_urls:
                                    enqueued_urls.add(norm_abs)
                                    queue.append((abs_url, depth + 1))

            except requests.RequestException as e:
                logger.debug("Error requesting %s during crawl: %s", current_url, e)

            if log_callback:
                found_summary = f"{docs_found_on_page} doc(s), {emails_found_on_page} email(s)"
                progress_msg = (
                    f"[CRAWL {len(visited_urls)}/{self.max_pages}] "
                    f"Visiting: {current_url} -> {found_summary}"
                )
                try:
                    log_callback(progress_msg)
                except Exception:
                    pass

        return {
            "document_targets": document_targets,
            "emails": sorted(crawled_emails),
            "cloud_buckets": sorted(cloud_buckets),
            "internal_ips": sorted(internal_ips),
            "crawled_urls": sorted(visited_urls),
        }
