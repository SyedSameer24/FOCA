"""Scraper and crawler module for FOCA CLI."""

from collections import deque
import logging
import os
from pathlib import Path
import random
import re
import time
from typing import Optional
import urllib.parse

import requests

from foca_core.models import DocumentTarget

logger = logging.getLogger(__name__)

# Realistic User-Agent rotation pool
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
        "Gecko/20100101 Firefox/124.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4.1 Safari/605.1.15"
    ),
]

DEFAULT_SUPPORTED_EXTENSIONS = ["pdf", "docx", "xlsx", "pptx", "jpg", "png"]
IGNORED_SPIDER_EXTENSIONS = {
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
}


class DocumentScraper:
    """Document discovery engine supporting search engine queries, web crawling, and disk scanning."""

    def __init__(
        self,
        request_delay: float = 1.5,
        max_spider_depth: int = 2,
        max_spider_pages: int = 30,
        timeout: int = 10,
    ) -> None:
        self.request_delay = request_delay
        self.max_spider_depth = max_spider_depth
        self.max_spider_pages = max_spider_pages
        self.timeout = timeout
        self.session = requests.Session()

    def _get_headers(self) -> dict[str, str]:
        """Construct rotating request headers simulating real browsers."""
        ua = random.choice(USER_AGENTS)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
        }

    def _jitter_sleep(self, base_delay: Optional[float] = None) -> None:
        """Introduce randomized delay between network requests to prevent IP throttling."""
        delay = (base_delay or self.request_delay) * random.uniform(0.85, 1.35)
        time.sleep(delay)

    def _clean_domain(self, domain_or_url: str) -> str:
        """Extract clean hostname from input string."""
        raw = domain_or_url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        parsed = urllib.parse.urlparse(raw)
        return (parsed.netloc or parsed.path).lower().split(":")[0]

    def _extract_filename(self, url: str, fallback_ext: str) -> str:
        """Derive a safe filename from a URL path."""
        parsed = urllib.parse.urlparse(url)
        path = urllib.parse.unquote(parsed.path)
        base = os.path.basename(path)
        if base and "." in base:
            # Clean unwanted characters
            clean_name = re.sub(r'[\/\\:\*\?"<>\|\s]', "_", base)
            return clean_name
        # Fallback name if URL doesn't contain a file name
        digest = abs(hash(url)) % 1000000
        return f"document_{digest}.{fallback_ext}"

    def search_duckduckgo(
        self,
        domain: str,
        file_types: list[str],
        max_results: int = 20,
    ) -> list[DocumentTarget]:
        """Query DuckDuckGo HTML interface for target domain and document extensions.

        Args:
            domain: Target domain to search against (e.g. example.com).
            file_types: List of document extensions (e.g. ['pdf', 'docx']).
            max_results: Cap on the number of targets returned.

        Returns:
            List of discovered DocumentTarget objects.
        """
        clean_domain = self._clean_domain(domain)
        discovered: list[DocumentTarget] = []
        seen_urls: set[str] = set()

        ddg_html_endpoint = "https://html.duckduckgo.com/html/"

        for ext in file_types:
            if len(discovered) >= max_results:
                break

            normalized_ext = ext.lstrip(".").lower()
            query = f"site:{clean_domain} filetype:{normalized_ext}"
            headers = self._get_headers()
            headers["Referer"] = "https://html.duckduckgo.com/"

            try:
                # DuckDuckGo HTML accepts POST data with q and b parameter
                resp = self.session.post(
                    ddg_html_endpoint,
                    data={"q": query, "b": ""},
                    headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code in (202, 403, 429) or "anomaly" in resp.text.lower() or "challenge" in resp.text.lower():
                    logger.info(
                        "DuckDuckGo search throttled or requested challenge for '%s' (status %d)",
                        normalized_ext,
                        resp.status_code,
                    )
                    continue

                if resp.status_code != 200:
                    logger.debug(
                        "Search request for %s returned status %d",
                        normalized_ext,
                        resp.status_code,
                    )
                    continue

                html_content = resp.text

                # Parse redirect links with uddg= parameter or direct anchors
                # Format: //duckduckgo.com/l/?uddg=https%3A%2F%2F...
                raw_uddg_matches = re.findall(
                    r'(?:uddg=)(https?[^&"\'\s>]+)',
                    html_content,
                    re.IGNORECASE,
                )
                raw_href_matches = re.findall(
                    r'href=["\'](https?://[^"\'\s>]+)["\']',
                    html_content,
                    re.IGNORECASE,
                )

                candidate_urls = []
                for match in raw_uddg_matches:
                    candidate_urls.append(urllib.parse.unquote(match))
                for match in raw_href_matches:
                    if "duckduckgo.com" not in match:
                        candidate_urls.append(match)

                for raw_url in candidate_urls:
                    clean_url = raw_url.split("&")[0].split("#")[0].strip()
                    if clean_url in seen_urls:
                        continue

                    parsed_url = urllib.parse.urlparse(clean_url)
                    url_netloc = parsed_url.netloc.lower()
                    url_path = parsed_url.path.lower()

                    # Confirm domain matches target domain or subdomain
                    if not (url_netloc == clean_domain or url_netloc.endswith("." + clean_domain)):
                        continue

                    # Confirm extension matches
                    if not (url_path.endswith(f".{normalized_ext}") or f".{normalized_ext}" in url_path):
                        continue

                    seen_urls.add(clean_url)
                    filename = self._extract_filename(clean_url, normalized_ext)
                    target = DocumentTarget(
                        url=clean_url,
                        filename=filename,
                        file_type=normalized_ext,
                        source_engine="duckduckgo",
                        status="discovered",
                    )
                    discovered.append(target)
                    if len(discovered) >= max_results:
                        break

            except requests.RequestException as e:
                logger.warning("DuckDuckGo request error for extension %s: %s", normalized_ext, e)

            self._jitter_sleep()

        return discovered

    def spider_domain(
        self,
        domain_or_url: str,
        file_types: list[str],
        max_results: int = 20,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None,
    ) -> list[DocumentTarget]:
        """Crawl internal pages of a target website to extract document links.

        Args:
            domain_or_url: Starting target domain or full URL.
            file_types: File extensions to look for.
            max_results: Maximum document targets to accumulate.
            max_depth: Crawling depth limit.
            max_pages: Crawling page count limit.

        Returns:
            List of discovered DocumentTarget items.
        """
        depth_limit = max_depth if max_depth is not None else self.max_spider_depth
        page_limit = max_pages if max_pages is not None else self.max_spider_pages

        raw_input = domain_or_url.strip()
        if not raw_input.startswith(("http://", "https://")):
            start_url = f"https://{raw_input}"
        else:
            start_url = raw_input

        clean_domain = self._clean_domain(start_url)
        target_exts = {f".{ext.lstrip('.').lower()}" for ext in file_types}

        visited_pages: set[str] = set()
        seen_targets: set[str] = set()
        discovered: list[DocumentTarget] = []

        # Queue contains (url, depth)
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])

        while queue and len(visited_pages) < page_limit and len(discovered) < max_results:
            current_url, depth = queue.popleft()

            # Normalize current url
            norm_current = current_url.split("#")[0].rstrip("/")
            if norm_current in visited_pages:
                continue
            visited_pages.add(norm_current)

            try:
                headers = self._get_headers()
                resp = self.session.get(
                    current_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                content_type = resp.headers.get("Content-Type", "").lower()
                # If page is not HTML, skip parsing for links
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue

                html = resp.text

                # Extract all anchor and resource links
                link_matches = re.findall(
                    r'(?:href|src)=["\']([^"\'\s>]+)["\']',
                    html,
                    re.IGNORECASE,
                )

                for link in link_matches:
                    clean_link = link.strip().split("#")[0]
                    if not clean_link or clean_link.startswith(("javascript:", "mailto:", "tel:", "data:")):
                        continue

                    # Resolve relative URLs
                    abs_url = urllib.parse.urljoin(current_url, clean_link)
                    parsed_abs = urllib.parse.urlparse(abs_url)

                    # Only inspect http or https
                    if parsed_abs.scheme not in ("http", "https"):
                        continue

                    parsed_netloc = parsed_abs.netloc.lower().split(":")[0]
                    # Enforce same-domain or subdomain constraint
                    if not (parsed_netloc == clean_domain or parsed_netloc.endswith("." + clean_domain)):
                        continue

                    path_lower = parsed_abs.path.lower()
                    path_ext = os.path.splitext(path_lower)[1]

                    # Document target check
                    if path_ext in target_exts:
                        if abs_url not in seen_targets:
                            seen_targets.add(abs_url)
                            ext_clean = path_ext.lstrip(".")
                            target = DocumentTarget(
                                url=abs_url,
                                filename=self._extract_filename(abs_url, ext_clean),
                                file_type=ext_clean,
                                source_engine="spider",
                                status="discovered",
                            )
                            discovered.append(target)
                            if len(discovered) >= max_results:
                                break
                    elif depth < depth_limit:
                        # Queue candidate internal page if not an ignored asset extension
                        if path_ext not in IGNORED_SPIDER_EXTENSIONS:
                            norm_candidate = abs_url.split("#")[0].rstrip("/")
                            if norm_candidate not in visited_pages:
                                queue.append((abs_url, depth + 1))

            except requests.RequestException as e:
                logger.debug("Spider request failed for %s: %s", current_url, e)

            self._jitter_sleep(0.4)

        return discovered

    def scan_local_directory(
        self,
        directory_path: str,
        file_types: list[str],
        max_results: int = 1000,
    ) -> list[DocumentTarget]:
        """Scan a local directory recursively for supported documents.

        Args:
            directory_path: Path to local folder.
            file_types: List of file extensions to include.
            max_results: Limit on returned targets.

        Returns:
            List of discovered DocumentTarget objects with local_path populated.
        """
        target_dir = Path(directory_path).resolve()
        if not target_dir.is_dir():
            logger.error("Specified local directory does not exist: %s", directory_path)
            return []

        target_exts = {f".{ext.lstrip('.').lower()}" for ext in file_types}
        discovered: list[DocumentTarget] = []

        for root, _, files in os.walk(target_dir):
            for file_name in files:
                ext = os.path.splitext(file_name)[1].lower()
                if ext in target_exts:
                    full_path = Path(root) / file_name
                    try:
                        size = full_path.stat().st_size
                    except OSError:
                        size = 0

                    target = DocumentTarget(
                        url=full_path.as_uri(),
                        filename=file_name,
                        file_type=ext.lstrip("."),
                        source_engine="local",
                        local_path=str(full_path),
                        size_bytes=size,
                        status="discovered",
                    )
                    discovered.append(target)
                    if len(discovered) >= max_results:
                        return discovered

        return discovered

    def discover(
        self,
        domain: str = "",
        file_types: Optional[list[str]] = None,
        max_results: int = 20,
        spider_mode: bool = False,
        local_dir: Optional[str] = None,
    ) -> list[DocumentTarget]:
        """Primary discovery orchestration method.

        Args:
            domain: Target domain to query or spider.
            file_types: Target document types (defaults to PDF, DOCX, XLSX, PPTX, JPG, PNG).
            max_results: Maximum files to discover.
            spider_mode: If True, engages internal web crawling.
            local_dir: Optional path to scan on disk instead of network scraping.

        Returns:
            Deduplicated list of DocumentTarget items.
        """
        types = file_types if file_types is not None else DEFAULT_SUPPORTED_EXTENSIONS

        # 1. Local disk scanning mode
        if local_dir:
            return self.scan_local_directory(local_dir, types, max_results=max_results)

        if not domain:
            return []

        results: list[DocumentTarget] = []
        seen_urls: set[str] = set()

        def add_unique(targets: list[DocumentTarget]) -> None:
            for t in targets:
                if t.url not in seen_urls:
                    seen_urls.add(t.url)
                    results.append(t)
                    if len(results) >= max_results:
                        break

        # 2. DuckDuckGo Search Discovery
        ddg_targets = self.search_duckduckgo(domain, types, max_results=max_results)
        add_unique(ddg_targets)

        # 3. Target Web Spider (if enabled or if DDG returned fewer than max_results)
        if spider_mode and len(results) < max_results:
            spider_targets = self.spider_domain(
                domain,
                types,
                max_results=max_results - len(results),
            )
            add_unique(spider_targets)

        return results
