"""Historical document discovery via Wayback Machine CDX API."""

import logging
import os
from typing import Optional
import urllib.parse

import requests

from foca_core.models import DocumentTarget

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class ArchiveDigger:
    """Historical archive digger discovering legacy documents through Wayback Machine."""

    def __init__(
        self,
        timeout: int = 15,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Initialize archive digger with timeout and optional custom session."""
        self.timeout = timeout
        self.session = session or requests.Session()

    def _clean_domain(self, domain_or_url: str) -> str:
        """Sanitize domain string removing protocols and paths."""
        raw = domain_or_url.strip().lower()
        if "://" in raw:
            parsed = urllib.parse.urlparse(raw)
            return parsed.netloc.split(":")[0]
        return raw.split("/")[0].split(":")[0]

    def _extract_filename(self, url: str, ext: str) -> str:
        """Extract a readable filename from URL or assign fallback."""
        try:
            parsed = urllib.parse.urlparse(url)
            basename = os.path.basename(parsed.path)
            if basename:
                unquoted = urllib.parse.unquote(basename)
                if not unquoted.lower().endswith(f".{ext}"):
                    return f"{unquoted}.{ext}"
                return unquoted
        except Exception:
            pass
        return f"archive_doc.{ext}"

    def dig_historical_documents(
        self,
        domain: str,
        file_types: list[str],
        limit: int = 100,
    ) -> list[DocumentTarget]:
        """Query Wayback Machine CDX API for historical documents matching target extensions."""
        clean_domain = self._clean_domain(domain)
        if not clean_domain:
            return []

        target_exts = {ext.strip().lstrip(".").lower() for ext in file_types if ext.strip()}
        if not target_exts:
            return []

        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?"
            f"url={clean_domain}/*&output=json&fl=original&collapse=urlkey&limit=150"
        )

        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json",
        }

        try:
            resp = self.session.get(cdx_url, headers=headers, timeout=min(self.timeout, 6))
            if resp.status_code != 200:
                logger.debug(
                    "Wayback CDX API returned status %s for domain %s",
                    resp.status_code,
                    clean_domain,
                )
                return []

            data = resp.json()
            if not isinstance(data, list) or len(data) <= 1:
                return []

        except (requests.RequestException, ValueError) as e:
            logger.debug("Failed querying Wayback Machine CDX for %s: %s", clean_domain, e)
            return []
        except Exception as e:
            logger.debug("Unexpected error during archive digging for %s: %s", clean_domain, e)
            return []

        discovered: list[DocumentTarget] = []
        seen_urls: set[str] = set()

        # CDX output format: first row is field names like ["original"]
        rows = data[1:]

        for row in rows:
            if isinstance(row, list) and row:
                raw_url = str(row[0]).strip()
            elif isinstance(row, str):
                raw_url = row.strip()
            else:
                continue

            if not raw_url or raw_url.lower() == "original" or raw_url in seen_urls:
                continue

            try:
                parsed = urllib.parse.urlparse(raw_url)
                path_lower = parsed.path.lower()
                ext = os.path.splitext(path_lower)[1].lstrip(".")

                # Also inspect raw_url ending if query parameters exist
                if not ext:
                    for target_ext in target_exts:
                        if path_lower.endswith(f".{target_ext}"):
                            ext = target_ext
                            break

                if ext in target_exts:
                    seen_urls.add(raw_url)
                    filename = self._extract_filename(raw_url, ext)
                    target = DocumentTarget(
                        url=raw_url,
                        filename=filename,
                        file_type=ext,
                        source_engine="wayback_archive",
                    )
                    discovered.append(target)

                    if len(discovered) >= limit:
                        break

            except Exception as e:
                logger.debug("Error processing archive URL %s: %s", raw_url, e)
                continue

        return discovered
