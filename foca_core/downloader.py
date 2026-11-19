"""Streaming document downloader with strict size limits and caching."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from pathlib import Path
import re
from typing import Callable, Optional
import urllib.parse

import requests

from foca_core.models import DocumentTarget

logger = logging.getLogger(__name__)

# Magic byte signatures for supported file types
MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "pdf": [b"%PDF-"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
}

DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_WORKERS = 5


class DocumentDownloader:
    """Safe, bounded, concurrent downloader for target documents."""

    def __init__(
        self,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
        timeout: int = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> None:
        self.max_file_size_bytes = max_file_size_bytes
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "*/*",
            }
        )

    def _sanitize_filename(self, filename: str, fallback_ext: str = "bin") -> str:
        """Sanitize filename to prevent directory traversal and remove invalid OS characters."""
        base = os.path.basename(filename)
        cleaned = re.sub(r'[\\/*?:"<>|\s]', "_", base).strip("._")
        if not cleaned:
            return f"target_doc.{fallback_ext}"
        if "." not in cleaned:
            return f"{cleaned}.{fallback_ext}"
        return cleaned

    def _resolve_domain(self, target: DocumentTarget) -> str:
        """Derive the target domain for subfolder grouping."""
        if target.url.startswith("file://") or not target.url.startswith(("http://", "https://")):
            return "local"
        parsed = urllib.parse.urlparse(target.url)
        netloc = parsed.netloc.split(":")[0].lower()
        return netloc or "misc"

    def _verify_content(self, initial_chunk: bytes, file_type: str) -> bool:
        """Check if initial bytes match expected file type signatures or contain HTML errors."""
        ext = file_type.lower().lstrip(".")
        first_64 = initial_chunk[:64].lower()

        # Check for HTML responses returned instead of real files
        if (
            b"<!doctype html" in first_64
            or b"<html" in first_64
            or b"<head" in first_64
            or b"<?xml" in first_64 and ext in ("pdf", "png", "jpg", "jpeg")
        ):
            return False

        expected_magics = MAGIC_SIGNATURES.get(ext)
        if expected_magics:
            # Check if any expected magic matches
            return any(initial_chunk.startswith(magic) for magic in expected_magics)

        # For unrecognized types, accept if not HTML
        return True

    def download_target(
        self,
        target: DocumentTarget,
        output_cache_dir: str = ".foca_cache",
    ) -> DocumentTarget:
        """Download a single DocumentTarget safely with streaming and bounds verification.

        Args:
            target: The DocumentTarget object to fetch.
            output_cache_dir: Root cache directory for downloads.

        Returns:
            Updated DocumentTarget with local_path and status.
        """
        # If target is already on local disk (from local scanner or prior step)
        if target.local_path and Path(target.local_path).is_file():
            target.size_bytes = Path(target.local_path).stat().st_size
            target.status = "ready"
            return target

        if not target.url.startswith(("http://", "https://")):
            target.status = "skipped (not an HTTP/HTTPS URL)"
            return target

        domain_folder = self._resolve_domain(target)
        dest_dir = Path(output_cache_dir) / domain_folder
        dest_dir.mkdir(parents=True, exist_ok=True)

        clean_name = self._sanitize_filename(target.filename, target.file_type)
        dest_path = dest_dir / clean_name

        # Check cache: skip if file already exists with non-zero size
        if dest_path.is_file() and dest_path.stat().st_size > 0:
            target.local_path = str(dest_path.resolve())
            target.size_bytes = dest_path.stat().st_size
            target.status = "cached"
            return target

        temp_path = dest_dir / f".part_{clean_name}_{os.getpid()}"

        try:
            with self.session.get(
                target.url,
                stream=True,
                timeout=self.timeout,
                allow_redirects=True,
            ) as response:
                if response.status_code != 200:
                    target.status = f"failed (HTTP {response.status_code})"
                    return target

                # Check Content-Length header if provided
                content_length_str = response.headers.get("Content-Length")
                if content_length_str and content_length_str.isdigit():
                    content_length = int(content_length_str)
                    if content_length > self.max_file_size_bytes:
                        target.status = f"failed (size {content_length} bytes exceeds 25MB limit)"
                        return target

                total_downloaded = 0
                file_handle = None

                try:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue

                        # Verify content signature on first non-empty chunk before writing
                        if file_handle is None:
                            if not self._verify_content(chunk, target.file_type):
                                target.status = f"failed (invalid MIME/signature for {target.file_type})"
                                return target
                            file_handle = open(temp_path, "wb")

                        total_downloaded += len(chunk)
                        if total_downloaded > self.max_file_size_bytes:
                            file_handle.close()
                            file_handle = None
                            temp_path.unlink(missing_ok=True)
                            target.status = "failed (exceeded 25MB limit during stream)"
                            return target

                        file_handle.write(chunk)
                finally:
                    if file_handle is not None:
                        file_handle.close()
                        file_handle = None

                if total_downloaded == 0:
                    target.status = "failed (empty response payload)"
                    temp_path.unlink(missing_ok=True)
                    return target

                # Atomic replacement
                temp_path.replace(dest_path)
                target.local_path = str(dest_path.resolve())
                target.size_bytes = total_downloaded
                target.status = "downloaded"
                return target

        except requests.RequestException as e:
            target.status = f"failed ({type(e).__name__})"
            temp_path.unlink(missing_ok=True)
            return target
        except OSError as e:
            target.status = f"failed (Disk IO error: {e})"
            temp_path.unlink(missing_ok=True)
            return target

    def download_targets(
        self,
        targets: list[DocumentTarget],
        output_cache_dir: str = ".foca_cache",
        progress_callback: Optional[Callable[[DocumentTarget], None]] = None,
    ) -> list[DocumentTarget]:
        """Download multiple targets concurrently using a bounded thread pool.

        Args:
            targets: List of DocumentTarget items to download.
            output_cache_dir: Target directory path for cached files.
            progress_callback: Optional callback invoked as each item finishes.

        Returns:
            List of processed DocumentTarget items.
        """
        if not targets:
            return []

        processed: list[DocumentTarget] = []
        workers = min(self.max_workers, len(targets))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_target = {
                executor.submit(self.download_target, target, output_cache_dir): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                try:
                    result = future.result()
                    processed.append(result)
                except Exception as exc:
                    target = future_to_target[future]
                    target.status = f"failed (unhandled error: {exc})"
                    processed.append(target)

                if progress_callback:
                    progress_callback(processed[-1])

        # Preserve original order
        target_map = {t.url: t for t in processed}
        return [target_map.get(t.url, t) for t in targets]
