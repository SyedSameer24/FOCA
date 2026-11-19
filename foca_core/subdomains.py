"""Passive multi-source subdomain discovery engine."""

import logging
import re
from typing import Optional
import requests

from foca_core.models import SubdomainResult

logger = logging.getLogger(__name__)


class SubdomainFinder:
    """Discovers subdomains using passive multi-source public feeds (HackerTarget, RapidDNS, crt.sh)."""

    CRT_SH_URL = "https://crt.sh/"
    HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q="
    RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?modules=subdomain"

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, user_agent: Optional[str] = None) -> None:
        """Initialize the subdomain finder with an optional custom user-agent."""
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

    def discover(self, domain: str, timeout: int = 10) -> SubdomainResult:
        """Aggregate subdomains from multiple passive sources without directly hitting the target domain."""
        clean_domain = self._normalize_domain(domain)
        if not clean_domain:
            return SubdomainResult(domain=domain, total_found=0, subdomains=[])

        subdomains: set[str] = set()

        # 1. Query HackerTarget Passive DNS Hostsearch
        try:
            self._discover_hackertarget(clean_domain, subdomains, timeout=timeout)
        except Exception as e:
            logger.debug("HackerTarget passive discovery error for %s: %s", clean_domain, e)

        # 2. Query RapidDNS Passive Certificate / DNS Index
        try:
            self._discover_rapiddns(clean_domain, subdomains, timeout=timeout)
        except Exception as e:
            logger.debug("RapidDNS passive discovery error for %s: %s", clean_domain, e)

        # 3. Query crt.sh Certificate Transparency (fast timeout fallback)
        try:
            self._discover_crtsh(clean_domain, subdomains, timeout=min(timeout, 6))
        except Exception as e:
            logger.debug("crt.sh passive discovery error for %s: %s", clean_domain, e)

        sorted_subdomains = sorted(subdomains)
        return SubdomainResult(
            domain=clean_domain,
            total_found=len(sorted_subdomains),
            subdomains=sorted_subdomains,
        )

    def _discover_hackertarget(self, clean_domain: str, collected: set[str], timeout: int) -> None:
        """Query HackerTarget hostsearch endpoint."""
        url = f"{self.HACKERTARGET_URL}{clean_domain}"
        headers = {"User-Agent": self.user_agent, "Accept": "text/plain"}
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and isinstance(getattr(resp, "text", None), str):
            for line in resp.text.splitlines():
                line = line.strip().lower()
                if not line or "," not in line:
                    continue
                host = line.split(",", 1)[0].strip()
                self._validate_and_add(host, clean_domain, collected)

    def _discover_rapiddns(self, clean_domain: str, collected: set[str], timeout: int) -> None:
        """Query RapidDNS subdomain directory."""
        url = self.RAPIDDNS_URL.format(domain=clean_domain)
        headers = {"User-Agent": self.user_agent, "Accept": "text/html"}
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and isinstance(getattr(resp, "text", None), str):
            escaped_domain = re.escape(clean_domain)
            pattern = re.compile(rf"([a-zA-Z0-9_\-\.]+\.{escaped_domain})", re.IGNORECASE)
            for match in pattern.findall(resp.text):
                self._validate_and_add(match, clean_domain, collected)

    def _discover_crtsh(self, clean_domain: str, collected: set[str], timeout: int) -> None:
        """Query crt.sh Certificate Transparency logs."""
        params = {"q": f"%.{clean_domain}", "output": "json"}
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        response = requests.get(self.CRT_SH_URL, params=params, headers=headers, timeout=timeout)
        if response.status_code == 200:
            entries = response.json()
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        self._extract_from_field(entry.get("name_value"), clean_domain, collected)
                        self._extract_from_field(entry.get("common_name"), clean_domain, collected)

    def _extract_from_field(self, raw_val: Optional[str], domain: str, collected: set[str]) -> None:
        """Extract valid domain names from a crt.sh string field."""
        if not raw_val or not isinstance(raw_val, str):
            return
        for line in raw_val.split("\n"):
            self._validate_and_add(line, domain, collected)

    def _validate_and_add(self, candidate: str, domain: str, collected: set[str]) -> None:
        """Sanitize and validate candidate hostname before adding."""
        if not isinstance(candidate, str):
            return
        c = candidate.strip().lower().rstrip(".")
        if c.startswith("*."):
            c = c[2:]
        elif c.startswith("*"):
            c = c[1:]
        c = c.lstrip(".")

        if not c:
            return

        if c == domain or c.endswith(f".{domain}"):
            if all(ch.isalnum() or ch in ".-_" for ch in c):
                if not any(bad in c for bad in ("@", "/", ":", "?", "&", "=", "%")):
                    collected.add(c)

    def _normalize_domain(self, domain: str) -> str:
        """Strip protocol and path information to obtain base domain."""
        d = domain.strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0].strip()
        return d.rstrip(".")
