"""RDAP / WHOIS domain registration lookup module."""

import logging
from typing import Any, Optional
import requests

from foca_core.models import WhoisResult

logger = logging.getLogger(__name__)


class WhoisLookup:
    """Performs domain registration and registrar reconnaissance via public RDAP endpoints."""

    RDAP_BASE_URL = "https://rdap.org/domain/"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def __init__(self, user_agent: Optional[str] = None) -> None:
        """Initialize WhoisLookup with optional user agent string."""
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

    def lookup(self, domain: str, timeout: int = 10) -> WhoisResult:
        """Query RDAP for domain registration details, events, and nameservers."""
        clean_domain = self._normalize_domain(domain)
        if not clean_domain:
            return WhoisResult(domain=domain)

        url = f"{self.RDAP_BASE_URL}{clean_domain}"
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rdap+json, application/json",
        }

        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    return self._parse_rdap_response(clean_domain, data)
            else:
                logger.debug(
                    "RDAP lookup for %s returned HTTP status %d",
                    clean_domain,
                    response.status_code,
                )
        except requests.Timeout:
            logger.debug("RDAP lookup timed out after %d seconds for %s", timeout, clean_domain)
        except requests.RequestException as req_err:
            logger.debug("Network error during RDAP lookup for %s: %s", clean_domain, str(req_err))
        except Exception as e:
            logger.debug("Unexpected error during RDAP lookup for %s: %s", clean_domain, str(e))

        return WhoisResult(domain=clean_domain)

    def _parse_rdap_response(self, domain: str, data: dict[str, Any]) -> WhoisResult:
        """Extract structured fields from RDAP JSON dictionary."""
        registrar = self._extract_registrar(data.get("entities"))

        creation_date: Optional[str] = None
        expiration_date: Optional[str] = None
        updated_date: Optional[str] = None

        events = data.get("events")
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = event.get("eventAction", "").lower()
                date_val = event.get("eventDate")
                if not date_val:
                    continue

                if action in ("registration", "registered") and not creation_date:
                    creation_date = str(date_val)
                elif action in ("expiration", "expire", "renewal") and not expiration_date:
                    expiration_date = str(date_val)
                elif action in ("last changed", "last update", "last updated") and not updated_date:
                    updated_date = str(date_val)

        status_list: list[str] = []
        raw_status = data.get("status")
        if isinstance(raw_status, list):
            status_list = [str(s).strip() for s in raw_status if s]
        elif isinstance(raw_status, str):
            status_list = [raw_status.strip()]

        nameservers: list[str] = []
        raw_ns = data.get("nameservers")
        if isinstance(raw_ns, list):
            for ns_entry in raw_ns:
                if isinstance(ns_entry, dict):
                    ns_name = ns_entry.get("ldhName") or ns_entry.get("handle")
                    if ns_name:
                        nameservers.append(str(ns_name).strip().lower())
                elif isinstance(ns_entry, str):
                    nameservers.append(ns_entry.strip().lower())

        return WhoisResult(
            domain=domain,
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            status=sorted(list(set(status_list))),
            nameservers=sorted(list(set(nameservers))),
        )

    def _extract_registrar(self, entities: Any) -> Optional[str]:
        """Traverse entity hierarchy to identify registrar name."""
        if not isinstance(entities, list):
            return None

        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                    for entry in vcard[1]:
                        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                            fn_val = entry[3]
                            if fn_val:
                                return str(fn_val).strip()
                if entity.get("handle"):
                    return str(entity["handle"]).strip()
                if entity.get("legalName"):
                    return str(entity["legalName"]).strip()

            nested = entity.get("entities")
            if nested:
                nested_reg = self._extract_registrar(nested)
                if nested_reg:
                    return nested_reg

        return None

    def _normalize_domain(self, domain: str) -> str:
        """Strip protocol and path information to obtain base domain."""
        d = domain.strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0].strip()
        return d.rstrip(".")
