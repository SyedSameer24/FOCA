"""DNS reconnaissance and mail infrastructure audit module."""

import logging
from typing import Any, Optional
import dns.exception
import dns.resolver

from foca_core.models import DNSAuditResult

logger = logging.getLogger(__name__)


class DNSAuditor:
    """Performs DNS enumeration and mail security analysis for target domains."""

    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        timeout: float = 5.0,
    ) -> None:
        """Initialize DNS auditor with optional custom resolvers and timeout."""
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def audit(self, domain: str) -> DNSAuditResult:
        """Perform full DNS audit for domain including A, AAAA, MX, NS, TXT, SPF, and DMARC."""
        clean_domain = self._normalize_domain(domain)
        if not clean_domain:
            return DNSAuditResult(domain=domain)

        a_records = self._query_record_strings(clean_domain, "A")
        aaaa_records = self._query_record_strings(clean_domain, "AAAA")
        ns_records = self._query_record_strings(clean_domain, "NS")
        txt_records = self._query_txt_records(clean_domain)
        mx_records = self._query_mx_records(clean_domain)

        spf_record = self._extract_spf(txt_records)
        dmarc_record = self._query_dmarc(clean_domain)
        mail_provider = self._detect_mail_provider(mx_records)

        return DNSAuditResult(
            domain=clean_domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            mail_provider=mail_provider,
        )

    def _normalize_domain(self, domain: str) -> str:
        """Strip URL protocol and path components to isolate the domain name."""
        d = domain.strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0].strip()
        return d.rstrip(".")

    def _query_record_strings(self, domain: str, rtype: str) -> list[str]:
        """Query standard DNS record types returning normalized string representations."""
        records: list[str] = []
        try:
            answers = self.resolver.resolve(domain, rtype)
            for rdata in answers:
                val = str(rdata).rstrip(".")
                if val and val not in records:
                    records.append(val)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            logger.debug("DNS query for %s %s returned no answer or timed out", domain, rtype)
        except Exception as e:
            logger.debug("Error querying %s record for %s: %s", rtype, domain, str(e))
        return sorted(records)

    def _query_mx_records(self, domain: str) -> list[dict[str, Any]]:
        """Query MX records returning list of dicts with host and priority keys."""
        mx_records: list[dict[str, Any]] = []
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                host = str(rdata.exchange).rstrip(".")
                priority = int(rdata.preference)
                mx_records.append({"host": host, "priority": priority})
            mx_records.sort(key=lambda x: (x["priority"], x["host"]))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            logger.debug("MX query for %s returned no answer or timed out", domain)
        except Exception as e:
            logger.debug("Error querying MX records for %s: %s", domain, str(e))
        return mx_records

    def _query_txt_records(self, domain: str) -> list[str]:
        """Query TXT records reassembling segmented RFC strings."""
        records: list[str] = []
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                if hasattr(rdata, "strings"):
                    val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                else:
                    val = str(rdata).strip('"')
                if val and val not in records:
                    records.append(val)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            logger.debug("TXT query for %s returned no answer or timed out", domain)
        except Exception as e:
            logger.debug("Error querying TXT records for %s: %s", domain, str(e))
        return sorted(records)

    def _extract_spf(self, txt_records: list[str]) -> Optional[str]:
        """Extract the SPF record from existing TXT records if present."""
        for record in txt_records:
            if record.lower().startswith("v=spf1"):
                return record
        return None

    def _query_dmarc(self, domain: str) -> Optional[str]:
        """Query _dmarc subdomain for DMARC TXT record."""
        dmarc_host = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                if hasattr(rdata, "strings"):
                    val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                else:
                    val = str(rdata).strip('"')
                if "v=dmarc1" in val.lower():
                    return val
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            logger.debug("DMARC query for %s returned no answer", dmarc_host)
        except Exception as e:
            logger.debug("Error querying DMARC record for %s: %s", dmarc_host, str(e))
        return None

    def _detect_mail_provider(self, mx_records: list[dict[str, Any]]) -> Optional[str]:
        """Identify mail provider from MX host signatures."""
        if not mx_records:
            return None

        combined_hosts = " ".join(record["host"].lower() for record in mx_records)

        if any(sig in combined_hosts for sig in ("google.com", "googlemail.com", "aspmx")):
            return "Google"
        if any(sig in combined_hosts for sig in ("outlook.com", "microsoft.com", "protection.outlook")):
            return "Microsoft"
        if any(sig in combined_hosts for sig in ("protonmail.ch", "proton.me")):
            return "Proton"
        if any(sig in combined_hosts for sig in ("zoho.com", "zoho.eu")):
            return "Zoho"
        if any(sig in combined_hosts for sig in ("fastmail.com", "messagingengine.com")):
            return "Fastmail"
        if any(sig in combined_hosts for sig in ("amazonses.com", "aws")):
            return "AWS"

        return "Private"
