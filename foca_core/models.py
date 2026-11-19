"""Data models for FOCA metadata extraction and organizational fingerprinting."""

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class DocumentTarget(BaseModel):
    """Represents a discovered document target to download and analyze."""

    model_config = ConfigDict(extra="ignore")

    url: str
    filename: str
    file_type: str
    source_engine: str = ""
    local_path: Optional[str] = None
    size_bytes: int = 0
    status: str = "pending"


class ExtractedMetadata(BaseModel):
    """Metadata extracted from a single document or media file."""

    model_config = ConfigDict(extra="ignore")

    file_path: str
    file_type: str
    author: Optional[str] = None
    creator_tool: Optional[str] = None
    producer: Optional[str] = None
    creation_date: Optional[str] = None
    modification_date: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    raw_properties: dict[str, Any] = Field(default_factory=dict)
    extracted_paths: list[str] = Field(default_factory=list)
    extracted_printers: list[str] = Field(default_factory=list)
    extracted_emails: list[str] = Field(default_factory=list)
    extracted_users: list[str] = Field(default_factory=list)

    @field_validator(
        "extracted_paths",
        "extracted_printers",
        "extracted_emails",
        "extracted_users",
        mode="before",
    )
    @classmethod
    def _coerce_to_sorted_list(cls, v: Any) -> list[str]:
        if isinstance(v, (set, frozenset)):
            return sorted(str(item) for item in v if item)
        if isinstance(v, list):
            seen = set()
            deduped = []
            for item in v:
                if item and str(item) not in seen:
                    seen.add(str(item))
                    deduped.append(str(item))
            return deduped
        if v is None:
            return []
        return [str(v)]


class DNSAuditResult(BaseModel):
    """Results of DNS reconnaissance and mail configuration audit."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[dict[str, Any]] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    mail_provider: Optional[str] = None


class SubdomainResult(BaseModel):
    """Results of subdomain discovery via Certificate Transparency logs."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    total_found: int = 0
    subdomains: list[str] = Field(default_factory=list)


class TechStackResult(BaseModel):
    """Results of web server technology and security headers fingerprinting."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    server_banner: Optional[str] = None
    powered_by: Optional[str] = None
    status_code: int = 0
    security_headers: dict[str, bool] = Field(default_factory=dict)
    detected_technologies: list[str] = Field(default_factory=list)


class WhoisResult(BaseModel):
    """Results of RDAP / WHOIS domain registration lookup."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    status: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)


class SocialProfileResult(BaseModel):
    """Discovered public social media organization profiles."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    profiles: dict[str, str] = Field(default_factory=dict)


class OrganizationFingerprint(BaseModel):
    """Aggregated organizational fingerprint derived from analyzed documents and OSINT."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_files_analyzed: int = 0
    discovered_users: list[str] = Field(default_factory=list)
    discovered_software: dict[str, int] = Field(default_factory=dict)
    discovered_operating_systems: dict[str, int] = Field(default_factory=dict)
    discovered_printers: list[str] = Field(default_factory=list)
    discovered_paths: list[str] = Field(default_factory=list)
    discovered_emails: list[str] = Field(default_factory=list)
    documents: list[ExtractedMetadata] = Field(default_factory=list)
    dns_audit: Optional[DNSAuditResult] = None
    subdomain_audit: Optional[SubdomainResult] = None
    tech_stack: Optional[TechStackResult] = None
    whois_info: Optional[WhoisResult] = None
    social_profiles: Optional[SocialProfileResult] = None
    crawled_emails: list[str] = Field(default_factory=list)
    cloud_buckets: list[str] = Field(default_factory=list)
    internal_ips: list[str] = Field(default_factory=list)
    crawled_urls: list[str] = Field(default_factory=list)
    archive_documents: list[str] = Field(default_factory=list)

    @field_validator(
        "discovered_users",
        "discovered_printers",
        "discovered_paths",
        "discovered_emails",
        "crawled_emails",
        "cloud_buckets",
        "internal_ips",
        "crawled_urls",
        "archive_documents",
        mode="before",
    )
    @classmethod
    def _coerce_collections_to_sorted_unique_list(cls, v: Any) -> list[str]:
        if isinstance(v, (set, frozenset, list, tuple)):
            clean_items = {str(item).strip() for item in v if item and str(item).strip()}
            return sorted(clean_items)
        if v is None:
            return []
        item_str = str(v).strip()
        return [item_str] if item_str else []

    def to_dict(self) -> dict[str, Any]:
        """Convert the fingerprint model to a standard dictionary with sorted list values."""
        data = self.model_dump()
        for key in (
            "discovered_users",
            "discovered_printers",
            "discovered_paths",
            "discovered_emails",
            "crawled_emails",
            "cloud_buckets",
            "internal_ips",
            "crawled_urls",
            "archive_documents",
        ):
            if isinstance(data.get(key), list):
                data[key] = sorted(list(set(data[key])))
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serialize the fingerprint model to formatted JSON."""
        return self.model_dump_json(indent=indent)
