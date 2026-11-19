"""Rich terminal reporting and structured export engine for FOCA CLI."""

import csv
import json
import os
from pathlib import Path
import re
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from foca_core.models import (
    DNSAuditResult,
    DocumentTarget,
    OrganizationFingerprint,
    SocialProfileResult,
    SubdomainResult,
    TechStackResult,
    WhoisResult,
)


class FocaReporter:
    """Renders high-contrast, clean CLI dashboards and exports JSON/CSV reports."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def print_banner(self) -> None:
        """Display clean, high-contrast ASCII header banner."""
        banner_text = (
            "  _____ ___   ____    _    \n"
            " |  ___/ _ \\ / ___|  / \\   \n"
            " | |_ | | | | |     / _ \\  \n"
            " |  _|| |_| | |___ / ___ \\ \n"
            " |_|   \\___/ \\____/_/   \\_\\\n"
            " ==========================================================\n"
            " FOCA - Document Metadata & Organizational OSINT Engine\n"
            " =========================================================="
        )
        self.console.print(f"[bold cyan]{banner_text}[/bold cyan]")
        self.console.print()

    def print_info(self, msg: str) -> None:
        """Print semantic information message."""
        self.console.print(f"[bold blue][*][/bold blue] {msg}")

    def print_success(self, msg: str) -> None:
        """Print semantic success message."""
        self.console.print(f"[bold green][+][/bold green] {msg}")

    def print_warning(self, msg: str) -> None:
        """Print semantic warning message."""
        self.console.print(f"[bold yellow][!][/bold yellow] {msg}")

    def print_error(self, msg: str) -> None:
        """Print semantic error message."""
        self.console.print(f"[bold red][-][/bold red] {msg}")

    def _format_size(self, size_bytes: int) -> str:
        """Convert byte count into readable KB/MB notation."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.2f} MB"

    def render_discovered_targets(self, targets: list[DocumentTarget]) -> None:
        """Render table of discovered document targets (useful in no-download mode)."""
        table = Table(
            title="Discovered Document Targets",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        table.add_column("No.", style="dim", width=4)
        table.add_column("Filename", style="bold white", max_width=35, overflow="ellipsis")
        table.add_column("Type", style="yellow", justify="center", width=8)
        table.add_column("Source Engine", style="blue", width=14)
        table.add_column("URL / URI", style="green", overflow="fold")

        if not targets:
            table.add_row("-", "No targets discovered", "-", "-", "-")
        else:
            for idx, target in enumerate(targets, start=1):
                table.add_row(
                    str(idx),
                    target.filename,
                    target.file_type.upper(),
                    target.source_engine,
                    target.url,
                )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def render_dns_audit(self, dns_audit: DNSAuditResult) -> None:
        """Render DNS and mail infrastructure audit table."""
        table = Table(
            title=f"DNS & Mail Infrastructure Audit: {dns_audit.domain}",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        table.add_column("Record Type", style="bold cyan", width=16)
        table.add_column("Values", style="bold white", overflow="fold")
        table.add_column("Mail Provider / Status", style="green", width=28)

        # A Records
        a_val = ", ".join(dns_audit.a_records) if dns_audit.a_records else "None"
        table.add_row("A", a_val, f"{len(dns_audit.a_records)} record(s)")

        # AAAA Records
        aaaa_val = ", ".join(dns_audit.aaaa_records) if dns_audit.aaaa_records else "None"
        table.add_row("AAAA", aaaa_val, f"{len(dns_audit.aaaa_records)} record(s)")

        # MX Records with Mail Provider
        if dns_audit.mx_records:
            mx_lines = [f"{r.get('host', '')} (prio: {r.get('priority', '')})" for r in dns_audit.mx_records]
            mx_val = "\n".join(mx_lines)
        else:
            mx_val = "None"
        provider_str = dns_audit.mail_provider or "Unknown / Private"
        table.add_row("MX", mx_val, f"Mail Provider: {provider_str}")

        # NS Records
        ns_val = ", ".join(dns_audit.ns_records) if dns_audit.ns_records else "None"
        table.add_row("NS", ns_val, f"{len(dns_audit.ns_records)} nameserver(s)")

        # TXT Records
        if dns_audit.txt_records:
            sample_txt = dns_audit.txt_records[:3]
            txt_val = "\n".join(sample_txt)
            if len(dns_audit.txt_records) > 3:
                txt_val += f"\n(+{len(dns_audit.txt_records) - 3} more)"
        else:
            txt_val = "None"
        table.add_row("TXT", txt_val, f"{len(dns_audit.txt_records)} record(s)")

        # SPF Status
        if dns_audit.spf_record:
            spf_status = "[bold green][+] Configured[/bold green]"
            spf_val = dns_audit.spf_record
        else:
            spf_status = "[bold red][-] Missing[/bold red]"
            spf_val = "No SPF record published"
        table.add_row("SPF Status", spf_val, spf_status)

        # DMARC Status
        if dns_audit.dmarc_record:
            dmarc_status = "[bold green][+] Configured[/bold green]"
            dmarc_val = dns_audit.dmarc_record
        else:
            dmarc_status = "[bold red][-] Missing[/bold red]"
            dmarc_val = "No DMARC record published"
        table.add_row("DMARC Status", dmarc_val, dmarc_status)

        self.console.print()
        self.console.print(table)
        self.console.print()

    def render_subdomains(self, subdomain_audit: SubdomainResult) -> None:
        """Render table of discovered passive subdomains and total count."""
        table = Table(
            title=f"Passive Subdomain Discovery (Total Found: {subdomain_audit.total_found}) - {subdomain_audit.domain}",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        table.add_column("No.", style="dim", width=6, justify="center")
        table.add_column("Discovered Subdomain FQDN", style="bold white", overflow="fold")

        if not subdomain_audit.subdomains:
            table.add_row("-", "No subdomains discovered via Certificate Transparency logs")
        else:
            for idx, sub in enumerate(subdomain_audit.subdomains, start=1):
                table.add_row(str(idx), sub)

        self.console.print()
        self.console.print(table)
        self.console.print()

    def render_tech_stack(self, tech_stack: TechStackResult) -> None:
        """Render web technology profile and HTTP security headers table."""
        # 1. Server Profile Table
        server_table = Table(
            title=f"Web Technology & Server Profile: {tech_stack.domain}",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        server_table.add_column("Attribute", style="bold cyan", width=22)
        server_table.add_column("Detected Value", style="bold white")

        http_code = str(tech_stack.status_code) if tech_stack.status_code else "No response"
        server_table.add_row("HTTP Status Code", http_code)
        server_table.add_row("Web Server", tech_stack.server_banner or "Undisclosed / Hidden")
        server_table.add_row("Powered By", tech_stack.powered_by or "Undisclosed / Hidden")

        tech_list = ", ".join(tech_stack.detected_technologies) if tech_stack.detected_technologies else "None detected"
        server_table.add_row("Detected Tech", tech_list)

        # 2. Security Headers Table
        headers_table = Table(
            title=f"HTTP Security Headers Audit: {tech_stack.domain}",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        headers_table.add_column("Security Header", style="bold cyan", width=30)
        headers_table.add_column("Status", justify="center", width=16)
        headers_table.add_column("Protection Scope", style="dim white")

        scope_map = {
            "Strict-Transport-Security": "Forces TLS/HTTPS encryption and prevents downgrade attacks",
            "Content-Security-Policy": "Mitigates cross-site scripting (XSS) and data injection",
            "X-Frame-Options": "Protects against clickjacking and framing attacks",
            "X-Content-Type-Options": "Disallows MIME-sniffing away from declared content-type",
            "Referrer-Policy": "Protects sensitive URL parameters from referrer leakages",
        }

        if not tech_stack.security_headers:
            headers_table.add_row("None evaluated", "[dim]N/A[/dim]", "No endpoint reached")
        else:
            for header, present in tech_stack.security_headers.items():
                if present:
                    status_str = "[bold green][+] Present[/bold green]"
                else:
                    status_str = "[bold red][-] Missing[/bold red]"
                scope_desc = scope_map.get(header, "HTTP Security Control")
                headers_table.add_row(header, status_str, scope_desc)

        self.console.print()
        self.console.print(server_table)
        self.console.print()
        self.console.print(headers_table)
        self.console.print()

    def render_whois(self, whois_info: WhoisResult) -> None:
        """Render domain registration details and RDAP records panel."""
        info_lines = [
            f"[bold white]Target Domain    :[/bold white] [cyan]{whois_info.domain}[/cyan]",
            f"[bold white]Registrar        :[/bold white] [green]{whois_info.registrar or 'Undisclosed / Not found'}[/green]",
            f"[bold white]Creation Date    :[/bold white] [yellow]{whois_info.creation_date or 'N/A'}[/yellow]",
            f"[bold white]Expiry Date      :[/bold white] [magenta]{whois_info.expiration_date or 'N/A'}[/magenta]",
            f"[bold white]Updated Date     :[/bold white] [dim white]{whois_info.updated_date or 'N/A'}[/dim white]",
            f"[bold white]Nameservers      :[/bold white] [cyan]{', '.join(whois_info.nameservers) if whois_info.nameservers else 'N/A'}[/cyan]",
            f"[bold white]Domain Status    :[/bold white] [white]{', '.join(whois_info.status) if whois_info.status else 'N/A'}[/white]",
        ]
        panel = Panel(
            "\n".join(info_lines),
            title=f"[bold cyan]Domain Registration & RDAP Record: {whois_info.domain}[/bold cyan]",
            border_style="cyan",
            box=box.SQUARE,
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()

    def render_social_profiles(self, social_profiles: SocialProfileResult) -> None:
        """Render discovered public social media presence table."""
        table = Table(
            title=f"Discovered Social Media Profiles: {social_profiles.domain}",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        table.add_column("Platform", style="bold cyan", width=20)
        table.add_column("Profile Link", style="green", overflow="fold")

        platform_labels = {
            "twitter": "Twitter / X",
            "linkedin": "LinkedIn",
            "github": "GitHub",
            "youtube": "YouTube",
            "facebook": "Facebook",
            "instagram": "Instagram",
        }

        if not social_profiles.profiles:
            table.add_row("None", "No public social media profiles discovered on homepage")
        else:
            for platform, url in sorted(social_profiles.profiles.items()):
                display_name = platform_labels.get(platform.lower(), platform.title())
                table.add_row(display_name, url)

        self.console.print()
        self.console.print(table)
        self.console.print()

    def render_dashboard(
        self,
        fingerprint: OrganizationFingerprint,
        targets: Optional[list[DocumentTarget]] = None,
    ) -> None:
        """Render multi-panel Rich dashboard summarizing extracted intelligence."""
        self.console.print()

        # 1. Executive Summary Panel
        doc_emails = set(fingerprint.discovered_emails)
        for d in fingerprint.documents:
            doc_emails.update(d.extracted_emails)
        total_unique_emails = len(doc_emails.union(fingerprint.crawled_emails))

        summary_lines = [
            f"[bold white]Target Domain / Identifier :[/bold white] [cyan]{fingerprint.domain}[/cyan]",
            f"[bold white]Scan Timestamp             :[/bold white] [cyan]{fingerprint.scan_timestamp}[/cyan]",
            f"[bold white]Total Documents Analyzed   :[/bold white] [cyan]{fingerprint.total_files_analyzed}[/cyan]",
            f"[bold white]Identified Users / Authors :[/bold white] [green]{len(fingerprint.discovered_users)}[/green]",
            f"[bold white]Identified Software Tools  :[/bold white] [yellow]{len(fingerprint.discovered_software)}[/yellow]",
            f"[bold white]Identified Operating Sys   :[/bold white] [magenta]{len(fingerprint.discovered_operating_systems)}[/magenta]",
            f"[bold white]Internal Paths Exposed     :[/bold white] [red]{len(fingerprint.discovered_paths)}[/red]",
            f"[bold white]Identified Printers        :[/bold white] [blue]{len(fingerprint.discovered_printers)}[/blue]",
            f"[bold white]Discovered Email Addresses :[/bold white] [cyan]{total_unique_emails}[/cyan]",
        ]

        if fingerprint.cloud_buckets:
            summary_lines.append(f"[bold white]Exposed Cloud Buckets      :[/bold white] [red]{len(fingerprint.cloud_buckets)}[/red]")
        if fingerprint.internal_ips:
            summary_lines.append(f"[bold white]Internal Network Leaks     :[/bold white] [red]{len(fingerprint.internal_ips)}[/red]")
        if fingerprint.crawled_urls:
            summary_lines.append(f"[bold white]Crawled Web Pages          :[/bold white] [cyan]{len(fingerprint.crawled_urls)}[/cyan]")
        if fingerprint.dns_audit:
            provider = fingerprint.dns_audit.mail_provider or "Configured"
            summary_lines.append(f"[bold white]DNS & Mail Infrastructure  :[/bold white] [green]{provider}[/green]")
        if fingerprint.subdomain_audit:
            summary_lines.append(f"[bold white]Discovered Subdomains      :[/bold white] [green]{fingerprint.subdomain_audit.total_found}[/green]")
        if fingerprint.tech_stack:
            server_name = fingerprint.tech_stack.server_banner or "Analyzed"
            summary_lines.append(f"[bold white]Web Server Signature       :[/bold white] [yellow]{server_name}[/yellow]")
        if fingerprint.whois_info:
            reg_name = fingerprint.whois_info.registrar or "Found"
            summary_lines.append(f"[bold white]Domain Registrar           :[/bold white] [cyan]{reg_name}[/cyan]")
        if fingerprint.social_profiles:
            summary_lines.append(f"[bold white]Public Social Profiles     :[/bold white] [green]{len(fingerprint.social_profiles.profiles)}[/green]")

        panel = Panel(
            "\n".join(summary_lines),
            title="[bold cyan]FOCA Organizational Fingerprint Summary[/bold cyan]",
            border_style="cyan",
            box=box.SQUARE,
        )
        self.console.print(panel)
        self.console.print()

        # Render OSINT modules if populated
        if fingerprint.dns_audit:
            self.render_dns_audit(fingerprint.dns_audit)
        if fingerprint.subdomain_audit:
            self.render_subdomains(fingerprint.subdomain_audit)
        if fingerprint.tech_stack:
            self.render_tech_stack(fingerprint.tech_stack)
        if fingerprint.whois_info:
            self.render_whois(fingerprint.whois_info)
        if fingerprint.social_profiles:
            self.render_social_profiles(fingerprint.social_profiles)

        # Check if document inspection sections should be displayed
        has_osint = any([
            fingerprint.dns_audit,
            fingerprint.subdomain_audit,
            fingerprint.tech_stack,
            fingerprint.whois_info,
            fingerprint.social_profiles,
        ])

        # If documents were analyzed OR no OSINT module ran, show document tables
        if fingerprint.documents or fingerprint.total_files_analyzed > 0 or not has_osint:
            self._render_document_tables(fingerprint, targets)

        # Discovered Employee Emails and Exposed Leaks Tables
        self._render_email_table(fingerprint)
        self._render_leaks_table(fingerprint)

    def _render_document_tables(
        self,
        fingerprint: OrganizationFingerprint,
        targets: Optional[list[DocumentTarget]] = None,
    ) -> None:
        """Render tables for users, software, network paths, and document catalog."""
        # 2. Table: Discovered Users / Authors
        user_table = Table(
            title="Discovered Users and Document Authors",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        user_table.add_column("User / Identity", style="bold white", width=26)
        user_table.add_column("Count", justify="center", width=8, style="green")
        user_table.add_column("Associated Source Files", style="dim white", overflow="ellipsis")

        user_doc_map: dict[str, list[str]] = {}
        for doc in fingerprint.documents:
            file_name = os.path.basename(doc.file_path)
            users_in_doc = set(doc.extracted_users)
            if doc.author:
                users_in_doc.add(doc.author)
            for u in users_in_doc:
                if u:
                    user_doc_map.setdefault(u, []).append(file_name)

        # Merge with fingerprint.discovered_users
        for u in fingerprint.discovered_users:
            if u not in user_doc_map:
                user_doc_map[u] = []

        if not user_doc_map:
            user_table.add_row("None identified", "0", "N/A")
        else:
            sorted_users = sorted(
                user_doc_map.items(),
                key=lambda item: len(item[1]),
                reverse=True,
            )
            for user, files in sorted_users:
                file_summary = ", ".join(files[:3])
                if len(files) > 3:
                    file_summary += f" (+{len(files) - 3} more)"
                user_table.add_row(user, str(len(files)), file_summary or "Inferred from metadata")

        self.console.print(user_table)
        self.console.print()

        # 3. Table: Software & Operating Systems
        tech_table = Table(
            title="Software and Operating Systems Fingerprint",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        tech_table.add_column("Component / Signature", style="bold white", width=36)
        tech_table.add_column("Category", style="yellow", width=22)
        tech_table.add_column("Detections", justify="center", style="green", width=12)

        tech_rows = []
        for os_name, count in fingerprint.discovered_operating_systems.items():
            tech_rows.append((os_name, "Operating System", count))
        for sw_name, count in fingerprint.discovered_software.items():
            tech_rows.append((sw_name, "Software / Tool", count))

        tech_rows.sort(key=lambda item: item[2], reverse=True)

        if not tech_rows:
            tech_table.add_row("None identified", "N/A", "0")
        else:
            for component, category, count in tech_rows:
                tech_table.add_row(component, category, str(count))

        self.console.print(tech_table)
        self.console.print()

        # 4. Table: Internal Paths & Printers
        infra_table = Table(
            title="Internal Network Artifacts (Paths & Printers)",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        infra_table.add_column("Type", style="yellow", width=10)
        infra_table.add_column("Value / Path", style="bold white", max_width=45, overflow="ellipsis")
        infra_table.add_column("Source Document", style="dim white", overflow="ellipsis")

        infra_rows = []
        for doc in fingerprint.documents:
            file_name = os.path.basename(doc.file_path)
            for p in doc.extracted_paths:
                infra_rows.append(("Path", p, file_name))
            for prn in doc.extracted_printers:
                infra_rows.append(("Printer", prn, file_name))

        if not infra_rows:
            infra_table.add_row("N/A", "No internal paths or printers detected", "N/A")
        else:
            for item_type, val, doc_name in infra_rows:
                infra_table.add_row(item_type, val, doc_name)

        self.console.print(infra_table)
        self.console.print()

        # 5. Table: Scanned Documents Summary
        doc_table = Table(
            title="Analyzed Document Catalog",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        doc_table.add_column("Filename", style="bold white", max_width=30, overflow="ellipsis")
        doc_table.add_column("Type", justify="center", style="yellow", width=8)
        doc_table.add_column("Size", justify="right", style="cyan", width=12)
        doc_table.add_column("Author / Owner", style="green", max_width=22, overflow="ellipsis")
        doc_table.add_column("Status", justify="center", width=14)

        if not fingerprint.documents:
            doc_table.add_row("No documents analyzed", "-", "-", "-", "-")
        else:
            target_status_map = {}
            if targets:
                for t in targets:
                    target_status_map[t.filename] = t.status

            for doc in fingerprint.documents:
                fname = os.path.basename(doc.file_path)
                try:
                    fsize = Path(doc.file_path).stat().st_size
                    fsize_str = self._format_size(fsize)
                except OSError:
                    fsize_str = "N/A"

                author_str = doc.author or (doc.extracted_users[0] if doc.extracted_users else "N/A")
                status = target_status_map.get(fname, "analyzed")
                status_formatted = f"[green]{status}[/green]" if "fail" not in status else f"[red]{status}[/red]"

                doc_table.add_row(
                    fname,
                    doc.file_type.upper(),
                    fsize_str,
                    author_str,
                    status_formatted,
                )

        self.console.print(doc_table)
        self.console.print()

    def _render_email_table(self, fingerprint: OrganizationFingerprint) -> None:
        """Render discovered employee emails and their source attribution."""
        email_table = Table(
            title="Discovered Employee Emails",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        email_table.add_column("Email", style="bold white", max_width=45, overflow="ellipsis")
        email_table.add_column("Source Type", style="yellow", width=30)

        email_sources: dict[str, set[str]] = {}
        for e in fingerprint.discovered_emails:
            if e and str(e).strip():
                email_sources.setdefault(str(e).strip(), set()).add("Document Metadata")
        for doc in fingerprint.documents:
            for e in doc.extracted_emails:
                if e and str(e).strip():
                    email_sources.setdefault(str(e).strip(), set()).add("Document Metadata")
        for e in fingerprint.crawled_emails:
            if e and str(e).strip():
                email_sources.setdefault(str(e).strip(), set()).add("Web Crawler")

        if not email_sources:
            email_table.add_row("None identified", "N/A")
        else:
            for email, sources in sorted(email_sources.items()):
                source_str = " & ".join(sorted(sources))
                email_table.add_row(email, source_str)

        self.console.print(email_table)
        self.console.print()

    def _render_leaks_table(self, fingerprint: OrganizationFingerprint) -> None:
        """Render exposed cloud storage buckets and private network leaks."""
        leak_table = Table(
            title="Exposed Cloud Storage & Network Leaks",
            box=box.SQUARE,
            header_style="bold cyan",
            border_style="cyan",
        )
        leak_table.add_column("Type", style="bold red", width=28)
        leak_table.add_column("Value/URL", style="bold white", overflow="fold")

        leak_rows: list[tuple[str, str]] = []
        for bucket in fingerprint.cloud_buckets:
            bucket_str = str(bucket).strip()
            if not bucket_str:
                continue
            bucket_lower = bucket_str.lower()
            if "s3" in bucket_lower or "amazonaws" in bucket_lower:
                l_type = "AWS S3 Bucket"
            elif "blob" in bucket_lower or "windows.net" in bucket_lower:
                l_type = "Azure Storage Blob"
            elif "storage.googleapis" in bucket_lower:
                l_type = "Google Cloud Storage"
            else:
                l_type = "Cloud Storage Bucket"
            leak_rows.append((l_type, bucket_str))

        for ip in fingerprint.internal_ips:
            if ip and str(ip).strip():
                leak_rows.append(("Private Internal IP", str(ip).strip()))

        for path in fingerprint.discovered_paths:
            if path and str(path).strip():
                leak_rows.append(("Internal File Path", str(path).strip()))

        for printer in fingerprint.discovered_printers:
            if printer and str(printer).strip():
                leak_rows.append(("Internal Printer UNC", str(printer).strip()))

        if not leak_rows:
            leak_table.add_row("None detected", "No cloud storage or private IP leaks identified")
        else:
            for l_type, l_val in sorted(leak_rows, key=lambda x: (x[0], x[1])):
                leak_table.add_row(l_type, l_val)

        self.console.print(leak_table)
        self.console.print()

    def export_json(self, fingerprint: OrganizationFingerprint, file_path: str) -> str:
        """Export fingerprint analysis including all OSINT modules to pretty indented JSON file.

        Args:
            fingerprint: Analyzed OrganizationFingerprint model.
            file_path: Destination path on disk.

        Returns:
            Resolved absolute path of the generated JSON file.
        """
        dest = Path(file_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        json_data = fingerprint.to_dict()
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        return str(dest)

    def export_csv(self, fingerprint: OrganizationFingerprint, file_path: str) -> str:
        """Export extracted documents metadata to tabular CSV file.

        Args:
            fingerprint: Analyzed OrganizationFingerprint model.
            file_path: Destination path on disk.

        Returns:
            Resolved absolute path of the generated CSV file.
        """
        dest = Path(file_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        headers = [
            "Filename",
            "File Path",
            "File Type",
            "Author",
            "Creator Tool",
            "Producer",
            "Company",
            "Creation Date",
            "Modification Date",
            "Extracted Users",
            "Extracted Paths",
            "Extracted Printers",
            "Extracted Emails",
        ]

        with open(dest, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for doc in fingerprint.documents:
                writer.writerow(
                    [
                        os.path.basename(doc.file_path),
                        doc.file_path,
                        doc.file_type,
                        doc.author or "",
                        doc.creator_tool or "",
                        doc.producer or "",
                        doc.company or "",
                        doc.creation_date or "",
                        doc.modification_date or "",
                        "; ".join(doc.extracted_users),
                        "; ".join(doc.extracted_paths),
                        "; ".join(doc.extracted_printers),
                        "; ".join(doc.extracted_emails),
                    ]
                )

        return str(dest)

    def _generate_summary_text(
        self,
        fingerprint: OrganizationFingerprint,
        target_identity: str,
    ) -> str:
        """Generate clean, human-readable plain-text executive briefing."""
        doc_emails = set(fingerprint.discovered_emails)
        for d in fingerprint.documents:
            doc_emails.update(d.extracted_emails)
        all_emails = sorted(
            {e.strip() for e in doc_emails.union(fingerprint.crawled_emails) if e and str(e).strip()}
        )

        all_leaks_set = set(fingerprint.internal_ips)
        all_leaks_set.update(fingerprint.discovered_paths)
        all_leaks_set.update(fingerprint.discovered_printers)
        for doc in fingerprint.documents:
            all_leaks_set.update(doc.extracted_paths)
            all_leaks_set.update(doc.extracted_printers)
        all_leaks = sorted({l.strip() for l in all_leaks_set if l and str(l).strip()})

        lines = [
            "=" * 72,
            "FOCA ORGANIZATIONAL RECONNAISSANCE & METADATA AUDIT REPORT",
            "=" * 72,
            f"Target Identifier       : {target_identity}",
            f"Scan Timestamp          : {fingerprint.scan_timestamp}",
            f"Total Documents Audited : {fingerprint.total_files_analyzed}",
            f"Identified Users/Owners : {len(fingerprint.discovered_users)}",
            f"Discovered Email Addrs  : {len(all_emails)}",
            f"Software / Tools Found  : {len(fingerprint.discovered_software)}",
            f"Operating Systems Found : {len(fingerprint.discovered_operating_systems)}",
            f"Discovered Subdomains   : {fingerprint.subdomain_audit.total_found if fingerprint.subdomain_audit else 0}",
            f"Cloud Storage Buckets   : {len(fingerprint.cloud_buckets)}",
            f"Internal Network Leaks  : {len(all_leaks)}",
            f"Crawled Web Endpoints   : {len(fingerprint.crawled_urls)}",
            "-" * 72,
            "",
            "1. DISCOVERED USERS & DOCUMENT AUTHORS",
            "-" * 40,
        ]
        if fingerprint.discovered_users:
            for u in fingerprint.discovered_users:
                lines.append(f"  - {u}")
        else:
            lines.append("  (None identified)")

        lines.extend([
            "",
            "2. DISCOVERED EMAIL ADDRESSES",
            "-" * 40,
        ])
        if all_emails:
            for e in all_emails:
                lines.append(f"  - {e}")
        else:
            lines.append("  (None discovered)")

        lines.extend([
            "",
            "3. EXPOSED CLOUD STORAGE BUCKETS",
            "-" * 40,
        ])
        if fingerprint.cloud_buckets:
            for b in fingerprint.cloud_buckets:
                lines.append(f"  - {b}")
        else:
            lines.append("  (None identified)")

        lines.extend([
            "",
            "4. INTERNAL NETWORK & PATH LEAKS",
            "-" * 40,
        ])
        if all_leaks:
            for leak in all_leaks:
                lines.append(f"  - {leak}")
        else:
            lines.append("  (None identified)")

        lines.extend([
            "",
            "5. DNS & MAIL INFRASTRUCTURE",
            "-" * 40,
        ])
        if fingerprint.dns_audit:
            lines.append(f"  Mail Provider : {fingerprint.dns_audit.mail_provider or 'Configured'}")
            lines.append(f"  SPF Record    : {fingerprint.dns_audit.spf_record or 'None'}")
            lines.append(f"  DMARC Record  : {fingerprint.dns_audit.dmarc_record or 'None'}")
            if fingerprint.dns_audit.mx_records:
                lines.append("  MX Records    :")
                for mx in fingerprint.dns_audit.mx_records:
                    if isinstance(mx, dict):
                        lines.append(f"    - {mx.get('exchange', mx)} (prio: {mx.get('preference', '-')})")
                    else:
                        lines.append(f"    - {mx}")
            if fingerprint.dns_audit.ns_records:
                lines.append(f"  Name Servers  : {', '.join(fingerprint.dns_audit.ns_records)}")
        else:
            lines.append("  (DNS audit not performed)")

        lines.extend([
            "",
            "6. DISCOVERED SUBDOMAINS",
            "-" * 40,
        ])
        if fingerprint.subdomain_audit and fingerprint.subdomain_audit.subdomains:
            for sub in fingerprint.subdomain_audit.subdomains:
                lines.append(f"  - {sub}")
        else:
            lines.append("  (None discovered)")

        lines.extend([
            "",
            "7. WEB TECHNOLOGY & SECURITY HEADERS",
            "-" * 40,
        ])
        if fingerprint.tech_stack:
            lines.append(f"  Web Server    : {fingerprint.tech_stack.server_banner or 'Undisclosed'}")
            lines.append(f"  Powered By    : {fingerprint.tech_stack.powered_by or 'Undisclosed'}")
            lines.append(f"  Technologies  : {', '.join(fingerprint.tech_stack.detected_technologies) or 'None'}")
            if fingerprint.tech_stack.security_headers:
                lines.append("  Security Headers:")
                for h, present in fingerprint.tech_stack.security_headers.items():
                    status = "PRESENT" if present else "MISSING"
                    lines.append(f"    - {h:30s} : {status}")
        else:
            lines.append("  (Tech stack audit not performed)")

        lines.extend([
            "",
            "8. ANALYZED DOCUMENTS CATALOG",
            "-" * 40,
        ])
        if fingerprint.documents:
            for doc in fingerprint.documents:
                fname = os.path.basename(doc.file_path)
                author = doc.author or (doc.extracted_users[0] if doc.extracted_users else "Unknown")
                lines.append(f"  - {fname} ({doc.file_type.upper()}) | Author: {author}")
        else:
            lines.append("  (No documents analyzed)")

        lines.extend(["", "=" * 72, "END OF REPORT", "=" * 72, ""])
        return "\n".join(lines)

    def render_export_box(self, output_dir: str, file_paths: dict[str, str]) -> None:
        """Render a prominent Rich Box displaying the destination folder and generated report files."""
        lines = [
            f"[bold white]Output Directory :[/bold white] [bold cyan]{output_dir}[/bold cyan]",
            "",
            "[bold white]Generated Reconnaissance Artifacts:[/bold white]",
            "  [bold green][+][/bold green] [bold white]full_report.json[/bold white]           : Complete structured JSON intelligence report",
            "  [bold green][+][/bold green] [bold white]metadata_catalog.csv[/bold white]       : Tabular document metadata and authorship catalog",
            "  [bold green][+][/bold green] [bold white]emails.txt[/bold white]                 : Discovered employee email addresses",
            "  [bold green][+][/bold green] [bold white]subdomains.txt[/bold white]             : Discovered subdomains attack surface",
            "  [bold green][+][/bold green] [bold white]cloud_buckets.txt[/bold white]          : Identified AWS, GCP, and Azure storage buckets",
            "  [bold green][+][/bold green] [bold white]internal_network_leaks.txt[/bold white] : Private IPs, local system paths, and printer leaks",
            "  [bold green][+][/bold green] [bold white]crawled_urls.txt[/bold white]           : Crawled web endpoints and discovered links",
            "  [bold green][+][/bold green] [bold white]summary.txt[/bold white]                : Clean executive plain-text reconnaissance briefing",
        ]
        panel = Panel(
            "\n".join(lines),
            title="[bold cyan]FOCA SCAN ARTIFACTS SAVED[/bold cyan]",
            border_style="green",
            box=box.ROUNDED,
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()

    def export_all(
        self,
        fingerprint: OrganizationFingerprint,
        target_identity: str,
        output_base_dir: str = "./foca_output",
        print_box: bool = True,
    ) -> dict[str, str]:
        """Export all 8 intelligence files to <output_base_dir>/<clean_target>/ and display summary box.

        Args:
            fingerprint: Analyzed OrganizationFingerprint model.
            target_identity: Target domain or scan identifier.
            output_base_dir: Base directory for output folders.
            print_box: Whether to render the prominent Rich summary box to console.

        Returns:
            Dictionary mapping artifact names and keys to absolute file paths.
        """
        raw_target = (
            target_identity.strip()
            .replace("https://", "")
            .replace("http://", "")
            .rstrip("/")
        )
        clean_target = re.sub(r'[\\/*?:"<>|\s]', "_", raw_target).strip("._") or "scan"
        target_dir = (Path(output_base_dir) / clean_target).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        # 1. full_report.json
        json_path = target_dir / "full_report.json"
        self.export_json(fingerprint, str(json_path))

        # 2. metadata_catalog.csv
        csv_path = target_dir / "metadata_catalog.csv"
        self.export_csv(fingerprint, str(csv_path))

        # 3. emails.txt
        emails_path = target_dir / "emails.txt"
        doc_emails = set(fingerprint.discovered_emails)
        for doc in fingerprint.documents:
            doc_emails.update(doc.extracted_emails)
        all_emails = sorted(
            {e.strip() for e in doc_emails.union(fingerprint.crawled_emails) if e and str(e).strip()}
        )
        with open(emails_path, "w", encoding="utf-8") as f:
            for email in all_emails:
                f.write(f"{email}\n")

        # 4. subdomains.txt
        subdomains_path = target_dir / "subdomains.txt"
        subdomains = []
        if fingerprint.subdomain_audit and fingerprint.subdomain_audit.subdomains:
            subdomains = sorted(
                {s.strip() for s in fingerprint.subdomain_audit.subdomains if s and str(s).strip()}
            )
        with open(subdomains_path, "w", encoding="utf-8") as f:
            for sub in subdomains:
                f.write(f"{sub}\n")

        # 5. cloud_buckets.txt
        cloud_buckets_path = target_dir / "cloud_buckets.txt"
        buckets = sorted(
            {b.strip() for b in fingerprint.cloud_buckets if b and str(b).strip()}
        )
        with open(cloud_buckets_path, "w", encoding="utf-8") as f:
            for b in buckets:
                f.write(f"{b}\n")

        # 6. internal_network_leaks.txt
        internal_leaks_path = target_dir / "internal_network_leaks.txt"
        all_leaks_set = set(fingerprint.internal_ips)
        all_leaks_set.update(fingerprint.discovered_paths)
        all_leaks_set.update(fingerprint.discovered_printers)
        for doc in fingerprint.documents:
            all_leaks_set.update(doc.extracted_paths)
            all_leaks_set.update(doc.extracted_printers)
        leaks = sorted({l.strip() for l in all_leaks_set if l and str(l).strip()})
        with open(internal_leaks_path, "w", encoding="utf-8") as f:
            for leak in leaks:
                f.write(f"{leak}\n")

        # 7. crawled_urls.txt
        crawled_urls_path = target_dir / "crawled_urls.txt"
        urls = sorted({u.strip() for u in fingerprint.crawled_urls if u and str(u).strip()})
        with open(crawled_urls_path, "w", encoding="utf-8") as f:
            for u in urls:
                f.write(f"{u}\n")

        # 8. summary.txt
        summary_path = target_dir / "summary.txt"
        summary_text = self._generate_summary_text(fingerprint, target_identity)
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary_text)

        result_map = {
            "json": str(json_path),
            "csv": str(csv_path),
            "emails": str(emails_path),
            "subdomains": str(subdomains_path),
            "cloud_buckets": str(cloud_buckets_path),
            "internal_network_leaks": str(internal_leaks_path),
            "crawled_urls": str(crawled_urls_path),
            "summary": str(summary_path),
            "full_report.json": str(json_path),
            "metadata_catalog.csv": str(csv_path),
            "emails.txt": str(emails_path),
            "subdomains.txt": str(subdomains_path),
            "cloud_buckets.txt": str(cloud_buckets_path),
            "internal_network_leaks.txt": str(internal_leaks_path),
            "crawled_urls.txt": str(crawled_urls_path),
            "summary.txt": str(summary_path),
        }

        if print_box:
            self.render_export_box(str(target_dir), result_map)

        return result_map
