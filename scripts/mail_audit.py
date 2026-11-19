#!/usr/bin/env python3
"""Mail Audit: Check email servers, SPF, and DMARC security for any domain.

Usage:
    python scripts/mail_audit.py <domain>
"""

import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from foca_core.dns_audit import DNSAuditor
from foca_core.reporter import FocaReporter


def main() -> int:
    console = Console()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        console.print(
            Panel(
                "[bold cyan]Mail & Domain Security Audit[/bold cyan]\n"
                "Inspects MX servers, SPF records, DMARC policies, and mail hygiene.\n\n"
                "[bold white]Usage:[/bold white]\n"
                "  python scripts/mail_audit.py <domain>\n\n"
                "[bold white]Example:[/bold white]\n"
                "  python scripts/mail_audit.py example.com",
                title="[bold cyan]FOCA Mail Audit[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return 0

    domain = sys.argv[1].strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split(":")[0]

    console.print(f"[bold cyan][*] Auditing mail security for:[/] [bold white]{domain}[/]")
    with console.status("[bold cyan]Resolving DNS & mail records...", spinner="dots"):
        result = DNSAuditor().audit(domain)

    reporter = FocaReporter(console)
    console.print()
    reporter.render_dns_audit(result)
    console.print()

    # Security Evaluation Card
    spf_status = "[bold green]Protected[/bold green]" if result.spf_record else "[bold red]Vulnerable (Missing SPF)[/bold red]"
    dmarc_status = "[bold green]Protected[/bold green]" if result.dmarc_record else "[bold red]Vulnerable (Missing DMARC)[/bold red]"

    summary_table = Table(
        title="Email Spoofing Defense Evaluation",
        box=box.ROUNDED,
        border_style="cyan",
    )
    summary_table.add_column("Security Control", style="bold white")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Details", style="dim white")

    summary_table.add_row(
        "SPF Record",
        spf_status,
        result.spf_record or "No SPF rule found. Domain may be spoofed.",
    )
    summary_table.add_row(
        "DMARC Policy",
        dmarc_status,
        result.dmarc_record or "No DMARC rule found. Domain has no reject/quarantine policy.",
    )
    summary_table.add_row(
        "Mail Provider",
        f"[bold cyan]{result.mail_provider or 'Unknown'}[/bold cyan]",
        f"{len(result.mx_records)} MX server(s) configured",
    )

    console.print(summary_table)
    console.print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
