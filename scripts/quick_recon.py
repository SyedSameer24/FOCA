#!/usr/bin/env python3
"""Quick Recon: Fast passive reconnaissance for any domain.

Usage:
    python scripts/quick_recon.py <domain>
"""

import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.panel import Panel
from rich import box

from foca_core.dns_audit import DNSAuditor
from foca_core.tech_stack import TechStackAnalyzer
from foca_core.subdomains import SubdomainFinder
from foca_core.whois_lookup import WhoisLookup
from foca_core.reporter import FocaReporter
from foca_core.models import OrganizationFingerprint


def main() -> int:
    console = Console()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        console.print(
            Panel(
                "[bold cyan]Quick Recon Script[/bold cyan]\n"
                "Runs fast passive reconnaissance (DNS + Web Tech + Subdomains + Whois) in seconds.\n\n"
                "[bold white]Usage:[/bold white]\n"
                "  python scripts/quick_recon.py <domain>\n\n"
                "[bold white]Example:[/bold white]\n"
                "  python scripts/quick_recon.py example.com",
                title="[bold cyan]FOCA Quick Recon[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return 0

    domain = sys.argv[1].strip().lower()
    # Clean protocol/slashes
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split(":")[0]

    console.print(f"[bold cyan][*] Running Quick Recon against:[/] [bold white]{domain}[/]")
    reporter = FocaReporter(console)

    dns_audit = None
    tech_stack = None
    subdomains = None
    whois_info = None

    with console.status("[bold cyan]Gathering intelligence...", spinner="dots"):
        try:
            dns_audit = DNSAuditor().audit(domain)
        except Exception as e:
            console.print(f"[bold red][-] DNS audit error:[/] {e}")

        try:
            tech_stack = TechStackAnalyzer().analyze(domain)
        except Exception as e:
            console.print(f"[bold red][-] Tech stack error:[/] {e}")

        try:
            subdomains = SubdomainFinder().discover(domain)
        except Exception as e:
            console.print(f"[bold red][-] Subdomain error:[/] {e}")

        try:
            whois_info = WhoisLookup().lookup(domain)
        except Exception as e:
            console.print(f"[bold red][-] Whois error:[/] {e}")

    # Render results
    console.print()
    if dns_audit:
        reporter.render_dns_audit(dns_audit)
        console.print()

    if tech_stack:
        reporter.render_tech_stack(tech_stack)
        console.print()

    if subdomains and subdomains.total_found > 0:
        reporter.render_subdomains(subdomains)
        console.print()

    if whois_info:
        reporter.render_whois(whois_info)
        console.print()

    console.print(f"[bold green][+] Quick Recon complete for:[/] [bold white]{domain}[/]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
