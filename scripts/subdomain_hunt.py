#!/usr/bin/env python3
"""Subdomain Hunt: Fast passive subdomain discovery via Certificate Transparency.

Usage:
    python scripts/subdomain_hunt.py <domain> [--save]
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

from foca_core.subdomains import SubdomainFinder


def main() -> int:
    console = Console()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        console.print(
            Panel(
                "[bold cyan]Passive Subdomain Hunter[/bold cyan]\n"
                "Finds active and historical subdomains using Certificate Transparency logs.\n"
                "Sends zero packets to the target server.\n\n"
                "[bold white]Usage:[/bold white]\n"
                "  python scripts/subdomain_hunt.py <domain> [--save]\n\n"
                "[bold white]Example:[/bold white]\n"
                "  python scripts/subdomain_hunt.py example.com\n"
                "  python scripts/subdomain_hunt.py example.com --save",
                title="[bold cyan]FOCA Subdomain Hunt[/bold cyan]",
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

    save_to_file = "--save" in sys.argv

    console.print(f"[bold cyan][*] Querying Certificate Transparency logs for:[/] [bold white]{domain}[/]")
    with console.status("[bold cyan]Searching public certificates...", spinner="dots"):
        result = SubdomainFinder().discover(domain)

    console.print()
    if result.total_found == 0:
        console.print(f"[bold yellow][!] No subdomains discovered for {domain}.[/]")
        return 0

    table = Table(
        title=f"Discovered Subdomains for {domain} (Total: {result.total_found})",
        box=box.ROUNDED,
        border_style="cyan",
    )
    table.add_column("No.", justify="right", style="dim white", width=6)
    table.add_column("Subdomain FQDN", style="bold white")

    for i, sub in enumerate(result.subdomains, start=1):
        table.add_row(str(i), sub)

    console.print(table)
    console.print()

    if save_to_file:
        out_dir = Path("./foca_output")
        out_dir.mkdir(parents=True, exist_ok=True)
        txt_path = out_dir / f"subdomains_{domain}.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            for sub in result.subdomains:
                f.write(sub + "\n")
        console.print(f"[bold green][+] Saved {result.total_found} subdomains to:[/] [bold white]{txt_path}[/]\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
