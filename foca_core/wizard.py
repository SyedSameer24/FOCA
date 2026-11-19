"""Interactive Terminal UI (TUI) Wizard for FOCA CLI."""

import os
from pathlib import Path
import re
from typing import Any, Optional
import urllib.parse

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text


class InteractiveWizard:
    """Rich interactive configuration wizard guiding users through FOCA OSINT setup."""

    DEFAULT_ALL_EXTENSIONS = ["pdf", "docx", "xlsx", "pptx", "jpg", "png"]
    DEFAULT_DOC_EXTENSIONS = ["pdf", "docx", "xlsx", "pptx"]
    DEFAULT_IMG_EXTENSIONS = ["jpg", "png"]

    MODE_SPECS = {
        "1": {
            "key": "documents",
            "label": "Document Metadata Scraper (FOCA Core)",
            "desc": "Search engine dorking & metadata harvesting from public documents",
            "modules": ["documents"],
            "requires_docs": True,
            "is_local": False,
        },
        "2": {
            "key": "dns",
            "label": "DNS & Mail Server Audit",
            "desc": "Audit A, AAAA, MX, NS, TXT, SPF, and DMARC configurations",
            "modules": ["dns"],
            "requires_docs": False,
            "is_local": False,
        },
        "3": {
            "key": "subdomains",
            "label": "Passive Subdomain Discovery",
            "desc": "Enumerate subdomains using Certificate Transparency logs (crt.sh)",
            "modules": ["subdomains"],
            "requires_docs": False,
            "is_local": False,
        },
        "4": {
            "key": "tech",
            "label": "Web Tech & Security Headers",
            "desc": "Analyze web server banners, frameworks, and HTTP security headers",
            "modules": ["tech"],
            "requires_docs": False,
            "is_local": False,
        },
        "5": {
            "key": "whois",
            "label": "Domain Registration / Whois",
            "desc": "Query domain registrar, registration dates, and nameservers via RDAP",
            "modules": ["whois"],
            "requires_docs": False,
            "is_local": False,
        },
        "6": {
            "key": "social",
            "label": "Social Media Profiles",
            "desc": "Discover public social profiles linked on organization homepage",
            "modules": ["social"],
            "requires_docs": False,
            "is_local": False,
        },
        "7": {
            "key": "all",
            "label": "Full Organization Footprint (All modules combined)",
            "desc": "Run metadata scraper, DNS, subdomains, tech stack, whois, and social reconnaissance",
            "modules": ["documents", "dns", "subdomains", "tech", "whois", "social"],
            "requires_docs": True,
            "is_local": False,
        },
        "8": {
            "key": "local",
            "label": "Local Directory Document Audit",
            "desc": "Analyze metadata from documents stored in a local offline directory",
            "modules": ["documents"],
            "requires_docs": True,
            "is_local": True,
        },
    }

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def print_splash_banner(self) -> None:
        """Render high-impact, emoji-free ASCII art banner with system metadata."""
        ascii_art = (
            "  ███████╗ ██████╗  ██████╗  █████╗ \n"
            "  ██╔════╝██╔═══██╗██╔════╝ ██╔══██╗\n"
            "  █████╗  ██║   ██║██║      ███████║\n"
            "  ██╔══╝  ██║   ██║██║      ██╔══██║\n"
            "  ██║     ╚██████╔╝╚██████╗ ██║  ██║\n"
            "  ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝"
        )

        header_text = Text()
        header_text.append(ascii_art + "\n\n", style="bold cyan")
        header_text.append(
            "Document Metadata & Organizational OSINT Reconnaissance Engine\n",
            style="bold white",
        )
        header_text.append(
            "Version: v2.4.0-cli  |  License: Open Source  |  Arch: Cross-Platform (Windows & Linux)\n",
            style="dim white",
        )

        banner_panel = Panel(
            header_text,
            title="[bold cyan]FOCA INTERACTIVE SETUP WIZARD[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        self.console.print(banner_panel)
        self.console.print()

    @staticmethod
    def sanitize_domain(raw_input: str) -> str:
        """Strip protocols, paths, query parameters, credentials, and port numbers from input."""
        cleaned = raw_input.strip()
        if not cleaned:
            return ""

        if "://" not in cleaned:
            cleaned = "http://" + cleaned

        parsed = urllib.parse.urlsplit(cleaned)
        host = parsed.netloc or parsed.path.split("/")[0]

        if "@" in host:
            host = host.split("@")[-1]

        if ":" in host:
            host = host.split(":")[0]

        return host.lower().strip()

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate if the string is a valid hostname, FQDN, or IP address."""
        if not domain or len(domain) > 253 or " " in domain or ".." in domain:
            return False

        if domain == "localhost":
            return True

        # IPv4 pattern
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ipv4_pattern, domain):
            parts = domain.split(".")
            return all(0 <= int(p) <= 255 for p in parts)

        # Standard domain regex (RFC 1123 compliant labels)
        domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9\-]{2,}$"
        return bool(re.match(domain_pattern, domain))

    def step_operational_mode(self) -> str:
        """Prompt user for operational mode selection."""
        table = Table(
            title="Step 1: Operational Mode Selection",
            title_style="bold cyan",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
        )
        table.add_column("Option", style="bold cyan", justify="center", width=8)
        table.add_column("Operational Mode", style="bold white", width=36)
        table.add_column("Description", style="dim white")

        for key, spec in self.MODE_SPECS.items():
            table.add_row(f"[{key}]", spec["label"], spec["desc"])

        self.console.print(table)
        self.console.print()

        choice = Prompt.ask(
            "[bold yellow]Select operational mode [1-8][/bold yellow]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8"],
            default="1",
            console=self.console,
        )
        self.console.print()
        return choice

    def step_target_specification(self, mode_choice: str) -> tuple[str, Optional[str]]:
        """Prompt and validate target domain/URL or local directory path.

        Returns:
            Tuple of (domain, local_dir).
        """
        spec = self.MODE_SPECS.get(mode_choice, self.MODE_SPECS["1"])
        self.console.print("[bold cyan]Step 2: Target Specification[/bold cyan]")

        if not spec["is_local"]:
            while True:
                raw_target = Prompt.ask(
                    "[bold yellow]Enter target domain or URL[/bold yellow] (e.g. example.com)",
                    console=self.console,
                )
                domain = self.sanitize_domain(raw_target)
                if self.is_valid_domain(domain):
                    self.console.print(
                        f"[bold green][+][/bold green] Target domain validated: [bold white]{domain}[/bold white]\n"
                    )
                    return domain, None
                self.console.print(
                    "[bold red][-][/bold red] Invalid domain format. Please enter a valid domain or URL (e.g. target.com).\n"
                )
        else:
            while True:
                raw_dir = Prompt.ask(
                    "[bold yellow]Enter local directory path to scan[/bold yellow]",
                    console=self.console,
                )
                expanded = Path(raw_dir.strip()).expanduser().resolve()
                if expanded.is_dir():
                    dir_str = str(expanded)
                    self.console.print(
                        f"[bold green][+][/bold green] Local directory verified: [bold white]{dir_str}[/bold white]\n"
                    )
                    return "", dir_str
                self.console.print(
                    f"[bold red][-][/bold red] Directory not found: [white]{raw_dir}[/white]. Please specify an existing folder.\n"
                )

    def step_file_formats(self) -> list[str]:
        """Prompt user for target file format selection."""
        table = Table(
            title="Step 3: Target File Formats",
            title_style="bold cyan",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
        )
        table.add_column("Option", style="bold cyan", justify="center", width=8)
        table.add_column("Format Profile", style="bold white", width=24)
        table.add_column("Extensions Included", style="yellow")

        table.add_row(
            "[1]",
            "All Formats",
            ", ".join(self.DEFAULT_ALL_EXTENSIONS),
        )
        table.add_row(
            "[2]",
            "Documents Only",
            ", ".join(self.DEFAULT_DOC_EXTENSIONS),
        )
        table.add_row(
            "[3]",
            "Images Only",
            ", ".join(self.DEFAULT_IMG_EXTENSIONS),
        )
        table.add_row(
            "[4]",
            "Custom Selection",
            "User-specified comma-separated list",
        )

        self.console.print(table)
        self.console.print()

        choice = Prompt.ask(
            "[bold yellow]Select target file formats [1-4][/bold yellow]",
            choices=["1", "2", "3", "4"],
            default="1",
            console=self.console,
        )

        if choice == "1":
            selected = list(self.DEFAULT_ALL_EXTENSIONS)
        elif choice == "2":
            selected = list(self.DEFAULT_DOC_EXTENSIONS)
        elif choice == "3":
            selected = list(self.DEFAULT_IMG_EXTENSIONS)
        else:
            while True:
                custom_input = Prompt.ask(
                    "[bold yellow]Enter comma-separated file extensions[/bold yellow] (e.g. pdf,xlsx)",
                    default="pdf,docx",
                    console=self.console,
                )
                selected = [
                    ext.strip().lstrip(".").lower()
                    for ext in custom_input.split(",")
                    if ext.strip()
                ]
                if selected:
                    break
                self.console.print(
                    "[bold red][-][/bold red] At least one valid file extension must be specified.\n"
                )

        self.console.print(
            f"[bold green][+][/bold green] Target formats configured: [yellow]{', '.join(selected)}[/yellow]\n"
        )
        return selected

    def step_scope_and_limits(self) -> tuple[int, str]:
        """Prompt user for document limit and output directory."""
        self.console.print("[bold cyan]Step 4: Scope & Limits[/bold cyan]")

        max_files = IntPrompt.ask(
            "[bold yellow]Max documents limit[/bold yellow]",
            default=25,
            console=self.console,
        )
        if max_files <= 0:
            max_files = 25

        output_dir = Prompt.ask(
            "[bold yellow]Output directory path[/bold yellow]",
            default="./foca_output",
            console=self.console,
        )
        self.console.print(
            f"[bold green][+][/bold green] Limits configured: max [white]{max_files}[/white] files, output to [white]{output_dir}[/white]\n"
        )
        return max_files, output_dir

    def step_output_dir_only(self) -> str:
        """Prompt user for output directory path when file downloading is skipped."""
        self.console.print("[bold cyan]Step 3: Output Configuration[/bold cyan]")

        output_dir = Prompt.ask(
            "[bold yellow]Output directory path[/bold yellow]",
            default="./foca_output",
            console=self.console,
        )
        self.console.print(
            f"[bold green][+][/bold green] Output directory configured: [white]{output_dir}[/white]\n"
        )
        return output_dir

    def step_preflight_review(
        self,
        mode_key: str,
        mode_label: str,
        target_display: str,
        selected_modules: list[str],
        file_types: list[str],
        max_files: int,
        output_dir: str,
        spider_enabled: bool,
    ) -> bool:
        """Display Pre-Flight Review Card and confirm execution."""
        review_table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 2),
            expand=True,
        )
        review_table.add_column("Parameter", style="bold cyan", width=22)
        review_table.add_column("Configuration", style="bold white")

        review_table.add_row("Operational Mode", mode_label)
        review_table.add_row("Target Identifier", target_display)
        review_table.add_row("Active Modules", ", ".join(selected_modules).upper())

        if file_types:
            review_table.add_row("Target Extensions", ", ".join(file_types).upper())
        else:
            review_table.add_row("Target Extensions", "[dim white]N/A (Network Recon)[/dim white]")

        if max_files > 0:
            review_table.add_row("Document Cap Limit", str(max_files))
        else:
            review_table.add_row("Document Cap Limit", "[dim white]N/A (Network Recon)[/dim white]")

        review_table.add_row("Output Directory", output_dir)
        review_table.add_row(
            "Active Spider Crawl",
            "[bold green]Enabled[/bold green]"
            if spider_enabled
            else "[dim white]Disabled[/dim white]",
        )

        review_panel = Panel(
            review_table,
            title="[bold cyan]PRE-FLIGHT SCAN REVIEW[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )

        self.console.print("[bold cyan]Pre-Flight Review & Confirmation[/bold cyan]")
        self.console.print(review_panel)
        self.console.print()

        return Confirm.ask(
            "[bold yellow]Launch analysis scan?[/bold yellow]",
            default=True,
            console=self.console,
        )

    def run(self) -> Optional[dict[str, Any]]:
        """Execute the interactive wizard workflow and return scan configuration dictionary.

        Returns:
            Dictionary with keys: mode, modules, domain, local_dir, spider, file_types, max_files, output_dir.
            Returns None if cancelled or aborted by user.
        """
        try:
            self.print_splash_banner()

            # 1. Operational Mode
            mode_choice = self.step_operational_mode()
            spec = self.MODE_SPECS[mode_choice]
            mode_key = spec["key"]
            mode_label = spec["label"]
            selected_modules = list(spec["modules"])
            requires_docs = spec["requires_docs"]

            # 2. Target Specification
            domain, local_dir = self.step_target_specification(mode_choice)
            target_display = domain if domain else (local_dir or "local_inspection")

            # 3 & 4. File Formats & Limits OR Output Dir Only
            spider_flag = False
            if requires_docs:
                file_types = self.step_file_formats()
                max_files, output_dir = self.step_scope_and_limits()
            else:
                # Modes 2-6 (network-only reconnaissance): skip file download prompts
                file_types = []
                max_files = 0
                output_dir = self.step_output_dir_only()

            # 5. Pre-Flight Review Card
            confirmed = self.step_preflight_review(
                mode_key=mode_key,
                mode_label=mode_label,
                target_display=target_display,
                selected_modules=selected_modules,
                file_types=file_types,
                max_files=max_files,
                output_dir=output_dir,
                spider_enabled=spider_flag,
            )

            if not confirmed:
                self.console.print("\n[bold yellow][!] Scan aborted by user.[/bold yellow]\n")
                return None

            self.console.print("\n[bold green][+][/bold green] Configuration confirmed. Launching scan...\n")

            return {
                "mode": mode_key,
                "modules": selected_modules,
                "domain": domain,
                "local_dir": local_dir,
                "spider": spider_flag,
                "file_types": file_types,
                "max_files": max_files,
                "output_dir": output_dir,
            }

        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[bold yellow][!] Interactive wizard cancelled by user.[/bold yellow]\n")
            return None

    def prompt_post_scan_action(self, current_target: Optional[str] = None) -> str:
        """Prompt user for what they want to do next after completing a scan.

        Returns:
            One of: 'run_module', 'new_target', 'show_reports', 'exit'
        """
        try:
            target_str = current_target or "current target"
            self.console.print()
            table = Table(
                title=f"What Would You Like To Do Next? (Target: {target_str})",
                box=box.ROUNDED,
                border_style="cyan",
            )
            table.add_column("Option", style="bold green", width=10)
            table.add_column("Action", style="bold white", width=32)
            table.add_column("Description", style="dim white")

            table.add_row("[1]", "Run Another Module", f"Run Social Profiles, DNS, Subdomains, etc. on {target_str}")
            table.add_row("[2]", "Start New Scan", "Enter a brand new target domain or folder")
            table.add_row("[3]", "View Report Locations", "Show where saved JSON, CSV, and cache files are stored")
            table.add_row("[4]", "Exit FOCA", "Close the tool and return to terminal")

            self.console.print(table)
            self.console.print()

            choice = Prompt.ask(
                "[bold yellow]Select next action [1-4][/bold yellow]",
                choices=["1", "2", "3", "4", "q", "exit"],
                default="1",
                console=self.console,
            )

            if choice == "1":
                return "run_module"
            elif choice == "2":
                return "new_target"
            elif choice == "3":
                return "show_reports"
            else:
                return "exit"

        except (KeyboardInterrupt, EOFError):
            return "exit"

    def prompt_additional_module(
        self, current_target: str, output_dir: str
    ) -> Optional[dict[str, Any]]:
        """Prompt user to select another module to run on the current target."""
        try:
            self.console.print()
            table = Table(
                title=f"Choose Another Module to Run on {current_target}",
                box=box.ROUNDED,
                border_style="cyan",
            )
            table.add_column("Option", style="bold green", width=10)
            table.add_column("Module", style="bold white", width=30)
            table.add_column("What it does", style="dim white")

            table.add_row("[1]", "Social Media Profiles", "Find official accounts on GitHub, LinkedIn, Twitter/X, etc.")
            table.add_row("[2]", "DNS & Mail Server Audit", "Check A, MX, SPF, DMARC, and email provider security")
            table.add_row("[3]", "Passive Subdomain Discovery", "Discover hidden subdomains via Certificate Transparency")
            table.add_row("[4]", "Web Tech & Security Headers", "Inspect web server banners and HTTP security headers")
            table.add_row("[5]", "Domain Registration (Whois)", "Lookup domain registrar, registration & expiry dates")
            table.add_row("[6]", "Document Metadata Scraper", "Search & harvest public PDFs, Word, and Excel files")
            table.add_row("[7]", "Full Organization Footprint", "Run all reconnaissance modules together")
            table.add_row("[8]", "Back", "Return to the previous menu")

            self.console.print(table)
            self.console.print()

            choice = Prompt.ask(
                "[bold yellow]Select module to run [1-8][/bold yellow]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                default="1",
                console=self.console,
            )

            if choice == "8":
                return None

            modules_map = {
                "1": ("social", ["social"]),
                "2": ("dns", ["dns"]),
                "3": ("subdomains", ["subdomains"]),
                "4": ("tech", ["tech"]),
                "5": ("whois", ["whois"]),
                "6": ("documents", ["documents"]),
                "7": ("all", ["documents", "dns", "subdomains", "tech", "whois", "social"]),
            }

            mode_key, modules_list = modules_map[choice]

            file_types = []
            max_files = 0
            spider_flag = False

            if "documents" in modules_list:
                file_types = self.DEFAULT_ALL_EXTENSIONS
                max_files = 25
                spider_choice = Confirm.ask(
                    "[bold yellow]Enable active web spider crawling on target site?[/bold yellow]",
                    default=False,
                    console=self.console,
                )
                spider_flag = spider_choice

            return {
                "mode": mode_key,
                "modules": modules_list,
                "domain": current_target,
                "local_dir": None,
                "spider": spider_flag,
                "file_types": file_types,
                "max_files": max_files,
                "output_dir": output_dir,
            }

        except (KeyboardInterrupt, EOFError):
            return None

    def show_report_locations(self, output_dir: str, current_target: str) -> None:
        """Display report paths and saved artifact locations."""
        abs_output = os.path.abspath(output_dir)
        self.console.print()
        table = Table(
            title=f"Saved Reports & Files for {current_target}",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("File / Artifact", style="bold white", width=26)
        table.add_column("Location / Path", style="cyan")

        json_file = os.path.join(abs_output, f"foca_fingerprint_{current_target}.json")
        csv_file = os.path.join(abs_output, f"foca_metadata_{current_target}.csv")
        cache_dir = os.path.abspath(os.path.join(".foca_cache", current_target))

        table.add_row("Output Directory", abs_output)
        table.add_row("JSON Intelligence Report", json_file if os.path.exists(json_file) else f"{json_file} (ready)")
        table.add_row("CSV Document Catalog", csv_file if os.path.exists(csv_file) else f"{csv_file} (ready)")
        table.add_row("Downloaded Files Cache", cache_dir if os.path.exists(cache_dir) else f"{cache_dir} (cache)")

        self.console.print(table)
        self.console.print()
