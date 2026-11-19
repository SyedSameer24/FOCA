#!/usr/bin/env python3
"""FOCA CLI: Linux-grade Document Metadata & Organizational OSINT Harvester.

Usage:
    python main.py                     (Interactive TUI Setup Wizard)
    python main.py -d example.com [options]
    python main.py -l ./sample_documents [options]
"""

import argparse
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Optional

# Ensure UTF-8 console encoding for Windows Command Prompt and PowerShell
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from foca_core.analyzer import FingerprintAnalyzer
from foca_core.archive_digger import ArchiveDigger
from foca_core.deep_crawler import DeepCrawler
from foca_core.dns_audit import DNSAuditor
from foca_core.downloader import DocumentDownloader
from foca_core.extractor import MetadataExtractor
from foca_core.models import (
    DNSAuditResult,
    DocumentTarget,
    ExtractedMetadata,
    OrganizationFingerprint,
    SocialProfileResult,
    SubdomainResult,
    TechStackResult,
    WhoisResult,
)
from foca_core.reporter import FocaReporter
from foca_core.scraper import DocumentScraper
from foca_core.social_finder import SocialFinder
from foca_core.subdomains import SubdomainFinder
from foca_core.tech_stack import TechStackAnalyzer
from foca_core.whois_lookup import WhoisLookup
from foca_core.wizard import InteractiveWizard

logger = logging.getLogger("foca")


def print_custom_help(console: Optional[Console] = None) -> None:
    """Render a comprehensive, user-friendly rich command-line help screen."""
    console = console or Console()
    ascii_art = (
        "  ███████╗ ██████╗  ██████╗  █████╗ \n"
        "  ██╔════╝██╔═══██╗██╔════╝ ██╔══██╗\n"
        "  █████╗  ██║   ██║██║      ███████║\n"
        "  ██╔══╝  ██║   ██║██║      ██╔══██║\n"
        "  ██║     ╚██████╔╝╚██████╗ ██║  ██║\n"
        "  ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝"
    )
    console.print(
        Panel(
            f"[bold cyan]{ascii_art}[/]\n\n"
            "[bold white]Document Metadata & Organizational OSINT Reconnaissance Engine[/]\n"
            "[dim white]Version: v2.4.0-cli  |  Cross-Platform (Windows PowerShell, CMD, Linux)[/]",
            title="[bold cyan]FOCA COMMAND-LINE HELP[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    console.print("[bold cyan]BASIC USAGE:[/bold cyan]")
    console.print("  [bold green]python main.py[/bold green]                         [dim]Launch interactive terminal setup wizard[/dim]")
    console.print("  [bold green]python main.py -d <domain> [options][/bold green]  [dim]Run direct automated domain scan[/dim]")
    console.print("  [bold green]python main.py -l <folder> [options][/bold green]  [dim]Run offline local documents audit[/dim]")
    console.print()

    # Target Selection Table
    table_target = Table(title="Target Selection (Choose one target)", box=box.ROUNDED, border_style="cyan")
    table_target.add_column("Option", style="bold green", width=22)
    table_target.add_column("Description", style="white")
    table_target.add_row("-d, --domain <domain>", "Target domain to search and analyze (e.g. example.com)")
    table_target.add_row("-l, --local <folder>", "Local folder path containing documents to audit offline")
    console.print(table_target)
    console.print()

    # OSINT Modules Table
    table_osint = Table(title="OSINT Reconnaissance Modules", box=box.ROUNDED, border_style="cyan")
    table_osint.add_column("Option", style="bold green", width=22)
    table_osint.add_column("Description", style="white")
    table_osint.add_row("--all", "Run full organization footprint (all 6 modules combined)")
    table_osint.add_row("--dns", "Query A, AAAA, MX, NS, TXT, SPF, DMARC, and mail provider")
    table_osint.add_row("--subdomains", "Passive Certificate Transparency subdomain discovery (crt.sh)")
    table_osint.add_row("--tech", "Inspect web server banner, technologies, and HTTP security headers")
    table_osint.add_row("--whois", "Domain registration dates, registrar, and nameservers (RDAP)")
    table_osint.add_row("--social", "Find official social profiles linked on homepage (GitHub, LinkedIn, etc.)")
    console.print(table_osint)
    console.print()

    # Document Scraper Options Table
    table_scrap = Table(title="Document Scraping & Metadata Hunting", box=box.ROUNDED, border_style="cyan")
    table_scrap.add_column("Option", style="bold green", width=22)
    table_scrap.add_column("Default", style="dim cyan", width=14)
    table_scrap.add_column("Description", style="white")
    table_scrap.add_row("-s, --spider", "Disabled", "Direct website spider crawl to harvest linked documents")
    table_scrap.add_row("--deep", "Enabled", "Deep recursive crawl (depth 3, max 50 pages) harvesting emails & leaks")
    table_scrap.add_row("--no-archive", "Disabled", "Disable Wayback Machine historical document discovery")
    table_scrap.add_row("-t, --types <exts>", "pdf,docx,...", "Comma-separated extensions: pdf, docx, xlsx, pptx, jpg, png")
    table_scrap.add_row("-m, --max-files <N>", "20", "Maximum document downloads cap limit")
    table_scrap.add_row("--no-download", "Disabled", "Discover document URLs without downloading or analyzing")
    console.print(table_scrap)
    console.print()

    # Output Options Table
    table_out = Table(title="Output & Scripting Options", box=box.ROUNDED, border_style="cyan")
    table_out.add_column("Option", style="bold green", width=22)
    table_out.add_column("Default", style="dim cyan", width=14)
    table_out.add_column("Description", style="white")
    table_out.add_row("-o, --output <dir>", "./foca_output", "Folder to store generated JSON and CSV reports")
    table_out.add_row("--json", "Disabled", "Output clean raw JSON to stdout (for jq and Linux pipelines)")
    table_out.add_row("--examples", "Disabled", "Show practical real-world command recipes")
    table_out.add_row("-h, --help", "Disabled", "Display this formatted command-line help screen")
    console.print(table_out)
    console.print()

    # Quick Real-World Examples Box
    console.print(
        Panel(
            "[bold white]1. Full Organization Footprint (All Modules):[/bold white]\n"
            "   [bold green]python main.py -d example.com --all[/bold green]\n\n"
            "[bold white]2. Fast DNS & Email Security Hygiene Audit:[/bold white]\n"
            "   [bold green]python main.py -d example.com --dns[/bold green]\n\n"
            "[bold white]3. Passive Subdomain Attack Surface Discovery:[/bold white]\n"
            "   [bold green]python main.py -d example.com --subdomains[/bold green]\n\n"
            "[bold white]4. Web Tech Stack & Security Headers Audit:[/bold white]\n"
            "   [bold green]python main.py -d example.com --tech[/bold green]\n\n"
            "[bold white]5. Document Hunting with Web Spider (PDFs & Office):[/bold white]\n"
            "   [bold green]python main.py -d example.com --spider -t pdf,docx -m 25[/bold green]\n\n"
            "[bold white]6. Offline Local Folder Metadata Audit:[/bold white]\n"
            "   [bold green]python main.py -l C:\\path\\to\\documents -o .\\reports[/bold green]\n\n"
            "[bold white]7. Unix / PowerShell JSON Pipeline:[/bold white]\n"
            "   [bold green]python main.py -d example.com --dns --tech --json | jq .[/bold green]\n\n"
            "[dim white]For more detailed walkthroughs, run:[/] [bold cyan]python main.py --examples[/bold cyan]",
            title="[bold cyan]REAL-WORLD QUICK RECIPES[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()


def print_examples_screen(console: Optional[Console] = None) -> None:
    """Render detailed real-world command recipes and workflows."""
    console = console or Console()
    console.print(
        Panel(
            "[bold cyan]FOCA OSINT & Footprinting Recipes (Real-World Commands)[/bold cyan]\n"
            "Common tasks and workflows you can copy and run directly in your terminal.",
            title="[bold cyan]FOCA RECIPES & EXAMPLES[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    recipes = [
        (
            "1. Fast Network & Infrastructure Triage",
            "Discovers mail servers, DNS rules, web server software, and exposed HTTP headers in ~3 seconds.",
            "python main.py -d example.com --dns --tech",
        ),
        (
            "2. Passive Subdomain Attack Surface Discovery",
            "Queries Certificate Transparency logs to find subdomains without sending any traffic to the target.",
            "python main.py -d example.com --subdomains",
        ),
        (
            "3. Full Footprint (All OSINT Modules)",
            "Runs DNS, subdomains, web tech, whois, social profiles, and searches for public documents.",
            "python main.py -d example.com --all",
        ),
        (
            "4. Harvest & Fingerprint Specific Document Formats",
            "Finds and downloads public PDFs and Word files from a company, extracting usernames and software.",
            "python main.py -d example.com -t pdf,docx -m 25",
        ),
        (
            "5. Active Website Crawling (Spider Mode)",
            "Visits the target website directly and clicks through pages to find linked public files.",
            "python main.py -d example.com --spider -m 30",
        ),
        (
            "6. Offline Local Folder Metadata Inspection",
            "Audits documents sitting in a local directory on your PC and creates an Excel CSV report.",
            "python main.py -l C:\\path\\to\\documents -o .\\foca_output",
        ),
        (
            "7. JSON Automation for Linux Pipelines (jq / grep)",
            "Suppresses the terminal UI and outputs raw machine-readable JSON to stdout.",
            "python main.py -d example.com --dns --tech --json | jq .",
        ),
    ]

    for title, desc, cmd in recipes:
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
        table.add_column("Key", style="bold white", width=16)
        table.add_column("Value", style="cyan")
        table.add_row("Task", f"[bold white]{title}[/bold white]")
        table.add_row("What it does", f"[dim white]{desc}[/dim white]")
        table.add_row("Command", f"[bold green]{cmd}[/bold green]")
        console.print(table)
        console.print()


def parse_arguments() -> argparse.Namespace:
    """Configure and parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="foca",
        description="FOCA CLI - Advanced Document Metadata Analysis & Organizational OSINT Engine",
        add_help=False,
    )

    help_group = parser.add_argument_group("Help & Documentation")
    help_group.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Display formatted rich command-line help screen",
    )
    help_group.add_argument(
        "--examples",
        action="store_true",
        help="Show real-world workflow recipes and command examples",
    )

    mode_group = parser.add_argument_group("Target Selection (at least one required)")
    mode_group.add_argument(
        "-d",
        "--domain",
        type=str,
        help="Target domain to search for public documents (e.g. example.com)",
    )
    mode_group.add_argument(
        "-l",
        "--local",
        type=str,
        help="Local directory path containing documents to analyze",
    )

    osint_group = parser.add_argument_group("OSINT & Reconnaissance Modules")
    osint_group.add_argument(
        "--dns",
        action="store_true",
        help="Run DNS enumeration and mail server security audit",
    )
    osint_group.add_argument(
        "--subdomains",
        action="store_true",
        help="Run passive subdomain discovery via Certificate Transparency logs",
    )
    osint_group.add_argument(
        "--tech",
        action="store_true",
        help="Analyze web server technology and HTTP security headers",
    )
    osint_group.add_argument(
        "--whois",
        action="store_true",
        help="Perform domain registration and RDAP whois lookup",
    )
    osint_group.add_argument(
        "--social",
        action="store_true",
        help="Find public social media profiles linked on target domain",
    )
    osint_group.add_argument(
        "--all",
        action="store_true",
        help="Run full organization footprint (all modules combined)",
    )

    opt_group = parser.add_argument_group("Scraping & Discovery Options")
    opt_group.add_argument(
        "--passive",
        action="store_true",
        default=False,
        help="Run 100% stealth passive OSINT without sending direct crawl or spider traffic to target domain",
    )
    opt_group.add_argument(
        "-s",
        "--spider",
        action="store_true",
        help="Enable internal web spider crawling on the target domain",
    )
    opt_group.add_argument(
        "--deep",
        action="store_true",
        default=True,
        help="Enable deep recursive web crawling and link extraction (depth 3, max 50 pages) [default: Enabled]",
    )
    opt_group.add_argument(
        "--no-deep",
        action="store_false",
        dest="deep",
        help="Disable deep recursive crawler",
    )
    opt_group.add_argument(
        "--no-archive",
        action="store_true",
        default=False,
        help="Disable querying the Wayback Machine archive for historical documents",
    )
    opt_group.add_argument(
        "-t",
        "--types",
        type=str,
        default="pdf,docx,xlsx,pptx,jpg,png",
        help="Comma-separated file extensions to target (default: pdf,docx,xlsx,pptx,jpg,png)",
    )
    opt_group.add_argument(
        "-m",
        "--max-files",
        type=int,
        default=20,
        help="Maximum number of documents to discover or download (default: 20)",
    )

    out_group = parser.add_argument_group("Output & Execution Options")
    out_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="./foca_output",
        help="Output directory path for reports and cache (default: ./foca_output)",
    )
    out_group.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON to stdout (suppresses rich terminal UI for piping/scripting)",
    )
    out_group.add_argument(
        "--no-download",
        action="store_true",
        help="In domain mode, discover target URLs without downloading or analyzing them",
    )

    return parser.parse_args()


def run_pipeline(
    domain: Optional[str] = None,
    local_dir: Optional[str] = None,
    spider: bool = False,
    deep: bool = True,
    no_archive: bool = False,
    file_types: Optional[list[str]] = None,
    max_files: int = 20,
    output_dir_str: str = "./foca_output",
    json_mode: bool = False,
    no_download: bool = False,
    mode: Optional[str] = None,
    reporter: Optional[FocaReporter] = None,
    modules: Optional[list[str]] = None,
    run_dns: bool = False,
    run_subdomains: bool = False,
    run_tech: bool = False,
    run_whois: bool = False,
    run_social: bool = False,
    run_documents: bool = True,
    passive: bool = False,
) -> int:
    """Execute the end-to-end discovery, download, extraction, OSINT, and reporting pipeline."""
    reporter = reporter or FocaReporter()

    if passive:
        spider = False
        deep = False

    # Determine active modules from parameter or flags
    if modules is not None:
        run_dns = "dns" in modules or "all" in modules
        run_subdomains = "subdomains" in modules or "all" in modules
        run_tech = "tech" in modules or "all" in modules
        run_whois = "whois" in modules or "all" in modules
        run_social = "social" in modules or "all" in modules
        run_documents = "documents" in modules

    types = file_types or ["pdf", "docx", "xlsx", "pptx", "jpg", "png"]
    target_identity = (
        domain.strip()
        if domain
        else (os.path.basename(os.path.abspath(local_dir)) if local_dir else "local_inspection")
    )

    # 1. Terminal Banner & Info (Suppressed in JSON mode; banner printed once)
    if not json_mode:
        if not mode:
            reporter.print_banner()
        reporter.print_info(f"Target identifier : [cyan]{target_identity}[/cyan]")

        active_mod_labels = []
        if run_documents:
            active_mod_labels.append("Document Scraper")
            if deep:
                active_mod_labels.append("Deep Crawler (50 pages)")
            if not no_archive:
                active_mod_labels.append("Wayback Archive Digger")
        if run_dns:
            active_mod_labels.append("DNS & Mail Audit")
        if run_subdomains:
            active_mod_labels.append("Subdomain Discovery")
        if run_tech:
            active_mod_labels.append("Web Tech & Headers")
        if run_whois:
            active_mod_labels.append("Whois / RDAP")
        if run_social:
            active_mod_labels.append("Social Profiles")

        if active_mod_labels:
            reporter.print_info(f"Active modules    : [green]{', '.join(active_mod_labels)}[/green]")

        if run_documents:
            reporter.print_info(f"Target extensions : [yellow]{', '.join(types)}[/yellow]")
            reporter.print_info(f"Max documents cap : [white]{max_files}[/white]")
            if passive:
                reporter.print_info("Recon mode        : [green]Passive Stealth (zero crawl traffic to target)[/green]")
            elif deep:
                reporter.print_info("Deep crawl engine : [green]Enabled (Depth 3, Max 50 pages)[/green]")
            elif spider:
                reporter.print_info("Active crawling   : [green]Enabled (Depth 2, Max 30 pages)[/green]")

    # 2. Execute OSINT Modules (if enabled and domain available)
    dns_result: Optional[DNSAuditResult] = None
    subdomain_result: Optional[SubdomainResult] = None
    tech_result: Optional[TechStackResult] = None
    whois_result: Optional[WhoisResult] = None
    social_result: Optional[SocialProfileResult] = None

    clean_domain = domain.strip() if domain else None

    if run_dns and clean_domain:
        if not json_mode:
            reporter.print_info("Executing DNS and mail infrastructure audit...")
        try:
            auditor = DNSAuditor()
            dns_result = auditor.audit(clean_domain)
        except Exception as e:
            if not json_mode:
                reporter.print_warning(f"DNS audit encounter error: {e}")
            logger.debug("DNS audit error: %s", e)

    if run_subdomains and clean_domain:
        if not json_mode:
            reporter.print_info("Discovering subdomains via Certificate Transparency...")
        try:
            sub_finder = SubdomainFinder()
            subdomain_result = sub_finder.discover(clean_domain)
        except Exception as e:
            if not json_mode:
                reporter.print_warning(f"Subdomain discovery encounter error: {e}")
            logger.debug("Subdomain discovery error: %s", e)

    if run_tech and clean_domain:
        if not json_mode:
            reporter.print_info("Analyzing web technology stack and security headers...")
        try:
            tech_analyzer = TechStackAnalyzer()
            tech_result = tech_analyzer.analyze(clean_domain)
        except Exception as e:
            if not json_mode:
                reporter.print_warning(f"Tech stack analysis encounter error: {e}")
            logger.debug("Tech stack error: %s", e)

    if run_whois and clean_domain:
        if not json_mode:
            reporter.print_info("Querying domain registration and RDAP records...")
        try:
            whois_lookup = WhoisLookup()
            whois_result = whois_lookup.lookup(clean_domain)
        except Exception as e:
            if not json_mode:
                reporter.print_warning(f"Whois lookup encounter error: {e}")
            logger.debug("Whois error: %s", e)

    if run_social and clean_domain:
        if not json_mode:
            reporter.print_info("Searching for public social media profiles...")
        try:
            social_finder = SocialFinder()
            social_result = social_finder.find_profiles(clean_domain)
        except Exception as e:
            if not json_mode:
                reporter.print_warning(f"Social profile search encounter error: {e}")
            logger.debug("Social search error: %s", e)

    # 3. Document Discovery & Download Pipeline (if run_documents is True)
    targets: list[DocumentTarget] = []
    metadata_list: list[ExtractedMetadata] = []

    crawled_emails: list[str] = []
    cloud_buckets: list[str] = []
    internal_ips: list[str] = []
    crawled_urls: list[str] = []
    archive_documents: list[str] = []

    if run_documents:
        if not json_mode:
            reporter.print_info("Initializing document discovery subsystem...")

        if local_dir:
            scraper = DocumentScraper()
            targets = scraper.scan_local_directory(local_dir, types, max_results=max_files)
        else:
            discovered_targets: list[DocumentTarget] = []
            seen_target_urls: set[str] = set()

            # A. Deep Recursive Crawler (depth 3, max 50 pages)
            if deep and clean_domain:
                if not json_mode:
                    reporter.print_info("Executing DeepCrawler across web pages, robots.txt, and sitemaps...")

                def crawl_callback(msg: str) -> None:
                    if not json_mode:
                        reporter.console.print(f"[bold cyan][*] {msg}[/bold cyan]")

                try:
                    deep_crawler = DeepCrawler(max_depth=3, max_pages=50)
                    crawl_data = deep_crawler.crawl(
                        domain=clean_domain,
                        file_types=types,
                        log_callback=crawl_callback,
                    )
                    for t in crawl_data.get("document_targets", []):
                        if t.url not in seen_target_urls:
                            seen_target_urls.add(t.url)
                            discovered_targets.append(t)
                    crawled_emails.extend(crawl_data.get("emails", []))
                    cloud_buckets.extend(crawl_data.get("cloud_buckets", []))
                    internal_ips.extend(crawl_data.get("internal_ips", []))
                    crawled_urls.extend(crawl_data.get("crawled_urls", []))
                except Exception as e:
                    if not json_mode:
                        reporter.print_warning(f"Deep crawler error: {e}")
                    logger.debug("Deep crawler error: %s", e)

            # B. Archive Digger (Wayback Machine CDX API)
            if not no_archive and clean_domain:
                if not json_mode:
                    reporter.print_info("Digging historical documents via Wayback Machine CDX API...")
                try:
                    archive_digger = ArchiveDigger(timeout=10)
                    arch_targets = archive_digger.dig_historical_documents(
                        domain=clean_domain,
                        file_types=types,
                        limit=max_files,
                    )
                    for t in arch_targets:
                        archive_documents.append(t.url)
                        if t.url not in seen_target_urls:
                            seen_target_urls.add(t.url)
                            discovered_targets.append(t)
                except Exception as e:
                    if not json_mode:
                        reporter.print_warning(f"Archive digger error: {e}")
                    logger.debug("Archive digger error: %s", e)

            # C. Search Engine Dorking / Spidering
            try:
                scraper = DocumentScraper()
                if mode == "spider":
                    dork_targets = scraper.spider_domain(clean_domain or "", types, max_results=max_files)
                else:
                    dork_targets = scraper.discover(
                        domain=clean_domain or "",
                        file_types=types,
                        max_results=max_files,
                        spider_mode=spider,
                        local_dir=local_dir,
                    )
                for t in dork_targets:
                    if t.url not in seen_target_urls:
                        seen_target_urls.add(t.url)
                        discovered_targets.append(t)
            except Exception as e:
                if not json_mode:
                    reporter.print_warning(f"Search engine discovery error: {e}")
                logger.debug("Search engine discovery error: %s", e)

            targets = (
                discovered_targets[:max_files]
                if max_files and len(discovered_targets) > max_files
                else discovered_targets
            )

        if not json_mode:
            reporter.print_success(f"Discovered {len(targets)} document target(s).")

        # Handle --no-download Mode
        if no_download:
            # If no OSINT modules ran, preserve original early-exit behavior
            has_osint_results = any([dns_result, subdomain_result, tech_result, whois_result, social_result])
            if not has_osint_results:
                if json_mode:
                    target_dicts = [t.model_dump() for t in targets]
                    sys.stdout.write(json.dumps(target_dicts, indent=2) + "\n")
                else:
                    reporter.render_discovered_targets(targets)
                    reporter.print_info("Execution finished (no-download mode requested).")
                return 0

        # Downloader Subsystem
        if not no_download and targets:
            cache_dir = os.path.join(output_dir_str, "cache")
            downloader = DocumentDownloader()

            if not json_mode:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                    BarColumn(bar_width=40),
                    TaskProgressColumn(),
                    TimeRemainingColumn(),
                    console=reporter.console,
                ) as progress:
                    download_task = progress.add_task("Downloading targets...", total=len(targets))

                    def on_progress(_: DocumentTarget) -> None:
                        progress.advance(download_task, 1)

                    targets = downloader.download_targets(
                        targets=targets,
                        output_cache_dir=cache_dir,
                        progress_callback=on_progress,
                    )
            else:
                targets = downloader.download_targets(
                    targets=targets,
                    output_cache_dir=cache_dir,
                )

            # Metadata Extraction Subsystem
            extractor = MetadataExtractor()
            for target in targets:
                if target.local_path and os.path.isfile(target.local_path):
                    try:
                        meta = extractor.extract(target.local_path)
                        metadata_list.append(meta)
                    except Exception as e:
                        if not json_mode:
                            reporter.print_warning(
                                f"Failed extracting metadata from {target.filename}: {e}"
                            )

    # 4. Fingerprint Analysis & Model Synthesis
    analyzer = FingerprintAnalyzer()
    fingerprint = analyzer.analyze_session(
        domain=target_identity,
        metadata_list=metadata_list,
    )

    # Attach OSINT results to the fingerprint model
    if dns_result is not None:
        fingerprint.dns_audit = dns_result
    if subdomain_result is not None:
        fingerprint.subdomain_audit = subdomain_result
    if tech_result is not None:
        fingerprint.tech_stack = tech_result
    if whois_result is not None:
        fingerprint.whois_info = whois_result
    if social_result is not None:
        fingerprint.social_profiles = social_result

    # Attach deep crawler, cloud bucket, IP leaks, and archive intelligence
    fingerprint.crawled_emails = sorted(list(set(crawled_emails)))
    fingerprint.cloud_buckets = sorted(list(set(cloud_buckets)))
    fingerprint.internal_ips = sorted(list(set(internal_ips)))
    fingerprint.crawled_urls = sorted(list(set(crawled_urls)))
    fingerprint.archive_documents = sorted(list(set(archive_documents)))

    # 5. Report Generation & Complete Exports (Saves 8 files in output_dir/<target>/)
    reporter.export_all(
        fingerprint=fingerprint,
        target_identity=target_identity,
        output_base_dir=output_dir_str,
        print_box=(not json_mode),
    )

    # Maintain backward compatibility for root output folder
    safe_name = re.sub(r'[\\/*?:"<>|\s]', "_", target_identity).strip("._") or "scan"
    output_dir = Path(output_dir_str).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    json_export_path = str(output_dir / f"foca_fingerprint_{safe_name}.json")
    csv_export_path = str(output_dir / f"foca_metadata_{safe_name}.csv")

    reporter.export_json(fingerprint, json_export_path)
    reporter.export_csv(fingerprint, csv_export_path)

    # 6. CLI Presentation / Stdout Output
    if json_mode:
        sys.stdout.write(fingerprint.to_json(indent=2) + "\n")
    else:
        if no_download and targets:
            reporter.render_discovered_targets(targets)

        reporter.render_dashboard(fingerprint, targets=targets)
        reporter.print_info("Analysis complete.")

    return 0


def main() -> int:
    """Orchestrate the end-to-end FOCA intelligence gathering pipeline."""
    # When no command-line arguments are provided, launch Interactive Wizard
    if len(sys.argv) == 1:
        wizard = InteractiveWizard()
        config = wizard.run()
        if not config:
            return 0

        current_target = config.get("domain") or config.get("local_dir")
        output_dir = config.get("output_dir", "./foca_output")

        run_pipeline(
            domain=config.get("domain"),
            local_dir=config.get("local_dir"),
            spider=config.get("spider", False),
            deep=config.get("deep", True),
            file_types=config.get("file_types"),
            max_files=config.get("max_files", 25),
            output_dir_str=output_dir,
            json_mode=False,
            no_download=False,
            mode=config.get("mode"),
            modules=config.get("modules"),
        )

        # Interactive post-scan loop: keep asking user what's next
        while True:
            action = wizard.prompt_post_scan_action(current_target)
            if action == "exit" or not action:
                break
            elif action == "new_target":
                config = wizard.run()
                if not config:
                    break
                current_target = config.get("domain") or config.get("local_dir")
                output_dir = config.get("output_dir", "./foca_output")
                run_pipeline(
                    domain=config.get("domain"),
                    local_dir=config.get("local_dir"),
                    spider=config.get("spider", False),
                    deep=config.get("deep", True),
                    file_types=config.get("file_types"),
                    max_files=config.get("max_files", 25),
                    output_dir_str=output_dir,
                    json_mode=False,
                    no_download=False,
                    mode=config.get("mode"),
                    modules=config.get("modules"),
                )
            elif action == "show_reports":
                if current_target:
                    wizard.show_report_locations(output_dir, current_target)
            elif action == "run_module":
                if not current_target:
                    continue
                mod_config = wizard.prompt_additional_module(current_target, output_dir)
                if not mod_config:
                    continue
                run_pipeline(
                    domain=mod_config.get("domain"),
                    local_dir=mod_config.get("local_dir"),
                    spider=mod_config.get("spider", False),
                    deep=mod_config.get("deep", True),
                    file_types=mod_config.get("file_types"),
                    max_files=mod_config.get("max_files", 25),
                    output_dir_str=output_dir,
                    json_mode=False,
                    no_download=False,
                    mode=mod_config.get("mode"),
                    modules=mod_config.get("modules"),
                )

        wizard.console.print("\n[bold cyan][*] Thank you for using FOCA. Goodbye![/bold cyan]\n")
        return 0

    args = parse_arguments()
    if getattr(args, "help", False):
        print_custom_help()
        return 0
    if getattr(args, "examples", False):
        print_examples_screen()
        return 0

    reporter = FocaReporter()

    # Input Validation for Flag Mode
    if not args.domain and not args.local:
        if args.json:
            sys.stdout.write(
                json.dumps(
                    {"error": "Either --domain (-d) or --local (-l) must be specified."},
                    indent=2,
                )
                + "\n"
            )
        else:
            reporter.print_banner()
            reporter.print_error("Missing target! Either --domain (-d) or --local (-l) is required.")
            print("\nRun 'python main.py --help' for usage instructions.")
        return 1

    if args.local and not os.path.isdir(args.local):
        if args.json:
            sys.stdout.write(
                json.dumps(
                    {"error": f"Specified local directory not found: {args.local}"},
                    indent=2,
                )
                + "\n"
            )
        else:
            reporter.print_banner()
            reporter.print_error(f"Specified local directory does not exist: {args.local}")
        return 1

    file_types = [
        ext.strip().lstrip(".").lower()
        for ext in args.types.split(",")
        if ext.strip()
    ]
    if not file_types:
        file_types = ["pdf", "docx", "xlsx", "pptx", "jpg", "png"]

    # Determine module flags
    has_osint_flags = any([
        args.dns,
        args.subdomains,
        args.tech,
        args.whois,
        args.social,
        args.all,
    ])

    if args.all:
        run_dns = True
        run_subdomains = True
        run_tech = True
        run_whois = True
        run_social = True
        run_documents = True
        is_deep = not args.passive
    elif has_osint_flags:
        run_dns = args.dns
        run_subdomains = args.subdomains
        run_tech = args.tech
        run_whois = args.whois
        run_social = args.social
        run_documents = bool(args.local or args.spider or args.deep or args.no_download)
        is_deep = bool((args.deep or args.spider) and not args.passive)
    else:
        # Default domain reconnaissance: run full passive OSINT footprint + document inspection
        run_dns = True
        run_subdomains = True
        run_tech = True
        run_whois = True
        run_social = True
        run_documents = True
        is_deep = False if args.passive else getattr(args, "deep", False)

    return run_pipeline(
        domain=args.domain.strip() if args.domain else None,
        local_dir=args.local,
        spider=args.spider,
        deep=is_deep,
        no_archive=args.no_archive,
        file_types=file_types,
        max_files=args.max_files,
        output_dir_str=args.output,
        json_mode=args.json,
        no_download=args.no_download,
        reporter=reporter,
        run_dns=run_dns,
        run_subdomains=run_subdomains,
        run_tech=run_tech,
        run_whois=run_whois,
        run_social=run_social,
        run_documents=run_documents,
        passive=args.passive,
    )


if __name__ == "__main__":
    sys.exit(main())
