#!/usr/bin/env python3
"""Audit Docs: Offline document metadata scanner for local folders.

Usage:
    python scripts/audit_docs.py <folder_path>
"""

import os
import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

from foca_core.scraper import DocumentScraper
from foca_core.extractor import MetadataExtractor
from foca_core.analyzer import FingerprintAnalyzer
from foca_core.reporter import FocaReporter


def main() -> int:
    console = Console()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        console.print(
            Panel(
                "[bold cyan]Local Document Metadata Audit[/bold cyan]\n"
                "Scans an offline folder of documents (PDF, DOCX, XLSX, PPTX, Images),\n"
                "extracts author information, usernames, and software, and exports to CSV.\n\n"
                "[bold white]Usage:[/bold white]\n"
                "  python scripts/audit_docs.py <folder_path>\n\n"
                "[bold white]Example:[/bold white]\n"
                "  python scripts/audit_docs.py C:\\Users\\Name\\Documents\n"
                "  python scripts/audit_docs.py ./sample_docs",
                title="[bold cyan]FOCA Local Document Audit[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return 0

    target_dir = sys.argv[1].strip()
    if not os.path.isdir(target_dir):
        console.print(f"[bold red][-] Error:[/] Directory not found: {target_dir}")
        return 1

    console.print(f"[bold cyan][*] Scanning local folder:[/] [bold white]{target_dir}[/]")
    file_types = ["pdf", "docx", "xlsx", "pptx", "jpg", "png"]
    scraper = DocumentScraper()
    targets = scraper.scan_local_directory(target_dir, file_types)

    if not targets:
        console.print("[bold yellow][!] No matching documents (PDF, DOCX, XLSX, PPTX, Images) found in this folder.[/]")
        return 0

    console.print(f"[bold green][+] Found {len(targets)} document(s). Extracting metadata...[/]")

    extractor = MetadataExtractor()
    extracted_records = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Processing documents...", total=len(targets))
        for t in targets:
            if t.local_path and os.path.exists(t.local_path):
                meta = extractor.extract(t.local_path)
                meta.file_type = t.file_type
                extracted_records.append(meta)
            progress.advance(task)

    analyzer = FingerprintAnalyzer()
    folder_name = os.path.basename(os.path.abspath(target_dir)) or "local_folder"
    fingerprint = analyzer.analyze_session(folder_name, extracted_records)

    reporter = FocaReporter(console)
    console.print()
    reporter.render_dashboard(fingerprint)

    output_dir = Path("./foca_output")
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_file = output_dir / f"audit_{folder_name}.csv"
    json_file = output_dir / f"audit_{folder_name}.json"

    reporter.export_csv(fingerprint, str(csv_file))
    reporter.export_json(fingerprint, str(json_file))

    console.print()
    console.print(f"[bold green][+] Saved CSV report:[/] [bold white]{csv_file}[/]")
    console.print(f"[bold green][+] Saved JSON report:[/] [bold white]{json_file}[/]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
