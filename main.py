import sys
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from modules.extractor import FeatureExtractor
from modules.scraper import scrape_url_content
from modules.ai_engine import PhishingDetector

console = Console()


def display_banner():
    console.print(
        Panel.fit(
            "[bold cyan]AI-POWERED PHISHING URL & OSINT THREAT ANALYZER[/bold cyan]\n"
            "[dim]Hybrid Lexical + WHOIS + Generative AI SOC Triage Engine[/dim]",
            border_style="cyan",
        )
    )


def run_analysis(target_url: str, export_json: bool = False):
    console.print(f"\n[bold blue][*] Starting Investigation:[/bold blue] [underline]{target_url}[/underline]\n")

    # 1. Lexical & OSINT Extraction
    with console.status("[bold green]Extracting lexical features & querying WHOIS OSINT records...[/bold green]"):
        extractor = FeatureExtractor(target_url)
        lexical = extractor.extract_lexical_features()
        whois_info = extractor.get_whois_info()

    # 2. Live Web Content Scraping
    with console.status("[bold green]Fetching target webpage & inspecting HTML DOM/forms...[/bold green]"):
        page_data = scrape_url_content(lexical["normalized_url"])

    # 3. Hybrid Heuristic + Generative AI Analysis
    with console.status("[bold green]Running Heuristic Rule Engine & Gemini AI Semantic Triage...[/bold green]"):
        detector = PhishingDetector()
        heuristic_score, triggered_rules = detector.calculate_heuristic_score(lexical, whois_info, page_data)
        ai_verdict = detector.analyze_with_ai(lexical, whois_info, page_data)

    # --- BUILD OSINT & TELEMETRY TABLE ---
    table = Table(title="OSINT & Technical Telemetry", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Indicator", style="bold white", width=24)
    table.add_column("Extracted Value", style="cyan")

    age_display = f"{whois_info['domain_age_days']} days" if whois_info["domain_age_days"] is not None else "Unknown / Private"
    table.add_row("Registered Domain", lexical["registered_domain"] or "N/A")
    table.add_row("Domain Age (WHOIS)", age_display)
    table.add_row("Registrar", str(whois_info["registrar"]))
    table.add_row("HTTPS / TLS Enabled", "Yes" if lexical["uses_https"] else "[bold red]No (Insecure HTTP)[/bold red]")
    table.add_row("Raw IP Hostname", "[bold red]Yes[/bold red]" if lexical["is_ip_address"] else "No")
    table.add_row("Subdomain Depth", str(lexical["subdomain_count"]))
    table.add_row("Page Reachable", f"Yes (HTTP {page_data['status_code']})" if page_data["reachable"] else f"No ({page_data['error']})")
    table.add_row("Page Title", page_data["title"] or "N/A")
    table.add_row("Password Input Field", "[bold red]Detected[/bold red]" if page_data["has_password_field"] else "None")
    table.add_row("Heuristic Rule Score", f"{heuristic_score} / 100")

    console.print(table)

    # --- BUILD FINAL VERDICT PANEL ---
    risk_colors = {
        "Low": "green",
        "Medium": "yellow",
        "High": "red",
        "Critical": "bold red",
    }
    color = risk_colors.get(ai_verdict.risk_level, "yellow")

    all_flags = list(dict.fromkeys(triggered_rules + ai_verdict.red_flags))
    flags_formatted = "\n".join([f"  • {flag}" for flag in all_flags])

    verdict_body = (
        f"[bold]Phishing Detected:[/bold] [{color}]{ai_verdict.phishing_intent_detected}[/{color}]\n"
        f"[bold]Severity Level:[/bold]    [{color}]{ai_verdict.risk_level.upper()}[/{color}] (AI Confidence: {ai_verdict.confidence_score}%)\n"
        f"[bold]Target Brand:[/bold]      {ai_verdict.impersonated_brand}\n\n"
        f"[bold]SOC Analyst Summary:[/bold]\n{ai_verdict.analyst_summary}\n\n"
        f"[bold]Detected Red Flags & Indicators:[/bold]\n{flags_formatted}"
    )

    console.print("\n")
    console.print(Panel(verdict_body, title="[bold white]FINAL THREAT ASSESSMENT[/bold white]", border_style=color))

    # Optional JSON Report Export
    if export_json:
        report = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "lexical_features": lexical,
            "whois_osint": whois_info,
            "page_telemetry": {k: v for k, v in page_data.items() if k != "text_snippet"},
            "heuristic_score": heuristic_score,
            "ai_assessment": ai_verdict.model_dump(),
        }
        filename = f"report_{lexical['registered_domain'] or 'scan'}.json".replace(":", "_")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[bold green][+] Full JSON audit report saved to:[/bold green] {filename}")


if __name__ == "__main__":
    display_banner()
    if len(sys.argv) > 1:
        url_arg = sys.argv[1]
        save_flag = "--save" in sys.argv
        run_analysis(url_arg, export_json=save_flag)
    else:
        while True:
            user_url = console.input("\n[bold yellow]Enter URL to scan (or 'exit' to quit): [/bold yellow]").strip()
            if user_url.lower() in ("exit", "quit", "q"):
                console.print("[dim]Exiting analyzer.[/dim]")
                break
            if user_url:
                run_analysis(user_url, export_json=True)