from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from .ferox import FeroxOptions, run_ferox
from .nmap import guess_web_urls, parse_open_ports_from_gnmap
from .utils import ensure_dir, run_cmd

console = Console()


def main() -> None:
    console.print(
        Panel.fit(
            "[bold green]PyRecon[/bold green]\n"
            "[dim]Nmap full TCP (-sV -p-) → parse ports → thorough scan on open ports → optional ferox/nuclei[/dim]",
            border_style="cyan",
        )
    )

    target = Prompt.ask("[bold]Target (IP or domain)[/bold]").strip()
    if not target:
        console.print("[red]No target provided.[/red]")
        return

    base_dir = Path("scans") / target / datetime.now().strftime("%Y%m%d_%H%M%S")
    ensure_dir(base_dir)
    console.print(f"[dim]Output directory:[/dim] [bold]{base_dir}[/bold]\n")

    # 1) Discover: full TCP + service version
    base_prefix = base_dir / f"{target}_fulltcp_sV"
    rc = run_cmd(
        ["nmap", "-sV", "-p-", "-T4", "-vv", "-oA", str(base_prefix), target],
        "Nmap #1: Full TCP (-p-) + Service Version (-sV)",
    )
    if rc != 0:
        console.print("[red]Base scan failed.[/red]")
        return

    # Parse open ports from gnmap
    open_ports = parse_open_ports_from_gnmap(Path(str(base_prefix) + ".gnmap"))

    table = Table(title="Open TCP Ports Detected", show_lines=True)
    table.add_column("Ports", style="bold green")
    table.add_row(", ".join(map(str, open_ports)) if open_ports else "None found")
    console.print(table)

    # 2) Thorough scan only on open ports
    if open_ports:
        ports_csv = ",".join(map(str, open_ports))
        thorough_out = base_dir / f"{target}_thorough.nmap"
        run_cmd(
            ["nmap", "-sC", "-sV", "-p", ports_csv, "-T4", "-vv", "-oN", str(thorough_out), target],
            "Nmap #2: Thorough (-sC -sV) on Open Ports Only",
        )

        # Optional vuln scripts
        if Confirm.ask("Run Nmap vuln scripts on open ports? (--script vuln)"):
            vuln_out = base_dir / f"{target}_vuln.nmap"
            run_cmd(
                ["nmap", "--script", "vuln", "-p", ports_csv, "-T4", "-vv", "-oN", str(vuln_out), target],
                "Nmap #3: Vulnerability Scripts (--script vuln)",
            )
    else:
        console.print("[yellow]No open ports parsed. Skipping thorough/vuln scans.[/yellow]")

    # Feroxbuster menu
    if Confirm.ask("Run Feroxbuster?"):
        urls = guess_web_urls(target, open_ports)
        if not urls:
            console.print("[yellow]No common web ports detected. Enter a URL manually.[/yellow]")
            manual = Prompt.ask("URL (e.g., http://target:8080)").strip()
            urls = [manual] if manual else []

        if urls:
            console.print("\n[bold cyan]Web targets:[/bold cyan]")
            for i, u in enumerate(urls, 1):
                console.print(f"  [bold]{i}[/bold]. {u}")

            pick = Prompt.ask("Choose (1 or 1,2 or 'all')", default="all").strip().lower()
            if pick != "all":
                chosen = []
                for part in pick.split(","):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part)
                        if 1 <= idx <= len(urls):
                            chosen.append(urls[idx - 1])
                urls = chosen if chosen else urls

            wordlists = {
                "1": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "2": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "3": "/usr/share/wordlists/dirb/common.txt",
                "4": "CUSTOM",
            }

            wl_table = Table(title="Ferox Wordlists", show_lines=True)
            wl_table.add_column("Option", style="bold")
            wl_table.add_column("Path", style="green")
            for k, v in wordlists.items():
                wl_table.add_row(k, v)
            console.print(wl_table)

            wl_choice = Prompt.ask("Pick wordlist option", choices=list(wordlists.keys()), default="1")
            wl_path = wordlists[wl_choice]
            if wl_path == "CUSTOM":
                wl_path = Prompt.ask("Enter full path to wordlist").strip()

            threads = IntPrompt.ask("Threads", default=50)
            add_ext = Confirm.ask("Add extensions? (php,asp,aspx,jsp,txt,bak)")
            extensions = "php,asp,aspx,jsp,txt,bak" if add_ext else None

            opts = FeroxOptions(wordlist=wl_path, depth=2, threads=threads, extensions=extensions)
            run_ferox(urls, base_dir, opts)
        else:
            console.print("[red]No URLs provided. Skipping Feroxbuster.[/red]")

    # Nuclei toggle (basic)
    if Confirm.ask("Run Nuclei?"):
        nuclei_out = base_dir / f"{target}_nuclei.txt"
        run_cmd(["nuclei", "-u", target, "-o", str(nuclei_out)], "Nuclei Scan")

    console.rule("[bold green]Done[/bold green]")
    console.print(f"[bold cyan]Saved to:[/bold cyan] {base_dir}")


if __name__ == "__main__":
    main()
