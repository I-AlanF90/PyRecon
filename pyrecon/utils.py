import re
import shlex
import subprocess
from pathlib import Path
from typing import List, Optional

from rich.console import Console

console = Console()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: List[str], desc: str, cwd: Optional[Path] = None) -> int:
    console.rule(f"[bold cyan]{desc}")
    console.print(f"[yellow]$ {' '.join(shlex.quote(c) for c in cmd)}[/yellow]\n")
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
        return p.returncode
    except FileNotFoundError:
        console.print(f"[bold red]Missing tool:[/bold red] {cmd[0]} (not found in PATH)")
        return 127


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)
