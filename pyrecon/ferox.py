from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .utils import run_cmd, sanitize_filename


@dataclass
class FeroxOptions:
    wordlist: str
    depth: int = 2
    threads: int = 50
    extensions: Optional[str] = None


def run_ferox(urls: List[str], out_dir: Path, opts: FeroxOptions) -> None:
    for url in urls:
        out_file = out_dir / f"ferox_{sanitize_filename(url)}.txt"

        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", opts.wordlist,
            "-d", str(opts.depth),
            "-t", str(opts.threads),
            "-o", str(out_file),
        ]

        if opts.extensions:
            cmd += ["-x", opts.extensions]

        run_cmd(cmd, f"Feroxbuster: {url} (depth={opts.depth})")
