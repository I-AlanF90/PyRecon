import re
from pathlib import Path
from typing import List


def parse_open_ports_from_gnmap(gnmap_path: Path) -> List[int]:
    """
    Parse open TCP ports from an Nmap .gnmap file.
    Looks for segments like: 22/open/tcp//ssh///
    """
    ports = set()
    if not gnmap_path.exists():
        return []

    data = gnmap_path.read_text(errors="ignore")

    for match in re.finditer(r"Ports:\s*(.+)", data):
        ports_blob = match.group(1)
        for p in ports_blob.split(","):
            p = p.strip()
            m = re.match(r"(\d+)/open/tcp", p)
            if m:
                ports.add(int(m.group(1)))

    return sorted(ports)


def guess_web_urls(target: str, open_ports: List[int]) -> List[str]:
    """
    Heuristic: common web ports -> propose URLs for ferox/nuclei.
    """
    common_web = (80, 443, 8000, 8080, 8443, 8888, 3000, 5000)
    web_ports = [p for p in open_ports if p in common_web]

    urls: List[str] = []
    for p in web_ports:
        scheme = "https" if p in (443, 8443) else "http"
        default = (scheme == "http" and p == 80) or (scheme == "https" and p == 443)
        urls.append(f"{scheme}://{target}" if default else f"{scheme}://{target}:{p}")
    return urls
