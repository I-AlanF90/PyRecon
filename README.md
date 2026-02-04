# PyRecon


**PyRecon** is a lightweight, **port-driven recon orchestrator** that automates a clean enumeration workflow:
1) run a full TCP discovery scan,
2) extract open ports,
3) run a thorough scan only against what’s open,
4) optionally chain web/content discovery and vulnerability checks.

Designed to keep recon fast, repeatable, and organized (great for labs + OSCP-style workflows).

---

## Features

- **Port-driven Nmap workflow**
  - **Discovery:** `nmap -sV -p-` (full TCP + service detection)
  - **Parse open ports** from `.gnmap`
  - **Thorough scan:** `nmap -sC -sV -p <open_ports>` (only the ports that matter)

- **Optional additions**
  - Nmap vuln scripts: `--script vuln` (runs against open ports only)
  - **Feroxbuster** (interactive prompts)
    - choose wordlist
    - depth fixed to **2**
    - set thread count
    - optional extensions (`php,asp,aspx,jsp,txt,bak`)
  - **Nuclei** toggle

- **Clean output structure**
  - every run writes to a timestamped folder under `scans/<target>/<timestamp>/`

- **Colorful terminal UI**
  - uses `rich` for panels/tables/prompt flow

---

## Install

> Requires Python 3.9+ recommended.

```bash
pip install -r requirements.txt
```
<img width="1181" height="557" alt="PyRecon" src="https://github.com/user-attachments/assets/a98bb85f-e130-45c1-87d1-f25c5f7587a1" />
