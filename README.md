# PyRecon

Port-driven recon orchestrator:
- Nmap full TCP + service detect (`-sV -p-`)
- Parses open ports
- Runs thorough scan only on open ports (`-sC -sV -p <ports>`)
- Optional: Feroxbuster + Nuclei

## Install
pip install -r requirements.txt

## Run
python3 -m pyrecon.cli
python3 PyRecon.py
