# PyRecon

Port-driven recon orchestrator:
- Nmap full TCP + service detect (`-sV -p-`)
- Parses open ports
- Runs thorough scan only on open ports (`-sC -sV -p <ports>`)
- Optional: Feroxbuster + Nuclei

## Install
pip install -r requirements.txt

## Run
- python3 -m pyrecon.cli
- python3 PyRecon.py

<img width="1181" height="557" alt="PyRecon" src="https://github.com/user-attachments/assets/a98bb85f-e130-45c1-87d1-f25c5f7587a1" />
