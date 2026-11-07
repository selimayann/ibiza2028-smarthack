"""Punctul de intrare: python -m netscan <comandă>.

Fișier COMUN. Fiecare adaugă doar comanda lui, după ce anunță echipa:
  analyze         -> Radu   (netscan.engine)
  network, scan   -> Oneata (netscan.scan)
  ui, diff, delete-history -> RBRT (netscan.ui)
"""
from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netscan", description="Secure Networks, Simply Explained")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="findings.csv + scores.csv pentru un folder de fișiere nmap XML (fără rețea)")
    a.add_argument("folder")
    a.add_argument("--out", default=".", help="unde se scriu CSV-urile")

    sub.add_parser("network", help="afișează interfața, subnetul și gateway-ul detectate")

    s = sub.add_parser("scan", help="scanare live, doar în rețeaua proprie")
    s.add_argument("target", nargs="?", help="IP sau subnet; implicit subnetul curent")
    s.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")

    sub.add_parser("ui", help="pornește interfața web locală")

    d = sub.add_parser("diff", help="diferența dintre două scanări")
    d.add_argument("old")
    d.add_argument("new")

    sub.add_parser("delete-history", help="șterge istoricul local")
    return p


def _cmd_analyze(folder: str, out: str) -> int:
    # Import local: celelalte comenzi nu au nevoie de motor la pornire.
    from netscan.engine import analyze_folder, write_results
    from netscan.engine.common import STATUS_ERROR

    try:
        scans = analyze_folder(folder)
    except NotADirectoryError:
        print(f"Eroare: '{folder}' nu este un folder.", file=sys.stderr)
        return 2
    if not scans:
        print(f"Atenție: nu am găsit fișiere .xml în '{folder}'.", file=sys.stderr)
    for scan in scans:
        if scan.status == STATUS_ERROR:
            print(f"{scan.file}: EROARE ({scan.error_code})")
        else:
            print(f"{scan.file}: scor {scan.score}, {len(scan.findings)} constatări")
    findings_path, scores_path = write_results(scans, out)
    print(f"Scrise: {findings_path} și {scores_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Consola Windows poate avea o codare fără diacritice: print() nu trebuie să crape.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _cmd_analyze(args.folder, args.out)
    raise NotImplementedError(f"Comanda '{args.command}' nu e implementată încă.")
