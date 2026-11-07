"""Punctul de intrare: python -m netscan <comandă>.

Fișier COMUN. Fiecare adaugă doar comanda lui, după ce anunță echipa:
  analyze         -> Radu   (netscan.engine)
  network, scan   -> Oneata (netscan.scan)
  ui, diff, delete-history -> RBRT (netscan.ui)
"""
from __future__ import annotations

import argparse


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raise NotImplementedError(f"Comanda '{args.command}' nu e implementată încă.")
