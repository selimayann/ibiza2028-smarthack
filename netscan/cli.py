"""Punctul de intrare: python -m netscan <comandă>.

Fișier COMUN. Fiecare adaugă doar comanda lui, după ce anunță echipa:
  analyze         -> Radu   (netscan.engine)
  network, scan   -> Oneata (netscan.scan)
  ui, diff, delete-history -> RBRT (netscan.ui)
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netscan", description="Secure Networks, Simply Explained")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="findings.csv + scores.csv pentru un folder de fișiere nmap XML (fără rețea)")
    a.add_argument("folder")
    a.add_argument("--out", default=".", help="unde se scriu CSV-urile")

    n = sub.add_parser("network", help="afișează interfața, subnetul și gateway-ul detectate")
    n.add_argument("--lang", choices=["ro", "en"], default="ro")

    s = sub.add_parser("scan", help="scanare live, doar în rețeaua proprie")
    s.add_argument("target", nargs="?", help="IP sau subnet; implicit subnetul curent")
    s.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")
    s.add_argument("--lang", choices=["ro", "en"], default="ro")

    sub.add_parser("ui", help="pornește interfața web locală")

    d = sub.add_parser("diff", help="diferența dintre două scanări")
    d.add_argument("old")
    d.add_argument("new")

    sub.add_parser("delete-history", help="șterge istoricul local")
    return p


def load_env_file(path: str | Path = ".env") -> None:
    """Citește KEY=VALUE din .env în os.environ, fără să suprascrie ce e deja setat.
    Fără dependențe; ignoră comentariile și liniile goale. Lipsa fișierului nu e eroare."""
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def _setup_console() -> None:
    """Diacriticele nu trebuie să dea crash pe consolele Windows (cp1252) sau când ieșirea e redirecționată."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:  # redirecționat (fișier, pipe, Git Bash): UTF-8, ca să rămână diacriticele
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


# --- Oneata: network, scan ----------------------------------------------------------------------

def cmd_network(args) -> int:
    from netscan.scan.network import describe, detect_network

    info = detect_network()
    print(describe(info, args.lang))
    return 0 if info.scan_allowed else 2


def cmd_scan(args) -> int:
    from netscan.scan import runner
    from netscan.scan.network import describe

    plan = runner.prepare_scan(args.target)
    if plan.network is not None:
        print(describe(plan.network, args.lang))
        print()
    print(plan.message(args.lang))
    if not plan.ok:
        return 2

    print()
    if not args.confirm:
        print("Dry-run. Comanda care ar rula:" if args.lang == "ro" else "Dry-run. The command that would run:")
        print("  " + runner.format_command(plan.args))
        print("Adaugă --confirm ca să pornești scanarea." if args.lang == "ro" else "Add --confirm to start the scan.")
        return 0

    result = runner.execute(plan)
    if not result.ok:
        print(result.message(args.lang))
        return 2
    print(("Scanare salvată în " if args.lang == "ro" else "Scan saved to ") + result.out_path)
    return 0


COMMANDS = {
    "network": cmd_network,
    "scan": cmd_scan,
}


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    load_env_file()
    args = build_parser().parse_args(argv)
    handler = COMMANDS.get(args.command)
    if handler is None:
        raise NotImplementedError(f"Comanda '{args.command}' nu e implementată încă.")
    return handler(args)
