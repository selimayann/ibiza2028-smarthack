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
    a.add_argument(
        "--unmatched",
        action="store_true",
        help="scrie în plus unmatched_services.csv (servicii deschise fără constatare)",
    )

    n = sub.add_parser("network", help="afișează interfața, subnetul și gateway-ul detectate")
    n.add_argument("--lang", choices=["ro", "en"], default="ro")

    s = sub.add_parser("scan", help="scanare live, doar în rețeaua proprie")
    s.add_argument("target", nargs="?", help="IP sau subnet; implicit subnetul curent")
    s.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")
    s.add_argument("--lang", choices=["ro", "en"], default="ro")

    u = sub.add_parser("ui", help="pornește interfața web locală")
    u.add_argument("--port", type=int, default=5000)
    u.add_argument("--lang", choices=["ro", "en"], default="ro")

    d = sub.add_parser("diff", help="diferența dintre două scanări")
    d.add_argument("old", help="fișierul nmap XML de înainte")
    d.add_argument("new", help="fișierul nmap XML de după")
    d.add_argument("--save", action="store_true", help="salvează ambele scanări în istoric")
    d.add_argument("--lang", choices=["ro", "en"], default="ro")

    h = sub.add_parser("delete-history", help="șterge istoricul local")
    h.add_argument("--yes", action="store_true", help="fără întrebarea de confirmare")
    h.add_argument("--lang", choices=["ro", "en"], default="ro")

    q = sub.add_parser("ask", help="asistentul: răspunde la o întrebare doar din scanare (fără rețea)")
    q.add_argument("file", help="fișierul nmap XML")
    q.add_argument("question", help="întrebarea, între ghilimele")
    q.add_argument("--previous", help="o scanare anterioară, pentru „ce s-a schimbat?”")
    q.add_argument("--lang", choices=["ro", "en"], default="ro")
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


# --- Radu: analyze ------------------------------------------------------------------------------

def cmd_analyze(args) -> int:
    # Import local: celelalte comenzi nu au nevoie de motor la pornire.
    from netscan.engine import analyze_folder, write_results
    from netscan.engine.common import STATUS_ERROR

    try:
        scans = analyze_folder(args.folder)
    except NotADirectoryError:
        print(f"Eroare: '{args.folder}' nu este un folder.", file=sys.stderr)
        return 2
    if not scans:
        print(f"Atenție: nu am găsit fișiere .xml în '{args.folder}'.", file=sys.stderr)
    for scan in scans:
        if scan.status == STATUS_ERROR:
            print(f"{scan.file}: EROARE ({scan.error_code})")
        else:
            print(f"{scan.file}: scor {scan.score}, {len(scan.findings)} constatări")
    findings_path, scores_path = write_results(scans, args.out)
    print(f"Scrise: {findings_path} și {scores_path}")
    if args.unmatched:
        from netscan.engine import write_unmatched_csv

        unmatched_path, count = write_unmatched_csv(scans, args.out)
        print(f"Servicii fără constatare: {count}, scrise în {unmatched_path}")
    return 0


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


# --- RBRT: ui, diff, delete-history -------------------------------------------------------------

def cmd_ui(args) -> int:
    from netscan.ui.commands import cmd_ui as run_ui

    return run_ui(port=args.port, lang=args.lang)


def cmd_diff(args) -> int:
    from netscan.ui.commands import cmd_diff as run_diff

    return run_diff(args.old, args.new, lang=args.lang, save=args.save)


def cmd_delete_history(args) -> int:
    from netscan.ui.commands import cmd_delete_history as run_delete

    return run_delete(lang=args.lang, yes=args.yes)


def cmd_ask(args) -> int:
    """B: asistentul FR-12. Doar răspunsuri din scanare; LLM-ul nu e folosit din linia de comandă."""
    from netscan.engine.parser import analyze_file
    from netscan.scan.assistant import answer

    scan = analyze_file(args.file)
    previous = analyze_file(args.previous) if args.previous else None
    print(answer(args.question, scan, lang=args.lang, previous=previous).text)
    return 0 if scan.status == "ok" else 2


COMMANDS = {
    "analyze": cmd_analyze,
    "network": cmd_network,
    "scan": cmd_scan,
    "ui": cmd_ui,
    "diff": cmd_diff,
    "delete-history": cmd_delete_history,
    "ask": cmd_ask,
}


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    load_env_file()
    args = build_parser().parse_args(argv)
    handler = COMMANDS.get(args.command)
    if handler is None:
        raise NotImplementedError(f"Comanda '{args.command}' nu e implementată încă.")
    return handler(args)
