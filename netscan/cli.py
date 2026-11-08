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

    a = sub.add_parser("analyze", help="findings.csv + scores.csv pentru un folder de fișiere nmap XML sau un singur fișier (fără rețea)")
    a.add_argument("folder")
    a.add_argument("--out", default=".", help="unde se scriu CSV-urile")
    a.add_argument(
        "--unmatched",
        action="store_true",
        help="scrie în plus unmatched_services.csv (servicii deschise fără constatare)",
    )

    n = sub.add_parser("network", help="afișează interfața, subnetul și gateway-ul detectate")
    n.add_argument("--lang", choices=["ro", "en"], default="ro")

    s = sub.add_parser("scan", help="scanarea completă (nmap), doar în hotspotul echipei; fără --confirm doar arată comanda")
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
    q.add_argument("--local-ai", action="store_true",
                   help="reformulează cu modelul AI local (Ollama pe 127.0.0.1), verificat de validator")
    q.add_argument("--verify-text", metavar="TEXT",
                   help="demo: verifică un text (ex. un răspuns inventat) cu validatorul anti-halucinații")

    w = sub.add_parser("watch", help="monitorul: scanează periodic doar hotspotul și anunță schimbările (FR-13)")
    w.add_argument("target", nargs="?", help="IP sau subnet; implicit subnetul curent")
    w.add_argument("--every", type=float, default=15, help="minute între scanări (minimum 10)")
    w.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")
    w.add_argument("--lang", choices=["ro", "en"], default="ro")

    dm = sub.add_parser("demo-ai-check", help="demo: validatorul anti-halucinații pe texte simulate (fără rețea, fără AI)")
    dm.add_argument("file", help="o scanare nmap XML, de ex. fixtures/lab/scan_01_before.xml")
    dm.add_argument("--lang", choices=["ro", "en"], default="ro")

    im = sub.add_parser("import-scans", help="aduce scanările monitorului în istoric (ca utilizator normal, nu admin)")
    im.add_argument("folder", nargs="?", default="scans", help="folderul cu watch_*.xml (implicit scans/)")
    im.add_argument("--lang", choices=["ro", "en"], default="ro")

    t = sub.add_parser("trap", help="ușa-capcană: notează doar cine a încercat să se conecteze (IP, oră, port) și închide; nu citește nimic")
    t.add_argument("--port", type=int, default=2323, help="portul capcanei (1024–65535)")
    t.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")
    t.add_argument("--lang", choices=["ro", "en"], default="ro")

    li = sub.add_parser("listen", help="ascultare pasivă: numele anunțate de dispozitive (mDNS/SSDP), fără să trimită nimic")
    li.add_argument("--confirm", action="store_true", help="fără acest flag se face doar dry-run")
    li.add_argument("--lang", choices=["ro", "en"], default="ro")
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
    from netscan.engine import analyze_file, analyze_folder, write_results
    from netscan.engine.common import STATUS_ERROR

    try:
        # un singur fișier (ex. verificarea live „re-run” pe un fișier ales de juriu) sau un folder întreg
        scans = [analyze_file(args.folder)] if Path(args.folder).is_file() else analyze_folder(args.folder)
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
    """B: asistentul FR-12 (D8: opțional, modelul AI local). Răspunsurile vin din scanare; AI-ul doar reformulează."""
    from netscan.engine.parser import analyze_file
    from netscan.scan import ai_check, local_llm
    from netscan.scan.assistant import answer

    ro = args.lang == "ro"
    scan = analyze_file(args.file)

    if args.verify_text is not None:
        check = ai_check.check_llm_text(args.verify_text, scan)
        if check.ok:
            print("Validator: textul e acceptat (tot ce menționează există în scanare)." if ro
                  else "Validator: text accepted (everything it mentions exists in the scan).")
        else:
            print(("Validator: text RESPINS, ar fi afișat răspunsul predefinit. Motive: " if ro
                   else "Validator: text REJECTED, the predefined answer would be shown. Reasons: ")
                  + ", ".join(check.problems))
        return 0 if check.ok else 1

    previous = analyze_file(args.previous) if args.previous else None
    llm = None
    if args.local_ai:
        try:
            llm = local_llm.make_llm(force=True)
        except local_llm.NotLocalError as e:
            print(("Nu folosesc AI-ul: " if ro else "Not using AI: ") + str(e))
    result = answer(args.question, scan, lang=args.lang, previous=previous, llm=llm)
    print(result.text)
    if args.local_ai:
        if result.source == "llm":
            print("\n[AI local, verificat de validator]" if ro else "\n[local AI, checked by the validator]")
        else:
            print(("\n[răspuns predefinit; AI-ul local a fost respins sau indisponibil: " if ro
                   else "\n[predefined answer; local AI rejected or unavailable: ")
                  + ", ".join(result.problems or ["-"]) + "]")
    return 0 if scan.status == "ok" else 2


def cmd_watch(args) -> int:
    """B: monitorul periodic (fără agenți). Aceleași verificări ca `scan`, la fiecare ciclu."""
    from netscan.scan.watch import watch

    return watch(args.every, args.confirm, lang=args.lang, target=args.target)


def cmd_demo_ai_check(args) -> int:
    """B: demonstrația validatorului (inovație): texte simulate, validatorul real, fără rețea și fără model."""
    from netscan.scan.ai_demo import run_demo

    return run_demo(args.file, lang=args.lang)


def cmd_import_scans(args) -> int:
    """B: pasul neprivilegiat al monitorului (NFR-04): XML-urile din scans/ -> istoric + alerte."""
    from pathlib import Path as _P

    from netscan.scan.watch import import_scans

    return import_scans(_P(args.folder), lang=args.lang)


def cmd_trap(args) -> int:
    """B: ușa-capcană, doar pe IP-ul din hotspot: notează cine a încercat (IP, oră, port), închide imediat, nu citește nimic."""
    from netscan.scan.trap import run_trap

    return run_trap(args.confirm, port=args.port, lang=args.lang)


def cmd_listen(args) -> int:
    """B: ascultare pasivă mDNS/SSDP doar pe interfața hotspotului; nu trimite cereri, nu deschide link-uri."""
    from netscan.scan.passive import run_listen

    return run_listen(args.confirm, lang=args.lang)


COMMANDS = {
    "analyze": cmd_analyze,
    "network": cmd_network,
    "scan": cmd_scan,
    "ui": cmd_ui,
    "diff": cmd_diff,
    "delete-history": cmd_delete_history,
    "ask": cmd_ask,
    "watch": cmd_watch,
    "import-scans": cmd_import_scans,
    "demo-ai-check": cmd_demo_ai_check,
    "trap": cmd_trap,
    "listen": cmd_listen,
}


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    load_env_file()
    args = build_parser().parse_args(argv)
    handler = COMMANDS.get(args.command)
    if handler is None:
        raise NotImplementedError(f"Comanda '{args.command}' nu e implementată încă.")
    return handler(args)
