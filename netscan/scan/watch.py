"""Monitorul (B): supraveghere periodică a hotspotului, fără agenți pe dispozitive (FR-13).

La fiecare ciclu:
1. rețeaua și ținta se verifică din nou (aceleași verificări ca `scan`: SSID, o singură rețea, guardrail);
   dacă laptopul nu mai e pe hotspot, ciclul se sare și NU se scanează nimic;
2. nmap rulează cu exact aceeași comandă ca `scan --confirm` (listă fixă de argumente, --max-rate 100, -n);
3. motorul analizează XML-ul (aceleași reguli), în memorie;
4. se compară cu scanarea anterioară și se dau alerte în terminal, în RO/EN: dispozitiv nou/plecat, port
   nou/închis, problemă nouă/rezolvată, scor schimbat.
NFR-04: procesul cu drepturi de administrator scrie DOAR fișierele XML (scans/). Istoricul (SQLite) și alertele
(data/alerts.jsonl) le scrie `import-scans`, rulat ca utilizator normal, ca să rămână ale utilizatorului și
să le vadă UI-ul.

Fără `--confirm` doar arată ce ar face (dry-run). Intervalul minim e de 10 minute (o scanare durează ~3,5 min).
Un singur monitor poate rula odată (fișier de blocare). Se păstrează doar ultimele KEEP_XML fișiere XML
ale monitorului (conțin MAC-uri reale); istoricul rămâne în SQLite, cu MAC mascat.
Motorul, regulile și CSV-urile nu se schimbă: monitorul doar le folosește.
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from netscan.model import Finding, Host, Scan
from netscan.scan import local_data, runner
from netscan.scan.device_info import describe

MIN_INTERVAL_MIN = 10
KEEP_XML = 5
WATCH_PREFIX = "watch_"
SCANS_DIR = Path("scans")

SEV = {"ro": {"high": "gravă", "medium": "medie", "low": "mică", "info": "informativă"},
       "en": {"high": "high", "medium": "medium", "low": "low", "info": "info"}}
TEXTS = {
    "ro": {
        "NEW_DEVICE": "Dispozitiv nou în rețea: {ip} ({type}).",
        "DEVICE_GONE": "Dispozitivul {ip} ({type}) nu mai e în rețea.",
        "PORT_OPENED": "Port nou deschis: {ip}, port {port}/{proto}{service}.",
        "PORT_CLOSED": "Port închis: {ip}, port {port}/{proto}.",
        "FINDING_NEW": "Problemă nouă: {code} pe {ip}{port} ({sev}).",
        "FINDING_RESOLVED": "Problemă rezolvată: {code} pe {ip}{port}.",
        "SCORE": "Scorul s-a schimbat: {before} → {after}.",
        "baseline": "Prima scanare: {n} dispozitive, scor {score}. De acum te anunț când se schimbă ceva.",
        "no_change": "Nicio schimbare față de scanarea anterioară (scor {score}).",
        "skipped": "Ciclu sărit, nu am scanat: {why}",
        "failed": "Scanarea a eșuat: {why}",
        "next": "Următoarea scanare la {at}. Oprește cu Ctrl+C.",
        "dry_run": "Dry-run. La fiecare {every} minute aș rula (doar dacă ești pe hotspot):",
        "add_confirm": "Adaugă --confirm ca să pornești monitorul (terminal de Administrator).",
        "too_often": "Intervalul minim e de {min} minute (o scanare durează cam 3,5 minute).",
        "locked": "Un monitor rulează deja (PID {pid}). Oprește-l înainte să pornești altul.",
        "stopped": "Monitor oprit.",
        "import_hint": ("Monitorul scrie doar fișierele XML (scans/). Pentru istoric și UI rulează, ca utilizator normal: "
                        "python -m netscan import-scans"),
        "import_admin": ("Rulează import-scans ca utilizator normal, nu ca Administrator: istoricul trebuie să fie al tău, "
                         "ca să-l vadă UI-ul."),
        "imported": "Am adus în istoric {n} scanări ale monitorului și {a} alerte.",
    },
    "en": {
        "NEW_DEVICE": "New device on the network: {ip} ({type}).",
        "DEVICE_GONE": "Device {ip} ({type}) left the network.",
        "PORT_OPENED": "New open port: {ip}, port {port}/{proto}{service}.",
        "PORT_CLOSED": "Port closed: {ip}, port {port}/{proto}.",
        "FINDING_NEW": "New problem: {code} on {ip}{port} ({sev}).",
        "FINDING_RESOLVED": "Problem fixed: {code} on {ip}{port}.",
        "SCORE": "The score changed: {before} → {after}.",
        "baseline": "First scan: {n} devices, score {score}. From now on I'll tell you when something changes.",
        "no_change": "No change since the previous scan (score {score}).",
        "skipped": "Cycle skipped, nothing scanned: {why}",
        "failed": "The scan failed: {why}",
        "next": "Next scan at {at}. Stop with Ctrl+C.",
        "dry_run": "Dry-run. Every {every} minutes I would run (only while on the hotspot):",
        "add_confirm": "Add --confirm to start the monitor (Administrator terminal).",
        "too_often": "The minimum interval is {min} minutes (a scan takes about 3.5 minutes).",
        "locked": "A monitor is already running (PID {pid}). Stop it before starting another.",
        "stopped": "Monitor stopped.",
        "import_hint": ("The monitor only writes XML files (scans/). For the history and the UI, run as a normal user: "
                        "python -m netscan import-scans"),
        "import_admin": ("Run import-scans as a normal user, not as Administrator: the history must be yours so the UI "
                         "can see it."),
        "imported": "Imported {n} monitor scans and {a} alerts into the history.",
    },
}


@dataclass
class Alert:
    kind: str                 # NEW_DEVICE | DEVICE_GONE | PORT_OPENED | PORT_CLOSED | FINDING_NEW | FINDING_RESOLVED | SCORE
    ts: float
    ip: Optional[str] = None
    port: Optional[int] = None
    proto: Optional[str] = None
    code: Optional[str] = None
    severity: Optional[str] = None
    text_ro: str = ""
    text_en: str = ""

    def text(self, lang: str) -> str:
        return self.text_en if lang == "en" else self.text_ro


@dataclass
class CycleResult:
    status: str               # "baseline" | "changes" | "no_change" | "skipped" | "failed"
    message: str = ""
    alerts: list[Alert] = field(default_factory=list)
    scan: Optional[Scan] = None


def _type_label(lang: str, host: Optional[Host]) -> str:
    from netscan.ui.i18n import device_type_label
    dtype = describe(host).device_type if host else "unknown"
    return device_type_label(lang, dtype).lower()


def _port_txt(f: Finding, lang: str) -> str:
    return (f", port {f.port}" if f.port is not None else "")


def build_alerts(old: Scan, new: Scan, ts: Optional[float] = None) -> list[Alert]:
    """Alertele dintre două scanări, din `diff()`-ul istoricului. Ordinea: probleme noi, dispozitive noi,
    porturi noi, probleme rezolvate, porturi închise, dispozitive plecate, scor."""
    from netscan.ui.storage import diff
    ts = time.time() if ts is None else ts
    d = diff(old, new)
    hosts_new = {h.device_id: h for h in new.hosts}
    hosts_old = {h.device_id: h for h in old.hosts}
    out: list[Alert] = []

    def make(kind, fmt: dict, **kw) -> Alert:
        return Alert(kind, ts, text_ro=TEXTS["ro"][kind].format(**fmt("ro")),
                     text_en=TEXTS["en"][kind].format(**fmt("en")), **kw)

    for f in d.new_findings:
        out.append(make("FINDING_NEW", lambda l, f=f: dict(code=f.code, ip=f.ip, port=_port_txt(f, l),
                                                           sev=SEV[l][f.severity]),
                        ip=f.ip, port=f.port, code=f.code, severity=f.severity))
    for h in d.new_devices:
        out.append(make("NEW_DEVICE", lambda l, h=h: dict(ip=h.ip, type=_type_label(l, h)), ip=h.ip))
    for dev, port, proto in d.opened_ports:
        h = hosts_new.get(dev)
        svc = next((p.service for p in (h.ports if h else []) if p.port == port and p.proto == proto), None)
        ip = h.ip if h else dev
        out.append(make("PORT_OPENED", lambda l, ip=ip, port=port, proto=proto, svc=svc:
                        dict(ip=ip, port=port, proto=proto, service=f" ({svc})" if svc else ""),
                        ip=ip, port=port, proto=proto))
    for f in d.resolved_findings:
        out.append(make("FINDING_RESOLVED", lambda l, f=f: dict(code=f.code, ip=f.ip, port=_port_txt(f, l)),
                        ip=f.ip, port=f.port, code=f.code, severity=f.severity))
    for dev, port, proto in d.closed_ports:
        h = hosts_old.get(dev) or hosts_new.get(dev)
        ip = h.ip if h else dev
        out.append(make("PORT_CLOSED", lambda l, ip=ip, port=port, proto=proto: dict(ip=ip, port=port, proto=proto),
                        ip=ip, port=port, proto=proto))
    for h in d.removed_devices:
        out.append(make("DEVICE_GONE", lambda l, h=h: dict(ip=h.ip, type=_type_label(l, h)), ip=h.ip))
    if d.score_before != d.score_after and d.score_before is not None and d.score_after is not None:
        out.append(make("SCORE", lambda l: dict(before=d.score_before, after=d.score_after)))
    return out


# --- un ciclu ------------------------------------------------------------------------------------------

def _prune_xml(scans_dir: Path, keep: int = KEEP_XML) -> None:
    files = sorted(scans_dir.glob(f"{WATCH_PREFIX}*.xml"))
    for old in files[:-keep] if keep > 0 else files:
        try:
            old.unlink()
        except OSError:
            pass


def run_cycle(previous: Optional[Scan], lang: str = "ro", target: Optional[str] = None,
              prepare: Callable = runner.prepare_scan, execute: Callable = runner.execute,
              analyze: Optional[Callable] = None, scans_dir: Path = SCANS_DIR,
              now: Callable = time.time) -> CycleResult:
    """Un ciclu complet, în procesul cu drepturi de administrator (NFR-04).

    Scrie DOAR fișierul XML în `scans_dir` (plus copia bazei de sonde, lângă el). Nu scrie în istoric și nici
    alerte pe disc: sub sudo / alt cont de admin, folderul de date ar putea fi altul sau ar rămâne al lui root,
    iar UI-ul (utilizator normal) nu l-ar vedea. Alertele se afișează în terminal; istoricul îl aduce
    `import-scans`, rulat ca utilizator normal. Nu ridică excepții pentru probleme de rețea."""
    t = TEXTS[lang if lang in TEXTS else "ro"]
    if analyze is None:
        from netscan.engine.parser import analyze_file as analyze

    out_path = scans_dir / time.strftime(f"{WATCH_PREFIX}%Y%m%d_%H%M%S.xml", time.localtime(now()))
    plan = prepare(target, out_path=out_path)
    if not plan.ok:                                   # altă rețea, SSID greșit, țintă refuzată...
        return CycleResult("skipped", t["skipped"].format(why=plan.message(lang)))
    result = execute(plan)
    if not result.ok:
        return CycleResult("failed", t["failed"].format(why=result.message(lang)))

    scan = analyze(str(out_path))                     # doar în memorie
    _prune_xml(scans_dir)
    if scan.status != "ok":
        return CycleResult("failed", t["failed"].format(why=scan.error_code or "?"))
    if previous is None:
        return CycleResult("baseline", t["baseline"].format(n=len(scan.hosts), score=scan.score), scan=scan)
    alerts = build_alerts(previous, scan, ts=now())
    if not alerts:
        return CycleResult("no_change", t["no_change"].format(score=scan.score), scan=scan)
    return CycleResult("changes", "\n".join(a.text(lang) for a in alerts), alerts=alerts, scan=scan)


# --- importul în istoric (utilizator normal) ---------------------------------------------------------------

def import_scans(scans_dir: Path = SCANS_DIR, db_path=None, lang: str = "ro", out: Callable[[str], None] = print,
                 is_admin: Callable[[], bool] = runner.is_admin, analyze: Optional[Callable] = None) -> int:
    """Aduce scanările monitorului (`watch_*.xml`) în istoric și scrie alertele dintre ele.
    Rulează ca utilizator normal, ca baza de date să fie a utilizatorului și s-o vadă UI-ul.
    Se poate rula de câte ori vrei: scanările deja importate se sar."""
    from netscan.ui.storage import find_scan, save_scan
    t = TEXTS[lang if lang in TEXTS else "ro"]
    if is_admin():
        out(t["import_admin"])
        return 2
    if analyze is None:
        from netscan.engine.parser import analyze_file as analyze
    previous: Optional[Scan] = None
    imported = n_alerts = 0
    for path in sorted(Path(scans_dir).glob(f"{WATCH_PREFIX}*.xml")):
        scan = analyze(str(path))
        if scan.status != "ok":
            continue
        if find_scan(scan.file, scan.started_at, db_path) is None:
            save_scan(scan, db_path)
            imported += 1
            if previous is not None:
                alerts = build_alerts(previous, scan, ts=float(scan.started_at or time.time()))
                local_data.append_events(local_data.alerts_path(db_path), (asdict(a) for a in alerts))
                n_alerts += len(alerts)
        previous = scan
    out(t["imported"].format(n=imported, a=n_alerts))
    return 0


# --- blocarea (un singur monitor) ---------------------------------------------------------------------
# Fișierul de blocare stă lângă XML-uri (folderul procesului privilegiat), nu în folderul de date.

def _lock_path(scans_dir: Path = SCANS_DIR) -> Path:
    return Path(scans_dir) / ".watch.lock"


def acquire_lock(scans_dir: Path = SCANS_DIR) -> Optional[int]:
    """None dacă am luat blocarea; altfel PID-ul monitorului care rulează deja."""
    path = _lock_path(scans_dir)
    try:
        pid = int(path.read_text().strip())
        import psutil
        if pid != os.getpid() and psutil.pid_exists(pid):
            return pid
    except (OSError, ValueError, ImportError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))
    return None


def release_lock(scans_dir: Path = SCANS_DIR) -> None:
    try:
        _lock_path(scans_dir).unlink()
    except FileNotFoundError:
        pass


def watch(every_min: float, confirm: bool, lang: str = "ro", target: Optional[str] = None,
          max_cycles: Optional[int] = None, out: Callable[[str], None] = print,
          sleep: Callable[[float], None] = time.sleep, cycle: Callable = run_cycle,
          scans_dir: Path = SCANS_DIR) -> int:
    t = TEXTS[lang if lang in TEXTS else "ro"]
    if every_min < MIN_INTERVAL_MIN:
        out(t["too_often"].format(min=MIN_INTERVAL_MIN))
        return 2
    if not confirm:
        plan = runner.prepare_scan(target)
        out(plan.message(lang))
        if plan.ok:
            out(t["dry_run"].format(every=int(every_min)))
            out("  " + runner.format_command(plan.args))
            out(t["add_confirm"])
        return 0 if plan.ok else 2

    other = acquire_lock(scans_dir)
    if other is not None:
        out(t["locked"].format(pid=other))
        return 2
    out(t["import_hint"])
    previous: Optional[Scan] = None
    done = 0
    try:
        while max_cycles is None or done < max_cycles:
            res = cycle(previous, lang=lang, target=target, scans_dir=scans_dir)
            out(time.strftime("[%H:%M] ") + res.message)
            if res.scan is not None:
                previous = res.scan
            done += 1
            if max_cycles is not None and done >= max_cycles:
                break
            out(t["next"].format(at=time.strftime("%H:%M", time.localtime(time.time() + every_min * 60))))
            sleep(every_min * 60)
    except KeyboardInterrupt:
        out(t["stopped"])
    finally:
        release_lock(scans_dir)
    return 0
