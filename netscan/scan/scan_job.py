"""Scanarea pornită din aplicație (B). Rulează în procesul cu drepturi de administrator, pornit de elevate.py
doar după acordul utilizatorului.

- `scan`: o scanare completă, exact comanda de la `scan --confirm` (plus `-v --stats-every 5s`, doar pentru
  afișarea progresului), cu aceleași verificări: hotspotul echipei, o singură rețea, guardrail.
- `auto`: la fel, apoi din nou la fiecare AUTO_EVERY_MIN minute, până o opresc din aplicație (fișierul de oprire),
  laptopul pleacă de pe hotspot (atunci ciclul se sare, fără scanare) sau aplicația se închide (nu mai atinge
  scans/.app.alive de APP_ALIVE_MAX_AGE_S secunde): scanarea automată nu trăiește după aplicație.

Reguli de siguranță, în plus față de `scan --confirm`:
- numele Wi-Fi TREBUIE citit (NETSCAN_REQUIRE_SSID=1 implicit aici): subnetul singur nu dovedește că e hotspotul
  nostru (orice hotspot de iPhone e 172.20.10.0/28);
- în timpul scanării verificăm rețeaua din nou la fiecare NETWORK_RECHECK_S secunde; dacă ai ieșit de pe hotspot
  (alt IP, alt subnet, alt Wi-Fi sau numele nu se mai poate citi), oprim nmap pe loc (NETWORK_CHANGED).

NFR-04: procesul de admin scrie DOAR în scans/: XML-ul nmap, copia bazei de sonde, progresul
(.scan_progress.json) și blocarea (.scan.lock). Nu atinge istoricul și nici data/: scanarea o aduce în istoric
aplicația, ca utilizator normal. Progresul conține doar faza, procentul și porturile găsite (IP, port, protocol).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from netscan.scan import network, runner

ROOT = Path(__file__).resolve().parents[2]
SCANS_DIR = ROOT / "scans"
PROGRESS_FILE = ".scan_progress.json"
LOCK_FILE = ".scan.lock"
STOP_FILE = ".scan.stop"
PART_SUFFIX = ".part"                  # XML-ul în lucru: scan_<dată>.xml.part
NOW_FILE = ".scan.now"                 # aplicația cere o scanare mai devreme (dispozitiv sau port riscant nou)
MIN_GAP_MIN = 10                       # dar nu mai des de o dată la 10 minute (ca `watch`)
WATCH_LOCK_FILE = ".watch.lock"        # monitorul din terminal (`watch`): nu scanăm de două ori odată
AUTO_EVERY_MIN = 15
APP_ALIVE_FILE = ".app.alive"          # atins de aplicație la ~10 s cât rulează scanarea automată (live.py)
APP_ALIVE_MAX_AGE_S = 120              # mai vechi de atât = aplicația s-a închis: oprim scanarea automată
NETWORK_RECHECK_S = 5                  # cât de des verificăm rețeaua în timpul scanării
NETWORK_CHANGED = "NETWORK_CHANGED"
APP_CLOSED = "APP_CLOSED"
BUSY = "BUSY"
MESSAGES = {
    NETWORK_CHANGED: ("Ai ieșit de pe hotspot, așa că am oprit scanarea.",
                      "You left the hotspot, so I stopped the scan."),
    APP_CLOSED: ("Am oprit scanarea automată: aplicația s-a închis.",
                 "I stopped automatic scanning: the app was closed."),
    BUSY: ("Rulează deja o scanare (sau monitorul din terminal). Încearcă din nou după ce se termină.",
           "A scan (or the terminal monitor) is already running. Try again when it finishes."),
}
MAX_DISCOVERED = 300
MAX_PROGRESS_BYTES = 64 * 1024

# Fazele unei scanări, în ordine, cu ponderea lor aproximativă din durata totală (pentru bara de progres).
PHASES = (("discover", 5), ("tcp", 35), ("udp", 25), ("services", 25), ("scripts", 10))
_WEIGHT = dict(PHASES)
_ORDER = [p for p, _ in PHASES]

_PHASE_NAMES = (
    ("ARP Ping Scan", "discover"), ("Ping Scan", "discover"), ("Parallel DNS", "discover"),
    ("SYN Stealth Scan", "tcp"), ("Connect Scan", "tcp"), ("UDP Scan", "udp"),
    ("Service scan", "services"), ("NSE", "scripts"), ("Script scan", "scripts"),
)
_TIMING = re.compile(r"^(?P<name>[A-Za-z][A-Za-z ]*?) Timing: About (?P<pct>\d{1,3}(?:\.\d+)?)% done"
                     r"(?:; ETC: \S+ \((?P<h>\d+):(?P<m>\d{2}):(?P<s>\d{2}) remaining\))?")
_INITIATING = re.compile(r"^Initiating (?P<name>.+?)(?: at \d{1,2}:\d{2})?\.?$")
_COMPLETED = re.compile(r"^Completed (?P<name>.+?) at ")
_DISCOVERED = re.compile(r"^Discovered open port (?P<port>\d{1,5})/(?P<proto>tcp|udp) on (?P<ip>\d{1,3}(?:\.\d{1,3}){3})$")
_DONE = re.compile(r"^Nmap done: \d+ IP addresses? \((?P<up>\d+) hosts? up\)")


def _phase_of(name: str) -> Optional[str]:
    for prefix, phase in _PHASE_NAMES:
        if name.startswith(prefix):
            return phase
    return None


class Progress:
    """Starea scanării, construită din ieșirea lui nmap. Doar date simple, validate."""

    def __init__(self, job: str, now: Callable[[], float] = time.time):
        self.now = now
        self.data: dict = {"v": 1, "job": job, "state": "running", "pid": os.getpid(), "started": now(),
                           "updated": now(), "phase": None, "phase_pct": 0.0, "percent": 0.0, "eta_s": None,
                           "discovered": [], "hosts_up": None, "file": None, "code": None,
                           "msg_ro": "", "msg_en": "", "next_at": None}
        self._done_phases: set[str] = set()
        self._scanned = False          # a început scanarea porturilor (NSE-ul de dinainte nu contează)

    def _recompute(self) -> None:
        done = sum(_WEIGHT[p] for p in self._done_phases)
        cur = self.data["phase"]
        if cur and cur not in self._done_phases:
            done += _WEIGHT[cur] * min(self.data["phase_pct"], 100.0) / 100.0
        # bara nu merge niciodată înapoi (nmap poate relua fazele pentru alt grup de dispozitive)
        self.data["percent"] = max(self.data["percent"], round(min(done, 99.0), 1))

    def _phase(self, name: str) -> Optional[str]:
        """Faza pentru o linie nmap. Cu --script, nmap rulează NSE și ÎNAINTE de scanare (pre-scanare): o ignorăm."""
        phase = _phase_of(name)
        if phase in ("tcp", "udp"):
            self._scanned = True
        if phase in ("services", "scripts") and not self._scanned:
            return None
        return phase

    def feed(self, line: str) -> bool:
        """Interpretează o linie de la nmap. True dacă s-a schimbat ceva de afișat."""
        line = line.strip()
        m = _DISCOVERED.match(line)
        if m:
            port, proto, ip = int(m["port"]), m["proto"], m["ip"]
            try:
                ip = str(ipaddress.IPv4Address(ip))
            except ValueError:
                return False
            item = {"ip": ip, "port": port, "proto": proto}
            if 1 <= port <= 65535 and item not in self.data["discovered"] \
                    and len(self.data["discovered"]) < MAX_DISCOVERED:
                self.data["discovered"].append(item)
                return True
            return False
        m = _TIMING.match(line)
        if m:
            phase = self._phase(m["name"])
            if phase is None:
                return False
            self._enter(phase)
            self.data["phase_pct"] = min(float(m["pct"]), 100.0)
            if m["h"] is not None:
                self.data["eta_s"] = int(m["h"]) * 3600 + int(m["m"]) * 60 + int(m["s"])
            self._recompute()
            return True
        m = _INITIATING.match(line)
        if m and self._phase(m["name"]):
            self._enter(self._phase(m["name"]))
            self.data["phase_pct"] = 0.0
            self.data["eta_s"] = None
            self._recompute()
            return True
        m = _COMPLETED.match(line)
        if m and self._phase(m["name"]):
            phase = self._phase(m["name"])
            if phase == self.data["phase"]:
                self._done_phases.add(phase)
                self.data["phase_pct"] = 100.0
                self._recompute()
            return True
        m = _DONE.match(line)
        if m:
            self.data["hosts_up"] = int(m["up"])
            return True
        return False

    def _enter(self, phase: str) -> None:
        cur = self.data["phase"]
        if phase != cur and (cur is None or _ORDER.index(phase) > _ORDER.index(cur)):
            # fazele de dinainte se consideră încheiate (nmap nu anunță mereu „Completed”)
            for p in _ORDER[:_ORDER.index(phase)]:
                self._done_phases.add(p)
        self.data["phase"] = phase

    def finish(self, state: str, file: Optional[str] = None, code: Optional[str] = None,
               msg_ro: str = "", msg_en: str = "") -> None:
        self.data.update(state=state, file=file, code=code, msg_ro=msg_ro[:300], msg_en=msg_en[:300],
                         eta_s=None)
        if state == "done":
            self.data["percent"] = 100.0


class ProgressWriter:
    """Scrie progresul atomic (fișier temporar + înlocuire), cel mult o dată la `every_s` secunde."""

    def __init__(self, scans_dir: Path, now: Callable[[], float] = time.time, every_s: float = 0.5):
        self.path = Path(scans_dir) / PROGRESS_FILE
        self.now = now
        self.every_s = every_s
        self._last = 0.0

    def write(self, data: dict, force: bool = False) -> None:
        t = self.now()
        if not force and t - self._last < self.every_s:
            return
        self._last = t
        data["updated"] = t
        tmp = self.path.with_name(PROGRESS_FILE + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)


def read_progress(scans_dir: Path) -> Optional[dict]:
    """Citit de aplicație (utilizator normal). Fișierul e tratat ca date nesigure: mărime limitată, câmpuri
    verificate. None dacă lipsește sau e stricat."""
    path = Path(scans_dir) / PROGRESS_FILE
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_PROGRESS_BYTES:
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    def num(key, lo=0.0, hi=float("inf")):
        v = data.get(key)
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi else None

    def text(key, limit=300):
        v = data.get(key)
        return v[:limit] if isinstance(v, str) else ""

    state = text("state", 20)
    if state not in ("running", "done", "failed", "refused", "stopped", "waiting_next"):
        return None
    discovered = []
    for item in data.get("discovered") or []:
        if not isinstance(item, dict) or len(discovered) >= MAX_DISCOVERED:
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(item.get("ip"))))
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and item.get("proto") in ("tcp", "udp"):
            discovered.append({"ip": ip, "port": port, "proto": item["proto"]})
    phase = text("phase", 20)
    file = text("file", 120)
    if file and (Path(file).name != file or not file.endswith(".xml")):
        file = ""
    pid = data.get("pid")
    return {"job": text("job", 10) or "scan", "state": state, "pid": pid if isinstance(pid, int) else None,
            "started": num("started"), "updated": num("updated"), "phase": phase if phase in _WEIGHT else None,
            "phase_pct": num("phase_pct", 0, 100) or 0.0, "percent": num("percent", 0, 100) or 0.0,
            "eta_s": num("eta_s", 0, 86400), "discovered": discovered, "hosts_up": num("hosts_up", 0, 65536),
            "file": file or None, "code": text("code", 40) or None, "msg_ro": text("msg_ro"),
            "msg_en": text("msg_en"), "next_at": num("next_at")}


# --- blocarea: o singură scanare odată -----------------------------------------------------------------

def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return False


def _create_time(pid: int) -> Optional[float]:
    try:
        import psutil
        return psutil.Process(pid).create_time()
    except Exception:
        return None


def _read_lock(path: Path) -> Optional[tuple[int, Optional[float]]]:
    """(pid, momentul pornirii procesului) din fișierul de blocare: JSON nou sau doar PID-ul (format vechi)."""
    try:
        text = path.read_text().strip()
    except OSError:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, int) and not isinstance(data, bool):
        return data, None
    if isinstance(data, dict) and isinstance(data.get("pid"), int):
        created = data.get("created")
        return data["pid"], float(created) if isinstance(created, (int, float)) else None
    return None


def _holder_alive(pid: int, created: Optional[float]) -> bool:
    """Procesul din blocare încă rulează? Cu momentul pornirii, un PID refolosit de alt program nu păcălește."""
    if not _pid_alive(pid):
        return False
    if created is None:
        return True
    now_created = _create_time(pid)
    return now_created is None or abs(now_created - created) < 1.0


def write_lock(scans_dir: Path) -> None:
    pid = os.getpid()
    (Path(scans_dir) / LOCK_FILE).write_text(json.dumps({"pid": pid, "created": _create_time(pid)}))


def lock_holder(scans_dir: Path) -> Optional[int]:
    """PID-ul scanării (din aplicație sau a monitorului din terminal) care rulează acum, altfel None."""
    for name in (LOCK_FILE, WATCH_LOCK_FILE):
        held = _read_lock(Path(scans_dir) / name)
        if held is None:
            continue
        pid, created = held
        if pid != os.getpid() and _holder_alive(pid, created):
            return pid
    return None


def clear_stale_lock(scans_dir: Path, log: Optional[Callable[[str], None]] = None) -> bool:
    """Șterge .scan.lock rămas de la o scanare al cărei proces nu mai rulează (închis brusc) și spune asta."""
    path = Path(scans_dir) / LOCK_FILE
    if not path.exists():
        return False
    held = _read_lock(path)
    if held is not None and (held[0] == os.getpid() or _holder_alive(*held)):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    pid = held[0] if held else "?"
    (log or (lambda m: print(m, file=sys.stderr)))(
        f"netscan: am șters o blocare veche ({LOCK_FILE}: procesul {pid} nu mai rulează). / "
        f"removed a stale lock ({LOCK_FILE}: process {pid} is not running).")
    return True


def stop_requested(scans_dir: Path) -> bool:
    return (Path(scans_dir) / STOP_FILE).exists()


def app_alive(scans_dir: Path, now: Callable[[], float] = time.time) -> bool:
    """Aplicația încă trăiește? (a atins scans/.app.alive în ultimele APP_ALIVE_MAX_AGE_S secunde)."""
    try:
        mtime = (Path(scans_dir) / APP_ALIVE_FILE).stat().st_mtime
    except OSError:
        return False
    return now() - mtime <= APP_ALIVE_MAX_AGE_S


def same_network(planned, current) -> bool:
    """Aceeași rețea ca la pornirea scanării: tot permisă, numele Wi-Fi citit și același (IP, subnet, Wi-Fi)."""
    if planned is None or current is None or not current.scan_allowed or not current.ssid:
        return False
    return (current.ip, current.cidr, current.ssid) == (planned.ip, planned.cidr, planned.ssid)


# --- rularea ------------------------------------------------------------------------------------------

def run_once(scans_dir: Path, job: str, writer: ProgressWriter, prepare: Callable = runner.prepare_scan,
             execute: Callable = runner.execute_streaming, now: Callable[[], float] = time.time,
             detect: Optional[Callable] = None) -> int:
    progress = Progress(job, now)
    # nmap scrie XML-ul în timp ce scanează: îl ține sub numele .part (aplicația citește doar *.xml) și îl
    # redenumește doar când e complet, ca un fișier pe jumătate scris să nu apară niciodată ca scanare.
    final = Path(scans_dir) / time.strftime("scan_%Y%m%d_%H%M%S.xml", time.localtime(now()))
    out_path = final.with_name(final.name + PART_SUFFIX)
    plan = prepare(None, out_path=out_path)
    if not plan.ok:
        progress.finish("refused", code=plan.reason_code, msg_ro=plan.msg_ro, msg_en=plan.msg_en)
        writer.write(progress.data, force=True)
        return 2
    writer.write(progress.data, force=True)

    def on_line(line: str) -> None:
        if progress.feed(line):
            writer.write(progress.data)

    # Rețeaua, verificată din nou cât rulează nmap (la NETWORK_RECHECK_S secunde): ai ieșit de pe hotspot -> stop.
    detect = detect or network.detect_network
    planned = getattr(plan, "network", None)
    left = {"flag": False, "checked": now()}

    def should_stop() -> bool:
        if left["flag"] or stop_requested(scans_dir):
            return True
        if now() - left["checked"] >= NETWORK_RECHECK_S:
            left["checked"] = now()
            try:
                current = detect()
            except Exception:
                current = None
            left["flag"] = not same_network(planned, current)
        return left["flag"]

    result = execute(plan, on_line, should_stop=should_stop)
    if left["flag"]:
        # chiar dacă nmap a apucat să termine, nu păstrăm o scanare din timpul căreia am plecat de pe hotspot
        ro, en = MESSAGES[NETWORK_CHANGED]
        progress.finish("stopped", code=NETWORK_CHANGED, msg_ro=ro, msg_en=en)
        rc = 1
        if result.ok:
            result = runner._refuse(NETWORK_CHANGED, ro=ro, en=en)
    elif result.ok:
        os.replace(out_path, final)
        progress.finish("done", file=final.name)
        rc = 0
    elif result.reason_code == runner.STOPPED:
        progress.finish("stopped", code=result.reason_code, msg_ro=result.msg_ro, msg_en=result.msg_en)
        rc = 1
    else:
        progress.finish("failed", code=result.reason_code, msg_ro=result.msg_ro, msg_en=result.msg_en)
        rc = 2
    if not result.ok:
        try:
            out_path.unlink()                  # o scanare neterminată nu rămâne pe disc
        except OSError:
            pass
    writer.write(progress.data, force=True)
    return rc


def main(argv: list[str], scans_dir: Path = SCANS_DIR, run: Callable = run_once,
         sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time,
         load_env: bool = True) -> int:
    job = argv[0] if argv else ""
    if job not in ("scan", "auto"):
        return 2
    if load_env:
        from netscan.cli import load_env_file
        load_env_file(ROOT / ".env")        # NETSCAN_EXPECTED_SSID etc., exact ca la `scan --confirm`
    # Scanarea din aplicație atinge rețeaua: fără numele Wi-Fi citit nu scanăm (fail-closed). Gol sau lipsă = 1;
    # doar un „0” scris explicit (pentru dezvoltare) îl dezactivează.
    if not (os.environ.get("NETSCAN_REQUIRE_SSID") or "").strip():
        os.environ["NETSCAN_REQUIRE_SSID"] = "1"
    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)
    writer = ProgressWriter(scans_dir, now)
    clear_stale_lock(scans_dir)
    if lock_holder(scans_dir) is not None:
        prog = read_progress(scans_dir)
        if prog is None or prog["state"] not in ("running", "waiting_next"):
            # monitorul din terminal (fără progres propriu): aplicația află de ce nu pornim, în loc să aștepte
            ro, en = MESSAGES[BUSY]
            writer.write({"v": 1, "job": job, "state": "refused", "pid": os.getpid(), "started": now(),
                          "code": BUSY, "msg_ro": ro, "msg_en": en, "file": None, "next_at": None}, force=True)
        return 3                            # rulează deja o scanare; aplicația afișează progresul ei
    write_lock(scans_dir)
    try:
        last_start = now()
        rc = run(scans_dir, job, writer)
        app_closed = False
        while job == "auto" and not stop_requested(scans_dir):
            next_at = last_start + AUTO_EVERY_MIN * 60
            data = (read_progress(scans_dir) or {}) | {"v": 1, "job": job, "state": "waiting_next",
                                                         "pid": os.getpid(), "next_at": next_at}
            writer.write(data, force=True)
            while now() < next_at and not stop_requested(scans_dir):
                if not app_alive(scans_dir, now):
                    app_closed = True          # aplicația s-a închis: scanarea automată nu continuă fără ea
                    break
                if (scans_dir / NOW_FILE).exists() and now() - last_start >= MIN_GAP_MIN * 60:
                    break                      # risc nou văzut live: scanăm acum (dar nu mai des de 10 min)
                sleep(1.0)
            if app_closed or stop_requested(scans_dir):
                break
            try:
                (scans_dir / NOW_FILE).unlink()
            except OSError:
                pass
            last_start = now()
            rc = run(scans_dir, job, writer)
        if job == "auto":
            data = (read_progress(scans_dir) or {}) | {"v": 1, "job": job, "state": "stopped", "pid": os.getpid(),
                                                         "next_at": None}
            if app_closed:
                ro, en = MESSAGES[APP_CLOSED]
                data |= {"code": APP_CLOSED, "msg_ro": ro, "msg_en": en}
            writer.write(data, force=True)
        return rc
    finally:
        for name in (LOCK_FILE, STOP_FILE, NOW_FILE):
            try:
                (scans_dir / name).unlink()
            except OSError:
                pass
