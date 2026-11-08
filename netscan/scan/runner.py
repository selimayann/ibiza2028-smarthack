"""Runner nmap (Oneata): listă de argumente, niciodată shell=True; dry-run fără --confirm.
Singurul pas care cere drepturi de administrator (NFR-04).

Ordinea (docs/roles/B_Oneata_Siguranta_Scanare_AI.md, 2.2):
    network -> check_target -> (fără --confirm: afișează comanda și ieși) -> (cu --confirm: rulează nmap)

Ținta trimisă lui nmap e întotdeauna rețeaua normalizată de guardrail (ex. "172.20.10.5/32"),
niciodată textul scris de utilizator.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from netscan.scan import guardrail, network

UDP_PORTS = "53,123,161,1900,5353"
# Porturile din catalog care lipsesc din top 1000 nmap (mqtt, redis, mongodb)
CATALOG_EXTRA_TCP = [1883, 6379, 27017]
MAX_RATE = "100"  # regula de ≤100 pachete/secundă
TOP_PORTS_FILE = Path(__file__).with_name("top1000_tcp.txt")
DEFAULT_SCANS_DIR = Path("scans")

# Coduri de refuz proprii runner-ului (în plus față de stările din network și guardrail).
NETWORK_NOT_OK = "NETWORK_NOT_OK"
NO_TOP_PORTS = "NO_TOP_PORTS"
NMAP_NOT_FOUND = "NMAP_NOT_FOUND"
NMAP_IFACE_NOT_FOUND = "NMAP_IFACE_NOT_FOUND"
NOT_ADMIN = "NOT_ADMIN"
NMAP_FAILED = "NMAP_FAILED"
NO_SERVICE_PROBES = "NO_SERVICE_PROBES"
ALREADY_RUNNING = "ALREADY_RUNNING"
LOCK_NAME = ".scan.lock"          # în scans/: o singură scanare odată (din terminal SAU din aplicație)
PART_SUFFIX = ".part"             # nmap scrie aici; abia la final devine .xml (aplicația nu vede fișiere pe jumătate)

MESSAGES: dict[str, tuple[str, str]] = {
    NO_TOP_PORTS: (
        "Lipsește lista de porturi netscan/scan/top1000_tcp.txt.",
        "The port list netscan/scan/top1000_tcp.txt is missing.",
    ),
    NMAP_NOT_FOUND: (
        "Nu găsesc nmap. Instalează-l de pe nmap.org (pe Windows, împreună cu Npcap).",
        "I can't find nmap. Install it from nmap.org (on Windows, together with Npcap).",
    ),
    NMAP_IFACE_NOT_FOUND: (
        "nmap nu găsește interfața rețelei tale. Verifică cu: nmap --iflist",
        "nmap can't find your network interface. Check with: nmap --iflist",
    ),
    NOT_ADMIN: (
        "Scanarea live cere drepturi de administrator. Pe Windows deschide terminalul ca Administrator; "
        "pe Linux/macOS folosește sudo.",
        "Live scanning needs administrator rights. On Windows open the terminal as Administrator; "
        "on Linux/macOS use sudo.",
    ),
    NMAP_FAILED: ("Scanarea nmap a eșuat.", "The nmap scan failed."),
    ALREADY_RUNNING: (
        "Rulează deja o scanare (din terminal sau din aplicație). Așteaptă să se termine: două scanări odată "
        "dublează traficul și strică rezultatele.",
        "A scan is already running (from the terminal or the app). Wait for it to finish: two scans at once "
        "double the traffic and spoil the results.",
    ),
    NO_SERVICE_PROBES: (
        "Nu găsesc fișierul nmap-service-probes al nmap. Reinstalează nmap.",
        "I can't find nmap's nmap-service-probes file. Reinstall nmap.",
    ),
}


@dataclass
class ScanPlan:
    ok: bool
    reason_code: str
    msg_ro: str
    msg_en: str
    network: Optional[network.NetworkInfo] = None
    target: Optional[str] = None          # ținta normalizată de guardrail
    args: list[str] = field(default_factory=list)
    out_path: Optional[str] = None
    service_probes: Optional[str] = None   # nmap-service-probes original
    versiondb: Optional[str] = None        # copia fără sonde pe portul 53

    def message(self, lang: str = "ro") -> str:
        return self.msg_ro if lang == "ro" else self.msg_en


def _refuse(code: str, info=None, target=None, ro: Optional[str] = None, en: Optional[str] = None) -> ScanPlan:
    mro, men = MESSAGES.get(code, ("", ""))
    return ScanPlan(False, code, ro or mro, en or men, network=info, target=target)


# --- argumentele nmap -----------------------------------------------------------------------

def _port_in_list(port: int, ports: str) -> bool:
    for part in ports.split(","):
        a, _, b = part.partition("-")
        if a.isdigit() and int(a) <= port <= int(b or a):
            return True
    return False


def tcp_port_spec(top_ports: str) -> str:
    """Lista top 1000 (neatinsă) + porturile din CATALOG_EXTRA_TCP care nu sunt deja în ea."""
    extra = [str(p) for p in CATALOG_EXTRA_TCP if not _port_in_list(p, top_ports)]
    return ",".join([top_ports, *extra])


def build_nmap_args(target: str, iface: str, tcp_ports: str, out_path: str,
                    versiondb: Optional[str] = None) -> list[str]:
    """Comanda din instrucțiuni, cu porturile CATALOG_EXTRA_TCP adăugate la T:.
    `-n`: fără DNS invers (cererile ar ieși din hotspot prin DNS-ul operatorului).
    `--versiondb`: baza de sonde fără detecție de versiune pe portul 53 (vezi write_versiondb).
    Fiecare valoare e un argument separat; nimic nu trece prin shell."""
    args = [
        "nmap", "-n", "-sS", "-sU", "-sV", "--script", "http-title",
        "-p", f"T:{tcp_port_spec(tcp_ports)},U:{UDP_PORTS}",
        "--max-rate", MAX_RATE, "-e", iface,
    ]
    if versiondb:
        args += ["--versiondb", versiondb]
    return args + ["-oX", out_path, target]


# --- portul 53 fără sonde de versiune ---------------------------------------------------------
# La -sV, nmap trimite pe portul 53 interogări DNS (version.bind, DNS-SD, ...). Gateway-ul hotspotului
# (telefonul) le trimite mai departe la DNS-ul operatorului, deci ar ieși trafic din rețeaua noastră.
# Portul 53 rămâne scanat (U:53 e cerut), dar fără detecția de versiune: nicio regulă din catalog nu
# depinde de DNS. Folosim directiva oficială „Exclude” din nmap-service-probes, într-o copie locală.

NO_VERSION_PROBE_PORTS = "T:53,U:53"
VERSIONDB_NAME = "nmap-service-probes.netscan"


def find_service_probes(nmap_path: str) -> Optional[Path]:
    """Fișierul nmap-service-probes instalat odată cu nmap (Windows, Linux, macOS/Homebrew)."""
    exe_dir = Path(nmap_path).resolve().parent if nmap_path else None
    candidates = []
    if exe_dir is not None:
        candidates += [exe_dir / "nmap-service-probes", exe_dir.parent / "share" / "nmap" / "nmap-service-probes"]
    candidates += [Path(p) / "nmap-service-probes" for p in
                   ("/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap")]
    return next((c for c in candidates if c.is_file()), None)


def make_versiondb(text: str) -> str:
    """Adaugă NO_VERSION_PROBE_PORTS la directiva Exclude (sau o creează înaintea primei sonde)."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("Exclude "):
            end = line[len(line.rstrip("\r\n")):]
            lines[i] = line.rstrip("\r\n") + "," + NO_VERSION_PROBE_PORTS + end
            return "".join(lines)
    for i, line in enumerate(lines):
        if line.startswith("Probe "):
            lines.insert(i, f"Exclude {NO_VERSION_PROBE_PORTS}\n")
            return "".join(lines)
    return text + f"\nExclude {NO_VERSION_PROBE_PORTS}\n"


def write_versiondb(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(make_versiondb(src.read_text(encoding="utf-8", errors="surrogateescape")),
                   encoding="utf-8", errors="surrogateescape")
    return dst


def load_top_ports(path: Path = TOP_PORTS_FILE) -> Optional[str]:
    """Citește lista „21-23,25,80,…” și verifică să conțină doar cifre, virgule și cratime."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text or any(c not in "0123456789,-" for c in text):
        return None
    return text


def find_nmap() -> Optional[str]:
    found = shutil.which("nmap")
    if found:
        return found
    if sys.platform == "win32":
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
            if base:
                candidate = Path(base) / "Nmap" / "nmap.exe"
                if candidate.is_file():
                    return str(candidate)
    return None


def parse_nmap_iflist(text: str, ip: str) -> Optional[str]:
    """Din `nmap --iflist`, numele DEV al interfeței care are adresa `ip`.
    Pe Windows nmap folosește nume proprii (eth3, wlan0), diferite de „Wi-Fi”.
    Citim doar coloanele DEV și IP/MASK; MAC-ul nu e păstrat."""
    in_table = False
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts:
            in_table = False
            continue
        if parts[0] == "DEV":
            in_table = True
            continue
        if not in_table or parts[0].startswith("*"):
            continue
        # DEV (SHORT) IP/MASK TYPE UP MTU MAC
        for token in parts[1:4]:
            addr = token.split("/")[0]
            if addr == ip:
                return parts[0]
    return None


def resolve_nmap_iface(nmap_path: str, info: network.NetworkInfo, run: Callable) -> Optional[str]:
    if sys.platform != "win32":
        return info.iface  # pe Linux/macOS numele din sistem e același pentru nmap
    return parse_nmap_iflist(run([nmap_path, "--iflist"]) or "", info.ip or "")


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def default_out_path(scans_dir: Path = DEFAULT_SCANS_DIR) -> Path:
    return scans_dir / time.strftime("scan_%Y%m%d_%H%M%S.xml")


# --- planul și execuția ----------------------------------------------------------------------

def prepare_scan(
    target: Optional[str] = None,
    env: Optional[dict] = None,
    detect: Callable[[], network.NetworkInfo] = network.detect_network,
    run: Callable = network.run_command,
    nmap_path: Optional[str] = None,
    top_ports: Optional[str] = None,
    out_path: Optional[Path] = None,
    service_probes: Optional[Path] = None,
) -> ScanPlan:
    """network -> check_target -> argumentele nmap. Nu pornește nicio scanare."""
    env = os.environ if env is None else env

    info = detect()
    if not info.scan_allowed:
        ro, en = (network.status_message(info) if info.status in network.MESSAGES
                  else ("Rețeaua nu e potrivită pentru scanare.", "The network isn't suitable for scanning."))
        return _refuse(info.status, info, ro=ro, en=en)

    allowlist = guardrail.build_allowlist(info.cidr, env.get("NETSCAN_ALLOWLIST"))
    decision = guardrail.check_target(target if target is not None else (info.cidr or ""), allowlist)
    if not decision.ok:
        return _refuse(decision.reason_code, info, decision.network, decision.msg_ro, decision.msg_en)

    ports = top_ports if top_ports is not None else load_top_ports()
    if not ports:
        return _refuse(NO_TOP_PORTS, info, decision.network)

    nmap_path = nmap_path or find_nmap()
    if not nmap_path:
        return _refuse(NMAP_NOT_FOUND, info, decision.network)

    nmap_iface = resolve_nmap_iface(nmap_path, info, run)
    if not nmap_iface:
        return _refuse(NMAP_IFACE_NOT_FOUND, info, decision.network)

    probes = service_probes or find_service_probes(nmap_path)
    if probes is None or not Path(probes).is_file():
        return _refuse(NO_SERVICE_PROBES, info, decision.network)

    out = str(out_path or default_out_path())
    versiondb = str(Path(out).parent / VERSIONDB_NAME)
    args = build_nmap_args(decision.network, nmap_iface, ports, out, versiondb)
    return ScanPlan(True, guardrail.OK, decision.msg_ro, decision.msg_en,
                    network=info, target=decision.network, args=args, out_path=out,
                    service_probes=str(probes), versiondb=versiondb)


def _ready(plan: ScanPlan, nmap_path: Optional[str]) -> tuple[Optional[str], Optional[ScanPlan]]:
    """Verificările de dinaintea lui nmap: (calea nmap, None) sau (None, refuzul)."""
    if not plan.ok:
        return None, plan
    if not is_admin():
        return None, _refuse(NOT_ADMIN, plan.network, plan.target)
    nmap_path = nmap_path or find_nmap()
    if not nmap_path:
        return None, _refuse(NMAP_NOT_FOUND, plan.network, plan.target)
    Path(plan.out_path).parent.mkdir(parents=True, exist_ok=True)
    if plan.versiondb:
        try:
            write_versiondb(Path(plan.service_probes), Path(plan.versiondb))
        except OSError:
            return None, _refuse(NO_SERVICE_PROBES, plan.network, plan.target)
    return nmap_path, None


def _pid_alive(pid: int) -> bool:
    """Procesul mai rulează? (Pe Windows NU folosim os.kill: acolo ar opri procesul.)"""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                return False
            code = ctypes.c_ulong()
            ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
            k32.CloseHandle(h)
            return bool(ok) and code.value == 259          # STILL_ACTIVE
        except (AttributeError, OSError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def acquire_lock(scans_dir: Path) -> bool:
    """Ia lacătul scanării (fișier creat exclusiv, cu PID-ul nostru). Un lacăt rămas de la un proces mort se
    înlocuiește. False = altă scanare rulează acum."""
    lock = Path(scans_dir) / LOCK_NAME
    lock.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(str(os.getpid()))
            return True
        except FileExistsError:
            try:
                pid = int((lock.read_text(encoding="ascii") or "0").strip() or 0)
            except (OSError, ValueError):
                pid = 0
            if _pid_alive(pid):
                return False
            try:
                lock.unlink()                               # rămas de la o scanare oprită brusc
            except OSError:
                return False
    return False


def release_lock(scans_dir: Path) -> None:
    lock = Path(scans_dir) / LOCK_NAME
    try:
        if lock.read_text(encoding="ascii").strip() == str(os.getpid()):
            lock.unlink()
    except OSError:
        pass


def scan_running(scans_dir: Path) -> bool:
    """Rulează o scanare acum (lacătul e al unui proces viu)?"""
    lock = Path(scans_dir) / LOCK_NAME
    try:
        pid = int(lock.read_text(encoding="ascii").strip() or 0)
    except (OSError, ValueError):
        return False
    return _pid_alive(pid)


KNOWN_WAIT_S = 2.5   # cât lăsăm sistemul să facă ARP după datagramele goale (ca protecția live)


def known_hosts(plan: ScanPlan, poke=None, read=None, sleep=time.sleep) -> list[str]:
    """Adresele pe care Windows le vede ACUM conectate în hotspot (tabela ARP), doar din ținta aprobată de guardrail.
    Așa scanarea nu mai pierde laptopurile cu Wi-Fi în economie de energie (răspund greu la ARP-ul lui nmap, dar
    sistemul le ține minte). Orice eroare: [] (nmap își caută singur dispozitivele, ca înainte)."""
    import ipaddress
    info = plan.network
    if info is None or not info.ip or not info.cidr or not plan.target:
        return []
    try:
        from netscan.scan import neighbors
        net = ipaddress.ip_network(plan.target, strict=False)
        own = ipaddress.ip_address(info.ip)
        hosts = [str(h) for h in net.hosts() if h != own]
        if not hosts or len(hosts) > 254:
            return []
        (poke or neighbors.poke)(hosts, info.ip)
        sleep(KNOWN_WAIT_S)
        table = (read or neighbors.read_neighbors)(info) or {}
        found = sorted((ip for ip in table if ipaddress.ip_address(ip) in net and ip != info.ip),
                       key=lambda ip: tuple(int(x) for x in ip.split(".")))
        _write_present(plan, {ip: table[ip] for ip in found})
        return found
    except Exception:
        return []


PRESENT_SUFFIX = ".present.json"   # lângă scan_<dată>.xml: cine era conectat când a pornit scanarea


def present_path(xml_path: str | Path) -> Path:
    p = str(xml_path)
    for suf in (PART_SUFFIX, PART_SUFFIX):           # scan_x.xml.part(.part) -> scan_x.xml
        if p.endswith(suf):
            p = p[: -len(suf)]
    return Path(p + PRESENT_SUFFIX)


def _write_present(plan: ScanPlan, table: dict) -> None:
    """Lista aparatelor conectate la pornirea scanării (fără MAC complet: doar ce arată și Live)."""
    import json
    try:
        rows = [{"ip": ip, "mac_masked": getattr(n, "mac_masked", None), "vendor": getattr(n, "vendor", None),
                 "private_mac": bool(getattr(n, "private_mac", False)), "device_id": getattr(n, "device_id", None)}
                for ip, n in table.items()]
        present_path(plan.out_path).write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _with_known(args: list[str], plan: ScanPlan, known: list[str]) -> list[str]:
    """Ținta (ultimul argument, subnetul) înlocuită cu adresele prezente + -Pn. Nimic în afara țintei aprobate."""
    if not known or not args or args[-1] != plan.target:
        return args
    # --disable-arp-ping: pe rețeaua locală nmap face oricum ARP-ul lui (și cu -Pn); pe hotspot, laptopurile nu-i
    # răspund lui, deși sistemul le vede. Așa folosește tabela ARP a sistemului (tocmai împrospătată) și le verifică.
    return [*args[:-1], "-Pn", "--disable-arp-ping", *known]


def _passes(args: list[str], plan: ScanPlan, known: list[str]) -> list[list[str]]:
    """Comenzile nmap de rulat, pe rând (toate scriu în același -oX; a doua primește alt fișier, apoi se unesc).
    Gateway-ul (telefonul cu hotspotul) răspunde doar la ARP-ul lui nmap, iar laptopurile doar la cel al sistemului:
    -> trecerea 1: gateway-ul, ca înainte; trecerea 2: restul, cu -Pn --disable-arp-ping. Fără listă: ca înainte."""
    if not known or not args or args[-1] != plan.target:
        return [args]
    gw = plan.network.gateway if plan.network is not None else None
    others = [ip for ip in known if ip != gw]
    if not others:
        return [[*args[:-1], gw]] if gw in known else [args]
    rest = _with_known(args, plan, others)
    if gw not in known:
        return [rest]
    first = list(args[:-1]) + [gw]
    i = first.index("-oX") if "-oX" in first else -1
    if i >= 0:
        first[i + 1] = first[i + 1] + ".gw"          # fișierul trecerii gateway-ului (se unește cu cel principal)
    return [first, rest]


def _merge_hosts(main: Path, extra: Path) -> None:
    """Gazdele din `extra` (XML nmap) puse în `main`, înainte de <runstats>. `extra` se șterge."""
    import re
    try:
        hosts = re.findall(r"<host\b.*?</host>", extra.read_text(encoding="utf-8", errors="replace"), flags=re.S)
        if hosts and main.is_file():
            text = main.read_text(encoding="utf-8", errors="replace")
            k = text.rfind("<runstats>")
            if k > 0:
                main.write_text(text[:k] + "\n".join(hosts) + "\n" + text[k:], encoding="utf-8")
    finally:
        try:
            extra.unlink()
        except OSError:
            pass


def _out_of(args: list[str]) -> Optional[Path]:
    return Path(args[args.index("-oX") + 1]) if "-oX" in args else None


def _with_part(args: list[str], out_path: str) -> tuple[list[str], Path]:
    """Aceeași comandă, dar -oX scrie în <fișier>.xml.part; îl redenumim la final."""
    if out_path.endswith(PART_SUFFIX):          # scanarea din aplicație are deja fișierul ei .part (scan_job.py)
        return list(args), Path(out_path)
    part = Path(out_path + PART_SUFFIX)
    out = list(args)
    for i in range(len(out) - 1):
        if out[i] == "-oX" and out[i + 1] == out_path:
            out[i + 1] = str(part)
    return out, part


def _finish_part(part: Path, out_path: str, ok: bool) -> bool:
    """La succes: .part -> .xml (dintr-o mișcare). La eșec/oprire: .part se șterge. True = fișierul final există."""
    final = Path(out_path)
    if part == final:                            # fără .part al nostru: rămâne cum l-a scris nmap
        return final.is_file()
    if ok and part.is_file():
        os.replace(part, final)
    elif part.exists():
        try:
            part.unlink()
        except OSError:
            pass
    return final.is_file()


def execute(plan: ScanPlan, nmap_path: Optional[str] = None) -> ScanPlan:
    """Rulează nmap doar pentru un plan acceptat. Apelat doar cu --confirm."""
    nmap_path, refused = _ready(plan, nmap_path)
    if refused is not None:
        return refused
    scans_dir = Path(plan.out_path).parent
    if not acquire_lock(scans_dir):
        return _refuse(ALREADY_RUNNING, plan.network, plan.target)
    try:
        args, part = _with_part([nmap_path, *plan.args[1:]], plan.out_path)
        passes = _passes(args, plan, known_hosts(plan))
        rc = 0
        for one in passes:
            try:
                rc = subprocess.run(one, shell=False, check=False).returncode
            except OSError:
                rc = -1
            if rc != 0:
                break
        main = _out_of(passes[-1])
        for one in passes[:-1]:                          # trecerea gateway-ului: în fișierul principal
            extra = _out_of(one)
            if extra and main and rc == 0:
                _merge_hosts(main, extra)
            elif extra and extra.exists():
                extra.unlink()
        if not _finish_part(part, plan.out_path, rc == 0) or rc != 0:
            return _refuse(NMAP_FAILED, plan.network, plan.target)
        return plan
    finally:
        release_lock(scans_dir)


# --- execuția cu progres (scanarea pornită din aplicație, vezi scan_job.py) ---------------------
# `-v` afișează porturile deschise pe măsură ce sunt găsite, `--stats-every` afișează procentul. Ambele schimbă
# doar ce scrie nmap pe ecran, nu și ce trimite în rețea: restul comenzii rămâne exact cea de la `scan --confirm`.
PROGRESS_ARGS = ["-v", "--stats-every", "5s"]
# Viteza pe hotspot (doar scanarea din aplicație): cel puțin MIN_RATE pachete/s (altfel nmap încetinește mult când
# laptopurile cu firewall nu răspund), cel mult 2 reîncercări și timp de așteptare de rețea locală (pe hotspot
# răspunsurile vin în milisecunde). --max-rate 100 (din build_nmap_args) rămâne plafonul. Bugetul de ≤100 pachete/s
# e COMUN pentru tot ce trimite laptopul: cât rulează scanarea completă, verificările live (prezența și porturile,
# live.py) stau în pauză, deci totalul rămâne ≤100/s. Nu schimbă CE se verifică: aceleași porturi, aceeași
# detecție de versiuni (-sV), același script.
MIN_RATE = "80"
# 1 s (nu 300 ms): un laptop cu Wi-Fi-ul în economie de energie răspunde abia după câteva sute de ms; cu 300 ms ieșea
# „down” și lipsea din scanare. Plafonul de pachete rămâne același (--max-rate 100).
SPEED_ARGS = ["--min-rate", MIN_RATE, "--max-retries", "2", "--max-rtt-timeout", "1000ms"]
STOPPED = "STOPPED"


def speed_args(plan: ScanPlan) -> list[str]:
    """SPEED_ARGS + laptopul care scanează exclus din țintă (nu are rost să ne scanăm pe noi)."""
    own = plan.network.ip if plan.network is not None else None
    return [*SPEED_ARGS, *(["--exclude", own] if own else [])]
MAX_LINE = 500


def execute_streaming(plan: ScanPlan, on_line: Callable[[str], None],
                      should_stop: Callable[[], bool] = lambda: False, nmap_path: Optional[str] = None,
                      popen: Callable = subprocess.Popen, poll_s: float = 1.0) -> ScanPlan:
    """Ca execute(), dar citește ieșirea lui nmap linie cu linie (pentru progresul din aplicație).
    `should_stop()` adevărat -> nmap e oprit, iar rezultatul e un refuz STOPPED."""
    nmap_path, refused = _ready(plan, nmap_path)
    if refused is not None:
        return refused
    scans_dir = Path(plan.out_path).parent
    if not acquire_lock(scans_dir):
        return _refuse(ALREADY_RUNNING, plan.network, plan.target)
    try:
        return _stream(plan, nmap_path, on_line, should_stop, popen, poll_s)
    finally:
        release_lock(scans_dir)


def _stream(plan: ScanPlan, nmap_path: str, on_line, should_stop, popen, poll_s) -> ScanPlan:
    args, part = _with_part([nmap_path, *PROGRESS_ARGS, *speed_args(plan), *plan.args[1:]], plan.out_path)
    passes = _passes(args, plan, known_hosts(plan))
    kwargs = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if sys.platform == "win32" else {}
    stopped = threading.Event()
    rc = 0
    for one in passes:
        try:
            proc = popen(one, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         text=True, encoding="utf-8", errors="replace", shell=False, **kwargs)
        except OSError:
            return _refuse(NMAP_FAILED, plan.network, plan.target)

        def watchdog(proc=proc) -> None:
            while proc.poll() is None:
                if should_stop():
                    stopped.set()
                    proc.terminate()
                    return
                time.sleep(poll_s)

        threading.Thread(target=watchdog, daemon=True).start()
        for line in proc.stdout:
            on_line(line.rstrip("\r\n")[:MAX_LINE])
        rc = proc.wait()
        if rc != 0 or stopped.is_set():
            break
    main = _out_of(passes[-1])
    for one in passes[:-1]:                              # trecerea gateway-ului: în fișierul principal
        extra = _out_of(one)
        if extra and main and rc == 0 and not stopped.is_set():
            _merge_hosts(main, extra)
        elif extra and extra.exists():
            extra.unlink()
    done = _finish_part(part, plan.out_path, rc == 0 and not stopped.is_set())
    if stopped.is_set():
        return _refuse(STOPPED, plan.network, plan.target, "Scanarea a fost oprită.", "The scan was stopped.")
    if rc != 0 or not done:
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    return plan


def format_command(args: list[str]) -> str:
    """Comanda afișată la dry-run (doar pentru citit; nu se execută niciodată ca text)."""
    return subprocess.list2cmdline(args) if sys.platform == "win32" else " ".join(
        a if a and all(c.isalnum() or c in "-_.,:/=" for c in a) else "'" + a.replace("'", "'\\''") + "'"
        for a in args
    )
