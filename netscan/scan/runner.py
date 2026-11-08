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


def execute(plan: ScanPlan, nmap_path: Optional[str] = None) -> ScanPlan:
    """Rulează nmap doar pentru un plan acceptat. Apelat doar cu --confirm."""
    nmap_path, refused = _ready(plan, nmap_path)
    if refused is not None:
        return refused
    args = [nmap_path, *plan.args[1:]]
    try:
        result = subprocess.run(args, shell=False, check=False)
    except OSError:
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    if result.returncode != 0 or not Path(plan.out_path).is_file():
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    return plan


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
SPEED_ARGS = ["--min-rate", MIN_RATE, "--max-retries", "2", "--max-rtt-timeout", "300ms"]
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
    args = [nmap_path, *PROGRESS_ARGS, *speed_args(plan), *plan.args[1:]]
    kwargs = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if sys.platform == "win32" else {}
    try:
        proc = popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                     text=True, encoding="utf-8", errors="replace", shell=False, **kwargs)
    except OSError:
        return _refuse(NMAP_FAILED, plan.network, plan.target)

    stopped = threading.Event()

    def watchdog() -> None:
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
    if stopped.is_set():
        return _refuse(STOPPED, plan.network, plan.target, "Scanarea a fost oprită.", "The scan was stopped.")
    if rc != 0 or not Path(plan.out_path).is_file():
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    return plan


def format_command(args: list[str]) -> str:
    """Comanda afișată la dry-run (doar pentru citit; nu se execută niciodată ca text)."""
    return subprocess.list2cmdline(args) if sys.platform == "win32" else " ".join(
        a if a and all(c.isalnum() or c in "-_.,:/=" for c in a) else "'" + a.replace("'", "'\\''") + "'"
        for a in args
    )
