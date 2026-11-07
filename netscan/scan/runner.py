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


def build_nmap_args(target: str, iface: str, tcp_ports: str, out_path: str) -> list[str]:
    """Comanda din instrucțiuni, cu porturile CATALOG_EXTRA_TCP adăugate la T:.
    Fiecare valoare e un argument separat; nimic nu trece prin shell."""
    return [
        "nmap", "-sS", "-sU", "-sV", "--script", "http-title",
        "-p", f"T:{tcp_port_spec(tcp_ports)},U:{UDP_PORTS}",
        "--max-rate", MAX_RATE, "-e", iface, "-oX", out_path, target,
    ]


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
) -> ScanPlan:
    """network -> check_target -> argumentele nmap. Nu pornește nicio scanare."""
    env = os.environ if env is None else env

    info = detect()
    if not info.scan_allowed:
        ro, en = network.MESSAGES.get(info.status, ("Rețeaua nu e potrivită pentru scanare.",
                                                    "The network isn't suitable for scanning."))
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

    out = str(out_path or default_out_path())
    args = build_nmap_args(decision.network, nmap_iface, ports, out)
    return ScanPlan(True, guardrail.OK, decision.msg_ro, decision.msg_en,
                    network=info, target=decision.network, args=args, out_path=out)


def execute(plan: ScanPlan, nmap_path: Optional[str] = None) -> ScanPlan:
    """Rulează nmap doar pentru un plan acceptat. Apelat doar cu --confirm."""
    if not plan.ok:
        return plan
    if not is_admin():
        return _refuse(NOT_ADMIN, plan.network, plan.target)
    nmap_path = nmap_path or find_nmap()
    if not nmap_path:
        return _refuse(NMAP_NOT_FOUND, plan.network, plan.target)

    Path(plan.out_path).parent.mkdir(parents=True, exist_ok=True)
    args = [nmap_path, *plan.args[1:]]
    try:
        result = subprocess.run(args, shell=False, check=False)
    except OSError:
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    if result.returncode != 0 or not Path(plan.out_path).is_file():
        return _refuse(NMAP_FAILED, plan.network, plan.target)
    return plan


def format_command(args: list[str]) -> str:
    """Comanda afișată la dry-run (doar pentru citit; nu se execută niciodată ca text)."""
    return subprocess.list2cmdline(args) if sys.platform == "win32" else " ".join(
        a if a and all(c.isalnum() or c in "-_.,:/=" for c in a) else "'" + a.replace("'", "'\\''") + "'"
        for a in args
    )
