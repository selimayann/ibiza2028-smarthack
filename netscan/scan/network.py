"""FR-01 (Oneata): interfața activă, IP, subnet, gateway, SSID. Ignoră interfețele virtuale.
Vezi docs/roles/B_Oneata_Siguranta_Scanare_AI.md, secțiunea 2.2.

Cum lucrează:
1. ruta implicită (gateway + interfață) din comenzile sistemului, cu listă de argumente, fără shell:
   Windows `route print 0.0.0.0` · Linux `ip route show default` · macOS `route -n get default`;
2. adresele și măștile din `psutil`;
3. interfețele virtuale (loopback, Docker, WSL/Hyper-V, VirtualBox, VMware, VPN) sunt ignorate după nume
   și, pe Windows, după descrierea adaptorului (`Get-NetAdapter`), pentru că acolo un adaptor VirtualBox
   se poate numi simplu „Ethernet 2”;
4. SSID-ul doar pentru interfața activă (fără să listăm rețelele Wi-Fi din jur);
5. un VPN pornit (Tailscale, WireGuard, OpenVPN, AnyConnect, ZeroTier, tun/utun/wg) cu adresă IPv4 = laptopul nu
   e doar pe hotspot: status VPN_ON, deci nu scanăm (nici live, nici complet) până nu e oprit. Analiza unui fișier
   nu citește rețeaua, deci nu e afectată.

Nu trimite niciun pachet în rețea: nu folosește trucul cu socket UDP spre 8.8.8.8, nu face DNS.
MAC-urile nu sunt citite și nu apar nicăieri.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

try:  # psutil e dependență în pyproject.toml; dacă lipsește, raportăm clar în loc să crăpăm.
    import psutil
except ImportError:  # pragma: no cover - depinde de mediu
    psutil = None

# --- stări și avertismente -------------------------------------------------------------------

OK = "OK"
NO_NETWORK = "NO_NETWORK"
MULTIPLE_NETWORKS = "MULTIPLE_NETWORKS"
WRONG_SSID = "WRONG_SSID"
PSUTIL_MISSING = "PSUTIL_MISSING"
SSID_NOT_CONFIGURED = "SSID_NOT_CONFIGURED"   # fără NETSCAN_EXPECTED_SSID nu știm dacă e hotspotul nostru
SSID_UNREADABLE = "SSID_UNREADABLE"           # doar cu NETSCAN_REQUIRE_SSID=1: numele Wi-Fi nu a putut fi citit
VPN_ON = "VPN_ON"                             # un VPN e pornit lângă hotspot: laptopul nu e doar pe hotspot

W_SSID_UNKNOWN = "SSID_UNKNOWN"
W_NO_GATEWAY = "NO_GATEWAY"

MESSAGES: dict[str, tuple[str, str]] = {
    OK: ("Rețeaua a fost detectată.", "Network detected."),
    NO_NETWORK: (
        "Nu ești conectat la nicio rețea. Conectează-te la hotspotul echipei.",
        "You are not connected to any network. Connect to the team hotspot.",
    ),
    MULTIPLE_NETWORKS: (
        "Ești conectat la mai multe rețele în același timp (de exemplu Wi-Fi și cablu). "
        "Deconectează-le pe toate în afară de hotspotul echipei; până atunci nu scanez.",
        "You are connected to more than one network at the same time (for example Wi-Fi and cable). "
        "Disconnect everything except the team hotspot; until then I won't scan.",
    ),
    WRONG_SSID: (
        "Ești conectat la altă rețea Wi-Fi decât hotspotul echipei, așa că nu scanez.",
        "You are connected to a different Wi-Fi network than the team hotspot, so I won't scan.",
    ),
    PSUTIL_MISSING: (
        "Lipsește pachetul psutil. Rulează: pip install -e .",
        "The psutil package is missing. Run: pip install -e .",
    ),
    W_SSID_UNKNOWN: (
        "Nu am putut citi numele rețelei Wi-Fi. Verifică singur că ești pe hotspotul echipei.",
        "I couldn't read the Wi-Fi network name. Check yourself that you are on the team hotspot.",
    ),
    SSID_NOT_CONFIGURED: (
        "Nu știu numele hotspotului echipei, deci nu scanez. Setează NETSCAN_EXPECTED_SSID în .env.",
        "I don't know the team hotspot name, so I won't scan. Set NETSCAN_EXPECTED_SSID in .env.",
    ),
    SSID_UNREADABLE: (
        "Nu am putut citi numele rețelei Wi-Fi și NETSCAN_REQUIRE_SSID=1 e setat, deci nu scanez.",
        "I couldn't read the Wi-Fi network name and NETSCAN_REQUIRE_SSID=1 is set, so I won't scan.",
    ),
    VPN_ON: (
        "Ai un VPN pornit (%s). Brief-ul cere ca laptopul să fie doar pe hotspot: oprește VPN-ul înainte de scanare.",
        "You have a VPN turned on (%s). The brief requires the laptop to be only on the hotspot: turn the VPN off "
        "before scanning.",
    ),
    W_NO_GATEWAY: (
        "Rețeaua nu are gateway (router).",
        "The network has no gateway (router).",
    ),
}


@dataclass
class NetworkInfo:
    iface: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[str] = None          # subnetul, ex. "172.20.10.0/28"
    gateway: Optional[str] = None
    ssid: Optional[str] = None          # numele rețelei; TEXT NESIGUR (îl alege oricine)
    warnings: list[str] = field(default_factory=list)   # coduri din MESSAGES
    status: str = NO_NETWORK
    other_ifaces: list[str] = field(default_factory=list)  # la MULTIPLE_NETWORKS: celelalte interfețe
    vpn_ifaces: list[str] = field(default_factory=list)    # VPN-uri pornite cu IPv4 (vezi VPN_ON)

    @property
    def scan_allowed(self) -> bool:
        return self.status == OK

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DefaultRoute:
    gateway: Optional[str]
    iface: Optional[str] = None      # numele interfeței (Linux/macOS)
    iface_ip: Optional[str] = None   # IP-ul interfeței (Windows: route print dă IP, nu nume)
    metric: int = 0


# --- interfețe virtuale ----------------------------------------------------------------------

_VIRTUAL_NAME = re.compile(
    r"^(lo\d*|loopback.*|docker.*|br-.*|veth.*|virbr.*|vboxnet.*|vmnet.*|vEthernet.*|vSwitch.*"
    r"|utun.*|tun.*|tap.*|wg.*|tailscale.*|zt.*|ppp.*|ipsec.*|gif.*|stf.*|awdl.*|llw.*|anpi.*"
    r"|bridge.*|cni.*|flannel.*|kube.*|podman.*|lxc.*|lxd.*|isatap.*|teredo.*|.*vpn.*)$",
    re.IGNORECASE,
)
_VIRTUAL_DESC = re.compile(
    r"virtual|virtualbox|vmware|hyper-v|loopback|tap-windows|wintun|wireguard|tailscale|zerotier"
    r"|openvpn|vpn|anyconnect|fortinet|forticlient|globalprotect|wan miniport|teredo|isatap|6to4"
    r"|ip-https|kernel debug|npcap|pseudo",
    re.IGNORECASE,
)


# Un tunel VPN (nu Docker / Hyper-V / VirtualBox: acelea rămân doar ignorate, ca până acum).
_VPN_NAME = re.compile(
    r"^(utun\d*|tun\d*|wg\d*|tailscale.*|zt.*|zerotier.*|wireguard.*|openvpn.*|anyconnect.*|.*vpn.*)$",
    re.IGNORECASE,
)
_VPN_DESC = re.compile(
    r"wireguard|wintun|tailscale|zerotier|openvpn|tap-windows|anyconnect|cisco.*vpn|vpn",
    re.IGNORECASE,
)


def is_vpn_iface(name: str, description: Optional[str] = None) -> bool:
    if _VPN_NAME.match(name or ""):
        return True
    return bool(description and _VPN_DESC.search(description))


def vpn_ipv4_ifaces(ps, descriptions: dict[str, str]) -> list[str]:
    """Tunelurile VPN pornite care au o adresă IPv4 utilizabilă (un utun de macOS doar cu IPv6 nu contează)."""
    stats = ps.net_if_stats()
    out = []
    for name, addrs in ps.net_if_addrs().items():
        st = stats.get(name)
        if st is None or not st.isup or not is_vpn_iface(name, descriptions.get(name)):
            continue
        for a in addrs:
            if a.family != socket.AF_INET or not a.address:
                continue
            try:
                ip = ipaddress.IPv4Address(a.address)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            out.append(name)
            break
    return out


def status_message(info: "NetworkInfo") -> tuple[str, str]:
    """(ro, en) pentru starea rețelei, cu numele VPN-ului completat acolo unde e cazul."""
    return message(info.status, info)


def message(code: str, info: Optional["NetworkInfo"] = None) -> tuple[str, str]:
    ro, en = MESSAGES.get(code, ("Rețeaua nu e potrivită.", "The network isn't suitable."))
    if code == VPN_ON:
        names = ", ".join((info.vpn_ifaces if info is not None else None) or ["VPN"])
        ro, en = ro % names, en % names
    return ro, en


def is_virtual_iface(name: str, description: Optional[str] = None) -> bool:
    if _VIRTUAL_NAME.match(name or ""):
        return True
    if description and _VIRTUAL_DESC.search(description):
        return True
    if sys.platform.startswith("linux"):
        # Pe Linux, interfețele fizice au /sys/class/net/<nume>/device; cele virtuale nu.
        base = f"/sys/class/net/{name}"
        if os.path.isdir(base) and not os.path.exists(f"{base}/device"):
            return True
    return False


# --- rularea comenzilor ----------------------------------------------------------------------

Runner = Callable[[list[str]], Optional[str]]


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "oem" if sys.platform == "win32" else "", "latin-1"):
        if not enc:
            continue
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def run_command(args: list[str]) -> Optional[str]:
    """Rulează o comandă a sistemului (listă de argumente, niciodată shell). None dacă nu merge."""
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(args, capture_output=True, timeout=10, shell=False, check=False, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return _decode(r.stdout)


# --- parsere (funcții pure, testate pe text) -------------------------------------------------

def _ipv4(s: str) -> Optional[str]:
    try:
        return str(ipaddress.IPv4Address(s))
    except ValueError:
        return None


def parse_windows_route_print(text: str) -> list[DefaultRoute]:
    """`route print 0.0.0.0`. Rândurile active au 5 coloane: dest, mască, gateway, interfață, metrică.
    Rândurile „persistente” au 4 coloane și sunt ignorate. Nu depinde de limba Windows-ului."""
    routes = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) != 5 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        iface_ip = _ipv4(parts[3])
        if iface_ip is None or not parts[4].isdigit():
            continue
        routes.append(DefaultRoute(gateway=_ipv4(parts[2]), iface_ip=iface_ip, metric=int(parts[4])))
    return routes


def parse_linux_ip_route(text: str) -> list[DefaultRoute]:
    """`ip route show default` -> "default via 172.20.10.1 dev wlan0 proto dhcp metric 600"."""
    routes = []
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        kv = {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1)}
        if "dev" not in kv:
            continue
        metric = kv.get("metric", "0")
        routes.append(DefaultRoute(
            gateway=_ipv4(kv.get("via", "")),
            iface=kv["dev"],
            metric=int(metric) if metric.isdigit() else 0,
        ))
    return routes


def parse_macos_route_get(text: str) -> list[DefaultRoute]:
    """`route -n get default` -> linii „gateway: …” și „interface: …”."""
    fields = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()
    if "interface" not in fields:
        return []
    return [DefaultRoute(gateway=_ipv4(fields.get("gateway", "")), iface=fields["interface"])]


def parse_windows_netsh_ssid(text: str, iface: Optional[str]) -> Optional[str]:
    """`netsh wlan show interfaces`: SSID-ul blocului cu numele == iface (sau al singurului bloc).
    Nu depinde de limba Windows-ului: blocurile sunt separate de linii goale, câmpurile sunt indentate,
    iar primul câmp din bloc e numele interfeței (eticheta „Name” se traduce, „SSID” nu)."""
    blocks: list[dict[str, str]] = []
    current: Optional[dict[str, str]] = None
    for line in (text or "").splitlines():
        m = re.match(r"^\s+([^:]+?)\s*:\s?(.*)$", line)
        if not line.strip() or not m:
            current = None  # linie goală sau text neindentat („There is 1 interface…”): bloc închis
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if current is None:
            current = {"__name__": value}
            blocks.append(current)
        else:
            current.setdefault(key, value)
    candidates = [b for b in blocks if iface and b.get("__name__") == iface] or (blocks if len(blocks) == 1 else [])
    for b in candidates:
        ssid = b.get("SSID")
        if ssid:
            return ssid
    return None


def parse_iw_link(text: str) -> Optional[str]:
    """`iw dev <iface> link` -> „SSID: nume”."""
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("SSID:"):
            return s[5:].strip() or None
    return None


def parse_macos_ssid(text: str) -> Optional[str]:
    """`ipconfig getsummary <iface>` („ SSID : nume”) sau `networksetup -getairportnetwork <iface>`
    („Current Wi-Fi Network: nume”). macOS 14.4+ poate întoarce „<redacted>”."""
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^SSID\s*:\s*(.+)$", s) or re.match(r"^Current Wi-?Fi Network:\s*(.+)$", s)
        if m:
            value = m.group(1).strip()
            if value and value.lower() != "<redacted>":
                return value
    return None


def parse_windows_adapters(text: str) -> dict[str, str]:
    """JSON de la `Get-NetAdapter | Select Name, InterfaceDescription | ConvertTo-Json` -> {nume: descriere}."""
    try:
        data = json.loads(text or "")
    except ValueError:
        return {}
    if isinstance(data, dict):
        data = [data]
    out = {}
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and item.get("Name"):
            out[str(item["Name"])] = str(item.get("InterfaceDescription") or "")
    return out


# --- citirea de pe sistem ---------------------------------------------------------------------

def _platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def read_default_routes(run: Runner, platform: str) -> list[DefaultRoute]:
    if platform == "windows":
        return parse_windows_route_print(run(["route", "print", "0.0.0.0"]) or "")
    if platform == "macos":
        return parse_macos_route_get(run(["route", "-n", "get", "default"]) or "")
    return parse_linux_ip_route(run(["ip", "-4", "route", "show", "default"]) or "")


def read_adapter_descriptions(run: Runner, platform: str) -> dict[str, str]:
    if platform != "windows":
        return {}
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress"
    )
    return parse_windows_adapters(run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script]) or "")


def read_ssid(run: Runner, platform: str, iface: Optional[str]) -> Optional[str]:
    """Doar rețeaua la care e conectată interfața; nu listăm rețelele din jur."""
    if not iface:
        return None
    if platform == "windows":
        return parse_windows_netsh_ssid(run(["netsh", "wlan", "show", "interfaces"]) or "", iface)
    if platform == "macos":
        return (parse_macos_ssid(run(["ipconfig", "getsummary", iface]) or "")
                or parse_macos_ssid(run(["networksetup", "-getairportnetwork", iface]) or ""))
    ssid = parse_iw_link(run(["iw", "dev", iface, "link"]) or "")
    if ssid:
        return ssid
    ssid = (run(["iwgetid", "-r", iface]) or "").strip()
    if ssid:
        return ssid
    # Numele conexiunii NetworkManager (de obicei e chiar SSID-ul).
    ssid = (run(["nmcli", "-t", "-g", "GENERAL.CONNECTION", "device", "show", iface]) or "").strip()
    return ssid or None


@dataclass(frozen=True)
class _Iface:
    name: str
    ip: str
    netmask: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Interface(f"{self.ip}/{self.netmask}").network


def physical_ipv4_ifaces(ps, descriptions: dict[str, str]) -> list[_Iface]:
    """Interfețele pornite, nevirtuale, cu o adresă IPv4 utilizabilă (nu loopback, nu 169.254.x.x)."""
    stats = ps.net_if_stats()
    out = []
    for name, addrs in ps.net_if_addrs().items():
        st = stats.get(name)
        if st is None or not st.isup or is_virtual_iface(name, descriptions.get(name)):
            continue
        for a in addrs:
            if a.family != socket.AF_INET or not a.address or not a.netmask:
                continue
            ip = ipaddress.IPv4Address(a.address)
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            out.append(_Iface(name, a.address, a.netmask))
            break
    return out


def detect_network(
    run: Runner = run_command,
    ps=None,
    platform: Optional[str] = None,
    env: Optional[dict] = None,
) -> NetworkInfo:
    """Detectează rețeaua curentă. Parametrii există doar ca să poată fi înlocuiți în teste."""
    ps = ps if ps is not None else psutil
    platform = platform or _platform()
    env = os.environ if env is None else env

    if ps is None:
        return NetworkInfo(status=PSUTIL_MISSING)

    descriptions = read_adapter_descriptions(run, platform)
    physical = physical_ipv4_ifaces(ps, descriptions)
    vpns = vpn_ipv4_ifaces(ps, descriptions)
    by_name = {i.name: i for i in physical}
    by_ip = {i.ip: i for i in physical}

    # Ruta implicită pe o interfață fizică, cu metrica cea mai mică.
    chosen: Optional[_Iface] = None
    gateway: Optional[str] = None
    for r in sorted(read_default_routes(run, platform), key=lambda r: r.metric):
        iface = by_name.get(r.iface) if r.iface else by_ip.get(r.iface_ip)
        if iface is not None:
            chosen, gateway = iface, r.gateway
            break

    if chosen is None and len(physical) == 1:
        chosen = physical[0]  # rețea fără gateway (de ex. hotspot fără internet)

    if chosen is None:
        return NetworkInfo(status=MULTIPLE_NETWORKS if len(physical) > 1 else NO_NETWORK,
                           other_ifaces=[i.name for i in physical], vpn_ifaces=vpns)

    info = NetworkInfo(
        iface=chosen.name,
        ip=chosen.ip,
        cidr=str(chosen.network),
        gateway=gateway,
        status=OK,
    )
    if gateway is None:
        info.warnings.append(W_NO_GATEWAY)

    others = [i.name for i in physical if i.name != chosen.name]
    if others:
        info.status = MULTIPLE_NETWORKS
        info.other_ifaces = others

    info.ssid = read_ssid(run, platform, chosen.name)
    expected = (env.get("NETSCAN_EXPECTED_SSID") or "").strip()
    if not expected:
        if info.status == OK:
            info.status = SSID_NOT_CONFIGURED
    elif info.ssid is None:
        # Implicit doar avertisment (pe unele sisteme Windows numele Wi-Fi nu se poate citi fără permisiunea
        # de locație). Cu NETSCAN_REQUIRE_SSID=1 refuzăm: sigur înainte de comod.
        if (env.get("NETSCAN_REQUIRE_SSID") or "").strip() == "1":
            if info.status == OK:
                info.status = SSID_UNREADABLE
        else:
            info.warnings.append(W_SSID_UNKNOWN)
    elif info.ssid != expected and info.status == OK:
        info.status = WRONG_SSID

    if vpns:
        # Un VPN pornit = laptopul nu e doar pe hotspot (brief-ul). Refuzăm; dacă rețeaua e deja refuzată din
        # alt motiv, VPN-ul apare totuși ca avertisment, ca să știi ce mai ai de oprit.
        info.vpn_ifaces = vpns
        if info.status == OK:
            info.status = VPN_ON
        else:
            info.warnings.append(VPN_ON)

    return info


def describe(info: NetworkInfo, lang: str = "ro") -> str:
    """Text simplu pentru comanda `network`."""
    idx = 0 if lang == "ro" else 1
    labels = {
        "ro": ("Interfață", "IP", "Subnet", "Gateway", "Rețea Wi-Fi", "Stare", "Rețeaua",
               "hotspotul echipei (scanez doar în %s)", "nu scanez aici (vezi starea de mai sus)",
               "Alte rețele active"),
        "en": ("Interface", "IP", "Subnet", "Gateway", "Wi-Fi network", "Status", "Network",
               "team hotspot (I only scan inside %s)", "I won't scan here (see the status above)",
               "Other active networks"),
    }["ro" if lang == "ro" else "en"]
    dash = "—"
    lines = [
        f"{labels[0]}: {info.iface or dash}",
        f"{labels[1]}: {info.ip or dash}",
        f"{labels[2]}: {info.cidr or dash}",
        f"{labels[3]}: {info.gateway or dash}",
        f"{labels[4]}: {info.ssid or dash}",
    ]
    if info.other_ifaces:
        lines.append(f"{labels[9]}: {', '.join(info.other_ifaces)}")
    lines.append(f"{labels[5]}: {info.status} — {message(info.status, info)[idx]}")
    for w in info.warnings:
        lines.append(f"! {message(w, info)[idx]}")
    lines.append(f"{labels[6]}: " + (labels[7] % (info.cidr or dash) if info.scan_allowed else labels[8]))
    return "\n".join(lines)
