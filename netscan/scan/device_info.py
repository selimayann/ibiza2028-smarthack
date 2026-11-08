"""FR-03 (Oneata/B): informațiile despre dispozitive pentru afișare: producător, MAC privat, tip.

Ce face, după ghid:
- **Producătorul din OUI**, offline: lista oficială IEEE din `data/oui.tsv.gz` (generată cu build_oui.py).
  Se folosește doar dacă nmap n-a dat deja un producător.
- **MAC aleatoriu** (a doua cifră hex a primului octet e 2, 6, A sau E: adresă administrată local)
  → „adresă privată (telefon/laptop modern)”. Pentru astfel de adrese nu căutăm producător.
- **Tipul**: gateway = router; după porturi: 554 cameră, 9100/631 imprimantă, 8008/8009 TV,
  3389/445 PC Windows (completează ghicirea din netscan/engine/devices.py). Un NAS (Synology, QNAP,
  Western Digital, Buffalo, Asustor sau un nume ca „nas”/„nas01”) are și el 445 deschis: rămâne „server”.

Important: nimic de aici nu ajunge în reguli, findings, scor sau CSV-uri. UNKNOWN_DEVICE folosește
în continuare doar producătorul din XML (răspunsul mentorilor la întrebarea 5). Funcțiile întorc
o copie a dispozitivului, doar pentru afișare. MAC-ul real nu e folosit: ajung primii 3 octeți
din `mac_masked`.
"""
from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Optional

from netscan.engine.devices import guess_device_type
from netscan.model import Host

OUI_FILE = Path(__file__).with_name("data") / "oui.tsv.gz"
_PRIVATE_SECOND_DIGIT = frozenset("26AE")
_PREFIX = re.compile(r"^([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})")

# Tipurile din ghid (FR-03), după porturile deschise, în ordinea priorității.
_PORT_TYPES: tuple[tuple[frozenset[int], str], ...] = (
    (frozenset({554}), "camera"),
    (frozenset({9100, 631}), "printer"),
    (frozenset({8008, 8009}), "tv"),
    (frozenset({3389, 445}), "pc_windows"),
)
# Tipuri „slabe” pe care porturile de mai sus au voie să le corecteze.
_WEAK_TYPES = frozenset({None, "", "unknown", "server", "phone_laptop"})
# Producătorii de NAS (stocare în rețea): au SMB (445) deschis, dar nu sunt calculatoare Windows.
_NAS_VENDORS = ("synology", "qnap", "western digital", "buffalo", "asustor")
_NAS_HOSTNAME = re.compile(r"^nas\d*$")


@dataclass(frozen=True)
class DeviceInfo:
    vendor: Optional[str]
    vendor_source: Optional[str]   # "nmap" | "ieee" | None
    private_mac: bool
    device_type: str


def mac_prefix(mac: Optional[str]) -> Optional[str]:
    """„50:C7:BF:XX:XX:XX” sau un MAC complet → „50C7BF”."""
    m = _PREFIX.match((mac or "").strip())
    return "".join(m.groups()).upper() if m else None


def is_private_mac(mac: Optional[str]) -> bool:
    prefix = mac_prefix(mac)
    return bool(prefix) and prefix[1] in _PRIVATE_SECOND_DIGIT


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    try:
        with gzip.open(OUI_FILE, "rt", encoding="utf-8") as f:
            return dict(line.rstrip("\n").split("\t", 1) for line in f if "\t" in line)
    except OSError:
        return {}


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Producătorul din lista IEEE offline; None pentru MAC privat sau prefix necunoscut."""
    if is_private_mac(mac):
        return None
    prefix = mac_prefix(mac)
    return _oui_table().get(prefix) if prefix else None


def is_nas(vendor: Optional[str], hostname: Optional[str]) -> bool:
    """NAS după producător sau după un nume ca „nas”, „nas01”, „casa-nas” (nu „jonas”)."""
    v = (vendor or "").lower()
    if any(name in v for name in _NAS_VENDORS):
        return True
    return any(_NAS_HOSTNAME.match(part) for part in re.split(r"[^a-z0-9]+", (hostname or "").lower()))


def _open_ports(host: Host) -> set[int]:
    return {p.port for p in host.ports if p.state == "open"}


# Hotspot de pe telefon vs. router adevărat (doar pentru eticheta din UI; nimic nu ajunge în CSV sau în scor).
# iPhone își pune hotspotul mereu în 172.20.10.0/28, cu telefonul la .1; 62078/tcp e serviciul de sincronizare iOS.
# Un hotspot Android vechi stă la 192.168.43.1; altfel îl recunoaștem doar dacă e gateway-ul rețelei de acum.
# Un router adevărat are producător (OUI) și, de obicei, o pagină de administrare pe 80/443.
IPHONE_HOTSPOT_IP = "172.20.10.1"
ANDROID_HOTSPOT_IP = "192.168.43.1"
IOS_SYNC_PORT = 62078
_ADMIN_PORTS = frozenset({80, 443, 8080, 8443})
HOTSPOT_TYPES = frozenset({"hotspot_iphone", "hotspot_phone"})


def phone_hotspot(host: Host, vendor: Optional[str] = None, gateway_ip: Optional[str] = None) -> Optional[str]:
    """„hotspot_iphone” / „hotspot_phone” când routerul rețelei e de fapt un telefon; altfel None.
    Cere cel puțin două semne, ca un router adevărat să nu fie etichetat greșit."""
    ports = _open_ports(host)
    private = is_private_mac(host.mac_masked)
    has_admin = bool(ports & _ADMIN_PORTS)
    is_gateway = bool(gateway_ip) and host.ip == gateway_ip
    ios = IOS_SYNC_PORT in ports
    if host.ip == IPHONE_HOTSPOT_IP and (ios or private):
        return "hotspot_iphone"
    if is_gateway and ios and not has_admin:
        return "hotspot_iphone"
    if (is_gateway or host.ip == ANDROID_HOTSPOT_IP) and private and not vendor and not has_admin:
        return "hotspot_phone"
    return None


def describe(host: Host, gateway_ip: Optional[str] = None) -> DeviceInfo:
    private = is_private_mac(host.mac_masked)
    if host.vendor:
        vendor, source = host.vendor, "nmap"
    else:
        vendor = lookup_vendor(host.mac_masked)
        source = "ieee" if vendor else None

    dtype = host.device_type
    if source == "ieee":  # nmap n-a știut producătorul: ghicim din nou, cu numele din lista IEEE
        dtype = guess_device_type(vendor, host.hostname, host.ports)

    hotspot = phone_hotspot(host, vendor, gateway_ip)
    if hotspot:
        dtype = hotspot
    elif gateway_ip and host.ip == gateway_ip:
        dtype = "router"
    elif is_nas(vendor, host.hostname) and dtype in _WEAK_TYPES | {"pc_windows"}:
        dtype = "server"                               # NAS: stocare în rețea, nu un PC Windows
    elif dtype in _WEAK_TYPES:
        ports = _open_ports(host)
        for wanted, kind in _PORT_TYPES:
            if ports & wanted:
                dtype = kind
                break
        else:
            if private and dtype in (None, "", "unknown"):
                dtype = "phone_laptop"
    return DeviceInfo(vendor, source, private, dtype or "unknown")


def display_host(host: Host, gateway_ip: Optional[str] = None) -> Host:
    """O copie a dispozitivului pentru UI, cu producătorul și tipul completate. Originalul rămâne neatins."""
    info = describe(host, gateway_ip)
    return replace(host, vendor=info.vendor, device_type=info.device_type)

# Porturi pe care le are doar Windows (serviciul RPC, descoperirea în rețea, Hyper-V, partajarea fișierelor).
WINDOWS_PORTS = frozenset({135, 139, 445, 2179, 5357})
_RELABEL_AS_PC = frozenset({"iot", "unknown", "server", "phone_laptop", "", None})


def windows_pc(host: Host) -> Optional[str]:
    """„pc_windows” pentru afișare când aparatul are porturi pe care le are doar Windows (ex. 135 și 5357), chiar
    dacă motorul a ghicit altceva (de ex. „IoT”, pentru că rulează și un program de casă inteligentă pe 1883).
    Doar eticheta și animațiile din aplicație; tipul din motor și scorul rămân neschimbate."""
    if host.device_type not in _RELABEL_AS_PC:
        return None
    hits = _open_ports(host) & WINDOWS_PORTS
    return "pc_windows" if len(hits) >= 2 or 445 in hits or 135 in hits else None
