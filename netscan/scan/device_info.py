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

    if gateway_ip and host.ip == gateway_ip:
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
