"""Cine e conectat ACUM la hotspot, fără nmap și fără drepturi de administrator (B, protecția live).

Cum: câte o datagramă UDP GOALĂ (portul 9, „discard”) spre fiecare adresă din hotspot. Ca s-o poată trimite,
sistemul întreabă prin ARP „cine are adresa asta?”: dispozitivele conectate răspund, cele plecate nu. După câteva
secunde citim tabela ARP a sistemului (`arp -a` pe Windows și macOS, `ip neigh` pe Linux): o intrare rezolvată
înseamnă dispozitiv prezent acum. Pe Windows și Linux, o intrare veche e verificată din nou la prima datagramă și
dispare dacă dispozitivul nu mai răspunde, deci și plecările se văd în câteva secunde.

Siguranță:
- adresele le alege live.py, doar din subnetul hotspotului și doar dacă trec de guardrail;
- socket-ul e legat de IP-ul laptopului din hotspot, deci datagramele nu pot pleca pe altă interfață;
- datagrama e goală și nu citim niciun răspuns: ARP-ul îl face sistemul, noi citim doar tabela lui;
- MAC-ul complet nu iese din această funcție: rămân doar primii 3 octeți (AA:BB:CC:XX:XX:XX), ca peste tot.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from netscan.scan import device_info, network

DISCARD_PORT = 9                       # portul „discard”: nimeni nu răspunde cu date pe el
MAX_TABLE_LINES = 2000                 # o tabelă ARP mai lungă e ignorată (nu e a unui hotspot)

_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_WIN_MAC = r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})"
_WIN_LINE = re.compile(rf"^\s*{_IPV4}\s+{_WIN_MAC}\s+(\S+)\s*$")
_WIN_IFACE = re.compile(rf"^\S.*?:\s*{_IPV4}\s+---")            # „Interface: 172.20.10.10 --- 0xb” (și localizat)
_MAC_LINE = re.compile(rf"\({_IPV4}\) at ([0-9A-Fa-f]{{1,2}}(?::[0-9A-Fa-f]{{1,2}}){{5}})\b")
_LINUX_LINE = re.compile(rf"^{_IPV4}\s+.*\blladdr\s+([0-9A-Fa-f]{{2}}(?::[0-9A-Fa-f]{{2}}){{5}})\b(.*)$")
_LINUX_ABSENT = ("FAILED", "INCOMPLETE")


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac_masked: str                    # doar primii 3 octeți
    vendor: Optional[str]              # din lista IEEE offline; None pentru MAC privat sau necunoscut
    private_mac: bool                  # MAC aleatoriu (telefoane și laptopuri moderne)


def _normalize_mac(raw: str) -> Optional[str]:
    parts = re.split(r"[-:]", raw.strip())
    if len(parts) != 6 or not all(1 <= len(p) <= 2 for p in parts):
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if all(o == 0 for o in octets) or all(o == 0xFF for o in octets):
        return None                    # intrare nerezolvată sau broadcast
    if octets[0] & 1:
        return None                    # MAC de grup (multicast): nu e un dispozitiv
    return ":".join(f"{o:02X}" for o in octets)


def mask_mac(raw: str) -> Optional[str]:
    """„66-48-42-94-c3-64” -> „66:48:42:XX:XX:XX”. None dacă nu e MAC-ul unui dispozitiv."""
    mac = _normalize_mac(raw)
    return None if mac is None else mac[:8] + ":XX:XX:XX"


def _in_hotspot(ip: str, net: ipaddress.IPv4Network, own_ip: Optional[str]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return (addr in net and addr not in (net.network_address, net.broadcast_address)
            and str(addr) != own_ip)


def _neighbor(ip: str, raw_mac: str) -> Optional[Neighbor]:
    masked = mask_mac(raw_mac)
    if masked is None:
        return None
    return Neighbor(ip=ip, mac_masked=masked, vendor=device_info.lookup_vendor(masked),
                    private_mac=device_info.is_private_mac(masked))


def parse_windows_arp(text: str, own_ip: str, cidr: str) -> dict[str, Neighbor]:
    """`arp -a -N <ip>`: doar secțiunea interfeței hotspotului. Windows nu listează intrările nerezolvate."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    out: dict[str, Neighbor] = {}
    in_iface = False
    for line in (text or "").splitlines()[:MAX_TABLE_LINES]:
        head = _WIN_IFACE.match(line)
        if head:
            in_iface = head.group(1) == own_ip
            continue
        m = _WIN_LINE.match(line)
        if not (in_iface and m) or not _in_hotspot(m.group(1), net, own_ip):
            continue
        n = _neighbor(m.group(1), m.group(2))
        if n is not None:
            out[n.ip] = n
    return out


def parse_macos_arp(text: str, own_ip: str, cidr: str) -> dict[str, Neighbor]:
    """`arp -an -i <iface>`: „? (172.20.10.1) at 66:48:42:94:c3:64 on en0 …”; „(incomplete)” = absent."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    out: dict[str, Neighbor] = {}
    for line in (text or "").splitlines()[:MAX_TABLE_LINES]:
        m = _MAC_LINE.search(line)
        if not m or not _in_hotspot(m.group(1), net, own_ip):
            continue
        n = _neighbor(m.group(1), m.group(2))
        if n is not None:
            out[n.ip] = n
    return out


def parse_linux_neigh(text: str, own_ip: str, cidr: str) -> dict[str, Neighbor]:
    """`ip neigh show dev <iface>`: stările FAILED și INCOMPLETE înseamnă că dispozitivul nu a răspuns."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    out: dict[str, Neighbor] = {}
    for line in (text or "").splitlines()[:MAX_TABLE_LINES]:
        m = _LINUX_LINE.match(line.strip())
        if not m or any(s in m.group(3) for s in _LINUX_ABSENT) or not _in_hotspot(m.group(1), net, own_ip):
            continue
        n = _neighbor(m.group(1), m.group(2))
        if n is not None:
            out[n.ip] = n
    return out


def _platform() -> str:
    if sys.platform == "win32":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux"


def read_neighbors(info: network.NetworkInfo, run: Callable[[list[str]], Optional[str]] = network.run_command,
                   platform: Optional[str] = None) -> Optional[dict[str, Neighbor]]:
    """Dispozitivele prezente în subnetul hotspotului (fără laptopul nostru). None dacă tabela nu se poate citi."""
    if not (info.ip and info.cidr):
        return None
    platform = platform or _platform()
    if platform == "windows":
        text = run(["arp", "-a", "-N", info.ip])
        return None if text is None else parse_windows_arp(text, info.ip, info.cidr)
    if platform == "macos":
        text = run(["arp", "-an", "-i", info.iface]) if info.iface else None
        return None if text is None else parse_macos_arp(text, info.ip, info.cidr)
    text = run(["ip", "neigh", "show", "dev", info.iface]) if info.iface else None
    return None if text is None else parse_linux_neigh(text, info.ip, info.cidr)


def poke(ips: Iterable[str], bind_ip: str,
         make_socket: Callable[[], socket.socket] = lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
         gap_s: float = 0.04, sleep: Callable[[float], None] = time.sleep) -> int:
    """Câte o datagramă goală spre fiecare adresă (ca sistemul să facă ARP), cel mult 25 pe secundă.
    Întoarce câte s-au trimis."""
    sent = 0
    with make_socket() as sock:
        sock.bind((bind_ip, 0))        # doar pe interfața hotspotului
        for ip in ips:
            try:
                sock.sendto(b"", (str(ipaddress.IPv4Address(ip)), DISCARD_PORT))
                sent += 1
            except (OSError, ValueError):
                continue
            sleep(gap_s)
    return sent
