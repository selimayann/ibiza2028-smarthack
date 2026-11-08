"""Ascultarea pasivă (B): numele pe care dispozitivele le anunță singure în rețea (mDNS și SSDP).

Idee din Wireshark (decodarea anunțurilor), fără captură de trafic: ne abonăm doar la grupurile de anunțuri
mDNS (224.0.0.251:5353) și SSDP (239.255.255.250:1900) pe interfața hotspotului și citim ce trimit
dispozitivele de la sine. Ghidul permite explicit „ascultarea pasivă (mDNS/SSDP) doar pe interfața aleasă”.

Reguli:
- pornește doar când rețeaua e OK (hotspotul echipei, o singură rețea); fără --confirm doar dry-run;
- nu trimite cereri și NU deschide link-urile din anunțuri (LOCATION din SSDP poate duce oriunde);
- acceptă doar anunțuri de la IP-uri din subnetul hotspotului;
- tot ce vine din pachete e text nesigur: parser cu limite stricte, nume curățate și tăiate la 60 de caractere;
- păstrează local doar IP, nume, serviciu, oră (data/device_names.jsonl), șterse de „Șterge istoricul”.
  Numele pot conține nume de persoane („iPhone-lui-Andrei”), de aceea rămân doar pe laptop.
"""
from __future__ import annotations

import ipaddress
import select
import socket
import struct
import time
from typing import Callable, Iterable, Optional

from netscan.scan import local_data, network

MDNS = ("224.0.0.251", 5353)
SSDP = ("239.255.255.250", 1900)
MAX_NAME = 60
MAX_PACKET = 9000
MAX_RECORDS = 64
MAX_POINTER_JUMPS = 16
NAMES_FILE = "device_names.jsonl"

SERVICES = {
    "_googlecast._tcp": "Google Cast (TV / Chromecast)",
    "_airplay._tcp": "AirPlay (Apple TV / boxă)",
    "_raop._tcp": "AirPlay audio",
    "_ipp._tcp": "Imprimantă", "_ipps._tcp": "Imprimantă", "_printer._tcp": "Imprimantă",
    "_pdl-datastream._tcp": "Imprimantă",
    "_hap._tcp": "HomeKit (dispozitiv inteligent)",
    "_spotify-connect._tcp": "Spotify Connect (boxă)",
    "_smb._tcp": "Partajare de fișiere",
    "_companion-link._tcp": "Dispozitiv Apple",
    "_sleep-proxy._udp": "Dispozitiv Apple",
    "_http._tcp": "Pagină web",
}
SERVICES_EN = {"Imprimantă": "Printer", "Partajare de fișiere": "File sharing", "Dispozitiv Apple": "Apple device",
               "Pagină web": "Web page", "HomeKit (dispozitiv inteligent)": "HomeKit (smart device)",
               "Google Cast (TV / Chromecast)": "Google Cast (TV / Chromecast)",
               "AirPlay (Apple TV / boxă)": "AirPlay (Apple TV / speaker)", "Spotify Connect (boxă)": "Spotify Connect (speaker)"}

TEXTS = {
    "ro": {"announced": "Dispozitiv anunțat: {ip} — „{name}”{service}.",
           "listening": "Ascult anunțurile dispozitivelor pe {ip} (doar hotspotul). Nu trimit nimic. Oprește cu Ctrl+C.",
           "dry_run": "Dry-run. Aș asculta anunțurile mDNS și SSDP pe {ip} (doar hotspotul), fără să trimit nimic. "
                      "Adaugă --confirm ca să pornești.",
           "refused": "Nu ascult: {why}", "port_busy": "Nu pot asculta pe portul {port} (e folosit de sistem); continui fără el.",
           "nothing": "Nu pot asculta pe niciun port.", "stopped": "Ascultare oprită."},
    "en": {"announced": "Device announced: {ip} — \"{name}\"{service}.",
           "listening": "Listening to device announcements on {ip} (hotspot only). Sending nothing. Stop with Ctrl+C.",
           "dry_run": "Dry-run. I would listen to mDNS and SSDP announcements on {ip} (hotspot only), sending nothing. "
                      "Add --confirm to start.",
           "refused": "Not listening: {why}", "port_busy": "Can't listen on port {port} (used by the system); continuing without it.",
           "nothing": "Can't listen on any port.", "stopped": "Listening stopped."},
}


def clean(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())[:MAX_NAME]
    return text or None


# --- mDNS (DNS) ----------------------------------------------------------------------------------------

def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """Numele DNS de la `pos`, cu pointeri de comprimare limitați. Întoarce (nume, poziția de după nume)."""
    labels, jumps, end = [], 0, None
    while True:
        if pos >= len(data):
            raise ValueError("nume trunchiat")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data) or jumps >= MAX_POINTER_JUMPS:
                raise ValueError("pointer invalid")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            continue
        if length > 63 or pos + 1 + length > len(data):
            raise ValueError("etichetă invalidă")
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", errors="replace"))
        pos += 1 + length
        if len(labels) > 32:
            raise ValueError("nume prea lung")
    return ".".join(labels), (end if end is not None else pos)


def parse_mdns(data: bytes) -> list[dict]:
    """Înregistrările utile dintr-un pachet mDNS: [{type, name, value}], type ∈ PTR | SRV | TXT | A."""
    if len(data) < 12 or len(data) > MAX_PACKET:
        return []
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    pos, out = 12, []
    try:
        for _ in range(min(qd, MAX_RECORDS)):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(min(an + ns + ar, MAX_RECORDS)):
            name, pos = _read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            rdata_start, pos = pos, pos + rdlen
            if pos > len(data):
                break
            if rtype == 12:                                  # PTR
                value, _ = _read_name(data, rdata_start)
                out.append({"type": "PTR", "name": name, "value": value})
            elif rtype == 33 and rdlen >= 7:                 # SRV
                target, _ = _read_name(data, rdata_start + 6)
                out.append({"type": "SRV", "name": name, "value": target})
            elif rtype == 1 and rdlen == 4:                  # A
                out.append({"type": "A", "name": name, "value": socket.inet_ntoa(data[rdata_start:pos])})
            elif rtype == 16:                                # TXT
                i, items = rdata_start, {}
                while i < pos:
                    ln = data[i]
                    item = data[i + 1:i + 1 + ln].decode("utf-8", errors="replace")
                    i += 1 + ln
                    if "=" in item:
                        k, v = item.split("=", 1)
                        items[k.lower()] = v
                out.append({"type": "TXT", "name": name, "value": items})
    except (ValueError, struct.error, IndexError):
        pass
    return out


def describe_mdns(records: list[dict]) -> Optional[dict]:
    """Din înregistrări: {"name", "service"}. Numele: TXT fn (Google Cast) / numele instanței / hostname-ul."""
    service = None
    name = None
    for r in records:
        for svc, label in SERVICES.items():
            if svc in r["name"] or (isinstance(r["value"], str) and svc in r["value"]):
                service = service or label
        if r["type"] == "TXT" and isinstance(r["value"], dict):
            name = name or r["value"].get("fn") or r["value"].get("md") or r["value"].get("ty")
    for r in records:
        if not name and r["type"] in ("PTR", "SRV") and isinstance(r["value"], str):
            inst = r["value"] if r["type"] == "PTR" else r["name"]
            if "._" in inst:
                name = inst.split("._", 1)[0]
    for r in records:
        if not name and r["type"] == "A":
            name = r["name"].removesuffix(".local")
    name = clean(name)
    if not name and not service:
        return None
    return {"name": name or "?", "service": service}


# --- SSDP --------------------------------------------------------------------------------------------

def parse_ssdp(data: bytes) -> Optional[dict]:
    """Anunț SSDP (NOTIFY sau răspuns): {"name", "service"} din SERVER și NT/ST. LOCATION e ignorat."""
    if len(data) > MAX_PACKET:
        return None
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not (lines[0].upper().startswith("NOTIFY") or lines[0].upper().startswith("HTTP/1.1 200")):
        return None
    headers = {}
    for line in lines[1:40]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().upper()] = v.strip()
    kind = headers.get("NT") or headers.get("ST") or ""
    service = ("Router (UPnP)" if "InternetGatewayDevice" in kind else
               "TV / Chromecast (DIAL)" if "dial" in kind.lower() else
               "Media (TV / boxă)" if "MediaRenderer" in kind else
               "Imprimantă" if "Printer" in kind else
               "UPnP" if kind else None)
    name = clean(headers.get("SERVER"))
    if not name and not service:
        return None
    return {"name": name or "?", "service": service}


# --- ascultarea ----------------------------------------------------------------------------------------

def names_path(db_path=None):
    return local_data.data_dir(db_path) / NAMES_FILE


def load_names(db_path=None) -> dict[str, dict]:
    """{ip: {"name", "service", "ts"}}: ultimul nume anunțat de fiecare IP (pentru UI)."""
    out: dict[str, dict] = {}
    for e in local_data.read_events(names_path(db_path)):
        if isinstance(e.get("ip"), str):
            out[e["ip"]] = {"name": clean(e.get("name")) or "?", "service": clean(e.get("service")), "ts": e.get("ts")}
    return out


class Listener:
    """Ține minte ce a văzut în sesiunea curentă și scrie doar schimbările."""

    def __init__(self, cidr: str, own_ip: Optional[str], lang: str = "ro", out: Callable[[str], None] = print,
                 db_path=None, now: Callable[[], float] = time.time):
        self.net = ipaddress.IPv4Network(cidr, strict=False)
        self.own_ip, self.lang, self.out, self.db_path, self.now = own_ip, lang, out, db_path, now
        self.seen: dict[str, tuple] = {}

    def handle(self, data: bytes, src_ip: str, port: int) -> Optional[dict]:
        try:
            ip = ipaddress.IPv4Address(src_ip)
        except ValueError:
            return None
        if ip not in self.net or src_ip == self.own_ip:
            return None                                       # doar dispozitive din hotspot, nu noi înșine
        info = describe_mdns(parse_mdns(data)) if port == MDNS[1] else parse_ssdp(data)
        if not info:
            return None
        key = (info["name"], info["service"])
        if self.seen.get(src_ip) == key:
            return None
        first = src_ip not in self.seen
        self.seen[src_ip] = key
        event = {"ts": self.now(), "ip": src_ip, "name": info["name"], "service": info["service"]}
        local_data.append_events(names_path(self.db_path), [event])
        if first:
            svc = info["service"]
            if svc and self.lang == "en":
                svc = SERVICES_EN.get(svc, svc)
            self.out(time.strftime("[%H:%M] ") + TEXTS[self.lang]["announced"].format(
                ip=src_ip, name=info["name"], service=f" ({svc})" if svc else ""))
        return event


def _open_socket(group: tuple[str, int], iface_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", group[1]))
    mreq = socket.inet_aton(group[0]) + socket.inet_aton(iface_ip)   # abonare doar pe interfața hotspotului
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def run_listen(confirm: bool, lang: str = "ro", out: Callable[[str], None] = print,
               detect: Callable = network.detect_network, seconds: Optional[float] = None, db_path=None) -> int:
    t = TEXTS[lang if lang in TEXTS else "ro"]
    info = detect()
    if not info.scan_allowed or not info.ip or not info.cidr:
        ro, en = network.status_message(info)
        out(t["refused"].format(why=en if lang == "en" else ro))
        return 2
    if not confirm:
        out(t["dry_run"].format(ip=info.ip))
        return 0

    socks = {}
    for group in (MDNS, SSDP):
        try:
            socks[_open_socket(group, info.ip)] = group[1]
        except OSError:
            out(t["port_busy"].format(port=group[1]))
    if not socks:
        out(t["nothing"])
        return 2
    listener = Listener(info.cidr, info.ip, lang, out, db_path)
    out(t["listening"].format(ip=info.ip))
    end = None if seconds is None else time.time() + seconds
    try:
        while end is None or time.time() < end:
            ready, _, _ = select.select(list(socks), [], [], 1.0)
            for s in ready:
                try:
                    data, (src, _) = s.recvfrom(MAX_PACKET)
                except OSError:
                    continue
                listener.handle(data, src, socks[s])
    except KeyboardInterrupt:
        out(t["stopped"])
    finally:
        for s in socks:
            s.close()
    return 0
