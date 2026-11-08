"""Numele unui calculator din hotspot („LAPTOP-ALEX”), ca în „Rețea” din Windows.

Cum: o singură întrebare NetBIOS „cum te cheamă?” (node status, UDP 137) trimisă DOAR acelui aparat, din laptopul
nostru, în hotspot. Nu trece prin DNS (nu iese din rețea) și nu se citește nimic altceva. Calculatoarele Windows
răspund cu numele lor; telefoanele de obicei nu răspund (atunci rămâne producătorul).
Numele primit e text nesigur: păstrăm doar litere, cifre, „-” și „_”, cel mult 15 caractere (limita NetBIOS),
iar la afișare îl escapează Jinja, ca orice alt text.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
from typing import Callable, Optional

PORT = 137
_CLEAN = re.compile(r"[^A-Za-z0-9_-]")


def _request(tid: int) -> bytes:
    """NBSTAT pentru numele „*” (oricine): antetul + întrebarea, ca `nbtstat -A`."""
    name = b"*" + b"\x00" * 15
    enc = bytes(b for c in name for b in (0x41 + (c >> 4), 0x41 + (c & 0x0F)))
    return struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + bytes([32]) + enc + b"\x00" + struct.pack(">HH", 0x21, 1)


def parse_reply(data: bytes, tid: int) -> Optional[str]:
    """Numele calculatorului (primul nume unic cu sufixul 0x00) din răspuns, curățat. None dacă nu e un răspuns bun."""
    try:
        if len(data) < 57 or struct.unpack(">H", data[:2])[0] != tid:
            return None
        pos = 12
        if data[pos] & 0xC0 == 0xC0:          # nume comprimat (pointer)
            pos += 2
        else:
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        pos += 2 + 2 + 4                      # tip, clasă, TTL
        pos += 2                              # lungimea datelor
        count = data[pos]
        pos += 1
        for _ in range(min(count, 64)):
            raw, suffix, flags = data[pos:pos + 15], data[pos + 15], struct.unpack(">H", data[pos + 16:pos + 18])[0]
            pos += 18
            if suffix == 0x00 and not flags & 0x8000:      # numele calculatorului (nu al grupului de lucru)
                name = _CLEAN.sub("", raw.decode("ascii", "ignore").strip())
                return name[:15] or None
    except (IndexError, struct.error):
        return None
    return None


def query_name(ip: str, bind_ip: Optional[str] = None, timeout: float = 0.8,
               make_socket: Callable[[], socket.socket] = lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) -> Optional[str]:
    """Întreabă aparatul `ip` cum îl cheamă. Doar adrese private (rețeaua locală). Orice eroare: None."""
    try:
        if not ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None
    tid = int.from_bytes(os.urandom(2), "big")
    try:
        with make_socket() as sock:
            if bind_ip:
                sock.bind((bind_ip, 0))       # doar pe interfața hotspotului
            sock.settimeout(timeout)
            sock.sendto(_request(tid), (ip, PORT))
            data, src = sock.recvfrom(1024)
            if src[0] != ip:
                return None
            return parse_reply(data, tid)
    except OSError:
        return None


# ---------- numele unui Mac / iPhone / Linux: o întrebare mDNS directă („cine e la adresa asta?”) ----------
# Ca NetBIOS, dar felul în care se prezintă aparatele Apple și Linux în rețeaua locală (Bonjour). O singură întrebare,
# trimisă DOAR acelui aparat, pe portul 5353, cu răspuns cerut tot direct (unicast). Răspunsul e text nesigur.
MDNS_PORT = 5353
_CLEAN_HOST = re.compile(r"[^A-Za-z0-9 _'-]")


def _dns_name(labels: list[str]) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in labels) + b"\x00"


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    parts, jumped, end = [], False, pos
    while depth < 20:
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped, pos, depth = True, ptr, depth + 1
            continue
        parts.append(data[pos + 1:pos + 1 + n].decode("utf-8", "ignore"))
        pos += 1 + n
    return ".".join(parts), (end if jumped else pos)


def parse_mdns_ptr(data: bytes) -> Optional[str]:
    """Numele din răspunsul PTR („MacBook-ul-lui-Alex.local” -> „MacBook-ul-lui-Alex”), curățat."""
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        if an < 1:
            return None
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(min(an, 16)):
            _, pos = _read_name(data, pos)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 12:
                host, _ = _read_name(data, pos)
                host = host[:-6] if host.lower().endswith(".local") else host
                host = _CLEAN_HOST.sub("", host).strip()[:40]
                return host or None
            pos += rdlen
    except (IndexError, struct.error):
        return None
    return None


def query_mdns_name(ip: str, bind_ip: Optional[str] = None, timeout: float = 0.8,
                    make_socket: Callable[[], socket.socket] = lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) -> Optional[str]:
    """Întreabă aparatul `ip` (doar adrese private) cum îl cheamă, prin mDNS direct. Orice eroare: None."""
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_private or addr.version != 4:
            return None
    except ValueError:
        return None
    rev = list(reversed(ip.split("."))) + ["in-addr", "arpa"]
    q = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + _dns_name(rev) + struct.pack(">HH", 12, 0x8001)   # PTR, IN, răspuns direct
    try:
        with make_socket() as sock:
            if bind_ip:
                sock.bind((bind_ip, 0))
            sock.settimeout(timeout)
            sock.sendto(q, (ip, MDNS_PORT))
            data, src = sock.recvfrom(2048)
            if src[0] != ip:
                return None
            return parse_mdns_ptr(data)
    except OSError:
        return None


def computer_name(ip: str, bind_ip: Optional[str] = None) -> Optional[str]:
    """Numele aparatului: întâi ca Windows (NetBIOS), apoi ca Apple / Linux (mDNS)."""
    return query_name(ip, bind_ip) or query_mdns_name(ip, bind_ip)
