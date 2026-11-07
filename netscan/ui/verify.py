"""Verificarea pașilor de reparare: „Am făcut asta” nu se crede pe cuvânt.

Două surse de date reale, nimic ghicit:
1. Live, doar la apăsarea butonului: O SINGURĂ conexiune TCP la portul problemei, pe adresa din scanare,
   și doar dacă regulile de siguranță ale scanării (netscan/scan/network + guardrail) spun că adresa e în
   rețeaua la care e conectat laptopul acum. Nu se trimite nimic în afara rețelei locale.
   - conexiune refuzată  -> portul e închis: pas verificat
   - conexiune acceptată -> problema e încă acolo
   - fără răspuns / UDP / fără port / altă rețea -> nu se poate confirma de aici (trebuie o scanare nouă)
2. O scanare mai nouă a aceleiași rețele (vezi view.verified_by_newer): dacă dispozitivul apare în ea,
   iar problema nu, pasul e verificat.

Scorul după pașii verificați îl calculează tot motorul (netscan.engine.scoring.compute_score), nu UI-ul.
"""
from __future__ import annotations

import errno
import os
import socket
from dataclasses import dataclass
from typing import Callable

from netscan.model import Finding, Host, Scan

# Rezultatele verificării (și cheia textului din i18n: "verify_" + result)
VERIFIED = "ok"             # portul nu mai răspunde
STILL_OPEN = "open"         # portul răspunde încă
STILL_OPEN_VERSION = "version"   # OUTDATED_SERVICE: portul e deschis, versiunea se vede doar la o scanare nouă
UDP = "udp"
NO_PORT = "noport"
OTHER_NETWORK = "network"
NO_ANSWER = "noanswer"
RESULTS = (VERIFIED, STILL_OPEN, STILL_OPEN_VERSION, UDP, NO_PORT, OTHER_NETWORK, NO_ANSWER)

PROBE_TIMEOUT = 1.5  # secunde, o singură încercare

Probe = Callable[[str, int], str]           # (ip, port) -> "closed" | "open" | "unknown"
TargetCheck = Callable[[str], bool]         # ip -> e în rețeaua mea?


@dataclass(frozen=True)
class Check:
    result: str
    ip: str
    port: int | None

    @property
    def verified(self) -> bool:
        return self.result == VERIFIED


def tcp_probe(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> str:
    """O conexiune TCP: "closed" doar dacă dispozitivul a răspuns că portul e închis (refuz)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return "closed"
        return "unknown"   # timeout, gazdă oprită, firewall care ignoră: nu putem trage concluzii


def target_in_my_network(ip: str) -> bool:
    """Regulile scanării (Oneata): rețea potrivită + adresa în allowlist (subnetul interfeței active)."""
    try:
        from netscan.scan import guardrail, network
        info = network.detect_network()
        if not info.scan_allowed:
            return False
        allowlist = guardrail.build_allowlist(info.cidr, os.environ.get("NETSCAN_ALLOWLIST"))
        return guardrail.check_target(f"{ip}/32", allowlist).ok
    except Exception:  # fără informații despre rețea nu atingem nimic
        return False


def _tcp_port(host: Host | None, port: int) -> bool:
    protos = {p.proto for p in (host.ports if host else []) if p.port == port}
    return "tcp" in protos or not protos


def check_finding(scan: Scan, finding: Finding, probe: Probe = tcp_probe,
                  in_my_network: TargetCheck = target_in_my_network) -> Check:
    if finding.port is None:
        return Check(NO_PORT, finding.ip, None)
    host = next((h for h in scan.hosts if h.device_id == finding.device_id), None)
    if not _tcp_port(host, finding.port):
        return Check(UDP, finding.ip, finding.port)
    if not in_my_network(finding.ip):
        return Check(OTHER_NETWORK, finding.ip, finding.port)
    state = probe(finding.ip, finding.port)
    if state == "closed":
        return Check(VERIFIED, finding.ip, finding.port)
    if state == "open":
        return Check(STILL_OPEN_VERSION if finding.code == "OUTDATED_SERVICE" else STILL_OPEN,
                     finding.ip, finding.port)
    return Check(NO_ANSWER, finding.ip, finding.port)
