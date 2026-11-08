"""Verificarea pașilor de reparare: „Am făcut asta” nu se crede pe cuvânt.

Două surse de date reale, nimic ghicit:
1. Live, doar la apăsarea butonului: O SINGURĂ conexiune TCP la portul problemei, pe adresa din scanare,
   și doar dacă regulile de siguranță ale scanării (netscan/scan/network + guardrail) spun că adresa e în
   rețeaua la care e conectat laptopul acum. Nu se trimite nimic în afara rețelei locale.
   - conexiune refuzată  -> portul e închis: pas verificat
   - conexiune acceptată -> problema e încă acolo
   - fără răspuns / UDP / fără port / altă rețea -> nu se poate confirma de aici (trebuie o scanare nouă)
   Se bate la ușă DOAR pentru cea mai nouă scanare scrisă de scanerul nostru (scans/), niciodată pentru
   Validation / Test Set / lab sau alte fișiere analizate, și doar dacă pe IP e același dispozitiv (device_id).
2. O scanare mai nouă a aceleiași rețele (vezi view.verified_by_newer): dacă dispozitivul apare în ea,
   iar problema nu, pasul e verificat.

Scorul după pașii verificați îl calculează tot motorul (netscan.engine.scoring.compute_score), nu UI-ul.
"""
from __future__ import annotations

import errno
import os
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from netscan.model import Finding, Host, Scan

# Rezultatele verificării (și cheia textului din i18n: "verify_" + result)
VERIFIED = "ok"             # portul nu mai răspunde
STILL_OPEN = "open"         # portul răspunde încă
STILL_OPEN_VERSION = "version"   # OUTDATED_SERVICE: portul e deschis, versiunea se vede doar la o scanare nouă
UDP = "udp"
NO_PORT = "noport"
OTHER_NETWORK = "network"
NO_ANSWER = "noanswer"
FILE_ONLY = "file_only"         # scanare dintr-un fișier / mai veche: nu atingem rețeaua deloc
OTHER_DEVICE = "other_device"   # pe IP-ul din scanare e acum alt dispozitiv (alt device_id)
RESULTS = (VERIFIED, STILL_OPEN, STILL_OPEN_VERSION, UDP, NO_PORT, OTHER_NETWORK, NO_ANSWER, FILE_ONLY, OTHER_DEVICE)
# Rezultate care primesc doar IP-ul în text (restul primesc portul și IP-ul; FILE_ONLY nu primește nimic).
IP_ONLY = (NO_PORT, OTHER_NETWORK, OTHER_DEVICE)

# Secunde, o singură încercare. Pe Windows o conexiune refuzată se anunță abia după ~2 s (sistemul mai
# retrimite SYN de două ori înainte să renunțe): cu 1,5 s un port închis ar părea „fără răspuns".
PROBE_TIMEOUT = 3.0

Probe = Callable[[str, int], str]           # (ip, port) -> "closed" | "open" | "unknown"
TargetCheck = Callable[[str], bool]         # ip -> e în rețeaua mea?
SameDevice = Callable[[str, str], Optional[bool]]   # (ip, device_id) -> True / False / None (nu știm)


@dataclass(frozen=True)
class Check:
    result: str
    ip: str
    port: int | None

    @property
    def verified(self) -> bool:
        return self.result == VERIFIED


_SIO_TCP_INITIAL_RTO = 0x98000011   # Windows: parametrii primului SYN (fără retrimiteri)


def _no_syn_retries(sock: socket.socket) -> None:
    """Pe Windows, un port închis (RST) e reîncercat de sistem încă ~2 s înainte de „refuzat”. Fără retrimiterea
    SYN-ului, refuzul vine imediat și pleacă un singur pachet. Dacă nu merge, rămâne comportamentul obișnuit."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        class _Rto(ctypes.Structure):
            _fields_ = [("Rtt", ctypes.c_ushort), ("MaxSynRetransmissions", ctypes.c_ubyte)]

        params = _Rto(0xFFFF, 0xFE)   # RTT nespecificat, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS
        returned = wintypes.DWORD()
        ctypes.WinDLL("ws2_32").WSAIoctl(ctypes.c_size_t(sock.fileno()), wintypes.DWORD(_SIO_TCP_INITIAL_RTO),
                                         ctypes.byref(params), ctypes.sizeof(params), None, 0,
                                         ctypes.byref(returned), None, None)
    except Exception:
        pass


def tcp_probe(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> str:
    """O conexiune TCP: "closed" doar dacă dispozitivul a răspuns că portul e închis (refuz)."""
    try:
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM) as sock:
            _no_syn_retries(sock)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return "closed"
        return "unknown"   # timeout, gazdă oprită, firewall care ignoră: nu putem trage concluzii


def target_in_my_network(ip: str, env: Optional[dict] = None, detect: Optional[Callable] = None) -> bool:
    """Regulile scanării (Oneata): rețea potrivită + adresa în allowlist (subnetul interfeței active).
    În plus, numele Wi-Fi trebuie să fie EXACT hotspotul echipei (NETSCAN_EXPECTED_SSID): subnetul singur nu
    dovedește nimic (orice hotspot de iPhone e 172.20.10.0/28). Nume necitit sau neconfigurat = nu atingem."""
    env = os.environ if env is None else env
    try:
        from netscan.scan import guardrail, network
        expected = (env.get("NETSCAN_EXPECTED_SSID") or "").strip()
        if not expected:
            return False
        info = (detect or network.detect_network)()
        if not info.scan_allowed or info.ssid is None or info.ssid != expected:
            return False
        allowlist = guardrail.build_allowlist(info.cidr, env.get("NETSCAN_ALLOWLIST"))
        return guardrail.check_target(f"{ip}/32", allowlist).ok
    except Exception:  # fără informații despre rețea nu atingem nimic
        return False


def _tcp_port(host: Host | None, port: int) -> bool:
    protos = {p.proto for p in (host.ports if host else []) if p.port == port}
    return "tcp" in protos or not protos


def check_finding(scan: Scan, finding: Finding, probe: Probe = tcp_probe,
                  in_my_network: TargetCheck = target_in_my_network, *, probe_allowed: bool = True,
                  same_device: Optional[SameDevice] = None) -> Check:
    """O singură conexiune TCP, doar dacă TOATE condițiile sunt îndeplinite:
    - `probe_allowed`: scanarea e a noastră (scrisă de scanerul nostru în scans/) și e cea mai nouă; altfel
      (Validation / Test Set / lab / un fișier mai vechi) -> FILE_ONLY, fără nicio conexiune;
    - `same_device(ip, device_id)` nu spune False (pe IP e alt dispozitiv -> OTHER_DEVICE);
    - `in_my_network(ip)`: rețeaua echipei (SSID exact + subnet + allowlist)."""
    if finding.port is None:
        return Check(NO_PORT, finding.ip, None)
    host = next((h for h in scan.hosts if h.device_id == finding.device_id), None)
    if not _tcp_port(host, finding.port):
        return Check(UDP, finding.ip, finding.port)
    if not probe_allowed:
        return Check(FILE_ONLY, finding.ip, finding.port)
    if same_device is not None:
        try:
            same = same_device(finding.ip, finding.device_id)
        except Exception:      # nu putem afla: nu blocăm, dar nici nu ghicim (rămân celelalte condiții)
            same = None
        if same is False:
            return Check(OTHER_DEVICE, finding.ip, finding.port)
    if not in_my_network(finding.ip):
        return Check(OTHER_NETWORK, finding.ip, finding.port)
    state = probe(finding.ip, finding.port)
    if state == "closed":
        return Check(VERIFIED, finding.ip, finding.port)
    if state == "open":
        return Check(STILL_OPEN_VERSION if finding.code == "OUTDATED_SERVICE" else STILL_OPEN,
                     finding.ip, finding.port)
    return Check(NO_ANSWER, finding.ip, finding.port)


def message_args(result: str, ip: str, port: int | None) -> tuple:
    """Argumentele pentru textul „verify_<result>” din i18n (câte „%s” are fiecare)."""
    if result == FILE_ONLY:
        return ()
    if result in IP_ONLY:
        return (ip,)
    return (port, ip)
