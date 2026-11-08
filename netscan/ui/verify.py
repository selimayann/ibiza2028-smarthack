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
from dataclasses import dataclass, replace
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
STILL_PRESENT = "present"       # aparatul necunoscut e încă în rețea (răspunde)
GONE = "gone"                   # aparatul necunoscut nu mai e în rețea: verificat
RESULTS = (VERIFIED, STILL_OPEN, STILL_OPEN_VERSION, UDP, NO_PORT, OTHER_NETWORK, NO_ANSWER, FILE_ONLY, OTHER_DEVICE,
           STILL_PRESENT, GONE)
# Rezultate care primesc doar IP-ul în text (restul primesc portul și IP-ul; FILE_ONLY nu primește nimic).
IP_ONLY = (NO_PORT, OTHER_NETWORK, OTHER_DEVICE, STILL_PRESENT, GONE)
# Rezultatele care confirmă pasul (scorul de acum crește)
CONFIRMED = ("ok", "gone")

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
        return self.result in (VERIFIED, GONE)


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


# Două încercări scurte (fiecare un singur SYN): pe hotspot sau Wi-Fi aglomerat primul pachet se mai pierde.
PROBE_TRIES = (1.2, 2.0)


def _connect_once(ip: str, port: int, timeout: float) -> str:
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


def tcp_probe(ip: str, port: int, timeout: float | None = None) -> str:
    """Conexiune TCP: "closed" doar dacă dispozitivul a răspuns că portul e închis (refuz), "open" dacă a acceptat.
    La tăcere mai încercăm o dată (cel mult 2 pachete, ~3 s în total): un pachet pierdut nu mai dă „fără răspuns”."""
    tries = (timeout,) if timeout else PROBE_TRIES
    state = "unknown"
    for t in tries:
        state = _connect_once(ip, port, t)
        if state != "unknown":
            break
    return state


# Pentru UPnP (1900): o întrebare SSDP adresată doar acestui aparat (cum întreabă orice telefon din casă).
_SSDP = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")


def udp_probe(ip: str, port: int, timeout: float = 1.5) -> str:
    """Un pachet UDP mic, doar la acest aparat: răspuns -> "open"; „port inaccesibil” -> "closed"; tăcere -> "unknown"."""
    payload = _SSDP if port == 1900 else b"\x00"
    try:
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(payload)
            sock.recv(512)
            return "open"
    except (ConnectionResetError, ConnectionRefusedError):
        return "closed"            # Windows/Linux: aparatul a răspuns „portul nu există”
    except OSError as exc:
        if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
            return "closed"
        return "unknown"


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
                  same_device: Optional[SameDevice] = None, udp: Optional[Probe] = None) -> Check:
    """O singură conexiune TCP, doar dacă TOATE condițiile sunt îndeplinite:
    - `probe_allowed`: scanarea e a noastră (scrisă de scanerul nostru în scans/) și e cea mai nouă; altfel
      (Validation / Test Set / lab / un fișier mai vechi) -> FILE_ONLY, fără nicio conexiune;
    - `same_device(ip, device_id)` nu spune False (pe IP e alt dispozitiv -> OTHER_DEVICE);
    - `in_my_network(ip)`: rețeaua echipei (SSID exact + subnet + allowlist)."""
    host = next((h for h in scan.hosts if h.device_id == finding.device_id), None)
    if finding.port is None:
        # Aparatul necunoscut: e încă în rețea? Doar porturile lui TCP din scanare; fără ele nu putem afla.
        tcp = [p.port for p in (host.ports if host else []) if p.proto == "tcp" and p.state == "open"]
        if finding.code != "UNKNOWN_DEVICE" or not tcp or not probe_allowed:
            return Check(NO_PORT, finding.ip, None)
        if not in_my_network(finding.ip):
            return Check(OTHER_NETWORK, finding.ip, None)
        if device_is_up(replace(finding, port=-1), host, probe, None):
            return Check(STILL_PRESENT, finding.ip, None)
        return Check(GONE, finding.ip, None)
    if not _tcp_port(host, finding.port):
        # UDP (UPnP, SNMP…): un singur pachet; doar „răspunde” sau „port inaccesibil” sunt răspunsuri sigure
        if udp is None or not probe_allowed or not in_my_network(finding.ip):
            return Check(UDP, finding.ip, finding.port)
        state = udp(finding.ip, finding.port)
        if state == "closed":
            return Check(VERIFIED, finding.ip, finding.port)
        if state == "open":
            return Check(STILL_OPEN, finding.ip, finding.port)
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
    # Tăcere pe portul problemei. Multe aparate (telefoanele, cele cu firewall) nu răspund deloc pe un port închis.
    # Dacă ACELAȘI dispozitiv răspunde pe alt port din scanare, e pornit și în rețea: portul problemei nu mai e
    # accesibil din rețea, deci problema nu mai poate fi folosită -> verificat. Dacă nu răspunde nimic: e oprit.
    if device_is_up(finding, host, probe, scan):
        return Check(VERIFIED, finding.ip, finding.port)
    return Check(NO_ANSWER, finding.ip, finding.port)


# Câte alte porturi ale dispozitivului încercăm ca să aflăm dacă e pornit (în paralel, câte o conexiune fiecare).
ALIVE_PORTS = 2


def device_is_up(finding: Finding, host: Host | None, probe: Probe, scan: Scan | None = None) -> bool:
    """Dispozitivul răspunde (deschis SAU refuzat) pe alt port TCP pe care scanarea l-a găsit deschis.
    Doar porturile din scanare, ale aceluiași dispozitiv, pe aceeași adresă: nimic nou atins.
    Întâi porturile FĂRĂ probleme (ele rămân deschise după reparații); cele cu probleme pot tăcea și ele, fiind reparate."""
    problem_ports = {f.port for f in (scan.findings if scan else []) if f.device_id == finding.device_id}
    others = []
    for p in (host.ports if host else []):
        if p.proto == "tcp" and p.state == "open" and p.port != finding.port and p.port not in others:
            others.append(p.port)
    others.sort(key=lambda port: port in problem_ports)      # stabil: fără probleme întâi, în ordinea din scanare
    others = others[:ALIVE_PORTS]
    if not others:
        return False
    if len(others) == 1:
        return probe(finding.ip, others[0]) in ("open", "closed")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(others)) as pool:
        return any(r in ("open", "closed") for r in pool.map(lambda port: probe(finding.ip, port), others))


def message_args(result: str, ip: str, port: int | None) -> tuple:
    """Argumentele pentru textul „verify_<result>” din i18n (câte „%s” are fiecare)."""
    if result == FILE_ONLY:
        return ()
    if result in IP_ONLY:
        return (ip,)
    return (port, ip)
