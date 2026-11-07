"""Parser nmap XML -> Scan (fără findings și scor; acelea vin din rules.py).

Principii (NFR-03, NFR-05):
- orice fișier problematic întoarce Scan(status="error", error_code=...), nu excepție;
- niciun parser „tolerant" (fără recover): un fișier stricat nu produce findings;
- XML se citește doar cu defusedxml; entități și referințe externe sunt interzise;
- tot ce vine din fișier (titluri, bannere, hostname-uri) e text NESIGUR:
  se curăță de caractere de control și se limitează ca lungime;
- MAC-ul real nu iese din această funcție: doar `mac_masked` și `device_id`.

DTD: nmap însuși scrie `<!DOCTYPE nmaprun>` în fiecare fișier XML, deci NU putem
interzice orice DTD (am respinge fișiere legitime). Interzicem ce e periculos:
declarațiile de entități (XXE, „billion laughs") și referințele externe.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import sys
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

import defusedxml.ElementTree as DET
from defusedxml.common import DefusedXmlException

from netscan.engine.devices import guess_device_type
from netscan.engine.common import STATUS_OK, error_scan
from netscan.model import Host, Port, Scan

MAX_BYTES = 20 * 1024 * 1024  # 20 MB (NFR-03)
MAX_TEXT = 200  # lungime maximă pentru textele venite din fișier

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_UTF8_BOM = b"\xef\xbb\xbf"

# Mesaje expat care indică un fișier tăiat (terminat brusc), nu unul corupt
_TRUNCATION_HINTS = ("no element found", "unclosed token", "partial character")

_DEFAULT_SALT = "netscan-salt-implicit"  # NU e un secret; vezi _salt()
_salt_warned = False


# --------------------------------------------------------------------------- #
# Utilitare
# --------------------------------------------------------------------------- #
def _clean(value: str | None, maxlen: int = MAX_TEXT) -> str | None:
    """Curăță un text nesigur: fără caractere de control, tăiat, None dacă e gol."""
    if value is None:
        return None
    s = _CONTROL_RE.sub(" ", value).strip()
    if not s:
        return None
    return s[:maxlen]


def _salt() -> bytes:
    """Salt-ul pentru device_id, din variabila de mediu NETSCAN_SALT.

    Dacă lipsește folosim un salt implicit (nu e secret, deci device_id e mai
    slab față de o ghicire a MAC-ului) și avertizăm o singură dată pe stderr.
    """
    global _salt_warned
    salt = os.environ.get("NETSCAN_SALT")
    if not salt:
        if not _salt_warned:
            print(
                "AVERTISMENT: NETSCAN_SALT nu e setat; folosesc un salt implicit.",
                file=sys.stderr,
            )
            _salt_warned = True
        salt = _DEFAULT_SALT
    return salt.encode("utf-8")


def device_identity(mac: str | None, ip: str) -> tuple[str, str | None]:
    """(device_id, mac_masked). MAC-ul real e folosit doar aici și apoi aruncat."""
    if mac:
        norm = mac.strip().upper()
        if _MAC_RE.match(norm):
            digest = hashlib.sha256(_salt() + norm.encode("ascii")).hexdigest()
            masked = ":".join(norm.split(":")[:3]) + ":XX:XX:XX"
            return digest[:12], masked
    return "ip:" + ip, None


def extract_title(output: str | None) -> str | None:
    """Titlul paginii din output-ul scriptului nmap `http-title`.

    Se ia doar prima linie (următoarele sunt de tip „Requested resource was ...").
    Mesajele nmap care nu sunt titluri reale se ignoră.
    """
    if not output:
        return None
    first = next((ln.strip() for ln in output.splitlines() if ln.strip()), "")
    if not first:
        return None
    lowered = first.lower()
    if lowered.startswith("did not follow redirect"):
        return None
    if lowered.startswith("site doesn't have a title"):
        return None
    return _clean(first)


# --------------------------------------------------------------------------- #
# Parsare
# --------------------------------------------------------------------------- #
def _parse_port(el: Element) -> Port | None:
    proto = (el.get("protocol") or "").lower()
    if proto not in ("tcp", "udp"):
        return None
    try:
        number = int(el.get("portid", ""))
    except ValueError:
        return None
    if not 1 <= number <= 65535:
        return None
    state_el = el.find("state")
    state = _clean(state_el.get("state")) if state_el is not None else None
    if not state:
        return None

    service = product = version = extrainfo = tunnel = None
    svc = el.find("service")
    if svc is not None:
        service = _clean(svc.get("name"))
        product = _clean(svc.get("product"))
        version = _clean(svc.get("version"))
        extrainfo = _clean(svc.get("extrainfo"))
        tunnel = _clean(svc.get("tunnel"))

    title = None
    for script in el.iterfind("script"):
        if script.get("id") == "http-title":
            title = extract_title(script.get("output"))
            break

    return Port(
        port=number,
        proto=proto,
        state=state,
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
        tunnel=tunnel,
        title=title,
    )


def _parse_host(el: Element) -> Host | None:
    status = el.find("status")
    if status is not None and status.get("state") == "down":
        return None

    ip: str | None = None
    mac: str | None = None
    vendor: str | None = None
    for addr in el.iterfind("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4" and ip is None:
            try:
                ip = str(ipaddress.IPv4Address((addr.get("addr") or "").strip()))
            except ValueError:
                return None  # IP invalid: host ostil sau stricat, îl ignorăm
        elif kind == "mac" and mac is None:
            mac = addr.get("addr")
            vendor = _clean(addr.get("vendor"))
    if ip is None:
        return None  # fără IPv4 (de ex. doar IPv6): în afara domeniului acestui proiect

    hostname = None
    first_name = el.find("hostnames/hostname")
    if first_name is not None:
        hostname = _clean(first_name.get("name"))

    ports: list[Port] = []
    for port_el in el.iterfind("ports/port"):
        port = _parse_port(port_el)
        if port is not None:
            ports.append(port)
    ports.sort(key=lambda p: (p.port, p.proto))

    device_id, mac_masked = device_identity(mac, ip)
    mac = None  # MAC-ul real nu mai e folosit mai departe

    return Host(
        ip=ip,
        device_id=device_id,
        mac_masked=mac_masked,
        vendor=vendor,
        hostname=hostname,
        device_type=guess_device_type(vendor, hostname, ports),
        ports=ports,
    )


def parse_bytes(data: bytes, name: str) -> Scan:
    """Parsează conținutul unui fișier nmap XML. Nu ridică excepții."""
    if not data.lstrip(_UTF8_BOM).strip():
        return error_scan(name, "EMPTY")

    try:
        root = DET.fromstring(
            data,
            forbid_dtd=False,  # nmap scrie <!DOCTYPE nmaprun>; vezi docstring-ul modulului
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException:
        return error_scan(name, "XML_FORBIDDEN")
    except ParseError as exc:
        message = str(exc).lower()
        if any(hint in message for hint in _TRUNCATION_HINTS):
            return error_scan(name, "TRUNCATED")
        return error_scan(name, "INVALID_XML")
    except Exception:  # noqa: BLE001 - un fișier ostil nu are voie să dărâme unealta
        return error_scan(name, "INVALID_XML")

    if root.tag != "nmaprun":
        return error_scan(name, "NOT_NMAP")

    started_at: int | None
    try:
        started_at = int(root.get("start", ""))
    except ValueError:
        started_at = None

    hosts: list[Host] = []
    for host_el in root.iterfind("host"):
        host = _parse_host(host_el)
        if host is not None:
            hosts.append(host)
    hosts.sort(key=lambda h: int(ipaddress.IPv4Address(h.ip)))

    return Scan(file=name, status=STATUS_OK, started_at=started_at, hosts=hosts)


def parse_file(path: str | os.PathLike[str]) -> Scan:
    """Citește un fișier și îl parsează. Nu ridică excepții."""
    p = Path(path)
    name = p.name
    try:
        with p.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)  # citim cel mult limita + 1 octet
    except OSError:
        # Contractul nu are un cod pentru fișier ilizibil; vezi docs/questions.md
        return error_scan(name, "INVALID_XML")
    if len(data) > MAX_BYTES:
        return error_scan(name, "TOO_LARGE")
    return parse_bytes(data, name)


# Compatibilitate cu stub-ul din repo (docs/roles): celelalte module pot importa
# analyze_file / analyze_folder și de aici. Import târziu, ca să nu creăm un ciclu.
def analyze_file(path):  # noqa: F811
    from netscan.engine.analyze import analyze_file as _impl

    return _impl(path)


def analyze_folder(path):  # noqa: F811
    from netscan.engine.analyze import analyze_folder as _impl

    return _impl(path)
