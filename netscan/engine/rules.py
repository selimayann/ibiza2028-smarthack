"""Regulile catalogului oficial (FR-06). Pur cod, determinist, fără LLM, fără rețea.

Reguli generale:
1. Se iau în calcul DOAR porturile cu state == "open" (exact; `filtered` și
   `open|filtered` nu contează).
2. Se decide după NUMELE SERVICIULUI raportat de nmap (comparație exactă, litere
   mici), nu după numărul portului.
3. Fără cazuri speciale pe nume de fișiere sau pe IP-uri.
"""

from __future__ import annotations

import ipaddress
import re

from netscan.model import Finding, Host, Port

# cod -> (severitate, puncte)
CATALOG: dict[str, tuple[str, int]] = {
    "TELNET_OPEN": ("high", 20),
    "RDP_EXPOSED": ("high", 20),
    "VNC_EXPOSED": ("high", 20),
    "DB_EXPOSED": ("high", 20),
    "CAMERA_STREAM_EXPOSED": ("high", 20),
    "OUTDATED_SERVICE": ("high", 20),
    "FTP_CLEARTEXT": ("medium", 10),
    "HTTP_ADMIN_CLEARTEXT": ("medium", 10),
    "SMB_EXPOSED": ("medium", 10),
    "MQTT_EXPOSED": ("medium", 10),
    "UPNP_EXPOSED": ("medium", 10),
    "SNMP_EXPOSED": ("medium", 10),
    "PRINTER_RAW_EXPOSED": ("low", 5),
    "UNKNOWN_DEVICE": ("low", 5),
    "SSH_OPEN": ("info", 0),
}

# serviciu (exact, litere mici) -> cod; pe orice protocol
SERVICE_CODES: dict[str, str] = {
    "telnet": "TELNET_OPEN",
    "ms-wbt-server": "RDP_EXPOSED",
    "vnc": "VNC_EXPOSED",
    "mysql": "DB_EXPOSED",
    "postgresql": "DB_EXPOSED",
    "redis": "DB_EXPOSED",
    "mongodb": "DB_EXPOSED",
    "rtsp": "CAMERA_STREAM_EXPOSED",
    "ftp": "FTP_CLEARTEXT",
    "mqtt": "MQTT_EXPOSED",
    "jetdirect": "PRINTER_RAW_EXPOSED",
    "ssh": "SSH_OPEN",
}

# serviciu -> cod; DOAR pe UDP
UDP_ONLY_SERVICE_CODES: dict[str, str] = {
    "upnp": "UPNP_EXPOSED",
    "snmp": "SNMP_EXPOSED",
}

SMB_SERVICES = frozenset({"microsoft-ds", "netbios-ssn"})

HTTP_ADMIN_KEYWORDS = ("login", "admin", "config", "setup", "router", "settings")


# --------------------------------------------------------------------------- #
# Reguli izolate (ușor de schimbat dacă mentorii răspund altfel)
# --------------------------------------------------------------------------- #
def title_matches_admin(title: str | None) -> bool:
    """Titlul paginii conține un cuvânt-cheie? (subșir, fără diferență mari/mici)

    Singurul loc unde se decide potrivirea; vezi docs/questions.md.
    """
    if not title:
        return False
    lowered = title.lower()
    return any(word in lowered for word in HTTP_ADMIN_KEYWORDS)


_VERSION_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)")
# „3.X - 4.X" sau „3 - 4": interval ambiguu, nu putem spune ce versiune rulează
_VERSION_RANGE_RE = re.compile(r"[xX]\s*-\s*\d|\d\s+-\s+\d")


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    """„7.2p2 Ubuntu" -> (7, 2). None dacă nu începe cu o versiune numerică."""
    if not version:
        return None
    match = _VERSION_RE.match(version)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_outdated(port: Port) -> bool:
    """Lista „învechit" din catalog: vsftpd 2.3.4; OpenSSH < 7.4; Apache httpd <= 2.2.x;
    Microsoft IIS <= 7.5; Samba <= 3.x (neambiguu)."""
    product = (port.product or "").lower()
    version = port.version or ""
    vt = _version_tuple(version)
    if vt is None:
        return False

    if "vsftpd" in product:
        return vt == (2, 3, 4)
    if "openssh" in product:
        return vt < (7, 4)
    if "apache httpd" in product:
        return len(vt) >= 2 and vt[:2] <= (2, 2)
    if "microsoft iis" in product:
        return len(vt) >= 2 and vt[:2] <= (7, 5)
    if "samba" in product:
        if _VERSION_RANGE_RE.search(version):
            return False  # ex. „Samba smbd 3.X - 4.X": ambiguu, nu raportăm
        return vt[0] <= 3
    return False


def _pick_smb_port(candidates: list[Port]) -> Port:
    """Un singur finding SMB per dispozitiv: 445 dacă e deschis, altfel 139, altfel
    cel mai mic port rămas (caz neprevăzut de brief)."""
    def key(p: Port) -> tuple[int, int, str]:
        rank = 0 if p.port == 445 else 1 if p.port == 139 else 2
        return (rank, p.port, p.proto)

    return min(candidates, key=key)


# --------------------------------------------------------------------------- #
# Evaluare
# --------------------------------------------------------------------------- #
def _evidence(port: Port, with_title: bool = False) -> str:
    parts = [f"{port.port}/{port.proto}"]
    if port.service:
        parts.append(port.service)
    version_text = " ".join(x for x in (port.product, port.version) if x)
    if version_text:
        parts.append(version_text)
    text = " ".join(parts)
    if with_title and port.title:
        text += f", titlu: {port.title}"
    return text


def _make(file: str, host: Host, port: int | None, code: str, evidence: str) -> Finding:
    severity, points = CATALOG[code]
    return Finding(
        file=file,
        ip=host.ip,
        device_id=host.device_id,
        port=port,
        code=code,
        severity=severity,
        points=points,
        evidence=evidence,
    )


def _host_findings(file: str, host: Host) -> list[Finding]:
    found: list[Finding] = []
    open_ports = [p for p in host.ports if p.state == "open"]

    for port in open_ports:
        service = (port.service or "").strip().lower()

        code = SERVICE_CODES.get(service)
        if code is None and port.proto == "udp":
            code = UDP_ONLY_SERVICE_CODES.get(service)
        if code is not None:
            found.append(_make(file, host, port.port, code, _evidence(port)))

        if (
            service == "http"
            and (port.tunnel or "").strip().lower() != "ssl"
            and title_matches_admin(port.title)
        ):
            found.append(
                _make(file, host, port.port, "HTTP_ADMIN_CLEARTEXT", _evidence(port, True))
            )

        if is_outdated(port):
            found.append(_make(file, host, port.port, "OUTDATED_SERVICE", _evidence(port)))

    smb_ports = [
        p for p in open_ports if (p.service or "").strip().lower() in SMB_SERVICES
    ]
    if smb_ports:
        chosen = _pick_smb_port(smb_ports)
        found.append(_make(file, host, chosen.port, "SMB_EXPOSED", _evidence(chosen)))

    if open_ports and not host.vendor and not host.hostname:
        found.append(
            _make(
                file,
                host,
                None,
                "UNKNOWN_DEVICE",
                f"fără producător și fără nume, {len(open_ports)} port(uri) deschise",
            )
        )
    return found


def finding_sort_key(f: Finding) -> tuple[str, int, int, str]:
    """Ordinea din contract: (file, ip numeric, port cu None primul, code)."""
    return (
        f.file,
        int(ipaddress.IPv4Address(f.ip)),
        -1 if f.port is None else f.port,
        f.code,
    )


def evaluate(file: str, hosts: list[Host]) -> list[Finding]:
    """Aplică catalogul pe hosturi. Rezultatul e sortat și fără dubluri.

    O dublură = aceeași identitate (ip, port, cod), ca să nu apară două rânduri
    identice în findings.csv (de ex. același port raportat și pe TCP, și pe UDP).
    """
    unique: dict[tuple[str, int | None, str], Finding] = {}
    for host in hosts:
        for finding in _host_findings(file, host):
            unique.setdefault((finding.ip, finding.port, finding.code), finding)
    return sorted(unique.values(), key=finding_sort_key)
