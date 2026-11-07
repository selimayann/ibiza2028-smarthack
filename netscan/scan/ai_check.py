"""Validatorul pentru textele generate de LLM (Oneata). „Code decides, the model words, code checks.”

LLM-ul poate doar formula explicații și pași de reparare. Codul de aici verifică textul înainte să
ajungă în UI: orice IP, port, cod de finding sau CVE menționat trebuie să existe în scanare.
Dacă nu, se folosește textul predefinit (fallback-ul lui Ayan din netscan/explain/).

Tot aici se construiește contextul trimis modelului: doar câmpuri sigure, fără MAC, iar textul scris
de dispozitive (titluri de pagini, hostname-uri, versiuni) e marcat ca date nesigure, nu instrucțiuni.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from netscan.model import Finding, Scan

CATALOG = frozenset({
    "TELNET_OPEN", "RDP_EXPOSED", "VNC_EXPOSED", "DB_EXPOSED", "CAMERA_STREAM_EXPOSED", "OUTDATED_SERVICE",
    "FTP_CLEARTEXT", "HTTP_ADMIN_CLEARTEXT", "SMB_EXPOSED", "MQTT_EXPOSED", "UPNP_EXPOSED", "SNMP_EXPOSED",
    "PRINTER_RAW_EXPOSED", "UNKNOWN_DEVICE", "SSH_OPEN",
})

MAX_TEXT_LEN = 1200          # o explicație + 5 pași încap ușor
MAX_UNTRUSTED_LEN = 80       # cât din titlu / hostname / versiune ajunge în prompt

# Un punct după IP e acceptat dacă e final de propoziție („…pe 192.168.1.40.”), nu dacă urmează o cifră.
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d)(?!\.\d)")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CODE = re.compile(r"\b[A-Z]{2,}(?:_[A-Z]{2,})+\b")
_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
_URL = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
# Numere de telefon (ghidul: „orice port, IP, CVE sau număr de telefon care nu există în scanare”).
# Candidat: cel puțin 9 cifre, cu spații, cratime, puncte, paranteze sau „+” între ele.
_PHONE = re.compile(r"(?<![\w.:/-])\+?\(?\d[\d\s().-]{7,}\d(?!\w)(?![.:/-]\d)")


def has_phone_number(text: str) -> bool:
    """True dacă textul conține ceva ce arată a număr de telefon (nu IP, nu CVE, nu dată)."""
    clean = _IPV4.sub(" ", _CVE.sub(" ", text))   # IP-urile și CVE-urile se verifică separat
    for m in _PHONE.finditer(clean):
        if sum(c.isdigit() for c in m.group(0)) >= 9:
            return True
    return False
# „port 80”, „portul 8080”, „porturile 80 și 443”, „ports 80, 443”, „80/tcp”, „:8080”
_PORT_WORD = re.compile(r"\bport(?:ul|urile|s)?\s*(?:nr\.?\s*)?((?:\d{1,5}(?:\s*(?:,|și|si|and|or|sau)\s*)?)+)",
                        re.IGNORECASE)
_PORT_PROTO = re.compile(r"\b(\d{1,5})\s*/\s*(?:tcp|udp)\b", re.IGNORECASE)
_PORT_COLON = re.compile(r"(?<=[\d\w]):(\d{1,5})\b")


@dataclass
class CheckResult:
    ok: bool
    problems: list[str] = field(default_factory=list)


def _scan_facts(scan: Scan) -> tuple[set[str], set[int], set[str], str]:
    ips = {h.ip for h in scan.hosts} | {f.ip for f in scan.findings}
    ports = {p.port for h in scan.hosts for p in h.ports} | {f.port for f in scan.findings if f.port is not None}
    codes = {f.code for f in scan.findings}
    # CVE-urile pot apărea doar dacă sunt în datele scanării (evidence, product, version, extrainfo).
    blob = " ".join(
        [f.evidence or "" for f in scan.findings]
        + [" ".join(filter(None, (p.product, p.version, p.extrainfo))) for h in scan.hosts for p in h.ports]
    ).upper()
    return ips, ports, codes, blob


def mentioned_ports(text: str) -> set[int]:
    found: set[int] = set()
    for m in _PORT_WORD.finditer(text):
        found.update(int(x) for x in re.findall(r"\d{1,5}", m.group(1)))
    found.update(int(x) for x in _PORT_PROTO.findall(text))
    found.update(int(x) for x in _PORT_COLON.findall(text))
    return found


def check_llm_text(text: Optional[str], scan: Scan, finding: Optional[Finding] = None) -> CheckResult:
    """Verifică un text generat. `finding` = finding-ul explicat (opțional): atunci codurile menționate
    trebuie să fie chiar codul lui, iar IP-urile chiar IP-ul lui, ca explicația să nu vorbească de altceva."""
    problems: list[str] = []
    if not text or not text.strip():
        return CheckResult(False, ["EMPTY"])
    if len(text) > MAX_TEXT_LEN:
        problems.append("TOO_LONG")

    ips, ports, codes, blob = _scan_facts(scan)
    if finding is not None:
        ips, codes = {finding.ip}, {finding.code}
        ports = ports | ({finding.port} if finding.port is not None else set())

    for ip in _IPV4.findall(text):
        if ip not in ips:
            problems.append(f"IP:{ip}")
    for port in sorted(mentioned_ports(text)):
        if port not in ports:
            problems.append(f"PORT:{port}")
    for code in _CODE.findall(text):
        if code not in CATALOG:
            problems.append(f"UNKNOWN_CODE:{code}")
        elif code not in codes:
            problems.append(f"CODE:{code}")
    for cve in _CVE.findall(text):
        if cve.upper() not in blob:
            problems.append(f"CVE:{cve.upper()}")
    if _MAC.search(text):
        problems.append("MAC")
    if _URL.search(text):
        problems.append("URL")
    if has_phone_number(text):
        problems.append("PHONE")
    return CheckResult(not problems, problems)


def choose_text(llm_text: Optional[str], fallback: str, scan: Scan, finding: Optional[Finding] = None) -> tuple[str, str]:
    """Întoarce (text, sursa): textul LLM dacă trece verificarea, altfel textul predefinit."""
    if llm_text is not None and check_llm_text(llm_text, scan, finding).ok:
        return llm_text.strip(), "llm"
    return fallback, "fallback"


def _untrusted(value: Optional[str]) -> Optional[str]:
    """Text scris de dispozitiv: o singură linie, scurt, fără caractere de control."""
    if value is None:
        return None
    clean = "".join(ch if ch.isprintable() else " " for ch in value)
    clean = " ".join(clean.split())
    return clean[:MAX_UNTRUSTED_LEN]


def prompt_context(finding: Finding, scan: Scan) -> dict:
    """Datele despre un finding care pot fi trimise modelului. Fără MAC, fără device_id, fără SSID.
    Câmpurile din `untrusted_device_text` trebuie puse în prompt ca date, nu ca instrucțiuni."""
    host = next((h for h in scan.hosts if h.ip == finding.ip), None)
    port = None
    if host is not None and finding.port is not None:
        port = next((p for p in host.ports if p.port == finding.port), None)
    return {
        "code": finding.code,
        "severity": finding.severity,
        "ip": finding.ip,
        "port": finding.port,
        "proto": port.proto if port else None,
        "service": port.service if port else None,
        "device_type": host.device_type if host else None,
        "untrusted_device_text": {
            "product": _untrusted(port.product) if port else None,
            "version": _untrusted(port.version) if port else None,
            "page_title": _untrusted(port.title) if port else None,
            "hostname": _untrusted(host.hostname) if host else None,
            "vendor": _untrusted(host.vendor) if host else None,
        },
    }
