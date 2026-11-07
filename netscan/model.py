"""Contractul de date, în cod. Sursa: docs/contract.md (v1).

Fișier COMUN (Radu + RBRT). Se modifică doar după ce anunțați echipa, iar
docs/contract.md, acest fișier și fixtures/sample.json se schimbă în același commit.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, Optional

Severity = Literal["high", "medium", "low", "info"]
Status = Literal["ok", "error"]
ErrorCode = Literal["EMPTY", "TRUNCATED", "INVALID_XML", "XML_FORBIDDEN", "NOT_NMAP", "TOO_LARGE"]

SEVERITY_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Port:
    port: int
    proto: Literal["tcp", "udp"]
    state: str                       # exact ca în nmap: "open", "filtered", "open|filtered", ...
    service: Optional[str] = None    # atributul name din <service>
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    tunnel: Optional[str] = None     # "ssl" dacă nmap l-a pus
    title: Optional[str] = None      # titlul paginii web; TEXT NESIGUR


@dataclass
class Host:
    ip: str
    device_id: str                   # sha256(salt + MAC)[:12] sau "ip:" + ip
    mac_masked: Optional[str] = None # "AA:BB:CC:XX:XX:XX"; MAC-ul real nu apare niciodată
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    ports: list[Port] = field(default_factory=list)


@dataclass
class Finding:
    file: str
    ip: str
    device_id: str
    port: Optional[int]              # None doar la UNKNOWN_DEVICE
    code: str
    severity: Severity
    points: int
    evidence: str

    def key(self) -> tuple:
        """Identitatea unui finding în istoric: (device_id, port, code)."""
        return (self.device_id, self.port, self.code)


@dataclass
class Scan:
    file: str
    status: Status
    started_at: Optional[int] = None
    error_code: Optional[ErrorCode] = None
    score: Optional[int] = None
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Scan":
        hosts = [Host(**{**h, "ports": [Port(**p) for p in h.get("ports", [])]}) for h in d.get("hosts", [])]
        findings = [Finding(**f) for f in d.get("findings", [])]
        return Scan(**{**d, "hosts": hosts, "findings": findings})
