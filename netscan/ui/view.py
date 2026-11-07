"""Ordonarea pentru afișare, după contract (docs/contract.md, decizia 3).

UI-ul NU calculează severități, puncte sau scoruri: le ia din motor și doar le ordonează.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from netscan.model import SEVERITY_ORDER, Finding, Host, Scan

# Praguri propuse pentru eticheta scorului (de confirmat cu echipa).
BAND_GOOD_MIN = 80
BAND_FAIR_MIN = 50


def ip_key(ip: str) -> tuple:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (99, 0, ip)


def score_band(score: int | None) -> str | None:
    if score is None:
        return None
    if score >= BAND_GOOD_MIN:
        return "good"
    if score >= BAND_FAIR_MIN:
        return "fair"
    return "poor"


def finding_rank_key(f: Finding) -> tuple:
    """Cea mai gravă problemă: puncte ↓, severitate ↓, port ↑ (fără port la final)."""
    return (-f.points, -SEVERITY_ORDER.get(f.severity, -1), f.port is None, f.port or 0, f.code)


@dataclass
class DeviceView:
    host: Host
    findings: list[Finding] = field(default_factory=list)  # cea mai gravă prima

    @property
    def total_points(self) -> int:
        return sum(f.points for f in self.findings)

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, -1)).severity

    @property
    def worst(self) -> Finding | None:
        return self.findings[0] if self.findings else None


def rank_devices(scan: Scan) -> list[DeviceView]:
    """Dispozitive: suma punctelor ↓, severitatea maximă ↓, IP numeric ↑."""
    views: dict[str, DeviceView] = {h.device_id: DeviceView(host=h) for h in scan.hosts}
    for f in scan.findings:
        if f.device_id not in views:  # defensiv: finding fără host în listă
            views[f.device_id] = DeviceView(host=Host(ip=f.ip, device_id=f.device_id))
        views[f.device_id].findings.append(f)
    for v in views.values():
        v.findings.sort(key=finding_rank_key)
    return sorted(
        views.values(),
        key=lambda v: (-v.total_points, -SEVERITY_ORDER.get(v.max_severity or "", -1), ip_key(v.host.ip)),
    )


def most_dangerous(scan: Scan) -> DeviceView | None:
    ranked = rank_devices(scan)
    if not ranked or not ranked[0].findings:
        return None
    return ranked[0]
