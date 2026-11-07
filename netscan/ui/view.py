"""Ordonarea pentru afișare, după contract (docs/contract.md, decizia 3).

UI-ul NU calculează severități, puncte sau scoruri: le ia din motor și doar le ordonează.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace

from netscan.model import SEVERITY_ORDER, Finding, Host, Scan
from netscan.scan.device_info import DeviceInfo, describe

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
    info: DeviceInfo | None = None  # FR-03: producător (nmap/IEEE), MAC privat, tip; doar pentru afișare

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
    views: dict[str, DeviceView] = {}
    for h in scan.hosts:
        info = describe(h)  # FR-03, doar afișare: findings și scorul rămân cele din motor
        views[h.device_id] = DeviceView(
            host=replace(h, vendor=info.vendor, device_type=info.device_type), info=info
        )
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


# ---------- trendul scorului (FR-10), pentru graficul din istoric ----------

@dataclass
class TrendPoint:
    scan_id: int
    file: str
    started_at: int | None
    score: int
    x: float
    y: float


@dataclass
class Trend:
    points: list[TrendPoint]
    width: int
    height: int
    plot_left: int
    plot_right: int
    plot_top: int
    plot_bottom: int

    def y_for(self, score: int) -> float:
        return self.plot_bottom - (self.plot_bottom - self.plot_top) * score / 100

    @property
    def path(self) -> str:
        return " ".join(f"{'M' if i == 0 else 'L'}{p.x:.1f},{p.y:.1f}" for i, p in enumerate(self.points))

    @property
    def first(self) -> TrendPoint:
        return self.points[0]

    @property
    def last(self) -> TrendPoint:
        return self.points[-1]

    @property
    def direction(self) -> str:
        a, b = self.first.score, self.last.score
        return "up" if b > a else "down" if b < a else "same"


def score_trend(items, width: int = 640, height: int = 220) -> Trend | None:
    """Scorul în timp, din istoricul salvat (în ordinea istoricului). Doar scanările cu scor;
    fișierele cu eroare nu au scor și nu apar pe grafic. Nevoie de cel puțin 2 puncte."""
    scored = [s for s in items if s.status == "ok" and s.score is not None]
    if len(scored) < 2:
        return None
    left, right, top, bottom = 64, width - 60, 18, height - 36
    step = (right - left) / (len(scored) - 1)
    trend = Trend(points=[], width=width, height=height,
                  plot_left=left, plot_right=right, plot_top=top, plot_bottom=bottom)
    for i, s in enumerate(scored):
        trend.points.append(TrendPoint(scan_id=s.id, file=s.file, started_at=s.started_at, score=s.score,
                                       x=left + step * i, y=trend.y_for(s.score)))
    return trend
