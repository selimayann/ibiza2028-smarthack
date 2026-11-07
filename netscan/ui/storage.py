"""Istoricul în SQLite (RBRT): doar query-uri parametrizate; delete_history(); diff(old, new).

MAC-ul real nu ajunge niciodată aici: doar mac_masked și device_id (așa vine din model).
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from netscan.model import Finding, Host, Port, Scan

DEFAULT_DB_PATH = "data/netscan.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    started_at INTEGER,
    status TEXT NOT NULL,
    error_code TEXT,
    score INTEGER
);
CREATE TABLE IF NOT EXISTS hosts (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac_masked TEXT,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,
    position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    tunnel TEXT,
    title TEXT,
    position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    points INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    position INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def db_path() -> Path:
    return Path(os.environ.get("NETSCAN_DB_PATH") or DEFAULT_DB_PATH)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    p = Path(path) if path else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def save_scan(scan: Scan, path: str | Path | None = None) -> int:
    with closing(connect(path)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scans (file, started_at, status, error_code, score) VALUES (?, ?, ?, ?, ?)",
            (scan.file, scan.started_at, scan.status, scan.error_code, scan.score),
        )
        scan_id = cur.lastrowid
        assert scan_id is not None
        for hi, h in enumerate(scan.hosts):
            conn.execute(
                "INSERT INTO hosts (scan_id, device_id, ip, mac_masked, vendor, hostname, device_type, position)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, h.device_id, h.ip, h.mac_masked, h.vendor, h.hostname, h.device_type, hi),
            )
            for pi, p in enumerate(h.ports):
                conn.execute(
                    "INSERT INTO ports (scan_id, device_id, port, proto, state, service, product, version,"
                    " extrainfo, tunnel, title, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, h.device_id, p.port, p.proto, p.state, p.service, p.product, p.version,
                     p.extrainfo, p.tunnel, p.title, pi),
                )
        for fi, f in enumerate(scan.findings):
            conn.execute(
                "INSERT INTO findings (scan_id, device_id, ip, port, code, severity, points, evidence, position)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, f.device_id, f.ip, f.port, f.code, f.severity, f.points, f.evidence, fi),
            )
        return scan_id


@dataclass
class ScanSummary:
    id: int
    file: str
    started_at: int | None
    status: str
    error_code: str | None
    score: int | None


def list_scans(path: str | Path | None = None) -> list[ScanSummary]:
    """Istoricul, ordonat după started_at (cele fără dată la final), apoi după ordinea salvării."""
    with closing(connect(path)) as conn:
        rows = conn.execute(
            "SELECT id, file, started_at, status, error_code, score FROM scans"
            " ORDER BY started_at IS NULL, started_at, id"
        ).fetchall()
    return [ScanSummary(**dict(r)) for r in rows]


def get_scan(scan_id: int, path: str | Path | None = None) -> Scan | None:
    with closing(connect(path)) as conn:
        row = conn.execute(
            "SELECT file, started_at, status, error_code, score FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        hosts: dict[str, Host] = {}
        for h in conn.execute(
            "SELECT device_id, ip, mac_masked, vendor, hostname, device_type FROM hosts"
            " WHERE scan_id = ? ORDER BY position", (scan_id,)
        ):
            hosts[h["device_id"]] = Host(**dict(h))
        for p in conn.execute(
            "SELECT device_id, port, proto, state, service, product, version, extrainfo, tunnel, title"
            " FROM ports WHERE scan_id = ? ORDER BY position", (scan_id,)
        ):
            d = dict(p)
            device_id = d.pop("device_id")
            if device_id in hosts:
                hosts[device_id].ports.append(Port(**d))
        findings = [
            Finding(file=row["file"], **dict(f))
            for f in conn.execute(
                "SELECT ip, device_id, port, code, severity, points, evidence FROM findings"
                " WHERE scan_id = ? ORDER BY position", (scan_id,)
            )
        ]
    return Scan(file=row["file"], status=row["status"], started_at=row["started_at"],
                error_code=row["error_code"], score=row["score"],
                hosts=list(hosts.values()), findings=findings)


def find_scan(file: str, started_at: int | None, path: str | Path | None = None) -> int | None:
    """Id-ul unei scanări deja salvate (același fișier și aceeași dată), ca să nu o dublăm."""
    with closing(connect(path)) as conn:
        row = conn.execute(
            "SELECT id FROM scans WHERE file = ? AND started_at IS ? ORDER BY id LIMIT 1", (file, started_at)
        ).fetchone()
    return row["id"] if row else None


def previous_scan_id(scan_id: int, path: str | Path | None = None) -> int | None:
    """Ultima scanare citibilă (status "ok") dinaintea celei date, în ordinea istoricului.
    Fișierele cu eroare n-au dispozitive, deci o comparație cu ele ar arăta totul ca „nou”."""
    items = list_scans(path)
    ids = [s.id for s in items]
    if scan_id not in ids:
        return None
    for s in reversed(items[: ids.index(scan_id)]):
        if s.status == "ok":
            return s.id
    return None


def delete_history(path: str | Path | None = None) -> None:
    """Șterge tot istoricul (NFR-02)."""
    with closing(connect(path)) as conn, conn:
        for table in ("findings", "ports", "hosts", "scans"):
            conn.execute(f"DELETE FROM {table}")  # nume fixe din cod, nu date din scanare
    with closing(connect(path)) as conn:
        conn.execute("VACUUM")


@dataclass
class ScanDiff:
    new_devices: list[Host] = field(default_factory=list)
    removed_devices: list[Host] = field(default_factory=list)
    opened_ports: list[tuple[str, int, str]] = field(default_factory=list)   # (device_id, port, proto)
    closed_ports: list[tuple[str, int, str]] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    persistent_findings: list[Finding] = field(default_factory=list)          # din scanarea nouă
    matched_by_ip: list[Host] = field(default_factory=list)  # dispozitive (din scanarea nouă) recunoscute după IP, nu după MAC
    score_before: int | None = None
    score_after: int | None = None


def match_devices(old: Scan, new: Scan) -> dict[str, str]:
    """Potrivește dispozitivele dintre două scanări: device_id vechi -> device_id nou.

    1. Întâi după device_id (același MAC).
    2. Doar pentru ce rămâne nepotrivit: după IP, dacă
       - vendorul e același când ambele scanări îl au;
       - potrivirea e 1 la 1 (un IP cu mai mulți candidați, de oricare parte, nu se potrivește).
    Ce rămâne nepotrivit e „nou” sau „dispărut”. (MAC-ul se poate schimba între scanări, ex. V6a/V6b.)
    """
    old_ids = {h.device_id for h in old.hosts}
    new_ids = {h.device_id for h in new.hosts}
    mapping = {d: d for d in old_ids & new_ids}

    def by_ip(hosts: list[Host], taken: set[str]) -> dict[str, list[Host]]:
        groups: dict[str, list[Host]] = {}
        for h in hosts:
            if h.device_id not in taken:
                groups.setdefault(h.ip, []).append(h)
        return groups

    old_left = by_ip(old.hosts, set(mapping))
    new_left = by_ip(new.hosts, set(mapping.values()))
    for ip, olds in old_left.items():
        news = new_left.get(ip, [])
        if len(olds) != 1 or len(news) != 1:
            continue
        o, n = olds[0], news[0]
        if o.vendor and n.vendor and o.vendor.strip().lower() != n.vendor.strip().lower():
            continue
        mapping[o.device_id] = n.device_id
    return mapping


def _open_ports(scan: Scan, rename: dict[str, str] | None = None) -> set[tuple[str, int, str]]:
    rename = rename or {}
    return {(rename.get(h.device_id, h.device_id), p.port, p.proto)
            for h in scan.hosts for p in h.ports if p.state == "open"}


def diff(old: Scan, new: Scan) -> ScanDiff:
    """Diferența dintre două scanări. Dispozitivele se potrivesc cu match_devices(),
    findings după (device_id, port, code), cu device_id-ul vechi tradus în cel nou."""
    mapping = match_devices(old, new)
    matched_new = set(mapping.values())
    old_ports, new_ports = _open_ports(old, mapping), _open_ports(new)
    old_f = {(mapping.get(f.device_id, f.device_id), f.port, f.code): f for f in old.findings}
    new_f = {f.key(): f for f in new.findings}
    port_sort = lambda k: (k[0], k[1], k[2])  # noqa: E731
    return ScanDiff(
        new_devices=[h for h in new.hosts if h.device_id not in matched_new],
        removed_devices=[h for h in old.hosts if h.device_id not in mapping],
        opened_ports=sorted(new_ports - old_ports, key=port_sort),
        closed_ports=sorted(old_ports - new_ports, key=port_sort),
        resolved_findings=[f for k, f in old_f.items() if k not in new_f],
        new_findings=[f for k, f in new_f.items() if k not in old_f],
        persistent_findings=[f for k, f in new_f.items() if k in old_f],
        matched_by_ip=[h for h in new.hosts if h.device_id in matched_new and h.device_id not in mapping],
        score_before=old.score,
        score_after=new.score,
    )
