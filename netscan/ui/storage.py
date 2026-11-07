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
    """Scanarea dinaintea celei date, în ordinea istoricului."""
    ids = [s.id for s in list_scans(path)]
    if scan_id not in ids:
        return None
    i = ids.index(scan_id)
    return ids[i - 1] if i > 0 else None


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
    score_before: int | None = None
    score_after: int | None = None


def _open_ports(scan: Scan) -> set[tuple[str, int, str]]:
    return {(h.device_id, p.port, p.proto) for h in scan.hosts for p in h.ports if p.state == "open"}


def diff(old: Scan, new: Scan) -> ScanDiff:
    """Diferența dintre două scanări. Dispozitive după device_id, findings după (device_id, port, code)."""
    old_hosts = {h.device_id: h for h in old.hosts}
    new_hosts = {h.device_id: h for h in new.hosts}
    old_ports, new_ports = _open_ports(old), _open_ports(new)
    old_f = {f.key(): f for f in old.findings}
    new_f = {f.key(): f for f in new.findings}
    port_sort = lambda k: (k[0], k[1], k[2])  # noqa: E731
    return ScanDiff(
        new_devices=[h for d, h in new_hosts.items() if d not in old_hosts],
        removed_devices=[h for d, h in old_hosts.items() if d not in new_hosts],
        opened_ports=sorted(new_ports - old_ports, key=port_sort),
        closed_ports=sorted(old_ports - new_ports, key=port_sort),
        resolved_findings=[f for k, f in old_f.items() if k not in new_f],
        new_findings=[f for k, f in new_f.items() if k not in old_f],
        score_before=old.score,
        score_after=new.score,
    )
