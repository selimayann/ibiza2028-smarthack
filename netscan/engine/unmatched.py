"""D6: raportul serviciilor deschise care nu au produs nicio constatare.

Doar citește rezultatul deja calculat (Scan.hosts + Scan.findings). Nu atinge
regulile, scorul sau findings.csv / scores.csv. Se scrie doar la cerere
(`python -m netscan analyze <folder> --unmatched`), în `unmatched_services.csv`.
"""

from __future__ import annotations

import csv
import ipaddress
import os
from collections.abc import Iterable
from pathlib import Path

from netscan.engine.common import STATUS_ERROR
from netscan.engine.rules import SMB_SERVICES
from netscan.model import Scan

UNMATCHED_HEADER = ["file", "ip", "port", "proto", "service"]
UNMATCHED_FILENAME = "unmatched_services.csv"

_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _safe_cell(text: str) -> str:
    """Numele serviciului vine din fișier (text nesigur): neutralizăm formulele Excel."""
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def find_unmatched(scans: Iterable[Scan]) -> list[tuple[str, str, int, str, str]]:
    """Rânduri (file, ip, port, proto, service) pentru porturile `open` fără constatare."""
    rows: set[tuple[str, str, int, str, str]] = set()
    for scan in scans:
        if scan.status == STATUS_ERROR:
            continue
        covered = {(f.ip, f.port) for f in scan.findings if f.port is not None}
        for host in scan.hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                service = (port.service or "").strip()
                if service.lower() in SMB_SERVICES:
                    # SMB pe portul „nealeas" (139 când 445 e deschis) e acoperit de SMB_EXPOSED
                    continue
                if (host.ip, port.port) in covered:
                    continue
                rows.add((scan.file, host.ip, port.port, port.proto, service))
    return sorted(
        rows, key=lambda r: (r[0], int(ipaddress.IPv4Address(r[1])), r[2], r[3], r[4])
    )


def write_unmatched_csv(
    scans: list[Scan], out_dir: str | os.PathLike[str]
) -> tuple[Path, int]:
    """Scrie unmatched_services.csv în `out_dir`. Întoarce (cale, număr de rânduri)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / UNMATCHED_FILENAME
    rows = find_unmatched(scans)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\r\n")
        writer.writerow(UNMATCHED_HEADER)
        for file, ip, port, proto, service in rows:
            writer.writerow([_safe_cell(file), ip, port, proto, _safe_cell(service)])
    return path, len(rows)
