"""Exportul standard (FR-15): findings.csv și scores.csv.

Format exact din brief:
    findings.csv   file,ip,port,finding_code,severity   (port gol la UNKNOWN_DEVICE)
    scores.csv     file,network_score                   (ERROR pentru fișiere ilizibile)

Octeții scriși sunt aceiași pe orice sistem de operare (UTF-8 fără BOM, sfârșit
de linie "\\r\\n", exact ca fișierele oficiale expected_*.csv ale organizatorilor),
ca să fie respectat NFR-05 (determinism).
"""

from __future__ import annotations

import csv
import os
from collections.abc import Iterable
from pathlib import Path

from netscan.engine.rules import finding_sort_key
from netscan.engine.common import STATUS_ERROR
from netscan.model import Scan

FINDINGS_HEADER = ["file", "ip", "port", "finding_code", "severity"]
SCORES_HEADER = ["file", "network_score"]


def _writer(handle):
    return csv.writer(handle, lineterminator="\r\n")


def write_findings_csv(scans: Iterable[Scan], path: str | os.PathLike[str]) -> None:
    findings = [f for s in scans if s.status != STATUS_ERROR for f in s.findings]
    findings.sort(key=finding_sort_key)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = _writer(handle)
        writer.writerow(FINDINGS_HEADER)
        for f in findings:
            writer.writerow(
                [f.file, f.ip, "" if f.port is None else f.port, f.code, f.severity]
            )


def write_scores_csv(scans: Iterable[Scan], path: str | os.PathLike[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = _writer(handle)
        writer.writerow(SCORES_HEADER)
        for s in scans:
            if s.status == STATUS_ERROR or s.score is None:
                writer.writerow([s.file, "ERROR"])
            else:
                writer.writerow([s.file, s.score])


def write_results(
    scans: list[Scan], out_dir: str | os.PathLike[str]
) -> tuple[Path, Path]:
    """Scrie ambele fișiere în `out_dir` (creat dacă nu există)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings_path = out / "findings.csv"
    scores_path = out / "scores.csv"
    write_findings_csv(scans, findings_path)
    write_scores_csv(scans, scores_path)
    return findings_path, scores_path
