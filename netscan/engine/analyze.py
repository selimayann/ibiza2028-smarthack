"""Punctul de intrare al motorului: fișier XML -> Scan complet (hosturi, findings, scor).

`analyze_file` și `analyze_folder` sunt funcțiile folosite de UI (D) și de CLI.
Nu folosesc rețeaua și nu ridică excepții pentru fișiere stricate.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from netscan.engine.parser import parse_file
from netscan.engine.rules import evaluate
from netscan.engine.scoring import compute_score
from netscan.engine.common import STATUS_ERROR, error_scan
from netscan.model import Scan


def analyze_file(path: str | os.PathLike[str]) -> Scan:
    """Analizează un singur fișier nmap XML."""
    name = Path(path).name
    try:
        scan = parse_file(path)
        if scan.status == STATUS_ERROR:
            return scan
        scan.findings = evaluate(scan.file, scan.hosts)
        scan.score = compute_score(scan.findings)
        return scan
    except Exception as exc:  # noqa: BLE001
        # Plasă de siguranță: un bug nu are voie să oprească restul folderului.
        # Logăm doar tipul erorii (niciodată conținutul fișierului).
        print(
            f"EROARE INTERNĂ la {name}: {type(exc).__name__}",
            file=sys.stderr,
        )
        return error_scan(name, "INVALID_XML")


def list_scan_files(folder: str | os.PathLike[str]) -> list[Path]:
    """Fișierele *.xml din folder (fără subfoldere), în ordine alfabetică."""
    base = Path(folder)
    if not base.is_dir():
        raise NotADirectoryError(str(folder))
    return sorted(
        (p for p in base.iterdir() if p.is_file() and p.suffix.lower() == ".xml"),
        key=lambda p: p.name,
    )


def analyze_folder(folder: str | os.PathLike[str]) -> list[Scan]:
    """Analizează toate fișierele *.xml dintr-un folder. Un fișier stricat devine
    Scan cu status="error" și se continuă cu celelalte."""
    return [analyze_file(p) for p in list_scan_files(folder)]
