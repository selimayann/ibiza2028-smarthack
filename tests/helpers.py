"""Funcții comune pentru teste."""

from __future__ import annotations

import csv
from pathlib import Path

from netscan.engine import analyze_folder, write_results


def run_folder(folder: Path, out: Path):
    """Rulează exact fluxul comenzii `analyze`; întoarce (rânduri findings, scoruri)."""
    scans = analyze_folder(folder)
    findings_path, scores_path = write_results(scans, out)
    with open(findings_path, newline="", encoding="utf-8") as handle:
        rows = [tuple(r) for r in csv.reader(handle)]
    with open(scores_path, newline="", encoding="utf-8") as handle:
        scores = {r[0]: r[1] for r in list(csv.reader(handle))[1:]}
    return rows, scores
