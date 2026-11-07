"""Testele pe Validation Set.

Două variante, aceleași așteptări (tests/expected.py):
1. fișierele SINTETICE construite în tests/nmapxml.py (rulează mereu);
2. fișierele OFICIALE din fixtures/validation/ (se sar dacă lipsesc).

Comparăm MULȚIMI de rânduri: orice rând în plus sau în minus pică testul.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import nmapxml
from tests.expected import EXPECTED_ROWS, EXPECTED_SCORES
from tests.helpers import run_folder

REAL_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "validation"
FINDINGS_HEADER = ("file", "ip", "port", "finding_code", "severity")


def _check(folder: Path, tmp_path: Path) -> None:
    rows, scores = run_folder(folder, tmp_path / "out")
    assert rows[0] == FINDINGS_HEADER
    data = rows[1:]
    assert len(data) == len(set(data)), "rânduri duplicate în findings.csv"
    actual = set(data)
    assert actual - EXPECTED_ROWS == set(), "rânduri ÎN PLUS față de brief"
    assert EXPECTED_ROWS - actual == set(), "rânduri LIPSĂ față de brief"
    assert len(data) == 24
    assert scores == EXPECTED_SCORES


def test_synthetic_validation_set(tmp_path):
    folder = tmp_path / "synthetic"
    folder.mkdir()
    for name, build in nmapxml.SYNTHETIC_VALIDATION.items():
        (folder / name).write_text(build(), encoding="utf-8")
    _check(folder, tmp_path)


def _real_files_present() -> bool:
    return REAL_DIR.is_dir() and any(REAL_DIR.glob("*.xml"))


@pytest.mark.skipif(
    not _real_files_present(),
    reason="Validation Set-ul oficial nu e încă în fixtures/validation/",
)
def test_official_validation_set(tmp_path):
    _check(REAL_DIR, tmp_path)


@pytest.mark.skipif(
    not (REAL_DIR / "expected_findings.csv").exists()
    or not (REAL_DIR / "expected_scores.csv").exists(),
    reason="expected_findings.csv / expected_scores.csv oficiale nu sunt în fixtures/validation/",
)
def test_output_is_byte_identical_to_official_expected_csv(tmp_path):
    """Cea mai strictă verificare: fișierele noastre = fișierele oficiale, octet cu octet."""
    run_folder(REAL_DIR, tmp_path / "out")
    assert (tmp_path / "out" / "findings.csv").read_bytes() == (REAL_DIR / "expected_findings.csv").read_bytes()
    assert (tmp_path / "out" / "scores.csv").read_bytes() == (REAL_DIR / "expected_scores.csv").read_bytes()


def test_results_do_not_depend_on_file_names(tmp_path):
    """Fără cazuri speciale pe nume de fișiere: același conținut, alt nume, același rezultat."""
    folder = tmp_path / "renamed"
    folder.mkdir()
    (folder / "zzz_alt_nume_1.xml").write_text(nmapxml.v4_legacy(), encoding="utf-8")
    (folder / "aaa_alt_nume_2.xml").write_text(nmapxml.v5_nonstandard_ports(), encoding="utf-8")
    rows, scores = run_folder(folder, tmp_path / "out")
    assert scores == {"aaa_alt_nume_2.xml": "50", "zzz_alt_nume_1.xml": "25"}
    assert len(rows) - 1 == 3 + 6
