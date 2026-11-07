"""fixtures/traps/: fișiere mici de capcană, cu rezultat așteptat dedus din catalog.

Rulează exact fluxul comenzii `analyze` pe tot folderul. Un fișier nou în folder fără
rezultat așteptat în tests/expected_traps.py face testul să pice (nu rămân capcane neverificate).
"""

from __future__ import annotations

from pathlib import Path

from netscan.engine import analyze_folder
from tests import expected_traps as exp
from tests.helpers import run_folder

TRAPS = Path(__file__).resolve().parent.parent / "fixtures" / "traps"


def test_every_trap_file_has_an_expected_result():
    names = sorted(p.name for p in TRAPS.glob("*.xml"))
    assert names == sorted(exp.SCORES)


def test_trap_findings_match_hand_derived_expectation(tmp_path):
    rows, _ = run_folder(TRAPS, tmp_path)
    assert rows[0] == ("file", "ip", "port", "finding_code", "severity")
    assert rows[1:] == [tuple(r) for r in exp.FINDINGS]


def test_trap_scores_match_hand_derived_expectation(tmp_path):
    _, scores = run_folder(TRAPS, tmp_path)
    assert scores == exp.SCORES


def test_error_files_have_the_right_error_code_and_do_not_stop_the_folder():
    scans = {s.file: s for s in analyze_folder(TRAPS)}
    for name, code in exp.ERROR_CODES.items():
        assert scans[name].status == "error" and scans[name].error_code == code, name
        assert scans[name].score is None and scans[name].findings == []
    # fișierele bune de după cele stricate (ordine alfabetică) au fost analizate
    assert scans["T14_closed_and_filtered.xml"].status == "ok"
