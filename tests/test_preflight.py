"""scripts/preflight.py (Oneata): două rulări identice, rezultatul oficial pe Validation Set, hash-uri."""

from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAL = ROOT / "fixtures" / "validation"

_spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts" / "preflight.py")
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)


def _run(out: Path) -> tuple[int, str]:
    buf = io.StringIO()
    code = preflight.preflight(VAL, out, stream=buf)
    return code, buf.getvalue()


def test_preflight_on_validation_set(tmp_path):
    code, text = _run(tmp_path / "a")
    assert code == 0, text
    out = tmp_path / "a"
    # rezultatul e exact cel oficial (24 de rânduri + antet, scorurile din barem)
    assert (out / "findings.csv").read_bytes() == (VAL / "expected_findings.csv").read_bytes()
    assert (out / "scores.csv").read_bytes() == (VAL / "expected_scores.csv").read_bytes()
    assert len((out / "findings.csv").read_bytes().splitlines()) == 25
    assert "Rânduri în findings.csv: 24" in text and "Fișiere cu ERROR: 1" in text
    assert "V7_broken.xml" in text and "ERROR (TRUNCATED)" in text
    assert "identice byte cu byte" in text
    # raportul D6 e afișat și scris
    assert "Servicii văzute care nu sunt în catalog: 8" in text
    assert (out / "unmatched_services.csv").exists()


def test_hashes_file_matches_and_two_preflights_agree(tmp_path):
    hashes = []
    for name in ("a", "b"):
        assert _run(tmp_path / name)[0] == 0
        lines = (tmp_path / name / "hashes.txt").read_text(encoding="utf-8").splitlines()
        got = dict(reversed(line.split("  ", 1)) for line in lines if not line.startswith("#"))
        for file, digest in got.items():
            assert hashlib.sha256((tmp_path / name / file).read_bytes()).hexdigest() == digest
        hashes.append(got)
    assert hashes[0] == hashes[1] and set(hashes[0]) == {"findings.csv", "scores.csv"}


def test_stops_and_writes_nothing_when_runs_differ(tmp_path, monkeypatch):
    calls = []
    real = preflight.run_analyze

    def flaky(folder, out):
        stdout = real(folder, out)
        calls.append(out)
        if len(calls) == 2:  # a doua rulare dă alt scor: simulăm un motor nedeterminist
            p = out / "scores.csv"
            p.write_bytes(p.read_bytes().replace(b",90", b",91"))
        return stdout

    monkeypatch.setattr(preflight, "run_analyze", flaky)
    code, text = _run(tmp_path / "out")
    assert code == 1 and "NU sunt identice" in text and "scores.csv" in text
    assert not (tmp_path / "out").exists()


def test_bad_folder_is_refused(tmp_path):
    assert preflight.main([str(tmp_path / "nu-exista"), "--out", str(tmp_path / "o")]) == 2
