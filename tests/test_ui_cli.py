"""RBRT: comenzile diff și delete-history din CLI."""
from pathlib import Path

from netscan.cli import main
from netscan.ui import storage

VAL = Path(__file__).parent.parent / "fixtures" / "validation"


def test_diff_v6a_v6b(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_DB_PATH", str(tmp_path / "h.db"))
    assert main(["diff", str(VAL / "V6a_before.xml"), str(VAL / "V6b_after.xml"), "--save"]) == 0
    out = capsys.readouterr().out
    assert "Scor standard: 60 → 100" in out
    assert "Probleme rezolvate (3)" in out and "Probleme noi (0)" in out
    assert len(storage.list_scans()) == 2


def test_diff_broken_file(capsys):
    assert main(["diff", str(VAL / "V6a_before.xml"), str(VAL / "V7_broken.xml")]) == 2
    assert "pare incomplet" in capsys.readouterr().err


def test_diff_missing_file(capsys):
    assert main(["diff", "nu-exista.xml", str(VAL / "V6b_after.xml")]) == 2


def test_delete_history_asks_first(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NETSCAN_DB_PATH", str(tmp_path / "h.db"))
    main(["diff", str(VAL / "V6a_before.xml"), str(VAL / "V6b_after.xml"), "--save"])
    monkeypatch.setattr("builtins.input", lambda _: "nu")
    assert main(["delete-history"]) == 1
    assert len(storage.list_scans()) == 2
    monkeypatch.setattr("builtins.input", lambda _: "da")
    assert main(["delete-history"]) == 0
    assert storage.list_scans() == []
