"""B: textele de ajutor ale comenzilor spun exact ce face fiecare (fără rețea: doar parserul)."""
from netscan import cli


def _helps():
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    return {c.dest: c.help for c in sub._choices_actions}


def test_trap_help_says_it_only_records_who_tried_and_reads_nothing():
    text = _helps()["trap"]
    assert "Telnet fals" not in text and "nu citește nimic" in text and "IP, oră, port" in text
    assert "nu citește nimic" in cli.cmd_trap.__doc__ and "Telnet fals" not in cli.cmd_trap.__doc__


def test_scan_help_names_the_full_scan_and_the_hotspot():
    text = _helps()["scan"]
    assert "scanare live" not in text and "nmap" in text and "hotspot" in text


def test_no_help_mentions_dashboard():
    assert all("dashboard" not in (h or "").lower() for h in _helps().values())


def test_analyze_accepts_a_single_file_for_the_live_rerun(tmp_path):
    """Verificarea live „re-run”: juriul alege UN fișier; analyze îl primește direct, cu aceleași CSV-uri."""
    from pathlib import Path
    v = Path(__file__).resolve().parent.parent / "fixtures" / "validation"
    assert cli.main(["analyze", str(v / "V4_legacy.xml"), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "scores.csv").read_text(encoding="utf-8").splitlines() == ["file,network_score", "V4_legacy.xml,25"]
    assert len((tmp_path / "findings.csv").read_text(encoding="utf-8").splitlines()) == 7
    assert cli.main(["analyze", str(v / "V7_broken.xml"), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "scores.csv").read_text(encoding="utf-8").splitlines()[1] == "V7_broken.xml,ERROR"
