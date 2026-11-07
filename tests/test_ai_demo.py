"""B: demonstrația validatorului (demo-ai-check). Fără rețea, fără model AI."""
import socket
from pathlib import Path

import pytest

from netscan.cli import main as cli_main
from netscan.engine.parser import analyze_file
from netscan.scan import ai_check
from netscan.scan.ai_demo import build_examples, render

ROOT = Path(__file__).parent.parent
SCANS = [ROOT / "fixtures" / "lab" / "scan_01_before.xml", ROOT / "fixtures" / "lab" / "scan_03_after.xml",
         ROOT / "fixtures" / "validation" / "V2_smart_home.xml", ROOT / "fixtures" / "validation" / "V3_small_office.xml"]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("demo-ul nu are voie să folosească rețeaua")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


@pytest.mark.parametrize("path", SCANS, ids=lambda p: p.name)
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_wrong_examples_rejected_for_the_right_reason_and_good_one_passes(path, lang):
    scan = analyze_file(str(path))
    examples = build_examples(scan, lang)
    assert len(examples) == 4
    for ex in examples[:3]:
        check = ai_check.check_llm_text(ex.text, scan)
        assert not check.ok and set(ex.expected) <= set(check.problems), (ex.text, check.problems)
        assert set(check.problems) == set(ex.expected), "fiecare exemplu are exact greșeala pentru care e făcut"
    assert ai_check.check_llm_text(examples[3].text, scan).ok, examples[3].text


def test_example_types_cover_port_cve_ip_phone():
    kinds = {p.split(":")[0] for ex in build_examples(analyze_file(str(SCANS[0]))) for p in ex.expected}
    assert kinds == {"PORT", "CVE", "IP", "PHONE"}


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_output_fits_projector_and_is_labelled_simulation(lang):
    lines = render(analyze_file(str(SCANS[0])), lang)
    assert len(lines) <= 25 and all(len(l) <= 160 for l in lines)
    assert any("SIMULARE" in l for l in lines) and any("SIMULATION" in l for l in lines)
    text = "\n".join(lines)
    assert text.count("[RESPINS]") == 3 and text.count("[REJECTED]") == 3
    assert text.count("[ACCEPTAT]") == 1 and text.count("[ACCEPTED]") == 1
    assert "portul 3389 nu apare în scanare" in text and "port 3389 is not in the scan" in text


def test_cli_demo(capsys):
    assert cli_main(["demo-ai-check", str(SCANS[0])]) == 0
    out = capsys.readouterr().out
    assert "Demo: validatorul anti-halucinații" in out and "Textul verificat" in out


def test_cli_demo_on_broken_file(capsys):
    assert cli_main(["demo-ai-check", str(ROOT / "fixtures" / "validation" / "V7_broken.xml")]) == 2
    assert "nu a putut fi citit" in capsys.readouterr().out


@pytest.mark.parametrize("problem, ro, en", [
    ("PORT:3389", "portul 3389 nu apare în scanare", "port 3389 is not in the scan"),
    ("IP:10.0.0.1", "IP-ul 10.0.0.1 nu e în scanare", "IP 10.0.0.1 is not in the scan"),
    ("PHONE", "conține un număr de telefon", "it contains a phone number"),
    ("CVE:CVE-2024-1", "CVE-2024-1 nu apare în datele scanării", "CVE-2024-1 is not in the scan data"),
])
def test_explain_problem(problem, ro, en):
    assert ai_check.explain_problem(problem, "ro") == ro and ai_check.explain_problem(problem, "en") == en
