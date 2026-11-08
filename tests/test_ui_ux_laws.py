"""Reparațiile din revizia „Laws of UX”: verdictul nu spune „arată bine” când rămâne o problemă gravă,
cardurile din Verificări sunt mai scurte, butonul de verificare spune ce face cât așteaptă."""
from dataclasses import replace

from netscan.model import Finding, Host, Scan
from netscan.ui import i18n
from netscan.ui.view import verdict_view
from tests.test_ui_app import make_client, sample


def _scan(findings, score):
    return Scan(file="x.xml", status="ok", started_at=1, score=score,
                hosts=[Host(ip="192.168.1.40", device_id="d1")], findings=findings)


def _f(code, sev, port, pts):
    return Finding(file="x.xml", ip="192.168.1.40", device_id="d1", port=port, code=code, severity=sev,
                   points=pts, evidence="e")


def test_good_score_with_a_serious_problem_says_so():
    cam = _f("CAMERA_STREAM_EXPOSED", "high", 554, 20)
    v = verdict_view(_scan([cam], 80))
    assert v["band"] == "good" and v["score"] == 80                     # scorul și banda rămân cele standard
    assert v["verdict_key"] == "verdict_good_high_1"
    assert "problemă gravă" in i18n.t("ro", v["verdict_key"]) and "serious" in i18n.t("en", v["verdict_key"])


def test_other_verdicts_unchanged():
    assert verdict_view(_scan([_f("SSH_OPEN", "info", 22, 0)], 100))["verdict_key"] == "verdict_good"
    assert verdict_view(_scan([], 100))["verdict_key"] == "verdict_clean"
    two_high = [_f("TELNET_OPEN", "high", 23, 20), _f("RDP_EXPOSED", "high", 3389, 20)]
    assert verdict_view(_scan(two_high, 60))["verdict_key"] == "verdict_fair_high"
    poor = verdict_view(sample())
    assert poor["band"] == "poor" and poor["verdict_key"] == "verdict_poor"


def test_every_verdict_key_has_ro_and_en_text():
    for key in ("verdict_good_high", "verdict_good_high_1", "verdict_fair_high", "verdict_fair_high_1"):
        assert i18n.t("ro", key) != key and i18n.t("en", key) != key


def test_verify_button_has_a_busy_label(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    html = client.get("/").get_data(as_text=True)
    assert 'data-busy="Verific… (câteva secunde)"' in html
