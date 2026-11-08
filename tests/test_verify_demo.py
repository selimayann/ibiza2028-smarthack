"""Demo-ul cerut de mentor: 2 probleme ușor de verificat (Redis 6379, Mosquitto 1883), pe fișierul de test
fixtures/verify/verify_two_easy.xml. Arată exact ce se întâmplă la demo, fără să atingă rețeaua."""
from pathlib import Path

from netscan.engine import analyze_file
from netscan.engine.scoring import compute_score
from netscan.ui import verify
from netscan.ui.app import own_newest_scan

FILE = Path(__file__).parent.parent / "fixtures" / "verify" / "verify_two_easy.xml"


def _scan():
    s = analyze_file(FILE)
    assert s.status == "ok"
    return s


def test_the_file_has_exactly_the_two_easy_problems_plus_two_unverifiable():
    s = _scan()
    assert {(f.code, f.port) for f in s.findings} == {
        ("DB_EXPOSED", 6379), ("MQTT_EXPOSED", 1883), ("UNKNOWN_DEVICE", None), ("SSH_OPEN", 22)}
    assert s.score == 65


def test_stopping_the_two_services_confirms_both_and_the_engine_rescores():
    s = _scan()
    closed = lambda ip, port: "closed"                      # containerul oprit: portul refuză conexiunea
    fixed = set()
    for code in ("DB_EXPOSED", "MQTT_EXPOSED"):
        f = next(x for x in s.findings if x.code == code)
        assert verify.check_finding(s, f, closed, lambda ip: True).verified
        fixed.add(f.key())
    assert compute_score(f for f in s.findings if f.key() not in fixed) == 95


def test_still_running_service_is_not_confirmed():
    s = _scan()
    f = next(x for x in s.findings if x.code == "DB_EXPOSED")
    assert verify.check_finding(s, f, lambda ip, port: "open", lambda ip: True).result == verify.STILL_OPEN


def test_the_other_two_cannot_be_checked_by_a_port():
    s = _scan()
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    unk = next(x for x in s.findings if x.code == "UNKNOWN_DEVICE")
    assert verify.check_finding(s, unk, never, lambda ip: True).result == verify.NO_PORT


def test_a_hand_made_file_is_never_probed_live():
    # Fișierul de test nu e o scanare a noastră din scans/: aplicația nu bate la ușa nimănui pe baza lui.
    s = _scan()
    assert own_newest_scan(s) is False
    f = next(x for x in s.findings if x.code == "DB_EXPOSED")
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    assert verify.check_finding(s, f, never, lambda ip: True, probe_allowed=False).result == verify.FILE_ONLY
