"""Propoziția-rezumat din capul paginii principale: cazurile, singular/plural, RO/EN, text nesigur."""
import html
import re
from dataclasses import replace

import pytest

from netscan.model import Finding, Host, Scan
from netscan.ui import i18n
from netscan.ui.view import Summary, most_dangerous, summary_of
from tests.test_ui_app import XSS, make_client, sample


def text_of(page: str) -> str:
    """Textul frazei de sus, ca pe ecran (fără HTML)."""
    m = re.search(r'<p class="summary-text">(.*?)</p>', page, re.S)
    assert m, "fraza-rezumat lipsește din pagină"
    return html.unescape(m.group(1)).strip()


def finding(ip, port, code, sev, pts, dev=None):
    return Finding(file="x.xml", ip=ip, device_id=dev or ip, port=port, code=code, severity=sev, points=pts,
                   evidence="e")


def scan_with(*findings, hosts=None):
    hosts = hosts if hosts is not None else [Host(ip="10.0.0.5", device_id="10.0.0.5", device_type="camera")]
    return Scan(file="x.xml", status="ok", started_at=1, score=100 - sum(f.points for f in findings),
                hosts=hosts, findings=list(findings))


# ---------- cazurile cerute ----------

def test_problems_sentence_names_first_device_and_first_step(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    s = text_of(client.get("/").get_data(as_text=True))
    # sample: 1 problemă „high” (camera), 4 „medium”; primul dispozitiv: camera (30 de puncte)
    assert s.startswith("Începe cu Cameră: ")
    assert "Schimbă parola din fabrică a camerei cu una lungă și unică." in s


def test_sentence_in_english(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    s = text_of(client.get("/?lang=en").get_data(as_text=True))
    assert s.startswith("Start with Camera: ")
    assert "Change the camera's factory password to a long, unique one." in s


def test_no_problems(tmp_path):
    clean = scan_with()
    client, _ = make_client(tmp_path, [clean])
    assert text_of(client.get("/").get_data(as_text=True)) == "Nu am găsit probleme. Rețeaua ta arată bine."
    assert text_of(client.get("/?lang=en").get_data(as_text=True)) == (
        "I didn't find any problems. Your network looks good.")


def test_only_ssh_open_is_not_a_problem(tmp_path):
    only_ssh = scan_with(finding("10.0.0.5", 22, "SSH_OPEN", "info", 0))
    client, _ = make_client(tmp_path, [only_ssh])
    s = text_of(client.get("/").get_data(as_text=True))
    assert s.startswith("Nu am găsit probleme. Rețeaua ta arată bine.")
    assert "(SSH)" in s and "nu scade scorul" in s   # numele simplu al lui SSH_OPEN
    assert "Începe cu" not in s and "probleme grave" not in s


def test_error_scan(tmp_path):
    broken = Scan(file="x.xml", status="error", error_code="TRUNCATED")
    client, _ = make_client(tmp_path, [broken])
    page = client.get("/").get_data(as_text=True)
    assert text_of(page) == ("Nu pot spune nimic despre rețea din acest fișier. "
                             "Fișierul nu poate fi citit: pare incomplet.")
    assert "Traceback" not in page


def test_all_problems_verified_fixed_is_not_reported_as_clean():
    s = scan_with(finding("10.0.0.5", 23, "TELNET_OPEN", "high", 20))
    fixed = replace(s, findings=[])   # așa arată scanarea după ce toate problemele au fost verificate
    summary = summary_of(fixed, None, all_fixed=True)
    assert summary.kind == "fixed"
    assert i18n.summary_sentence("ro", summary) == "Ai rezolvat toate problemele pe care le-am găsit. Bravo!"
    assert i18n.summary_sentence("en", summary) == "You fixed all the problems I found. Well done!"


def test_history_page_has_the_same_sentence(tmp_path):
    from netscan.ui import storage

    client, app = make_client(tmp_path, [sample()])
    scan_id = storage.save_scan(sample(), app.config["DB_PATH"])
    s = text_of(client.get(f"/scan/{scan_id}").get_data(as_text=True))
    assert s.startswith("Începe cu Cameră: ")


# ---------- fraza și cardul de dedesubt spun același lucru ----------

def test_sentence_device_is_the_card_device(tmp_path):
    s = scan_with(
        finding("10.0.0.5", 23, "TELNET_OPEN", "high", 20),
        finding("10.0.0.9", 80, "HTTP_ADMIN_CLEARTEXT", "medium", 10),
        finding("10.0.0.9", 1883, "MQTT_EXPOSED", "medium", 10),
        finding("10.0.0.9", 21, "FTP_CLEARTEXT", "medium", 10),
        hosts=[Host(ip="10.0.0.5", device_id="10.0.0.5", device_type="router"),
               Host(ip="10.0.0.9", device_id="10.0.0.9", device_type="iot")])
    worst = most_dangerous(s)
    assert worst.host.ip == "10.0.0.9"   # 30 de puncte bat 20, chiar dacă primul e „high”
    client, _ = make_client(tmp_path, [s])
    sentence = text_of(client.get("/").get_data(as_text=True))
    assert sentence.startswith("Începe cu Dispozitiv inteligent (IoT): ")


# ---------- singular / plural ----------

@pytest.mark.parametrize("serious, minor, ro", [
    (1, 0, "Rețeaua ta are o problemă gravă."),
    (2, 0, "Rețeaua ta are 2 probleme grave."),
    (19, 0, "Rețeaua ta are 19 probleme grave."),
    (20, 0, "Rețeaua ta are 20 de probleme grave."),
    (0, 1, "Rețeaua ta are o problemă mai mică."),
    (0, 3, "Rețeaua ta are 3 probleme mai mici."),
    (0, 21, "Rețeaua ta are 21 de probleme mai mici."),
    (2, 1, "Rețeaua ta are 2 probleme grave și una mai mică."),
    (2, 3, "Rețeaua ta are 2 probleme grave și 3 mai mici."),
])
def test_plural_forms_ro(serious, minor, ro):
    assert i18n.summary_sentence("ro", Summary("problems", serious=serious, minor=minor)) == ro


@pytest.mark.parametrize("serious, minor, en", [
    (1, 0, "Your network has 1 serious problem."),
    (2, 0, "Your network has 2 serious problems."),
    (0, 1, "Your network has 1 smaller problem."),
    (0, 3, "Your network has 3 smaller problems."),
    (1, 1, "Your network has 1 serious problem and 1 smaller one."),
    (2, 3, "Your network has 2 serious problems and 3 smaller ones."),
])
def test_plural_forms_en(serious, minor, en):
    assert i18n.summary_sentence("en", Summary("problems", serious=serious, minor=minor)) == en


def test_step_without_final_punctuation_gets_a_full_stop():
    s = i18n.summary_sentence("ro", Summary("problems", serious=1), "Router", "Oprește Telnet")
    assert s == "Rețeaua ta are o problemă gravă. Începe cu Router: Oprește Telnet."


# ---------- text nesigur ----------

def test_untrusted_device_name_is_escaped_in_the_sentence(tmp_path):
    # numele anunțate apar doar lângă cea mai nouă scanare a noastră; numele dat de utilizator e tot text nesigur
    from netscan.ui import storage
    client, app = make_client(tmp_path, [sample()])
    storage.set_device_name("e1f2a3b4c5d6", XSS, app.config["DB_PATH"])   # camera (192.168.1.40)
    page = client.get("/").get_data(as_text=True)
    assert XSS not in page                                   # nicăieri neescapat
    assert text_of(page).startswith(f"Începe cu {XSS}: ")
    assert "&lt;script&gt;" in page


# ---------- ordinea în pagină ----------

def test_sentence_comes_before_any_card(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    page = client.get("/").get_data(as_text=True)
    assert page.index('id="summary"') < page.index('id="score"') < page.index('id="worst"')
