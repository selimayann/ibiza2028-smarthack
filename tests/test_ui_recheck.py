"""Bucla „Am reparat → Verifică din nou → dovada”: bifare, fișier nou, înainte/după (V6a→V6b și lab)."""
import html
import io
import re
from pathlib import Path

import pytest

from netscan.engine import analyze_file
from netscan.ui import i18n, storage
from netscan.ui.view import Proof, proof_of
from tests.test_ui_app import make_client

ROOT = Path(__file__).parent.parent
V6A, V6B = ROOT / "fixtures/validation/V6a_before.xml", ROOT / "fixtures/validation/V6b_after.xml"
LAB = ROOT / "fixtures/lab"


def load(*paths):
    return [analyze_file(p) for p in paths]


def lab_scans():
    return load(LAB / "scan_01_before.xml", LAB / "scan_02.xml", LAB / "scan_03_after.xml")


def ref(scan):
    """Scanarea din formular, după fișier (+ data), nu după poziția în listă."""
    return {"file": scan.file, "started_at": scan.started_at}


def fref(scan):
    """Referința „după” a unei scanări din folder, ca în pagina (fișier + dată)."""
    return f"f:{scan.file}|{scan.started_at}"


def tick(client, app, scan, index=0):
    """Bifează primul pas („Am făcut asta”). În teste verificarea live spune „nu e rețeaua mea”: pasul rămâne doar bifat."""
    f = scan.findings[index]
    return client.post("/action/done", data={"token": app.config["FORM_TOKEN"], **ref(scan), "device_id": f.device_id,
                                            "port": "" if f.port is None else f.port, "code": f.code})


def upload(client, app, data, name="scan_noua.xml", scan=None, **extra):
    form = {"token": app.config["FORM_TOKEN"], **ref(scan or load(V6A)[0]), "scanfile": (io.BytesIO(data), name),
            **extra}
    return client.post("/scan/upload", data=form, content_type="multipart/form-data")


def text(page: str, css: str) -> str:
    m = re.search(rf'<p class="{css}">(.*?)</p>', page, re.S)
    assert m, f"lipsește .{css}"
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))).split())


def ids(resp):
    m = re.search(r"/scan/(\d+)\?vs=(\d+)", resp.headers["Location"])
    assert m, resp.headers.get("Location")
    return int(m.group(1)), int(m.group(2))


# ---------- datele: V6a → V6b și lab ----------

def test_proof_v6a_to_v6b_is_60_to_100_with_3_resolved():
    before, after = load(V6A, V6B)
    p = proof_of(before, after, storage.diff(before, after))
    assert (p.score_before, p.score_after, p.closed, len(p.remaining), len(p.new)) == (60, 100, 3, 0, 0)
    assert {f.code for f in p.resolved} == {"TELNET_OPEN", "HTTP_ADMIN_CLEARTEXT", "UPNP_EXPOSED"}
    assert p.direction == "up"


def test_proof_lab_before_to_after_is_0_to_30():
    s1, _, s3 = lab_scans()
    p = proof_of(s1, s3, storage.diff(s1, s3))
    assert (p.score_before, p.score_after) == (0, 30)
    assert {f.code for f in p.resolved} == {"DB_EXPOSED", "TELNET_OPEN"} and p.closed == 2
    assert len(p.remaining) == 8 and not p.new


def test_proof_scores_come_from_the_engine_not_from_the_ui():
    before, after = load(V6A, V6B)
    p = proof_of(before, after, storage.diff(before, after))
    assert (p.score_before, p.score_after) == (before.score, after.score)


def test_no_proof_when_a_scan_has_no_score():
    ok, broken = load(V6A, ROOT / "fixtures/validation/V7_broken.xml")
    assert broken.status == "error"
    assert proof_of(ok, broken, storage.diff(ok, broken)) is None


# ---------- fraza de sub scor ----------

def _proof(closed, before=60, after=100, new=0):
    f = lambda: None  # noqa: E731
    return Proof(before=None, after=None, score_before=before, score_after=after,
                 resolved=[f] * closed, new=[f] * new)


@pytest.mark.parametrize("closed, before, after, new, ro, en", [
    (3, 60, 100, 0, "Ai închis 3 uși. Scorul a urcat de la 60 la 100.", "You closed 3 doors. The score went up from 60 to 100."),
    (1, 0, 10, 0, "Ai închis o ușă. Scorul a urcat de la 0 la 10.", "You closed 1 door. The score went up from 0 to 10."),
    (0, 40, 40, 0, "Nicio ușă închisă încă. Scorul a rămas 40.", "No doors closed yet. The score stayed at 40."),
    (25, 0, 100, 0, "Ai închis 25 de uși. Scorul a urcat de la 0 la 100.", "You closed 25 doors. The score went up from 0 to 100."),
    (1, 80, 70, 2, "Ai închis o ușă. Scorul a coborât de la 80 la 70. Au apărut și 2 probleme noi.",
     "You closed 1 door. The score went down from 80 to 70. 2 new problems also appeared."),
    (0, 50, 40, 1, "Nicio ușă închisă încă. Scorul a coborât de la 50 la 40. A apărut și o problemă nouă.",
     "No doors closed yet. The score went down from 50 to 40. One new problem also appeared."),
])
def test_proof_sentence(closed, before, after, new, ro, en):
    p = _proof(closed, before, after, new)
    assert i18n.proof_sentence("ro", p) == ro and i18n.proof_sentence("en", p) == en


# ---------- după bifare: „Verifică din nou” ----------

def test_recheck_panel_appears_only_after_a_step_is_ticked(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    assert "Verifică din nou" not in client.get("/").get_data(as_text=True)
    assert tick(client, app, scans[0]).status_code == 302
    page = client.get("/").get_data(as_text=True)
    assert "Ai reparat ceva? Verifică din nou." in page
    assert 'type="file"' in page and 'action="/scan/upload"' in page
    assert "python -m netscan scan --confirm" in page          # cum faci o scanare nouă
    assert "Am găsit deja o scanare mai nouă" not in page      # nu există încă una


def test_recheck_panel_in_english(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    page = client.get("/?lang=en").get_data(as_text=True)
    assert "Fixed something? Check again." in page and "New scan file (.xml)" in page and "How do I run a new scan?" in page


def test_recheck_offers_the_newer_scan_that_already_exists(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    page = client.get("/").get_data(as_text=True)
    assert "Am găsit deja o scanare mai nouă: V6b_after.xml." in page
    assert "Vezi înainte și după" in page


def test_compare_shows_proof_v6a_to_v6b(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    resp = client.post("/compare", data={"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[1])})
    assert resp.status_code == 302
    after_id, before_id = ids(resp)
    assert [s.file for s in storage.list_scans(app.config["DB_PATH"])] == ["V6a_before.xml", "V6b_after.xml"]
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert text(page, "proof-line") == "Ai închis 3 uși. Scorul a urcat de la 60 la 100."
    nums = re.findall(r'<span class="proof-num mono">(\d+)</span>', page)
    assert nums == ["60", "100"]
    card = re.search(r'<section class="proof .*?</section>', page, re.S).group(0)   # doar cardul „Dovada”
    assert "Reparat și dovedit (3)" in card and "Încă acolo (0)" in card and "Probleme noi" not in card
    for code in ("TELNET_OPEN", "UPNP_EXPOSED", "HTTP_ADMIN_CLEARTEXT"):   # numele simple, pe limba paginii
        assert html.escape(i18n.code_name("ro", code), quote=True) in page
    assert "V6a_before.xml" in page and "V6b_after.xml" in page


def test_compare_shows_proof_for_the_lab_scans_0_to_30(tmp_path):
    scans = lab_scans()
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    # cea mai nouă scanare din folder: scan_03_after (index 2), nu scan_02
    assert "scan_03_after.xml" in client.get("/").get_data(as_text=True)
    resp = client.post("/compare", data={"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[2])})
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert re.findall(r'<span class="proof-num mono">(\d+)</span>', page) == ["0", "30"]
    assert text(page, "proof-line") == "Ai închis 2 uși. Scorul a urcat de la 0 la 30."
    assert "Reparat și dovedit (2)" in page and "Încă acolo (8)" in page
    assert all(html.escape(i18n.code_name("ro", c), quote=True) in page for c in ("DB_EXPOSED", "TELNET_OPEN"))


def test_proof_in_english(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    loc = client.post("/compare", data={"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[1])}).headers["Location"]
    page = client.get(loc.split("#")[0] + "&lang=en").get_data(as_text=True)   # fără fragmentul #proof-h
    assert text(page, "proof-line") == "You closed 3 doors. The score went up from 60 to 100."
    assert "Fixed and proven (3)" in page and "Still there (0)" in page and "Proof: before and after" in page


def test_compare_refuses_bad_requests(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    ok = {"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[1])}
    assert client.post("/compare", data={**ok, "token": "gresit"}).status_code == 400
    assert client.post("/compare", data=ok, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    for bad in ("", "f1", "f99", "h99", "x1", "f-1", "f1; DROP TABLE scans", "../../etc/passwd", "f:nu-exista.xml",
                "f:V6b_after.xml|1"):
        assert client.post("/compare", data={**ok, "after": bad}).status_code == 400, bad
    assert storage.list_scans(app.config["DB_PATH"]) == []     # nimic salvat din cereri greșite


# ---------- fișier nou încărcat ----------

def test_upload_new_file_shows_proof_and_saves_both_scans(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    resp = upload(client, app, V6B.read_bytes(), "dupa_reparatii.xml")
    assert resp.status_code == 302
    after_id, before_id = ids(resp)
    saved = {s.id: s for s in storage.list_scans(app.config["DB_PATH"])}
    assert saved[before_id].file == "V6a_before.xml" and saved[after_id].file == "dupa_reparatii.xml"
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert re.findall(r'<span class="proof-num mono">(\d+)</span>', page) == ["60", "100"]
    assert text(page, "proof-line") == "Ai închis 3 uși. Scorul a urcat de la 60 la 100."


def test_uploading_the_same_new_file_twice_does_not_duplicate_history(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    upload(client, app, V6B.read_bytes(), "x.xml")
    upload(client, app, V6B.read_bytes(), "x.xml")
    assert len(storage.list_scans(app.config["DB_PATH"])) == 2


def test_upload_larger_than_the_normal_limit_still_works(tmp_path):
    big = V6B.read_bytes() + b"<!--" + b"x" * (2 * 1024 * 1024) + b"-->"      # XML valid, peste 1 MB
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    assert "/scan/" in upload(client, app, big, "mare.xml").headers["Location"]
    # limita de 1 MB rămâne pentru toate celelalte formulare
    resp = client.post("/history/save", data={"token": "x" * (2 * 1024 * 1024), "scan": 0})
    assert resp.status_code == 413


def test_upload_file_name_is_sanitised(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    resp = upload(client, app, V6B.read_bytes(), "../../<script>evil.xml")
    after_id, _ = ids(resp)
    name = storage.get_scan(after_id, app.config["DB_PATH"]).file
    assert "/" not in name and "<" not in name and name.endswith(".xml")
    assert not (tmp_path.parent / "evil.xml").exists()


@pytest.mark.parametrize("data, code, message", [
    (b"", "EMPTY", "Fișierul e gol."),
    (b"<nmaprun start=", "TRUNCATED", "pare incomplet"),
    (b"asta nu e xml", "INVALID_XML", "nu e un XML valid"),
    (b"<html><body>salut</body></html>", "NOT_NMAP", "nu pare a fi o scanare nmap"),
    (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>', "XML_FORBIDDEN", "periculoase"),
])
def test_bad_upload_shows_a_friendly_message_and_saves_nothing(tmp_path, data, code, message):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    resp = upload(client, app, data)
    assert resp.status_code == 302 and f"upload_error={code}" in resp.headers["Location"]
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "Nu am putut folosi fișierul ales." in page and message in page
    assert "Traceback" not in page
    assert storage.list_scans(app.config["DB_PATH"]) == []


def test_older_file_is_refused(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    # un fișier cu data de pornire mai veche decât scanarea de comparat nu poate fi „după reparații”
    older = V6A.read_bytes().replace(b'start="1793607841"', b'start="1700000000"')
    assert b'start="1700000000"' in older
    resp = upload(client, app, older, "veche.xml")
    assert "upload_error=OLDER" in resp.headers["Location"]
    assert "mai vechi decât scanarea" in client.get(resp.headers["Location"]).get_data(as_text=True)
    assert storage.list_scans(app.config["DB_PATH"]) == []


def test_upload_error_in_english(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    page = client.get("/?upload_error=TRUNCATED&lang=en").get_data(as_text=True)
    assert "I couldn&#39;t use the file you chose." in page and "incomplete" in page


def test_unknown_upload_error_code_is_not_echoed(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    page = client.get("/?upload_error=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "Nu am putut folosi" not in page


def test_upload_refuses_bad_token_and_cross_site(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    assert upload(client, app, V6B.read_bytes(), token="gresit").status_code == 400
    assert storage.list_scans(app.config["DB_PATH"]) == []
    cross = client.post("/scan/upload", headers={"Sec-Fetch-Site": "cross-site"},
                        data={"token": app.config["FORM_TOKEN"], **ref(scans[0]),
                              "scanfile": (io.BytesIO(V6B.read_bytes()), "x.xml")}, content_type="multipart/form-data")
    assert cross.status_code == 403


# ---------- istoric: dovada apare și fără „Verifică din nou” ----------

def test_history_page_shows_proof_against_previous_and_against_a_chosen_scan(tmp_path):
    scans = lab_scans()
    client, app = make_client(tmp_path, scans)
    db = app.config["DB_PATH"]
    id1, id2, id3 = (storage.save_scan(s, db) for s in scans)
    nums = lambda url: re.findall(r'<span class="proof-num mono">(\d+)</span>',  # noqa: E731
                                  client.get(url).get_data(as_text=True))
    assert nums(f"/scan/{id3}") == ["0", "30"]                   # față de anterioara (scan_02, la fel ca scan_01)
    assert nums(f"/scan/{id3}?vs={id1}") == ["0", "30"]          # față de una aleasă
    assert nums(f"/scan/{id2}") == ["0", "0"]                    # două scanări la fel: nimic de arătat în plus
    page = client.get(f"/scan/{id2}").get_data(as_text=True)
    assert text(page, "proof-line") == "Nicio ușă închisă încă. Scorul a rămas 0."
    for bad in ("abc", "99999", str(id3), "-1"):                 # ?vs nevalid: revine la anterioara, fără eroare
        assert client.get(f"/scan/{id3}?vs={bad}").status_code == 200


def test_first_scan_in_history_has_no_proof(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    sid = storage.save_scan(scans[0], app.config["DB_PATH"])
    assert 'id="proof"' not in client.get(f"/scan/{sid}").get_data(as_text=True)


def test_proof_comes_before_the_summary_sentence(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])
    loc = client.post("/compare", data={"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[1])}).headers["Location"]
    page = client.get(loc).get_data(as_text=True)
    assert page.index('id="proof"') < page.index('id="summary"')
    assert "Nu am găsit probleme. Rețeaua ta arată bine." in page   # după reparații: V6b nu mai are nicio problemă


def test_names_given_by_the_user_show_in_the_proof(tmp_path):
    scans = load(V6A, V6B)
    client, app = make_client(tmp_path, scans)
    storage.set_device_name(scans[0].findings[0].device_id, "Routerul din hol", app.config["DB_PATH"])
    tick(client, app, scans[0])
    loc = client.post("/compare", data={"token": app.config["FORM_TOKEN"], **ref(scans[0]), "after": fref(scans[1])}).headers["Location"]
    assert "Routerul din hol" in client.get(loc).get_data(as_text=True)


def test_upload_without_choosing_a_file_says_so(tmp_path):
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    resp = client.post("/scan/upload", data={"token": app.config["FORM_TOKEN"], **ref(scans[0])},
                       content_type="multipart/form-data")
    assert resp.status_code == 302 and "upload_error=NO_FILE" in resp.headers["Location"]


def test_upload_over_the_request_limit_gets_the_friendly_message(tmp_path):
    """Peste 20 MB + câmpuri, serverul oprește cererea înainte de formular (413): tot mesajul obișnuit, nu pagina brută."""
    scans = load(V6A)
    client, app = make_client(tmp_path, scans)
    tick(client, app, scans[0])          # „Verifică din nou” apare după ce bifezi un pas
    huge = V6B.read_bytes() + b"<!--" + b"x" * (22 * 1024 * 1024) + b"-->"
    resp = upload(client, app, huge, "uriasa.xml")
    assert resp.status_code == 302 and "upload_error=TOO_LARGE" in resp.headers["Location"]
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "Nu am putut folosi fișierul ales." in page and "prea mare" in page
    assert storage.list_scans(app.config["DB_PATH"]) == []
