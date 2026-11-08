"""Nume date dispozitivelor: salvare, afișare peste tot, escapare, ștergere, migrare sigură, validare."""
import html
import re
import sqlite3
from types import SimpleNamespace

from netscan.ui import i18n, storage
from tests.test_ui_app import XSS, make_client, sample

CAM = "e1f2a3b4c5d6"          # camera din sample.json: 192.168.1.40
ROUTER = "d1a2b3c4d5e6"
NAME = "Camera din sufragerie"


def save(client, app, name, device_id=CAM, **extra):
    s = sample()   # formularul numește scanarea după fișier (+ dată), nu după poziția în listă
    data = {"token": app.config["FORM_TOKEN"], "file": s.file, "started_at": s.started_at, "name": name, **extra}
    return client.post(f"/device/{device_id}/name", data=data)


def page(client, url):
    return client.get(url).get_data(as_text=True)


# ---------- stocare ----------

def test_save_update_and_read_back(tmp_path):
    db = tmp_path / "h.db"
    assert storage.device_names(db) == {}
    assert storage.set_device_name(CAM, NAME, db) == NAME
    assert storage.set_device_name(ROUTER, "Routerul meu", db) == "Routerul meu"
    assert storage.device_names(db) == {CAM: NAME, ROUTER: "Routerul meu"}
    storage.set_device_name(CAM, "Camera nouă", db)                # un nume nou îl înlocuiește pe cel vechi
    assert storage.device_names(db)[CAM] == "Camera nouă"
    assert len(storage.device_names(db)) == 2


def test_empty_name_removes_it(tmp_path):
    db = tmp_path / "h.db"
    storage.set_device_name(CAM, NAME, db)
    assert storage.set_device_name(CAM, "   ", db) is None
    assert storage.device_names(db) == {}


def test_name_is_cleaned_and_limited(tmp_path):
    db = tmp_path / "h.db"
    assert storage.set_device_name(CAM, "  Camera \x00\x1b  din\n\tsufragerie ", db) == NAME
    assert storage.set_device_name(CAM, "a" * storage.DEVICE_NAME_MAX, db) == "a" * 40   # exact limita: acceptat
    try:
        storage.set_device_name(CAM, "a" * 41, db)
    except ValueError:
        pass
    else:
        raise AssertionError("un nume de 41 de caractere trebuia refuzat")
    assert storage.device_names(db)[CAM] == "a" * 40                # refuzul nu strică ce era salvat


def test_sql_in_a_name_is_just_text(tmp_path):
    db = tmp_path / "h.db"
    storage.save_scan(sample(), db)
    evil = "x'); DROP TABLE scans;--"
    storage.set_device_name(CAM, evil, db)
    assert storage.device_names(db)[CAM] == evil
    assert len(storage.list_scans(db)) == 1                          # tabelul scans e intact


def test_old_database_is_migrated_without_losing_data(tmp_path):
    """O bază creată înainte să existe tabelul device_names: se deschide, își păstrează datele, primește tabelul."""
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, started_at INTEGER,"
        " status TEXT NOT NULL, error_code TEXT, score INTEGER);"
        "INSERT INTO scans (file, started_at, status, score) VALUES ('vechi.xml', 1700000000, 'ok', 60);")
    con.commit()
    con.close()
    assert [s.file for s in storage.list_scans(db)] == ["vechi.xml"]    # datele vechi sunt acolo
    assert storage.device_names(db) == {}                               # tabelul nou a apărut
    storage.set_device_name(CAM, NAME, db)
    assert storage.device_names(db) == {CAM: NAME}
    assert [s.file for s in storage.list_scans(db)] == ["vechi.xml"]
    storage.connect(db).close()                                         # a doua deschidere nu strică nimic
    assert storage.device_names(db) == {CAM: NAME}


def test_delete_history_removes_names_too(tmp_path):
    db = tmp_path / "h.db"
    storage.save_scan(sample(), db)
    storage.set_device_name(CAM, NAME, db)
    storage.delete_history(db)
    assert storage.device_names(db) == {}
    assert storage.list_scans(db) == []


# ---------- în aplicație ----------

def test_save_from_the_device_page_and_show_everywhere(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    resp = save(client, app, NAME)
    assert resp.status_code == 302 and "name=saved" in resp.headers["Location"]
    assert storage.device_names(app.config["DB_PATH"]) == {CAM: NAME}

    device = page(client, f"/device/{CAM}?scan=0&name=saved")
    assert NAME in device and "Am salvat numele." in device
    assert 'value="Camera din sufragerie"' in device                    # câmpul vine completat
    assert "192.168.1.40" in device                                      # IP-ul rămâne lângă nume

    overview = page(client, "/")
    worst = re.search(r'class="worst-device">(.*?)</h2>', overview, re.S).group(1)
    meta = re.search(r'<p class="device-meta">(.*?)</p>', overview, re.S).group(1)
    assert NAME in worst and "Cameră" in meta and '<span class="worst-ip" translate="no">192.168.1.40' in meta  # cardul „cel mai periculos”: nume, dedesubt „Tip · IP:port”
    rows = re.findall(r'<p class="dev-name">(.*?)</p>', overview, re.S)
    assert any(NAME in r for r in rows)                                  # lista dispozitivelor
    assert "Cameră" in overview                                          # tipul rămâne ca sub-titlu

    assert NAME in page(client, "/devices")                              # inventarul


def test_name_is_in_the_summary_sentence(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, NAME)
    s = re.search(r'<p class="summary-text">(.*?)</p>', page(client, "/"), re.S).group(1)
    assert f'<strong class="summary-device">{html.escape(NAME)}</strong>' in s     # numele iese în evidență
    s = html.unescape(re.sub(r"<[^>]+>", "", s))
    assert s.startswith(f"Începe cu {NAME}: ")


def test_other_devices_keep_their_type(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, NAME)
    rows = re.findall(r'<p class="dev-name">(.*?)</p>', page(client, "/"), re.S)
    assert len(rows) == 3
    assert sum(NAME in r for r in rows) == 1 and any("Router" in r for r in rows)


def test_name_replaces_type_in_journal_alerts():
    alert = SimpleNamespace(kind="NEW_DEVICE", device_id=CAM, device_type="camera", ip="192.168.1.40",
                            port=None, proto=None, code=None)
    assert i18n.alert_text("ro", alert) == "Un dispozitiv nou a apărut în rețea: Cameră, 192.168.1.40."
    assert i18n.alert_text("ro", alert, {CAM: NAME}) == (
        f"Un dispozitiv nou a apărut în rețea: {NAME}, 192.168.1.40.")
    assert i18n.alert_text("en", alert, {"alt-id": "x"}).startswith("A new device appeared on the network: Camera,")


def test_clear_button_removes_the_name(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, NAME)
    resp = save(client, app, NAME, action="clear")
    assert "name=cleared" in resp.headers["Location"]
    assert storage.device_names(app.config["DB_PATH"]) == {}
    assert NAME not in page(client, "/")
    assert "Am șters numele." in page(client, f"/device/{CAM}?scan=0&name=cleared")


def test_empty_field_also_removes_the_name(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, NAME)
    assert "name=cleared" in save(client, app, "  ").headers["Location"]
    assert storage.device_names(app.config["DB_PATH"]) == {}


def test_too_long_name_is_refused_with_a_message(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, "Nume bun")
    resp = save(client, app, "x" * 41)
    assert "name=too_long" in resp.headers["Location"]
    assert storage.device_names(app.config["DB_PATH"]) == {CAM: "Nume bun"}       # nu s-a schimbat nimic
    assert "cel mult 40 de caractere" in page(client, f"/device/{CAM}?scan=0&name=too_long")
    assert 'maxlength="40"' in page(client, f"/device/{CAM}?scan=0")              # și câmpul oprește tastarea


def test_name_in_english(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, "Living room camera")
    device = page(client, f"/device/{CAM}?scan=0&name=saved&lang=en")
    assert "Name saved." in device and "Remove name" in device and "Rename" in device


# ---------- text nesigur ----------

def test_script_in_a_name_is_escaped_everywhere(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, XSS)
    for url in ("/", f"/device/{CAM}?scan=0", "/devices", "/?lang=en"):
        body = page(client, url)
        assert XSS not in body, f"nume neescapat în {url}"
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body, f"numele lipsește din {url}"


def test_quote_in_a_name_cannot_break_out_of_the_input_value(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, '"><img src=x onerror=alert(1)>')
    body = page(client, f"/device/{CAM}?scan=0")
    assert "<img src=x" not in body
    assert 'value="&#34;&gt;&lt;img' in body


def test_name_not_shown_as_html_in_the_summary(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, XSS)
    assert XSS not in page(client, "/")


# ---------- cereri false ----------

def test_wrong_token_is_refused(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    resp = client.post(f"/device/{CAM}/name", data={"token": "nu-e-jetonul", "scan": 0, "name": NAME})
    assert resp.status_code == 400
    assert storage.device_names(app.config["DB_PATH"]) == {}


def test_cross_site_request_is_refused(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    resp = client.post(f"/device/{CAM}/name", headers={"Sec-Fetch-Site": "cross-site"},
                       data={"token": app.config["FORM_TOKEN"], "scan": 0, "name": NAME})
    assert resp.status_code == 403
    assert storage.device_names(app.config["DB_PATH"]) == {}


def test_unknown_device_gets_no_name(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    assert save(client, app, NAME, device_id="nu-exista").status_code == 404
    assert storage.device_names(app.config["DB_PATH"]) == {}


def test_delete_history_button_removes_names(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    save(client, app, NAME)
    assert storage.device_names(app.config["DB_PATH"]) == {CAM: NAME}
    client.post("/history/delete", data={"token": app.config["FORM_TOKEN"]})
    assert storage.device_names(app.config["DB_PATH"]) == {}
    assert NAME not in page(client, "/")
