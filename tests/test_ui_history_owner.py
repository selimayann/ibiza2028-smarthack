"""Al cui e istoricul: utilizatorul de sistem, mesajul de la istoric gol, fără să mutăm baza de date."""
import getpass
import html
import re
from pathlib import Path

from netscan.ui import app as ui_app
from netscan.ui import storage
from tests.test_ui_app import XSS, make_client, sample


def owner_line(page: str) -> str:
    m = re.search(r'<p class="history-owner">(.*?)</p>', page, re.S)
    assert m, "lipsește linia cu utilizatorul"
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))).split())


def fake_user(monkeypatch, name):
    monkeypatch.setattr(getpass, "getuser", lambda: name)


def test_history_says_whose_it_is(tmp_path, monkeypatch):
    fake_user(monkeypatch, "Radu")
    client, app = make_client(tmp_path, [sample()])
    storage.save_scan(sample(), app.config["DB_PATH"])
    page = client.get("/history").get_data(as_text=True)
    assert owner_line(page) == "Istoric pentru utilizatorul Radu pe acest calculator."
    assert "history-owner-note" not in page          # mesajul pentru istoric gol apare doar când e gol


def test_history_owner_in_english(tmp_path, monkeypatch):
    fake_user(monkeypatch, "Radu")
    client, app = make_client(tmp_path, [sample()])
    storage.save_scan(sample(), app.config["DB_PATH"])
    assert owner_line(client.get("/history?lang=en").get_data(as_text=True)) == "History for user Radu on this computer."


def test_empty_history_explains_it_may_be_another_user_and_data_is_not_lost(tmp_path, monkeypatch):
    fake_user(monkeypatch, "Radu")
    client, app = make_client(tmp_path, [sample()])
    page = client.get("/history").get_data(as_text=True)
    assert "Istoricul e gol" in page
    assert owner_line(page) == "Istoric pentru utilizatorul Radu pe acest calculator."
    text = html.unescape(page)
    assert "alt utilizator de Windows" in text and "Datele nu s-au pierdut" in text
    assert "alt folder" in text                                  # baza e relativă la folderul de pornire
    assert str(Path(app.config["DB_PATH"]).resolve()) in text    # arată unde a căutat


def test_empty_history_message_in_english(tmp_path, monkeypatch):
    fake_user(monkeypatch, "Radu")
    client, _ = make_client(tmp_path, [sample()])
    text = html.unescape(client.get("/history?lang=en").get_data(as_text=True))
    assert "different Windows user" in text and "isn't lost" in text and "Looking for the history in:" in text


def test_user_name_is_escaped(tmp_path, monkeypatch):
    fake_user(monkeypatch, XSS)
    client, _ = make_client(tmp_path, [sample()])
    page = client.get("/history").get_data(as_text=True)
    assert XSS not in page and "&lt;script&gt;" in page


def test_page_works_when_the_system_gives_no_user_name(tmp_path, monkeypatch):
    def boom():
        raise OSError("fără utilizator")
    monkeypatch.setattr(getpass, "getuser", boom)
    assert ui_app.current_user() is None
    client, app = make_client(tmp_path, [sample()])
    storage.save_scan(sample(), app.config["DB_PATH"])
    resp = client.get("/history")
    assert resp.status_code == 200
    assert owner_line(resp.get_data(as_text=True)) == "Istoric pe acest calculator."


def test_user_name_is_trimmed_and_limited(monkeypatch):
    fake_user(monkeypatch, "  " + "x" * 200 + "  ")
    assert ui_app.current_user() == "x" * 60
    fake_user(monkeypatch, "   ")
    assert ui_app.current_user() is None


def test_database_location_is_unchanged(monkeypatch):
    """Nu mutăm baza: rămâne NETSCAN_DB_PATH sau data/netscan.db."""
    monkeypatch.delenv("NETSCAN_DB_PATH", raising=False)
    assert storage.db_path() == Path("data/netscan.db")
