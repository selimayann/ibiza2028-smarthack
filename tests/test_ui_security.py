"""RBRT: reparațiile din auditul de securitate (DNS rebinding, AI pornit de alte site-uri, raportul descărcat)."""
import json
import re
from pathlib import Path
from urllib.parse import quote

from netscan.model import Scan
from netscan.ui.app import create_app

SAMPLE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def client(tmp_path):
    scan = Scan.from_dict(json.loads(SAMPLE.read_text(encoding="utf-8")))
    app = create_app({"SCAN_LOADER": lambda: [scan], "DB_PATH": tmp_path / "h.db", "TESTING": True})
    return app.test_client(), app


def test_only_local_host_names_are_accepted(tmp_path):
    """DNS rebinding: o cerere adresată altui nume (chiar dacă duce la 127.0.0.1) e refuzată."""
    c, _ = client(tmp_path)
    for host in ("127.0.0.1:5000", "localhost:5000", "localhost", "127.0.0.1"):
        assert c.get("/", headers={"Host": host}).status_code == 200, host
    for host in ("evil.example:5000", "evil.example", "127.0.0.1.evil.example", "attacker.localhost.com"):
        assert c.get("/", headers={"Host": host}).status_code == 400, host
        assert c.get("/history/delete", headers={"Host": host}).status_code == 400   # token-ul nu poate fi citit


def test_cross_site_cannot_run_the_assistant(tmp_path):
    c, _ = client(tmp_path)
    q = quote("Ce fac întâi?")
    assert c.get("/api/ask?scan=0&q=" + q, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.get("/api/ask?scan=0&q=" + q, headers={"Sec-Fetch-Site": "same-site"}).status_code == 403
    assert c.get("/api/ask?scan=0&q=" + q, headers={"Sec-Fetch-Site": "same-origin"}).get_json()["ok"]
    assert c.get("/api/ask?scan=0&q=" + q).get_json()["ok"]                   # fără header (unelte, teste)
    html = c.get("/?ask=1&q=" + q, headers={"Sec-Fetch-Site": "cross-site"}).get_data(as_text=True)
    assert 'id="ask-answer"' not in html                                      # pagina se deschide, dar fără răspuns
    assert 'id="ask-answer"' in c.get("/?ask=1&q=" + q, headers={"Sec-Fetch-Site": "same-origin"}).get_data(as_text=True)


def test_language_link_drops_internal_parameters(tmp_path):
    c, _ = client(tmp_path)
    html = c.get("/?scan=0&_scheme=javascript&_anchor=x&_method=DELETE").get_data(as_text=True)
    assert "_scheme" not in html and "_anchor" not in html and "_method" not in html


def test_delete_page_offers_to_delete_raw_scans_too(tmp_path):
    c, _ = client(tmp_path)
    html = c.get("/history/delete").get_data(as_text=True)
    # căsuța pentru fișierele brute (pot conține MAC-uri reale) e bifată implicit și spune unde sunt
    assert "Șterge și fișierele de scanare" in html and "scans/" in html
    assert re.search(r'<input type="checkbox" name="delete_raw" value="1" checked>', html)


def test_host_check_works_without_flask_trusted_hosts(tmp_path, monkeypatch):
    """Și pe Flask 3.0 (fără TRUSTED_HOSTS) cererile cu alt Host sunt refuzate de verificarea proprie."""
    scan = Scan.from_dict(json.loads(SAMPLE.read_text(encoding="utf-8")))
    app = create_app({"SCAN_LOADER": lambda: [scan], "DB_PATH": tmp_path / "h.db", "TESTING": True, "TRUSTED_HOSTS": None})
    c = app.test_client()
    assert c.get("/", headers={"Host": "evil.example:5000"}).status_code == 400
    assert c.get("/api/ask?scan=0&q=x", headers={"Host": "127.0.0.1.evil.example"}).status_code == 400
    assert c.get("/", headers={"Host": "127.0.0.1:5000"}).status_code == 200
    assert c.get("/", headers={"Host": "LOCALHOST:5000"}).status_code == 200
