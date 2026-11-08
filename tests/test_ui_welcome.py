"""Prima intrare în aplicație: „Bun venit” (prima scanare completă), apoi turul. Doar o dată; oricând la /bun-venit."""
from netscan.scan import network
from netscan.ui.app import create_app
from tests.test_ui_app import sample


def _app(tmp_path, **cfg):
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    base = {"SCAN_LOADER": lambda: [sample()], "DB_PATH": tmp_path / "data" / "h.db", "TESTING": True,
            "NET_CHECK": lambda ip: False, "USER_SCANS_DIR": scans_dir, "WELCOME_ON_FIRST_VISIT": True}
    app = create_app({**base, **cfg})
    return app.test_client(), app


def test_first_visit_starts_with_welcome_then_never_again(tmp_path):
    c, app = _app(tmp_path)
    r = c.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/bun-venit")
    html = c.get("/bun-venit").get_data(as_text=True)
    assert "Bun venit în SafeEel" in html and 'data-page="welcome"' in html
    r = c.post("/bun-venit/gata", data={"token": app.config["FORM_TOKEN"], "next": "tour"})
    assert r.status_code == 302 and "tour=1" in r.headers["Location"]
    assert c.get("/").status_code == 200                      # a doua oară: direct Acasă
    assert c.get("/bun-venit").status_code == 200             # pentru demo: oricând


def test_with_your_own_scans_there_is_no_welcome(tmp_path):
    c, app = _app(tmp_path)
    (tmp_path / "scans" / "scan_1.xml").write_text("<nmaprun/>")
    assert c.get("/").status_code == 200


def test_tests_and_links_with_arguments_are_never_redirected(tmp_path):
    c, app = _app(tmp_path, WELCOME_ON_FIRST_VISIT=False)
    assert c.get("/").status_code == 200
    c2, _ = _app(tmp_path / "b")
    assert c2.get("/?tour=1").status_code == 200              # turul pornit din meniu nu duce înapoi la „Bun venit”


def test_finish_needs_the_token(tmp_path):
    c, app = _app(tmp_path)
    assert c.post("/bun-venit/gata", data={"token": "gresit"}).status_code == 403


def test_off_the_hotspot_says_how_and_offers_the_example(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_EXPECTED_SSID", "RSH-Ibiza2028")
    info = network.NetworkInfo(iface="Wi-Fi", ip="10.0.0.5", cidr="10.0.0.0/24", gateway="10.0.0.1", ssid="UnivBuc Free")
    c, app = _app(tmp_path, NETWORK_DETECT=lambda: info)
    html = c.get("/bun-venit").get_data(as_text=True)
    assert "conectează laptopul la hotspotul echipei" in html and "UnivBuc Free" in html
    assert 'action="/live/scan"' not in html and "cu un exemplu" in html


def test_on_the_hotspot_the_scan_starts_from_here_and_comes_back_here(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_EXPECTED_SSID", "RSH-Ibiza2028")
    info = network.NetworkInfo(iface="Wi-Fi", ip="172.20.10.3", cidr="172.20.10.0/28", gateway="172.20.10.1",
                               ssid="RSH-Ibiza2028", status=network.OK)
    c, app = _app(tmp_path, NETWORK_DETECT=lambda: info)
    html = c.get("/bun-venit").get_data(as_text=True)
    assert 'action="/live/scan"' in html and 'name="back" value="welcome"' in html and 'name="confirm"' in html
    # fără acordul bifat: nu pornește nimic și rămânem pe „Bun venit”
    r = c.post("/live/scan", data={"token": app.config["FORM_TOKEN"], "back": "welcome", "job": "scan"})
    assert r.status_code == 302 and "/bun-venit" in r.headers["Location"]
