"""Navigarea: tabul activ arată de unde ai venit; comparația din Istoric e prima și spune când e altă rețea."""
from pathlib import Path

from netscan.engine import analyze_folder
from netscan.ui import storage
from netscan.ui.app import create_app

ROOT = Path(__file__).parent.parent


def _client(tmp_path, files):
    db = tmp_path / "h.db"
    scans = []
    for folder, name in files:
        s = next(x for x in analyze_folder(ROOT / "fixtures" / folder) if x.file == name)
        storage.save_scan(s, db)
        scans.append(s)
    app = create_app({"SCAN_LOADER": lambda: scans, "DB_PATH": db, "TESTING": True})
    return app.test_client(), [i.id for i in storage.list_scans(db)]


def _current(html):
    return html.split('aria-current="page">', 1)[1].split("<", 1)[0]


def test_device_from_devices_keeps_devices_tab(tmp_path):
    client, _ = _client(tmp_path, [("lab", "scan_01_before.xml")])
    inv = client.get("/devices").get_data(as_text=True)
    assert "from=devices" in inv
    href = inv.split('href="/device/', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    html = client.get("/device/" + href).get_data(as_text=True)
    assert _current(html) == "Dispozitive" and "Înapoi la Dispozitive" in html
    plain = client.get("/device/" + href.split("?", 1)[0] + "?scan=0").get_data(as_text=True)
    assert _current(plain) == "Dashboard" and "Înapoi la Dashboard" in plain


def test_journal_comparison_keeps_journal_tab_and_shows_comparison_first(tmp_path):
    client, ids = _client(tmp_path, [("lab", "scan_01_before.xml"), ("lab", "scan_03_after.xml")])
    journal = client.get("/journal").get_data(as_text=True)
    assert f"/scan/{ids[-1]}?from=journal" in journal
    html = client.get(f"/scan/{ids[-1]}?from=journal").get_data(as_text=True)
    assert _current(html) == "Jurnal" and "Înapoi la Jurnal" in html
    assert html.index('id="cmp-h"') < html.index('id="score-h"')          # comparația înaintea scorului
    assert "altă rețea" not in html                                         # aceeași rețea (lab)
    html = client.get(f"/scan/{ids[-1]}").get_data(as_text=True)
    assert _current(html) == "Istoric" and "Înapoi la Istoric" in html


def test_comparison_with_another_network_says_so(tmp_path):
    client, ids = _client(tmp_path, [("validation", "V1_home_basic.xml"), ("lab", "scan_01_before.xml")])
    html = client.get(f"/scan/{ids[-1]}").get_data(as_text=True)
    assert "Scanarea anterioară pare din altă rețea" in html


def test_new_problem_alerts_show_their_severity(tmp_path):
    client, _ = _client(tmp_path, [("validation", "V1_home_basic.xml"), ("lab", "scan_01_before.xml")])
    html = client.get("/journal").get_data(as_text=True)
    assert 'alert-sev-high' in html and '#i-high' in html                  # Telnet / baza de date: Ridicat
    assert '<strong class="alert-sev">Ridicat</strong> · Problemă nouă' in html
    assert '<strong class="alert-sev">Scăzut</strong>' in html             # dispozitiv necunoscut


def test_harm_line_on_device_page_and_dashboard(tmp_path):
    from netscan.explain import get_harm

    client, _ = _client(tmp_path, [("lab", "scan_01_before.xml")])
    dash = client.get("/").get_data(as_text=True)
    assert "Ce poate face cineva rău intenționat:" in dash
    inv = client.get("/devices").get_data(as_text=True)
    href = inv.split('href="/device/', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    page = client.get("/device/" + href).get_data(as_text=True)
    assert page.count('class="harm"') >= 1 and get_harm("FTP_CLEARTEXT", "ro") in page
    en = client.get("/device/" + href + "&lang=en").get_data(as_text=True)
    assert "What an attacker could do:" in en and get_harm("FTP_CLEARTEXT", "en").replace("'", "&#39;") in en
