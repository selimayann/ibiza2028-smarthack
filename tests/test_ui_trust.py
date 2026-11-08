"""Runda P1 a UI-ului: pagina „Ce știe SafeEel despre tine”, ușa-capcană la alegere, eticheta routerului, cuvintele
noi, jurnalul pliat, textele fără categorii zero, butonul asistentului, linkurile după fișier și vederea CSV.
Fără rețea: rețeaua curentă e o funcție de test (NETWORK_DETECT), monitorul live e simulat."""
import re
from dataclasses import replace

from netscan.engine.parser import _DEFAULT_SALT
from netscan.model import Scan
from netscan.scan.network import OK, WRONG_SSID, NetworkInfo
from netscan.ui import i18n, storage
from netscan.ui.alerts import FINDING_RESOLVED, PORT_CLOSED, alerts_between, fold_port_alerts
from netscan.ui.app import create_app
from netscan.ui.view import rank_devices
from tests.test_ui_app import sample
from tests.test_ui_live import FakeLive

FULL_MAC = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
GW = "192.168.1.1"
ROUTER_LABEL = "Routerul (telefonul cu hotspotul)"


def hotspot(gateway=GW, status=OK, ssid="RSH-Ibiza2028"):
    return NetworkInfo(iface="Wi-Fi", ip="192.168.1.10", cidr="192.168.1.0/24", gateway=gateway, ssid=ssid,
                       status=status)


def make(tmp_path, scans=None, **cfg):
    live = cfg.pop("LIVE", None) or FakeLive()
    base = {"SCAN_LOADER": lambda: scans if scans is not None else [sample()], "DB_PATH": tmp_path / "h.db",
            "TESTING": True, "LIVE": live, "USER_SCANS_DIR": tmp_path / "scans"}
    app = create_app({**base, **cfg})
    return app.test_client(), app, live


# ---------- 1. „Ce știe SafeEel despre tine” ----------

def test_trust_page_counts_what_is_stored_and_masks_the_mac(tmp_path):
    s = sample()
    c, app, live = make(tmp_path, NETWORK_DETECT=lambda: hotspot(status=WRONG_SSID))
    db = app.config["DB_PATH"]
    storage.save_scan(s, db)
    storage.mark_accepted(s, s.findings[0].key(), db)
    storage.mark_verified(s, [s.findings[1].key()], db)
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "a.xml").write_text("<nmaprun/>", encoding="utf-8")
    html = c.get("/trust").get_data(as_text=True)
    assert "<h1 class=\"page-title\">Ce știe SafeEel despre tine</h1>" in html
    assert "1 scanare salvată în istoric" in html and "3 dispozitive văzute" in html
    assert "5 probleme găsite" in html and "1 risc acceptat de tine" in html
    assert "1 pas confirmat ca reparat" in html and "0 pași bifați de tine" in html
    assert "1 fișier de scanare de la nmap" in html
    assert "AA:BB:CC:XX:XX:XX" in html and not FULL_MAC.search(html)
    assert str((tmp_path).resolve()) in html                           # folderul bazei de date
    assert "100 de pachete pe secundă" in html and "Fără AI online" in html
    assert "Nu ești conectat la hotspotul echipei" in html
    assert 'href="/history/delete"' in html
    assert live.calls == []                                           # nu pornește nimic


def test_trust_page_is_get_only_and_linked_from_every_page(tmp_path):
    c, _, live = make(tmp_path)
    assert c.post("/trust").status_code == 405
    for url in ("/", "/devices", "/journal", "/history", "/trust"):
        html = c.get(url).get_data(as_text=True)
        assert 'href="/trust"' in html and "Ce știe SafeEel despre tine" in html, url
    en = c.get("/trust?lang=en").get_data(as_text=True)
    assert "What SafeEel knows about you" in en and "Safety limits" in en and "Ce știe" not in en
    assert live.calls == []


def test_trust_page_network_states_without_touching_the_network(tmp_path):
    c, _, _ = make(tmp_path, NETWORK_DETECT=lambda: hotspot(ssid="<b>x</b>"))
    html = c.get("/trust").get_data(as_text=True)
    assert "Ești pe hotspotul echipei" in html and "&lt;b&gt;x&lt;/b&gt;" in html and "<b>x</b>" not in html
    assert "192.168.1.0/24" in html and "are adresa 192.168.1.1" in html

    def boom():
        raise OSError("nu")
    c2, _, _ = make(tmp_path / "b", NETWORK_DETECT=boom)
    html2 = c2.get("/trust").get_data(as_text=True)
    assert "Nu am putut citi rețeaua de acum" in html2 and "Nu ești conectat la hotspotul echipei" in html2
    # fără NETWORK_DETECT, cu monitorul de test al aplicației: „fără rețea”, nimic pornit
    app = create_app({"SCAN_LOADER": lambda: [], "DB_PATH": tmp_path / "c.db", "TESTING": True})
    assert "Nu ești conectat la hotspotul echipei" in app.test_client().get("/trust").get_data(as_text=True)


def test_trust_page_says_whose_salt_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_SALT", "cheia-echipei-lunga")
    c, _, _ = make(tmp_path)
    assert "cheia secretă a echipei" in c.get("/trust").get_data(as_text=True)
    monkeypatch.setenv("NETSCAN_SALT", _DEFAULT_SALT)
    assert "cheia implicită" in c.get("/trust").get_data(as_text=True)
    monkeypatch.delenv("NETSCAN_SALT")
    assert "cheia implicită" in c.get("/trust").get_data(as_text=True)


def test_stored_counts_never_returns_a_full_mac(tmp_path):
    s = sample()
    db = tmp_path / "h.db"
    assert storage.stored_counts(db).mac_example is None
    storage.save_scan(s, db)
    counts = storage.stored_counts(db)
    assert counts.scans == 1 and counts.hosts == 3 and counts.findings == 5
    assert counts.mac_example.endswith(":XX:XX:XX")


# ---------- 2. ușa-capcană: bifă separată, nebifată implicit ----------

def test_trap_is_a_separate_unchecked_opt_in(tmp_path):
    c, app, live = make(tmp_path)
    html = c.get("/protectie").get_data(as_text=True)
    box = re.search(r'<input type="checkbox" name="trap" value="1"[^>]*>', html).group(0)
    assert "checked" not in box and "required" not in box
    assert "Pornește și ușa-capcană (alertă dacă cineva din rețea încearcă să intre)" in html
    assert "oprită dacă nu o bifezi la pornire" in html
    token = app.config["FORM_TOKEN"]
    c.post("/live/start", data={"token": token, "confirm": "1"})
    assert live.calls == ["start"] and live.trap is False
    c.post("/live/start", data={"token": token, "confirm": "1", "trap": "1"})
    assert live.trap is True
    c.post("/live/start", data={"token": token, "confirm": "1", "trap": "yes"})
    assert live.trap is False
    # fără consimțământ, nici capcana nu pornește
    live.calls.clear()
    c.post("/live/start", data={"token": token, "trap": "1"})
    assert live.calls == []
    en = c.get("/protectie?lang=en").get_data(as_text=True)
    assert "Also turn on the trap door" in en


def test_active_panel_says_trap_was_not_chosen(tmp_path):
    from tests.test_ui_live import snapshot
    snap = snapshot("active")
    snap["trap_state"] = "off"
    live = FakeLive(snap)
    live.trap_wanted = False
    c, _, _ = make(tmp_path, LIVE=live)
    assert "nu ai bifat-o la pornire" in c.get("/live/panel").get_data(as_text=True)


# ---------- 3. eticheta routerului ----------

def test_router_label_only_for_our_newest_scan_on_the_team_hotspot(tmp_path):
    s = sample()
    router = next(d for d in rank_devices(s) if d.host.ip == GW)
    c, _, _ = make(tmp_path, [s], OWN_SCAN_CHECK=lambda x: True, NETWORK_DETECT=hotspot)
    page = c.get(f"/device/{router.host.device_id}").get_data(as_text=True)
    assert f"<h1>{ROUTER_LABEL}</h1>" in page
    devices = c.get("/devices").get_data(as_text=True)                  # lista e pe pagina „Dispozitive”
    assert ROUTER_LABEL in devices
    assert router.host.device_type == "router" and [d.host.device_type for d in rank_devices(s)] == \
        [d.host.device_type for d in rank_devices(sample())]     # tipul din motor nu se schimbă
    # fișier analizat (nu scanarea noastră) sau altă rețea: fără etichetă
    for cfg in ({"OWN_SCAN_CHECK": lambda x: False, "NETWORK_DETECT": hotspot},
                {"OWN_SCAN_CHECK": lambda x: True, "NETWORK_DETECT": lambda: hotspot(status=WRONG_SSID)},
                {"OWN_SCAN_CHECK": lambda x: True, "NETWORK_DETECT": lambda: hotspot(gateway="192.168.1.254")}):
        c2, _, _ = make(tmp_path / str(id(cfg)), [s], **cfg)
        assert ROUTER_LABEL not in c2.get(f"/device/{router.host.device_id}").get_data(as_text=True)


# ---------- 4. „Cuvinte noi” ----------

def test_device_page_has_new_words_from_the_glossary(tmp_path):
    s = sample()
    cam = next(d for d in rank_devices(s) if d.host.ip == "192.168.1.40")
    c, _, _ = make(tmp_path, [s])
    html = c.get(f"/device/{cam.host.device_id}").get_data(as_text=True)
    block = html.split('<details class="fold new-words">', 1)[1].split("</details>", 1)[0]
    assert "<summary>Cuvinte noi (" in block and "<dt>" in block and "<dd>" in block
    en = c.get(f"/device/{cam.host.device_id}?lang=en").get_data(as_text=True)
    assert "<summary>New words (" in en


# ---------- 5. jurnalul: porturile pliate sub problema lor ----------

def _after(s: Scan) -> Scan:
    hosts = [replace(h, ports=[p for p in h.ports if p.port != 554]) if h.ip == "192.168.1.40" else h for h in s.hosts]
    return replace(s, file="after.xml", started_at=s.started_at + 3600, hosts=hosts, score=60,
                   findings=[f for f in s.findings if f.port != 554])


def test_fold_port_alerts_keeps_only_unexplained_ports():
    s = sample()
    shown, folded = fold_port_alerts(alerts_between(s, _after(s)))
    assert [a.kind for a in folded] == [PORT_CLOSED] and folded[0].port == 554
    assert any(a.kind == FINDING_RESOLVED and a.port == 554 for a in shown)
    assert all(a.kind != PORT_CLOSED for a in shown)


def test_journal_folds_port_changes_into_details(tmp_path):
    s = sample()
    c, app, _ = make(tmp_path, [s])
    storage.save_scan(s, app.config["DB_PATH"])
    storage.save_scan(_after(s), app.config["DB_PATH"])
    html = c.get("/journal").get_data(as_text=True)
    fold = html.split('<details class="fold port-fold">', 1)[1].split("</details>", 1)[0]
    assert "Porturile din spatele acestor probleme (1)" in fold and "554/tcp" in fold
    outside = html.replace(fold, "")
    assert "554/tcp" not in outside and "Rezolvată: „" in outside   # Jurnalul: rânduri scurte, grupate pe dispozitiv


# ---------- 6. textele ----------

def test_verdict_sentence_lists_only_non_zero_categories(tmp_path):
    assert i18n.verdict_counts_text("ro", 1, 2, 0) == "Probleme găsite: 1 cu risc ridicat și 2 cu risc mediu."
    assert i18n.verdict_counts_text("en", 0, 2, 0) == "Problems found: 2 medium risk."
    assert i18n.verdict_counts_text("ro", 0, 0, 0, 1) == "Nimic riscant, doar 1 lucru de știut."
    assert i18n.verdict_counts_text("ro", 0, 0, 0, 20) == "Nimic riscant, doar 20 de lucruri de știut."
    assert i18n.verdict_counts_text("ro", 0, 0, 0, 0) == ""
    c, _, _ = make(tmp_path)
    html = c.get("/").get_data(as_text=True)
    chips = html.split('class="sev-chips verdict-chips"', 1)[1].split("</p>", 1)[0]   # sub verdict: etichete cu număr
    assert 'sev-chip-high' in chips and 'sev-chip-medium' in chips
    assert 'sev-chip-low' not in chips and 'sev-chip-info' not in chips              # doar categoriile care există


def test_steps_plural_and_welcome_shows_the_date(tmp_path):
    assert i18n.count_phrase("ro", 1, "steps_tally_accepted_one", "steps_tally_accepted") == "1 acceptat de tine"
    assert i18n.count_phrase("ro", 2, "steps_tally_accepted_one", "steps_tally_accepted") == "2 acceptate de tine"
    s = sample()
    c, _, _ = make(tmp_path, [s])
    html = c.get("/").get_data(as_text=True)
    welcome = re.search(r'<p class="msg msg-bot">([^<]*)</p>', html).group(1)
    assert "V2_smart_home.xml" not in welcome and "scanarea din " in welcome and str(2025) in welcome


# ---------- 7. butonul asistentului nu acoperă subsolul ----------

def test_fab_never_floats_over_content(tmp_path):
    from pathlib import Path
    css = (Path(__file__).parent.parent / "netscan" / "ui" / "static" / "style.css").read_text(encoding="utf-8")
    # ecrane late: coloană rezervată la dreapta pentru butonul rotund + loc sub subsol
    assert "body.has-fab main.wrap { padding-right: 5.75rem; }" in css
    assert "body.has-fab .foot-inner { padding-right: 5.75rem; }" in css   # aceeași înălțime ca pe celelalte pagini
    # telefon: butonul plutitor dispare, asistentul se deschide din antet
    assert "@media (max-width: 47.99rem) {\n  body.has-fab .ai-fab { display: none; }" in css
    c, _, _ = make(tmp_path)
    html = c.get("/").get_data(as_text=True)
    assert '<body class="has-fab">' in html
    top = re.search(r'<a class="ai-top" href="([^"]+)" data-chat-open', html).group(1)
    fab = re.search(r'<a class="ai-fab"[^>]*href="([^"]+)"', html).group(1)
    assert top == fab and "ask=1" in top and top.endswith("#chat")
    assert '<span class="sr-only">Întreabă asistentul AI</span>' in html   # numele butonului din antet
    assert "<body>" in c.get("/trust").get_data(as_text=True)          # fără asistent, fără spațiu în plus


# ---------- 8. linkurile după fișier + dată, nu după poziție ----------

def test_links_use_the_scan_file_not_its_position(tmp_path):
    a = sample()
    b = replace(a, file="b.xml", started_at=a.started_at + 60)
    c, _, _ = make(tmp_path, [b, a])
    html = c.get("/?scan=1").get_data(as_text=True)
    fab = re.search(r'<a class="ai-fab"[^>]*href="([^"]+)"', html).group(1)
    assert "file=V2_smart_home.xml" in fab and "scan=" not in fab
    assert '<input type="hidden" name="file" value="V2_smart_home.xml">' in html
    assert '<select id="scan" name="file" data-autosubmit>' in html
    assert '<option value="V2_smart_home.xml" title="V2_smart_home.xml" selected>' in html
    lang = re.search(r'<a href="([^"]+)" lang="en"', html).group(1)
    assert "file=V2_smart_home.xml" in lang and "scan=" not in lang
    # ?scan= rămâne doar ca rezervă la citire
    assert "V2_smart_home.xml" in c.get("/devices?scan=1").get_data(as_text=True)


# ---------- 9. vederea CSV folosește exact cuvintele din CSV ----------
