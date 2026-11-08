"""RBRT: UI pentru funcțiile lui Ayan (monitor, ușa-capcană, „ce vede cineva care ascultă”, nume anunțate).

Modulele lui Ayan sunt înlocuite aici cu module de probă care au EXACT forma de date descrisă de el, ca UI-ul
să poată fi testat și înainte de push-ul lui. Fără module (sau cu module care dau eroare), paginile merg normal.
"""
import json
import sys
import types
from pathlib import Path


import netscan.scan
from netscan.model import Scan
from netscan.ui.app import create_app

SAMPLE = Path(__file__).parent.parent / "fixtures" / "sample.json"
XSS = "<script>alert(1)</script>"


def sample() -> Scan:
    return Scan.from_dict(json.loads(SAMPLE.read_text(encoding="utf-8")))


def client_for(tmp_path, scans=None, own=False):
    cfg = {"SCAN_LOADER": lambda: scans if scans is not None else [sample()],
           "DB_PATH": tmp_path / "h.db", "TESTING": True}
    if own:
        cfg["OWN_SCAN_CHECK"] = lambda s: True
    app = create_app(cfg)
    return app.test_client()


def install(monkeypatch, name, **attrs):
    mod = types.ModuleType(f"netscan.scan.{name}")
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, f"netscan.scan.{name}", mod)
    monkeypatch.setattr(netscan.scan, name, mod, raising=False)
    return mod


def fake_local_data(monkeypatch, alerts=(), trap=()):
    data = {"alerts": list(alerts), "trap": list(trap)}
    install(monkeypatch, "local_data", alerts_path=lambda: "alerts", trap_path=lambda: "trap",
            read_events=lambda path: data[path])


def ev(kind, ts, ip="192.168.1.1", port=None, code=None, ro="", en=""):
    return {"kind": kind, "ts": ts, "ip": ip, "port": port, "proto": "tcp", "code": code, "severity": None,
            "text_ro": ro, "text_en": en}


# ---------- 1. alertele monitorului ----------

def test_monitor_not_run_links_to_live_protection(tmp_path):
    html = client_for(tmp_path).get("/journal").get_data(as_text=True)
    # fără comenzi de terminal: linkul duce la protecția live de pe pagina Acasă
    assert "Protecția live nu a rulat încă" in html and 'href="/#live-h"' in html
    assert "python -m netscan" not in html


def test_monitor_alerts_in_journal_newest_first(tmp_path, monkeypatch):
    """Ca la V6a → V6b: 3 probleme rezolvate apar în Jurnal ca „Rezolvat”, calm (verde + bifă)."""
    fake_local_data(monkeypatch, alerts=[
        ev("FINDING_RESOLVED", 100, code="HTTP_ADMIN_CLEARTEXT", ro="Problema „Pagină de administrare necriptată” a fost rezolvată."),
        ev("FINDING_RESOLVED", 101, code="UPNP_EXPOSED", ro="Problema „UPnP pornit” a fost rezolvată."),
        ev("FINDING_RESOLVED", 102, ip="192.168.1.30", code="TELNET_OPEN", ro="Problema „Telnet deschis” a fost rezolvată."),
        ev("NEW_DEVICE", 200, ip="192.168.1.77", ro="Un dispozitiv nou a apărut: 192.168.1.77."),
        ev("BOGUS", 300, ro="nu se afișează"),
    ])
    html = client_for(tmp_path).get("/journal").get_data(as_text=True)
    assert html.count('class="mon mon-good"') == 3 and html.count(">Rezolvat<") == 3
    assert 'class="mon mon-urgent"' in html and ">Dispozitiv nou<" in html
    assert html.index("Un dispozitiv nou a apărut") < html.index("Telnet deschis")   # cele mai noi primele
    assert "nu se afișează" not in html


def test_monitor_text_is_escaped_and_english(tmp_path, monkeypatch):
    fake_local_data(monkeypatch, alerts=[ev("FINDING_NEW", 1, ro=XSS, en="New problem on the router.")])
    c = client_for(tmp_path)
    assert XSS not in c.get("/journal").get_data(as_text=True)
    assert "New problem on the router." in c.get("/journal?lang=en").get_data(as_text=True)


def test_new_alerts_badge_until_journal_is_opened(tmp_path, monkeypatch):
    fake_local_data(monkeypatch, alerts=[ev("NEW_DEVICE", 1_000, ro="a"), ev("FINDING_NEW", 1_001, ro="b")])
    c = client_for(tmp_path)
    assert "2 alerte noi" in c.get("/").get_data(as_text=True)
    c.get("/journal")                          # cookie: am văzut jurnalul acum
    assert "alerte noi" not in c.get("/").get_data(as_text=True)


# ---------- 2. ușa-capcană ----------

def test_trap_attempt_calm_text_link_and_no_block_button(tmp_path, monkeypatch):
    fake_local_data(monkeypatch, trap=[{"ts": 1_762_540_920, "ip": "192.168.1.40", "port": 2323},
                                       {"ts": 1_762_540_000, "ip": "172.20.10.5", "port": 23},
                                       {"ts": 1, "ip": "nu-e-ip", "port": 1}])
    html = client_for(tmp_path).get("/journal").get_data(as_text=True)
    assert html.count("Încercare de intrare") == 2                       # IP-ul invalid e ignorat
    assert "Cineva din rețea (192.168.1.40) a încercat să intre" in html and "pe portul 2323" in html
    assert "Dacă nu știi cine e, verifică dispozitivul." in html
    assert "/device/e1f2a3b4c5d6" in html                               # 192.168.1.40 e camera din scanare
    assert html.count("Vezi dispozitivul") == 1                         # 172.20.10.5 nu e cunoscut: fără link
    low = html.lower()
    assert "blochează" not in low and "block" not in low.replace("blocks", "")


# ---------- 3. ce vede cineva care ascultă ----------

def fake_eavesdrop(monkeypatch):
    def get_eavesdrop(code, lang):
        if code not in ("FTP_CLEARTEXT", "TELNET_OPEN", "HTTP_ADMIN_CLEARTEXT"):
            return None
        return {"title": "Parola trece necriptată", "protocol": "HTTP",
                "lines": ["POST /login HTTP/1.1", "Host: 192.168.1.1", "user=admin&pass=parola123", XSS],
                "caption": "Exemplu inventat, nu date reale din rețeaua ta.", "fix": "Pornește HTTPS.", "highlight": 2}
    install(monkeypatch, "eavesdrop", get_eavesdrop=get_eavesdrop)


def test_eavesdrop_block_only_for_the_three_codes(tmp_path, monkeypatch):
    fake_eavesdrop(monkeypatch)
    c = client_for(tmp_path)
    cam = c.get("/device/e1f2a3b4c5d6").get_data(as_text=True)       # camera: CAMERA_STREAM + HTTP_ADMIN
    assert cam.count('class="eaves"') == 1 and "parola, la vedere" in cam
    assert "Exemplu inventat, nu date reale" in cam and "Pornește HTTPS." in cam
    assert XSS not in cam and "&lt;script&gt;" in cam
    hub = c.get("/device/f1a2b3c4d5e7").get_data(as_text=True)       # hub: doar MQTT
    assert 'class="eaves"' not in hub


def test_eavesdrop_on_do_first_card_when_step_is_one_of_three(tmp_path, monkeypatch):
    fake_eavesdrop(monkeypatch)
    c = client_for(tmp_path)
    assert "eaves-details" not in c.get("/").get_data(as_text=True)  # pasul 1: CAMERA_STREAM_EXPOSED
    app_client = c
    from netscan.ui.view import action_plan
    s = sample()
    f = action_plan(s)[0]
    token = app_client.application.config["FORM_TOKEN"]
    app_client.post("/action/done", data={"token": token, "file": s.file, "started_at": s.started_at,
                                          "device_id": f.device_id, "port": f.port, "code": f.code})
    html = app_client.get("/").get_data(as_text=True)                # pasul 2: HTTP_ADMIN_CLEARTEXT
    assert "eaves-details" in html and "Ce vede cineva care ascultă" in html


# ---------- 4. nume anunțate ----------

def test_announced_names_shown_escaped_and_cut(tmp_path, monkeypatch):
    long = "Chromecast-" + "x" * 80
    heard = sample().started_at + 60          # auzite chiar lângă scanare
    install(monkeypatch, "passive", load_names=lambda: {
        "192.168.1.40": {"name": XSS, "service": "Google Cast", "ts": heard},
        "192.168.1.1": {"name": long, "service": None, "ts": heard},
        "bad-ip": {"name": "ignorat"}})
    c = client_for(tmp_path, own=True)        # cea mai nouă scanare a noastră
    for url in ("/", "/devices", "/device/e1f2a3b4c5d6"):
        html = c.get(url).get_data(as_text=True)
        assert XSS not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "nume anunțat de dispozitiv" in html
    html = c.get("/devices").get_data(as_text=True)
    assert long[:60] in html and long[:61] not in html and "ignorat" not in html


def test_announced_names_only_on_our_newest_scan_and_near_its_time(tmp_path, monkeypatch):
    """Numele unui telefon de acum nu se lipește pe o scanare din fișier (lab, Validation) sau pe una veche."""
    from netscan.engine.parser import analyze_file

    lab = analyze_file(str(Path(__file__).parent.parent / "fixtures" / "lab" / "scan_01_before.xml"))
    ip = lab.hosts[0].ip
    install(monkeypatch, "passive", load_names=lambda: {ip: {"name": "Telefonul-Juratului", "service": None,
                                                             "ts": lab.started_at + 60}})
    # fișier analizat (nu e scanarea noastră): niciun nume
    assert "Telefonul-Juratului" not in client_for(tmp_path, [lab]).get("/").get_data(as_text=True)
    # a noastră, dar numele e auzit la 7 ore distanță de scanare: tot nimic
    install(monkeypatch, "passive", load_names=lambda: {ip: {"name": "Telefonul-Juratului", "service": None,
                                                             "ts": lab.started_at + 7 * 3600}})
    assert "Telefonul-Juratului" not in client_for(tmp_path, [lab], own=True).get("/").get_data(as_text=True)
    from netscan.ui import extras
    assert extras.names_near({ip: {"name": "x", "ts": None}}, lab.started_at) == {}
    assert extras.names_near({ip: {"name": "x", "ts": 5}}, None) == {}


def test_without_ayans_modules_pages_still_work(tmp_path, monkeypatch):
    for name in ("local_data", "eavesdrop", "passive"):
        install(monkeypatch, name)     # module goale: funcțiile lipsesc → UI-ul trebuie să meargă
    c = client_for(tmp_path)
    for url in ("/", "/devices", "/journal", "/device/e1f2a3b4c5d6"):
        assert c.get(url).status_code == 200
