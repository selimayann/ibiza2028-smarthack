"""B + RBRT: panoul „Rețeaua ta acum” din Dashboard și butoanele lui. Monitorul e simulat (fără rețea)."""
import re
import shutil
from pathlib import Path

import pytest

from netscan.ui import app as app_mod
from netscan.ui.app import create_app

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"
XSS = "<script>alert(1)</script>"
FULL_MAC = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")

IDLE = {"state": "idle", "job": None, "percent": 0.0, "discovered": [], "phase": None, "eta_s": None,
        "file": None, "msg_ro": "", "msg_en": "", "next_at": None}


def snapshot(status="off", devices=(), events=(), baseline=True):
    return {"on": status != "off", "status": status, "reason": None, "reason_ro": "", "reason_en": "",
            "ssid": "RSH-Ibiza2028" if status == "active" else None,
            "cidr": "172.20.10.0/28" if status == "active" else None,
            "own_ip": "172.20.10.10" if status == "active" else None, "devices": list(devices),
            "online": sum(1 for d in devices if d["online"]), "events": list(events),
            "trap_state": "listening" if status == "active" else "off", "trap_code": None, "trap_port": 2323,
            "last_sweep": 1.0, "last_pulse": None, "pulse_running": False, "baseline_done": baseline,
            "known_file": "scan_03_after.xml"}


def device(ip="172.20.10.9", vendor=XSS, ports=({"port": 23, "label": "Telnet"},), new=True):
    return {"ip": ip, "mac_masked": "D0:39:57:XX:XX:XX", "vendor": vendor, "private_mac": False, "online": True,
            "new": new, "first_seen": 1.0, "last_seen": 2.0, "in_scan": False, "device_type": None,
            "open_ports": list(ports), "pulsed": True}


class FakeLive:
    def __init__(self, snap=None, full=None, code="OK"):
        self.snap, self.full, self.code = snap or snapshot(), full or dict(IDLE), code
        self.calls = []

    def snapshot(self):
        return self.snap

    def full_scan_status(self):
        return self.full

    def start(self, trap=False):
        self.calls.append("start")
        self.trap = trap

    def stop(self):
        self.calls.append("stop")

    def request_full_scan(self, job):
        self.calls.append(("scan", job))
        return self.code

    def stop_full_scan(self):
        self.calls.append("scan_stop")


def client_for(tmp_path, live, scans=None):
    app = create_app({"SCAN_LOADER": lambda: scans or [], "DB_PATH": tmp_path / "h.db", "TESTING": True,
                      "LIVE": live})
    return app.test_client(), app.config["FORM_TOKEN"]


def test_dashboard_name_and_live_panel_off(tmp_path):
    c, _ = client_for(tmp_path, FakeLive())
    html = c.get("/").get_data(as_text=True)
    assert ">Acasă<" in html and "Rezumat" not in html
    assert 'id="live"' in html and "Pornește protecția live" in html and 'data-poll="0"' in html
    assert "Nimic nu iese din hotspot" in html
    en = c.get("/?lang=en").get_data(as_text=True)
    assert ">Home<" in en and "Start live protection" in en


def test_live_panel_active_escapes_device_data_and_masks_mac(tmp_path):
    ev = {"ts": 1.0, "kind": "NEW_DEVICE", "ip": "172.20.10.9", "port": None, "tone": "urgent",
          "text_ro": f"Dispozitiv nou în rețea: 172.20.10.9 ({XSS}).", "text_en": "New"}
    live = FakeLive(snapshot("active", [device()], [ev]))
    c, _ = client_for(tmp_path, live)
    resp = c.get("/live/panel")
    html = resp.get_data(as_text=True)
    assert resp.headers["Cache-Control"] == "no-store" and 'data-poll="2000"' in html
    assert XSS not in html and "&lt;script&gt;" in html
    assert "D0:39:57:XX:XX:XX" in html and not FULL_MAC.search(html)
    assert "Acces de la distanță necriptat (Telnet)" in html and "de verificat" in html and "portul 23" in html
    assert "nou" in html and "ascultă pe portul 2323" in html and "IP 172.20.10.9 · MAC D0:39:57:XX:XX:XX" in html
    assert 'data-latest="Dispozitiv nou' in html


@pytest.mark.parametrize("path", ["/live/start", "/live/stop", "/live/scan", "/live/scan/stop"])
def test_live_actions_need_the_token_and_same_site(tmp_path, path):
    live = FakeLive()
    c, token = client_for(tmp_path, live)
    assert c.post(path, data={"token": "gresit", "job": "scan"}).status_code == 400
    assert c.post(path, data={"token": token, "job": "scan"},
                  headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert live.calls == []


def test_start_stop_and_redirects(tmp_path):
    live = FakeLive()
    c, token = client_for(tmp_path, live)
    r = c.post("/live/start", data={"token": token, "confirm": "1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/#live")
    r = c.post("/live/stop", data={"token": token}, headers={"X-Requested-With": "fetch"})
    assert r.headers["Location"].endswith("/live/panel")
    assert live.calls == ["start", "stop"]


def test_scan_button_jobs_and_refusal_message(tmp_path):
    live = FakeLive(code="NOT_ON_HOTSPOT")
    c, token = client_for(tmp_path, live)
    other = c.get("/live/panel?live_msg=%3Cb%3E").get_data(as_text=True)   # doar mesajele cunoscute
    assert "live-msg" not in other and "&lt;b&gt;" not in other
    assert c.post("/live/scan", data={"token": token, "job": "rm -rf /"}).status_code == 400
    r = c.post("/live/scan", data={"token": token, "job": "auto", "confirm": "1"},
               headers={"X-Requested-With": "fetch"})
    assert live.calls == [("scan", "auto")] and "live_msg=NOT_ON_HOTSPOT" in r.headers["Location"]
    html = c.get("/live/panel?live_msg=NOT_ON_HOTSPOT").get_data(as_text=True)
    assert "Nu ești pe hotspotul echipei" in html
    # mesajul rămâne și la reîmprospătarea panoului (fără parametru), nu dispare după 2 s
    assert "Nu ești pe hotspotul echipei" in c.get("/live/panel").get_data(as_text=True)


def test_running_scan_shows_progress_and_found_ports(tmp_path):
    full = dict(IDLE, state="running", phase="tcp", percent=47.3, eta_s=130,
                discovered=[{"ip": "172.20.10.1", "port": 21, "proto": "tcp"}])
    c, _ = client_for(tmp_path, FakeLive(snapshot("active", [device()]), full))
    html = c.get("/live/panel").get_data(as_text=True)
    assert "verific ușile obișnuite (porturile)" in html and 'aria-valuenow="47"' in html and "w-45" in html
    assert "mai durează cam 2 min" in html and "172.20.10.1 · 21/tcp" in html and "Oprește scanarea" in html


def test_done_scan_links_to_its_result(tmp_path):
    from netscan.engine.parser import analyze_file
    scans = [analyze_file(str(LAB / "scan_01_before.xml")), analyze_file(str(LAB / "scan_03_after.xml"))]
    full = dict(IDLE, state="done", file="scan_03_after.xml", percent=100.0)
    c, _ = client_for(tmp_path, FakeLive(full=full), scans)
    html = c.get("/").get_data(as_text=True)
    assert "/?file=scan_03_after.xml" in html
    page = c.get("/?file=scan_03_after.xml").get_data(as_text=True)
    assert re.search(r'<option value="scan_03_after.xml" title="scan_03_after.xml" selected>', page)


def test_dashboard_prefers_your_own_scans_newest_first(tmp_path, monkeypatch):
    mine = tmp_path / "scans"
    mine.mkdir()
    shutil.copy(LAB / "scan_01_before.xml", mine)
    shutil.copy(LAB / "scan_03_after.xml", mine)
    monkeypatch.setattr(app_mod, "USER_SCANS_DIR", mine)
    monkeypatch.delenv("NETSCAN_SCANS_DIR", raising=False)
    assert [s.file for s in app_mod.load_dashboard_scans()] == ["scan_03_after.xml", "scan_01_before.xml"]
    monkeypatch.setenv("NETSCAN_SCANS_DIR", str(LAB))
    assert [s.file for s in app_mod.load_dashboard_scans()][:1] == ["scan_01_before.xml"]
    monkeypatch.delenv("NETSCAN_SCANS_DIR")
    monkeypatch.setattr(app_mod, "USER_SCANS_DIR", tmp_path / "gol")
    assert "V1_home_basic.xml" in [s.file for s in app_mod.load_dashboard_scans()]


def test_tests_never_get_a_real_live_monitor(tmp_path):
    app = create_app({"SCAN_LOADER": lambda: [], "DB_PATH": tmp_path / "h.db", "TESTING": True})
    snap = app.config["LIVE"].snapshot()
    assert snap["status"] == "off" and app.config["LIVE"].request_full_scan("scan") == "NOT_ON_HOTSPOT"
