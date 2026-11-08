"""B + RBRT: pașii ghidați (sar peste / accept riscul), reparațiile confirmate live, scanarea mai rapidă și
tabelul live pe înțeles. Fără rețea: totul e simulat."""
import json
import os
import re
import shutil
import time
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_file
from netscan.scan import live, runner, scan_job
from netscan.scan.network import NetworkInfo
from netscan.ui import i18n, storage
from netscan.ui.app import create_app
from netscan.ui.view import steps_view

from tests.test_live import HOTSPOT, Net, dev_id, make, nb, sweep, T0
from tests.test_ui_live import FakeLive, client_for, device, snapshot

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"
BEFORE = analyze_file(str(LAB / "scan_01_before.xml"))


def lab_nb(ip):
    """Dispozitivul din lab, văzut live cu ACELAȘI device_id ca în scanare (același MAC, același salt)."""
    host = next(h for h in analyze_file(str(LAB / "scan_01_before.xml")).hosts if h.ip == ip)
    return nb(ip, host.mac_masked or "66:48:42:XX:XX:XX", device_id=host.device_id)


# ---------- „Accept riscul”: problema rămâne, scorul nu se schimbă ----------

def test_accepted_risk_is_stored_cleared_and_deleted(tmp_path):
    db = tmp_path / "h.db"
    k = BEFORE.findings[0].key()
    storage.mark_accepted(BEFORE, k, db)
    assert storage.accepted_keys(BEFORE, db) == {k}
    storage.reset_done(BEFORE, db)
    assert storage.accepted_keys(BEFORE, db) == set()
    storage.mark_accepted(BEFORE, k, db)
    storage.delete_history(db)
    assert storage.accepted_keys(BEFORE, db) == set()


def test_accepted_step_keeps_the_score_and_moves_on():
    first = steps_view(BEFORE, set(), set(), {})
    k = first.steps[0].finding.key()
    sv = steps_view(BEFORE, set(), set(), {}, accepted={k})
    assert sv.steps[0].status == "accepted" and sv.accepted_count == 1
    assert sv.score_now == first.score_now == BEFORE.score            # scorul e al motorului, nu se negociază
    assert sv.index == 1 and k not in sv.fixed_keys


def _client(tmp_path, live_=None):
    app = create_app({"SCAN_LOADER": lambda: [BEFORE], "DB_PATH": tmp_path / "h.db", "TESTING": True,
                      "LIVE": live_ or FakeLive()})
    return app.test_client(), app.config["FORM_TOKEN"]


def test_accept_route_needs_token_same_site_and_a_real_finding(tmp_path):
    c, token = _client(tmp_path)
    f = steps_view(BEFORE, set(), set(), {}).steps[0].finding
    form = {"token": token, "file": BEFORE.file, "device_id": f.device_id, "port": f.port, "code": f.code}
    assert c.post("/action/accept", data={**form, "token": "x"}).status_code == 400
    assert c.post("/action/accept", data=form, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/action/accept", data={**form, "code": "INVENTAT"}).status_code == 400
    assert c.post("/action/accept", data=form).status_code == 302
    assert storage.accepted_keys(BEFORE, tmp_path / "h.db") == {f.key()}
    html = c.get("/?step=1").get_data(as_text=True)
    # pe Acasă rămâne starea pasului; numărătorile („1 acceptat de tine”) nu mai sunt pe cardul simplificat
    assert "Risc acceptat de tine" in html and "1 acceptate" not in html
    assert f'<span class="score-num">{BEFORE.score}</span>' in html


def test_step_card_has_skip_accept_and_where_to_do_it(tmp_path):
    c, _ = _client(tmp_path)
    html = c.get("/").get_data(as_text=True)
    assert "Sar peste acum" in html and "Accept riscul și trec mai departe" in html
    # „Unde se face” îl arată acum filmul (locul pentru el e pe card, cu problema și aparatul)
    assert 'class="film-slot"' in html and 'data-code="' in html


def test_gateway_gets_the_hotspot_explanation(tmp_path):
    worst = steps_view(BEFORE, set(), set(), {}).current.device.ip
    snap = snapshot("active")
    snap["gateway"] = worst
    c, _ = _client(tmp_path, FakeLive(snap))
    # routerul rețelei (la noi, telefonul cu hotspotul) primește filmul de router/hotspot
    assert 'data-router="1"' in c.get("/").get_data(as_text=True)


# ---------- reparațiile confirmate live -> scorul (al motorului) ----------

def _lab_scan_dir(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    shutil.copy(LAB / "scan_01_before.xml", scans / "scan_01_before.xml")
    return scans


def test_closed_finding_port_is_confirmed_and_recomputes_the_score(tmp_path):
    _lab_scan_dir(tmp_path)
    net = Net()
    net.present = {"172.20.10.14": lab_nb("172.20.10.14"), "172.20.10.1": lab_nb("172.20.10.1")}
    net.open = {"172.20.10.14": {22, 1883, 2121, 8080}, "172.20.10.1": {21, 53, 62078}}  # Telnet și Redis închise (ca în lab)
    m = make(net, tmp_path, persist=True)
    sweep(m, T0)
    db = tmp_path / "data" / "netscan.db"
    scan = m.known_scan().scan                      # analizată acum (salt-ul poate diferi de cel de la import)
    verified = storage.verified_keys(scan, db)
    assert {k[2] for k in verified} == {"TELNET_OPEN", "DB_EXPOSED"} and m.fixes == 2
    assert any(e.kind == "FIX_CONFIRMED" and "2323" in e.text_ro for e in m.events)
    sv = steps_view(scan, set(), verified, {})
    assert sv.score_now == 30 > scan.score                        # scorul urcă (ca scan_03_after), calculat de motor
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert m.fixes == 2                                              # o singură confirmare pe reparație


def test_unknown_answers_and_udp_findings_are_never_confirmed(tmp_path):
    _lab_scan_dir(tmp_path)
    net = Net()
    net.present = {"172.20.10.14": lab_nb("172.20.10.14")}
    m = make(net, tmp_path, persist=True, probe=lambda ip, port: "unknown")
    sweep(m, T0)
    assert m.fixes == 0 and storage.verified_keys(BEFORE, tmp_path / "data" / "netscan.db") == set()
    assert m.devices["172.20.10.14"].pulsed                          # verificat (e în scanare), dar fără refuz clar
    m2 = make(Net(), tmp_path, persist=True)
    cam = live.LiveDevice(ip="172.20.10.14", mac_masked=None, vendor=None, private_mac=False, first_seen=T0,
                          last_seen=T0, device_id=lab_nb("172.20.10.14").device_id)
    m2._confirm_fix(m2.known_scan(), cam, 1900, T0)                   # UPnP e UDP: o conexiune TCP nu spune nimic
    assert m2.fixes == 0


def test_dashboard_refreshes_the_score_when_a_fix_is_confirmed(tmp_path):
    snap = snapshot("active", [device()])
    snap["fixes"] = 3
    c, _ = client_for(tmp_path, FakeLive(snap))
    assert 'data-fixes="3"' in c.get("/live/panel").get_data(as_text=True)
    js = (ROOT / "netscan" / "ui" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'dataset.fixes' in js and '["#score", "#worst"]' in js


# ---------- risc nou -> scanarea automată pornește mai devreme ----------

def test_new_risk_asks_the_auto_scan_to_run_now_but_a_new_device_does_not(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1")}
    m = make(net, tmp_path)
    m.approve(dev_id("172.20.10.1"))
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / scan_job.PROGRESS_FILE).write_text(json.dumps(
        {"state": "waiting_next", "job": "auto", "pid": os.getpid(), "started": time.time()}))
    sweep(m, T0)
    assert not (tmp_path / "scans" / scan_job.NOW_FILE).exists()      # ce era deja acolo nu e risc nou
    net.present["172.20.10.9"] = nb("172.20.10.9")
    sweep(m, T0 + 20)
    assert not (tmp_path / "scans" / scan_job.NOW_FILE).exists()      # dispozitiv nou: întâi acordul tău
    net.open["172.20.10.1"] = {6379}
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert m.events[0].kind == "PORT_OPENED" and (tmp_path / "scans" / scan_job.NOW_FILE).exists()
    m._hb_stop.set()


def test_auto_job_runs_early_on_request_but_not_more_often_than_ten_minutes(tmp_path):
    scans = tmp_path / "scans"
    starts, clock = [], [1000.0]

    def run(scans_dir, job, writer):
        starts.append(clock[0])
        (scans / scan_job.NOW_FILE).write_text("now")                 # risc nou imediat după fiecare scanare
        return 0

    def sleep(s):
        clock[0] += 30
        if len(starts) == 3:
            (scans / scan_job.STOP_FILE).write_text("stop")

    scans.mkdir()
    (scans / scan_job.APP_ALIVE_FILE).write_text("viu")              # aplicația e deschisă
    scan_job.main(["auto"], scans_dir=scans, run=run, sleep=sleep, now=lambda: clock[0], load_env=False)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert len(starts) == 3 and all(scan_job.MIN_GAP_MIN * 60 <= g < scan_job.AUTO_EVERY_MIN * 60 for g in gaps)


# ---------- scanarea mai rapidă, tot în regula de 100 pachete/s ----------

def test_speed_args_keep_the_rate_rule_and_exclude_this_laptop():
    plan = runner.ScanPlan(True, "OK", "", "", network=HOTSPOT, args=["nmap", "-oX", "x", "172.20.10.0/28"])
    args = runner.speed_args(plan)
    rates = {args[i]: args[i + 1] for i in range(len(args) - 1) if args[i] in ("--min-rate", "--max-rate")}
    assert rates == {"--min-rate": "80"} and int(runner.MAX_RATE) == 100     # --max-rate 100 vine din build_nmap_args
    assert args[-2:] == ["--exclude", "172.20.10.10"] and "--version-intensity" not in args
    assert runner.speed_args(runner.ScanPlan(True, "OK", "", "")) == runner.SPEED_ARGS


# ---------- tabelul live pe înțeles ----------

@pytest.mark.parametrize("port, check, text", [
    (2323, True, "Acces de la distanță necriptat (Telnet)"), (8080, True, "Pagină web fără criptare"),
    (62078, False, "Sincronizare telefon/tabletă"), (53, False, "Nume de site-uri (DNS), normal la un router"),
    (7070, False, "Streaming audio/video"),
])
def test_port_meaning_in_plain_words(port, check, text):
    assert i18n.port_meaning("ro", port) == {"text": text, "check": check}


def test_unknown_port_uses_the_cleaned_label():
    assert i18n.port_meaning("ro", 31337, "elite")["text"] == "Un program (elite)"
    assert i18n.port_meaning("en", 31337)["text"] == "A program"


def test_live_table_names_the_router_and_hides_jargon(tmp_path):
    gw = dict(device(ip="172.20.10.1", vendor=None, ports=({"port": 21, "label": "ftp"},), new=False),
              is_gateway=True)
    c, _ = client_for(tmp_path, FakeLive(snapshot("active", [gw])))
    html = c.get("/live/panel").get_data(as_text=True)
    assert "Routerul (telefonul cu hotspotul)" in html and "Transfer de fișiere necriptat (FTP)" in html
    assert "msrpc" not in html and "tcpwrapped" not in html
