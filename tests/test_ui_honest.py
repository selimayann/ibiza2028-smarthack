"""WS-B: backend onest. Scorul mare e al motorului, acțiunile ajung pe scanarea văzută, verificarea nu atinge rețeaua
pentru fișiere analizate, nimic live nu pornește fără consimțământ, dovezile înainte/după nu ghicesc.
Fără rețea: monitorul live e simulat, verificarea pașilor folosește funcții de probă."""
import csv
import re
import shutil
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from flask import template_rendered

from netscan.engine import analyze_file
from netscan.model import Finding, Host, Port, Scan
from netscan.scan import network
from netscan.ui import app as app_mod
from netscan.ui import storage, verify
from netscan.ui.app import create_app
from netscan.ui.view import (csv_view, evidence_text, order_devices, proof_view, rank_devices, verdict_view,
                             verified_by_newer, worst_device)
from tests.test_ui_app import ref, sample
from tests.test_ui_live import IDLE, FakeLive, device, snapshot

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"
VALIDATION = ROOT / "fixtures" / "validation"
FULL_MAC = re.compile(r"([0-9A-F]{2}:){5}[0-9A-F]{2}")


def never_probe(ip, port):
    raise AssertionError(f"nu trebuia atinsă rețeaua ({ip}:{port})")


def make(tmp_path, scans, **cfg):
    base = {"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True}
    app = create_app({**base, **cfg})
    return app.test_client(), app


@contextmanager
def captured(app):
    """Contextul trimis template-urilor (contractul cu WS-C)."""
    seen = []

    def record(sender, template, context, **extra):
        seen.append((template.name, context))

    template_rendered.connect(record, app)
    try:
        yield seen
    finally:
        template_rendered.disconnect(record, app)


def ctx_of(app, client, url, name="overview.html"):
    with captured(app) as seen:
        resp = client.get(url)
        assert resp.status_code == 200
    return next(c for n, c in seen if n == name)


# ---------- 1. scorul onest + verdictul ----------

def test_big_score_is_always_the_engine_score_on_lab_scan_01(tmp_path):
    s1 = analyze_file(LAB / "scan_01_before.xml")
    s3 = analyze_file(LAB / "scan_03_after.xml")
    assert (s1.score, s3.score) == (0, 30)
    client, app = make(tmp_path, [s1, s3])
    ctx = ctx_of(app, client, "/?file=scan_01_before.xml")
    assert ctx["score_std"] == 0 and ctx["scan"].file == "scan_01_before.xml"
    html = client.get("/?file=scan_01_before.xml").get_data(as_text=True)
    assert '<span class="score-num">0</span>' in html
    # scan_03 nu a mai listat porturile 2323 și 6379: nu dovedește că au fost închise, deci nu confirmă nimic
    assert verified_by_newer(s1, [s3]) == {}
    assert ctx["score_now"] == 0 and ctx["score_now_differs"] is False


def test_score_now_is_separate_and_only_from_the_engine(tmp_path):
    s = sample()
    client, app = make(tmp_path, [s], OWN_SCAN_CHECK=lambda x: True, NET_CHECK=lambda ip: True,
                       PORT_PROBE=lambda ip, port: "closed")
    first = rank_devices(s)[0].worst
    client.post("/action/done", data={"token": app.config["FORM_TOKEN"], **ref(s), "device_id": first.device_id,
                                      "port": first.port, "code": first.code})
    ctx = ctx_of(app, client, "/")
    assert ctx["score_std"] == s.score == 40
    assert ctx["score_now"] > 40 and ctx["score_now_differs"] is True
    html = client.get("/").get_data(as_text=True)
    # cifra mare = scorul de acum (din motor, fără problemele confirmate); cel oficial (40) rămâne scris dedesubt
    assert f'<span class="score-num">{ctx["score_now"]}</span>' in html and "Scorul oficial al acestei scanări: 40." in html


def test_verdict_counts_engine_severities_and_names_the_worst():
    s = sample()
    v = verdict_view(s, set(), set(), "ro")
    assert v["band"] == "poor" and v["score"] == 40
    assert (v["n_high"], v["n_medium"], v["n_low"], v["n_info"]) == tuple(
        sum(1 for f in s.findings if f.severity == sev) for sev in ("high", "medium", "low", "info"))
    assert v["worst_ip"] == "192.168.1.40" and v["first_code"] == "CAMERA_STREAM_EXPOSED" and v["first_step"]
    assert v["n_devices"] == 3 and v["n_devices_with_problems"] == 3
    en = verdict_view(s, set(), set(), "en")
    assert en["worst_name"] and en["first_step"] != v["first_step"]
    assert verdict_view(Scan(file="x", status="error", error_code="EMPTY"))["band"] is None


def test_verdict_reports_a_tie_instead_of_hiding_it():
    f = lambda ip, port: Finding(file="x", ip=ip, device_id=ip, port=port, code="TELNET_OPEN",  # noqa: E731
                                 severity="high", points=20, evidence="e")
    scan = Scan(file="x", status="ok", score=60, hosts=[Host(ip="10.0.0.2", device_id="10.0.0.2"),
                                                         Host(ip="10.0.0.3", device_id="10.0.0.3")],
                findings=[f("10.0.0.2", 23), f("10.0.0.3", 23)])
    v = verdict_view(scan)
    assert v["worst_ip"] == "10.0.0.2" and v["tie_ip"] == "10.0.0.3"


def test_newer_scan_must_cover_the_port_and_be_the_same_network():
    old = sample()
    gone = rank_devices(old)[0].worst                                  # camera, port 554
    new = replace(old, file="after.xml", started_at=old.started_at + 3600,
                  findings=[f for f in old.findings if f.key() != gone.key()])
    assert verified_by_newer(old, [new]) == {gone.key(): "after.xml"}
    # aceeași cameră, dar scanarea nouă nu a văzut deloc portul 554: nu știm, deci nu e confirmat
    hosts = [replace(h, ports=[p for p in h.ports if p.port != 554]) if h.device_id == gone.device_id else h
             for h in old.hosts]
    assert verified_by_newer(old, [replace(new, hosts=hosts)]) == {}
    # altă rețea (alt /24): nu confirmă nimic
    other = replace(new, hosts=[replace(h, ip=h.ip.replace("192.168.1.", "10.9.9.")) for h in new.hosts])
    assert verified_by_newer(old, [other]) == {}


# ---------- 2. consecvență: cardul „Cel mai periculos” == primul rând din listă ----------

def test_worst_card_equals_first_device_row_after_verified_fixes(tmp_path):
    s = sample()
    client, app = make(tmp_path, [s])
    top = rank_devices(s)[0]
    storage.mark_verified(s, [f.key() for f in top.findings], app.config["DB_PATH"])
    ctx = ctx_of(app, client, "/")
    assert ctx["worst"].host.ip == ctx["devices"][0].host.ip == "192.168.1.1"
    assert ctx["devices"][-1].host.ip == top.host.ip                  # rezolvat complet -> la final
    assert ctx["fixed_keys"] == {f.key() for f in top.findings}
    html = client.get("/").get_data(as_text=True)
    worst_card = html.split('id="worst"', 1)[1].split("</section>", 1)[0]
    first_row = html.split('class="device-row"', 1)[1].split("</li>", 1)[0]
    assert "192.168.1.1" in worst_card and "192.168.1.1<" in first_row


def test_order_devices_puts_fixed_findings_last_and_keeps_contract_without_fixes():
    s = sample()
    assert [d.host.ip for d in order_devices(s)] == [d.host.ip for d in rank_devices(s)]
    router = next(d for d in rank_devices(s) if d.host.ip == "192.168.1.1")
    fixed = {router.findings[0].key()}
    row = next(d for d in order_devices(s, fixed) if d.host.ip == "192.168.1.1")
    assert row.findings[-1].key() in fixed and len(row.findings) == len(router.findings)
    w = worst_device(s, fixed)                                   # doar problemele nerezolvate, pe card
    assert w.host.ip == "192.168.1.40" and all(f.key() not in fixed for f in w.findings)
    cam_fixed = {f.key() for f in rank_devices(s)[0].findings}
    assert worst_device(s, cam_fixed).host.ip == "192.168.1.1"


# ---------- 3. identitatea scanării: după fișier, nu după poziție ----------

def test_accept_goes_to_the_scan_the_user_saw_even_after_a_new_scan_arrives(tmp_path):
    a = analyze_file(LAB / "scan_01_before.xml")
    b = analyze_file(LAB / "scan_03_after.xml")
    shown = [a]
    client, app = make(tmp_path, shown)
    f = rank_devices(a)[0].worst
    form = {"token": app.config["FORM_TOKEN"], **ref(a), "device_id": f.device_id, "port": f.port or "",
            "code": f.code}
    shown.insert(0, b)                      # între afișare și clic apare o scanare nouă, pe poziția 0
    resp = client.post("/action/accept", data=form)
    assert resp.status_code == 302 and "file=scan_01_before.xml" in resp.headers["Location"]
    assert storage.accepted_keys(a, app.config["DB_PATH"]) == {f.key()}
    assert storage.accepted_keys(b, app.config["DB_PATH"]) == set()


def test_missing_scan_gives_409_for_fetch_and_a_notice_otherwise(tmp_path):
    s = sample()
    client, app = make(tmp_path, [s])
    f = s.findings[0]
    form = {"token": app.config["FORM_TOKEN"], "file": "nu-mai-exista.xml", "device_id": f.device_id,
            "port": f.port, "code": f.code}
    resp = client.post("/action/accept", data=form, headers={"X-Requested-With": "fetch"})
    assert resp.status_code == 409 and "s-a schimbat" in resp.get_data(as_text=True)
    resp = client.post("/action/accept", data=form)
    assert resp.status_code == 302 and "notice=scan_list_changed" in resp.headers["Location"]
    ctx = ctx_of(app, client, resp.headers["Location"])
    assert "s-a schimbat" in ctx["notice"]
    # aceeași dată greșită = altă scanare (fișier refolosit)
    assert client.post("/action/accept", data={**form, "file": s.file, "started_at": "1"},
                       headers={"X-Requested-With": "fetch"}).status_code == 409
    # fără fișier: cerere greșită (poziția în listă nu mai e acceptată la POST)
    assert client.post("/action/accept", data={**{k: v for k, v in form.items() if k != "file"},
                                               "scan": 0}).status_code == 400
    assert storage.accepted_keys(s, app.config["DB_PATH"]) == set()


def test_get_links_by_file_and_old_scan_index_still_work(tmp_path):
    a, b = analyze_file(LAB / "scan_01_before.xml"), analyze_file(LAB / "scan_03_after.xml")
    client, app = make(tmp_path, [b, a])
    assert ctx_of(app, client, f"/?file={a.file}&started_at={a.started_at}")["scan"].file == a.file
    assert ctx_of(app, client, "/?scan=1")["scan"].file == a.file
    assert ctx_of(app, client, "/")["scan_ref"] == {"file": b.file, "started_at": b.started_at}


# ---------- 4. de unde vine scanarea: doar scanarea NOASTRĂ cea mai nouă poate fi verificată live ----------

def _tick(client, app, s, f):
    return client.post("/action/done", data={"token": app.config["FORM_TOKEN"], **ref(s), "device_id": f.device_id,
                                             "port": f.port, "code": f.code})


def test_analysed_file_is_never_probed(tmp_path):
    s = sample()                              # ca Validation / Test Set: nu e scris de scanerul nostru
    client, app = make(tmp_path, [s], NET_CHECK=lambda ip: True, PORT_PROBE=never_probe)
    f = rank_devices(s)[0].worst
    resp = _tick(client, app, s, f)
    assert "check=file_only" in resp.headers["Location"]
    db = app.config["DB_PATH"]
    assert storage.verified_keys(s, db) == set() and storage.done_keys(s, db) == {f.key()}
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "nu verific nimic în rețea" in html


class SameDeviceLive(FakeLive):
    def __init__(self, answer):
        super().__init__()
        self.answer, self.asked = answer, []

    def same_device(self, ip, device_id):
        self.asked.append((ip, device_id))
        return self.answer


def test_other_device_on_the_same_ip_is_not_confirmed(tmp_path):
    s = sample()
    live = SameDeviceLive(False)
    client, app = make(tmp_path, [s], LIVE=live, OWN_SCAN_CHECK=lambda x: True, NET_CHECK=lambda ip: True,
                       PORT_PROBE=never_probe)
    f = rank_devices(s)[0].worst
    resp = _tick(client, app, s, f)
    assert "check=other_device" in resp.headers["Location"] and live.asked == [(f.ip, f.device_id)]
    assert storage.verified_keys(s, app.config["DB_PATH"]) == set()
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "alt dispozitiv" in html


def test_same_device_or_unknown_allows_the_single_probe(tmp_path):
    s = sample()
    for answer in (True, None):
        calls = []
        client, app = make(tmp_path / str(answer), [s], LIVE=SameDeviceLive(answer), OWN_SCAN_CHECK=lambda x: True,
                           NET_CHECK=lambda ip: True, PORT_PROBE=lambda ip, port: calls.append(port) or "closed")
        f = rank_devices(s)[0].worst
        assert "check=ok" in _tick(client, app, s, f).headers["Location"] and calls == [f.port]


def test_own_newest_scan_only_for_our_newest_file(tmp_path, monkeypatch):
    mine = tmp_path / "scans"
    mine.mkdir()
    shutil.copy(LAB / "scan_01_before.xml", mine)
    shutil.copy(LAB / "scan_03_after.xml", mine)
    monkeypatch.delenv("NETSCAN_SCANS_DIR", raising=False)
    s1, s3 = analyze_file(mine / "scan_01_before.xml"), analyze_file(mine / "scan_03_after.xml")
    assert app_mod.own_newest_scan(s3, mine) is True
    assert app_mod.own_newest_scan(s1, mine) is False                      # mai veche
    assert app_mod.own_newest_scan(analyze_file(VALIDATION / "V2_smart_home.xml"), mine) is False
    assert app_mod.own_newest_scan(replace(s3, started_at=1), mine) is False   # alt conținut, același nume
    assert app_mod.own_newest_scan(s3, mine, env={"NETSCAN_SCANS_DIR": str(LAB)}) is False
    assert app_mod.own_newest_scan(s3, mine, env={"NETSCAN_SCANS_DIR": str(mine)}) is True
    assert app_mod.own_newest_scan(replace(s3, file="../scan_03_after.xml"), mine) is False
    assert app_mod.own_newest_scan(None, mine) is False


def test_tests_never_read_the_repo_scans_folder(tmp_path):
    _, app = make(tmp_path, [])
    assert Path(app.config["USER_SCANS_DIR"]) != app_mod.USER_SCANS_DIR
    assert app.config["OWN_SCAN_CHECK"](analyze_file(LAB / "scan_03_after.xml")) is False


def test_my_network_needs_the_exact_team_ssid(monkeypatch):
    def forbid(*a, **k):
        raise AssertionError("fără conexiuni")
    monkeypatch.setattr("socket.socket", forbid)
    ok = network.NetworkInfo(iface="wlan", ip="172.20.10.2", cidr="172.20.10.0/28", ssid="Echipa", status=network.OK)
    env = {"NETSCAN_EXPECTED_SSID": "Echipa"}
    assert verify.target_in_my_network("172.20.10.5", env, lambda: ok) is True
    # orice hotspot de iPhone are același subnet: fără numele exact, nu e al nostru
    assert verify.target_in_my_network("172.20.10.5", env, lambda: replace(ok, ssid=None)) is False
    assert verify.target_in_my_network("172.20.10.5", env, lambda: replace(ok, ssid="Altcineva")) is False
    called = []
    assert verify.target_in_my_network("172.20.10.5", {}, lambda: called.append(1) or ok) is False and not called
    assert verify.target_in_my_network("8.8.8.8", env, lambda: ok) is False


def test_check_finding_order_and_message_args():
    f = Finding(file="x", ip="10.0.0.5", device_id="d", port=23, code="TELNET_OPEN", severity="high", points=20,
                evidence="e")
    s = Scan(file="x", status="ok", hosts=[Host(ip="10.0.0.5", device_id="d", ports=[Port(23, "tcp", "open")])],
             findings=[f])
    assert verify.check_finding(s, f, never_probe, lambda ip: True, probe_allowed=False).result == verify.FILE_ONLY
    assert verify.check_finding(s, f, never_probe, lambda ip: True,
                                same_device=lambda ip, d: False).result == verify.OTHER_DEVICE
    assert verify.message_args(verify.FILE_ONLY, "ip", 1) == ()
    assert verify.message_args(verify.OTHER_DEVICE, "ip", 1) == ("ip",)
    assert verify.message_args(verify.VERIFIED, "ip", 1) == (1, "ip")
    from netscan.ui import i18n
    for lang in i18n.LANGS:            # fiecare rezultat are un text care primește exact argumentele lui
        for r in verify.RESULTS:
            assert i18n.t(lang, "verify_" + r) % verify.message_args(r, "1.2.3.4", 80)


# ---------- 5. consimțământ și protecția live ----------

class ApproveLive(FakeLive):
    def __init__(self, snap=None):
        super().__init__(snap)
        self.approved = []

    def approve(self, device_id):
        self.approved.append(device_id)
        return True


def test_live_start_and_scan_need_explicit_consent(tmp_path):
    live = FakeLive()
    client, app = make(tmp_path, [], LIVE=live)
    token = app.config["FORM_TOKEN"]
    r = client.post("/live/start", data={"token": token}, headers={"X-Requested-With": "fetch"})
    assert live.calls == [] and "CONSENT_REQUIRED" in r.headers["Location"]
    assert "Bifează confirmarea" in client.get("/live/panel").get_data(as_text=True)
    client.post("/live/scan", data={"token": token, "job": "scan"})
    client.post("/live/scan", data={"token": token, "job": "auto", "confirm": "0"})
    assert live.calls == []
    client.post("/live/start", data={"token": token, "confirm": "1"})
    client.post("/live/scan", data={"token": token, "job": "scan", "confirm": "1"})
    assert live.calls == ["start", ("scan", "scan")]


def test_live_message_stays_a_minute_and_is_not_in_the_version(tmp_path, monkeypatch):
    live = FakeLive()
    client, app = make(tmp_path, [], LIVE=live)
    before = ctx_of(app, client, "/live/panel", "_live_panel.html")["live"]
    client.post("/live/start", data={"token": app.config["FORM_TOKEN"]})
    after = ctx_of(app, client, "/live/panel", "_live_panel.html")["live"]
    assert after["msg"] == "CONSENT_REQUIRED" and after["version"] == before["version"]
    now = app_mod.time.time()
    monkeypatch.setattr(app_mod.time, "time", lambda: now + app_mod.LIVE_MSG_TTL_S + 1)
    assert ctx_of(app, client, "/live/panel", "_live_panel.html")["live"]["msg"] is None


def test_approve_route(tmp_path):
    live = ApproveLive()
    client, app = make(tmp_path, [], LIVE=live)
    token = app.config["FORM_TOKEN"]
    assert client.post("/live/approve", data={"token": "x", "device_id": "a1b2c3d4e5f6"}).status_code == 400
    assert client.post("/live/approve", data={"token": token, "device_id": "a1b2c3d4e5f6"},
                       headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/live/approve", data={"token": token, "device_id": "ip:172.20.10.9"}).status_code == 400
    assert live.approved == []
    assert client.post("/live/approve", data={"token": token, "device_id": "a1b2c3d4e5f6"}).status_code == 302
    assert live.approved == ["a1b2c3d4e5f6"]


def test_live_ctx_has_pause_approval_urgent_and_trap_note(tmp_path):
    now = app_mod.time.time()
    new = dict(device(), device_id="a1b2c3d4e5f6", needs_approval=True)
    noid = dict(device(ip="172.20.10.11"), device_id=None, needs_approval=True)
    events = [{"ts": now - 30, "kind": "NEW_DEVICE", "ip": "172.20.10.9", "port": None, "tone": "urgent",
               "text_ro": "nou", "text_en": "new"},
              {"ts": now - 3600, "kind": "TRAP", "ip": "172.20.10.9", "port": 2323, "tone": "urgent",
               "text_ro": "vechi", "text_en": "old"}]
    snap = dict(snapshot("active", [new, noid], events), paused_for_scan=True)
    client, app = make(tmp_path, [], LIVE=FakeLive(snap))
    live = ctx_of(app, client, "/live/panel", "_live_panel.html")["live"]
    assert live["paused_for_scan"] is True and live["has_urgent"] == 1
    assert live["needs_approval"] == [{"device_id": "a1b2c3d4e5f6", "ip": "172.20.10.9",
                                       "name": live["devices"][0]["name"]}]
    assert "nu citește nimic" in live["trap_note"].lower()


def test_run_never_autostarts_live(monkeypatch):
    calls = []

    class FakeMonitor:
        def autostart(self):
            calls.append("autostart")

    class FakeApp:
        config = {"LIVE": FakeMonitor()}

        def run(self, **kw):
            calls.append(("run", kw["host"]))

    monkeypatch.setattr(app_mod, "create_app", lambda: FakeApp())
    app_mod.run(port=5999)
    assert calls == [("run", "127.0.0.1")]


def test_reset_makes_live_forget_its_confirmations(tmp_path):
    class ForgetLive(FakeLive):
        forgotten: list = []

        def forget(self, file=None):
            self.forgotten.append(file)

    s = sample()
    live = ForgetLive()
    client, app = make(tmp_path, [s], LIVE=live)
    client.post("/action/reset", data={"token": app.config["FORM_TOKEN"], **ref(s)})
    assert live.forgotten == [s.file]


# ---------- 7. dovada (evidence) pe limba paginii ----------

def _ev(text, code="UNKNOWN_DEVICE"):
    return Finding(file="x", ip="1.1.1.1", device_id="d", port=None, code=code, severity="low", points=5, evidence=text)


def test_evidence_text_translates_engine_romanian_for_display_only():
    for n, ro, en in ((1, "1 port deschis", "1 open port"), (3, "3 porturi deschise", "3 open ports"),
                      (25, "25 de porturi deschise", "25 open ports")):
        f = _ev(f"fără producător și fără nume, {n} port(uri) deschise")
        assert evidence_text(f, "ro") == f"fără producător și fără nume, {ro}"
        assert evidence_text(f, "en") == f"no maker and no name, {en}"
        assert f.evidence.endswith("port(uri) deschise")                  # datele motorului rămân neatinse
    t = _ev("80/tcp http nginx, titlu: Router login, titlu: x", "HTTP_ADMIN_CLEARTEXT")
    assert evidence_text(t, "en") == "80/tcp http nginx, title: Router login, titlu: x"
    assert evidence_text(t, "ro") == t.evidence
    assert evidence_text(_ev("22/tcp ssh OpenSSH 7.2", "SSH_OPEN"), "en") == "22/tcp ssh OpenSSH 7.2"


def test_english_device_page_shows_no_romanian_evidence(tmp_path):
    s = Scan(file="u.xml", status="ok", score=95, hosts=[Host(ip="10.0.0.9", device_id="d9", ports=[
        Port(81, "tcp", "open")])], findings=[_ev("fără producător și fără nume, 1 port(uri) deschise")])
    s.findings[0] = replace(s.findings[0], ip="10.0.0.9", device_id="d9")
    client, app = make(tmp_path, [s])
    ctx = ctx_of(app, client, "/device/d9?lang=en", "device.html")
    assert ctx["evidence_text"](s.findings[0]) == "no maker and no name, 1 open port"


# ---------- 8. ștergerea istoricului șterge și scanările brute ----------

def _raw_folder(tmp_path):
    raw = tmp_path / "scans"
    raw.mkdir()
    for name in ("a.xml", "b.xml.part", ".scan_progress.json", "nmap-service-probes.netscan"):
        (raw / name).write_text("x", encoding="utf-8")
    return raw


def test_delete_history_with_raw_files(tmp_path):
    raw = _raw_folder(tmp_path)

    class ForgetLive(FakeLive):
        def __init__(self):
            super().__init__()
            self.forgot = []

        def forget(self, file=None):
            self.forgot.append(file)

    live = ForgetLive()
    client, app = make(tmp_path, [sample()], LIVE=live, USER_SCANS_DIR=raw)
    storage.save_scan(sample(), app.config["DB_PATH"])
    resp = client.post("/history/delete", data={"token": app.config["FORM_TOKEN"], "delete_raw": "1"})
    assert resp.status_code == 302 and "raw=1" in resp.headers["Location"]
    assert sorted(p.name for p in raw.iterdir()) == ["nmap-service-probes.netscan"]
    assert storage.list_scans(app.config["DB_PATH"]) == [] and live.forgot == [None]
    assert ctx_of(app, client, resp.headers["Location"], "history.html")["deleted_raw"] is True


def test_delete_history_without_raw_keeps_the_files(tmp_path):
    raw = _raw_folder(tmp_path)
    client, app = make(tmp_path, [sample()], USER_SCANS_DIR=raw)
    resp = client.post("/history/delete", data={"token": app.config["FORM_TOKEN"]})
    assert "raw=" not in resp.headers["Location"] and len(list(raw.iterdir())) == 4
    assert ctx_of(app, client, resp.headers["Location"], "history.html")["deleted_raw"] is None


def test_raw_delete_refuses_fixtures():
    with pytest.raises(ValueError):
        storage.delete_raw_scans(ROOT / "fixtures" / "lab")
    assert (LAB / "scan_01_before.xml").is_file()
    assert storage.delete_raw_scans(ROOT / "nu-exista-folderul") == 0


# ---------- 11. dovada înainte / după ----------

def test_proof_v6a_to_v6b():
    a, b = analyze_file(VALIDATION / "V6a_before.xml"), analyze_file(VALIDATION / "V6b_after.xml")
    p = proof_view(a, b, storage.diff(a, b))
    assert (p["score_before"], p["score_after"], p["direction"]) == (60, 100, "up")
    assert (p["n_fixed"], p["n_not_seen"], p["n_new"]) == (3, 0, 0)
    assert all(x["likely_same"] for x in p["fixed"])              # MAC schimbat: recunoscut după IP
    assert (p["file_before"], p["file_after"]) == ("V6a_before.xml", "V6b_after.xml")


def test_proof_lists_a_removed_device_as_not_seen():
    old = sample()
    cam = rank_devices(old)[0]
    new = replace(old, started_at=old.started_at + 60, hosts=[h for h in old.hosts if h.device_id != cam.host.device_id],
                  findings=[f for f in old.findings if f.device_id != cam.host.device_id], score=70)
    p = proof_view(old, new, storage.diff(old, new))
    assert p["n_fixed"] == 0 and {f.key() for f in p["not_seen"]} == {f.key() for f in cam.findings}


def test_history_page_and_report_get_proof_and_compare(tmp_path):
    client, app = make(tmp_path, [])
    db = app.config["DB_PATH"]
    storage.save_scan(analyze_file(VALIDATION / "V6a_before.xml"), db)
    b_id = storage.save_scan(analyze_file(VALIDATION / "V6b_after.xml"), db)
    ctx = ctx_of(app, client, f"/scan/{b_id}")
    assert ctx["proof"]["n_fixed"] == 3 and ctx["score_std"] == 100
    html = client.get(f"/scan/{b_id}").get_data(as_text=True)
    assert "60 → 100" in html and not FULL_MAC.search(html)
    rep = ctx_of(app, client, f"/scan/{b_id}/report", "report.html")
    assert rep["compare"] is not None and rep["proof"]["n_fixed"] == 3


# ---------- 10 + 12. raportul și rândurile ca în findings.csv ----------

def test_csv_view_matches_expected_findings_csv():
    s = analyze_file(VALIDATION / "V2_smart_home.xml")
    with open(VALIDATION / "expected_findings.csv", encoding="utf-8", newline="") as fh:
        expected = [r for r in csv.DictReader(fh) if r["file"] == s.file]
    rows = csv_view(s)["findings"]
    assert [{k: str(v) for k, v in r.items()} for r in rows] == expected
    assert csv_view(s)["score"] == {"file": "V2_smart_home.xml", "network_score": 40}
    broken = csv_view(Scan(file="V7_broken.xml", status="error", error_code="TRUNCATED"))
    assert broken["findings"] == [] and broken["score"]["network_score"] == "ERROR"


def test_report_rows_follow_the_home_page_steps(tmp_path):
    from netscan.ui.view import action_plan
    s = sample()
    client, app = make(tmp_path, [s])
    ctx = ctx_of(app, client, "/report", "report.html")
    assert [r["finding"].key() for r in ctx["rows"]] == [f.key() for f in action_plan(s)]
    assert [r["n"] for r in ctx["rows"]] == list(range(1, len(s.findings) + 1))
    assert ctx["score_std"] == 40 and ctx["csv"]["findings"]
