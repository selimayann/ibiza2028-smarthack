"""Regulile de angajare (WS-A): doar hotspotul echipei, ≤100 pachete/s în total, doar dispozitivele echipei,
acordul înainte de orice verificare, nicio confirmare inventată, nimic citit de la alții.

Totul e simulat: rețeaua, tabela ARP, conexiunile, nmap și capcana. Testele nu ating rețeaua."""
import json
import os
import shutil
import threading
import time
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_file
from netscan.model import Finding, Host, Port, Scan
from netscan.scan import eavesdrop, elevate, guardrail, live, network, runner, scan_job, trap
from netscan.scan.network import NetworkInfo
from netscan.ui import storage

from tests.test_live import ENV, HOTSPOT, VENUE, Net, dev_id, make, nb, sweep, T0

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"


def kinds(m):
    return [e.kind for e in m.events]


def lab_dir(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir(exist_ok=True)
    shutil.copy(LAB / "scan_01_before.xml", scans / "scan_01_before.xml")
    return scans


def lab_host(ip):
    return next(h for h in analyze_file(str(LAB / "scan_01_before.xml")).hosts if h.ip == ip)


def lab_nb(ip):
    h = lab_host(ip)
    return nb(ip, h.mac_masked or "66:48:42:XX:XX:XX", device_id=h.device_id)


def progress(scans, **data):
    scans.mkdir(parents=True, exist_ok=True)
    data.setdefault("started", time.time())
    (scans / scan_job.PROGRESS_FILE).write_text(json.dumps(data))


# ---------- 1. SSID fail-closed: subnetul singur nu e o dovadă ----------

IPHONE_NO_SSID = NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", gateway="172.20.10.1",
                             ssid=None, status="OK")        # „OK” la detect, dar numele Wi-Fi nu se poate citi
OTHER_IPHONE = NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", gateway="172.20.10.1",
                           ssid="iPhone-ul altei echipe", status="OK")


@pytest.mark.parametrize("info, env, code", [
    (IPHONE_NO_SSID, ENV, network.SSID_UNREADABLE),
    (OTHER_IPHONE, ENV, network.WRONG_SSID),
    (HOTSPOT, {}, network.SSID_NOT_CONFIGURED),
])
def test_live_gate_needs_the_exact_team_ssid(tmp_path, info, env, code):
    net, built, launched = Net(info), [], []
    m = make(net, tmp_path, env=env, trap_server=lambda *a: built.append(a), launcher=launched.append)
    net.present = {"172.20.10.1": nb("172.20.10.1")}
    m.approve(dev_id("172.20.10.1"))
    for i in range(4):
        sweep(m, T0 + i * 30)
    assert net.poked == [] and net.probed == [] and built == []
    assert m.status == live.PAUSED and m.reason == code and m.snapshot()["ssid"] is None
    assert m.request_full_scan("scan") == "NOT_ON_HOTSPOT" and launched == []


def test_unreadable_ssid_message_is_plain_in_both_languages(tmp_path):
    m = make(Net(IPHONE_NO_SSID), tmp_path)
    m.tick(T0)
    snap = m.snapshot()
    assert "Wi-Fi" in snap["reason_ro"] and "Wi-Fi" in snap["reason_en"]


@pytest.mark.parametrize("before, after", [(None, "1"), ("", "1"), ("1", "1"), ("0", "0")])
def test_in_app_scan_requires_a_readable_ssid_by_default(tmp_path, monkeypatch, before, after):
    if before is None:
        monkeypatch.setenv("NETSCAN_REQUIRE_SSID", "x")
        monkeypatch.delenv("NETSCAN_REQUIRE_SSID")
    else:
        monkeypatch.setenv("NETSCAN_REQUIRE_SSID", before)
    seen = []
    scan_job.main(["scan"], scans_dir=tmp_path / "scans",
                  run=lambda *a: seen.append(os.environ.get("NETSCAN_REQUIRE_SSID")) or 0, load_env=False)
    assert seen == [after]


def test_require_ssid_turns_an_unreadable_name_into_a_refusal_before_nmap():
    from tests.test_network import FakePsutil, WIN_IFACES, windows_runner
    env = {"NETSCAN_EXPECTED_SSID": "RSH-ibiza2028", "NETSCAN_REQUIRE_SSID": "1"}
    plan = runner.prepare_scan(None, env=env, nmap_path="nmap", top_ports="22,80",
                               detect=lambda: network.detect_network(windows_runner(netsh=None),
                                                                     FakePsutil(WIN_IFACES), "windows", env))
    assert not plan.ok and plan.reason_code == network.SSID_UNREADABLE and plan.args == []


def test_env_example_turns_require_ssid_on():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nNETSCAN_REQUIRE_SSID=1\n" in text.replace("\r\n", "\n")


# ---------- 2. bugetul de pachete e comun: live stă în pauză cât rulează nmap ----------

def test_no_sweep_and_no_pulse_while_the_full_scan_runs(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1")}
    m = make(net, tmp_path)
    m.approve(dev_id("172.20.10.1"))
    progress(tmp_path / "scans", state="running", job="scan", pid=os.getpid())
    for i in range(3):
        sweep(m, T0 + i * live.PULSE_EVERY_S)
    assert net.poked == [] and net.probed == []
    assert m.snapshot()["paused_for_scan"] is True and not m.allowed("172.20.10.1")
    progress(tmp_path / "scans", state="done", job="scan", pid=os.getpid())
    sweep(m, T0 + 4 * live.PULSE_EVERY_S)
    assert net.poked and net.probed and m.snapshot()["paused_for_scan"] is False


def test_an_in_flight_pulse_stops_probing_when_the_scan_starts(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "PROBE_WORKERS", 1)
    net = Net()
    net.present = {"172.20.10.5": nb("172.20.10.5")}
    m = make(net, tmp_path)
    m.approve(dev_id("172.20.10.5"))
    m.tick(T0)
    original = net.probe

    def probe(ip, port):
        m.paused_for_scan = True                        # scanarea completă a pornit după prima conexiune
        return original(ip, port)

    m.probe = probe
    m.tick(T0 + live.READ_AFTER_S)
    assert len(net.probed) == 1


def test_nmap_rate_is_80_to_100_packets_per_second():
    assert runner.SPEED_ARGS[:2] == ["--min-rate", "80"]
    args = runner.build_nmap_args("172.20.10.0/28", "wlan0", "22,80", "x.xml")
    i = args.index("--max-rate")
    assert args[i + 1] == "100" and int(runner.SPEED_ARGS[1]) <= int(args[i + 1])
    plan = runner.ScanPlan(True, "OK", "", "", network=HOTSPOT, args=args)
    assert runner.speed_args(plan)[-2:] == ["--exclude", "172.20.10.10"]   # laptopul nostru nu e țintă


# ---------- 3. rețeaua, verificată din nou în timpul scanării și înainte de fiecare tură ----------

def _run_with_network(tmp_path, seen_network, finish_anyway=False):
    scans = tmp_path / "scans"
    scans.mkdir(exist_ok=True)
    clock, calls = [1000.0], []

    def prepare(target, out_path):
        return runner.ScanPlan(True, "OK", "", "", network=HOTSPOT, target="172.20.10.0/28", out_path=str(out_path))

    def execute(plan, on_line, should_stop):
        for _ in range(20):
            clock[0] += 1
            if should_stop() and not finish_anyway:
                return runner._refuse(runner.STOPPED, ro="Scanarea a fost oprită.", en="The scan was stopped.")
        Path(plan.out_path).write_text("<nmaprun/>")
        return plan

    def detect():
        calls.append(clock[0])
        return seen_network

    rc = scan_job.run_once(scans, "scan", scan_job.ProgressWriter(scans, every_s=0), prepare=prepare,
                           execute=execute, now=lambda: clock[0], detect=detect)
    return rc, scan_job.read_progress(scans), sorted(p.name for p in scans.glob("*.xml*")), calls


@pytest.mark.parametrize("other", [
    VENUE,
    OTHER_IPHONE,                                                          # același subnet, alt Wi-Fi
    NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", ssid=None, status="OK"),
    NetworkInfo(iface="Wi-Fi", ip="172.20.10.11", cidr="172.20.10.0/28", ssid="RSH-Ibiza2028", status="OK"),
    NetworkInfo(status="NO_NETWORK"),
])
def test_leaving_the_hotspot_mid_scan_stops_nmap(tmp_path, other):
    rc, p, files, calls = _run_with_network(tmp_path, other)
    assert rc == 1 and p["state"] == "stopped" and p["code"] == "NETWORK_CHANGED"
    assert p["msg_ro"] == "Ai ieșit de pe hotspot, așa că am oprit scanarea."
    assert p["msg_en"] == "You left the hotspot, so I stopped the scan."
    assert files == [] and calls == [1005.0]                               # verificat la 5 s, oprit imediat


def test_same_network_is_rechecked_every_5_seconds_and_the_scan_finishes(tmp_path):
    rc, p, files, calls = _run_with_network(tmp_path, HOTSPOT)
    assert rc == 0 and p["state"] == "done" and len(files) == 1 and files[0].endswith(".xml")
    assert calls == [1005.0, 1010.0, 1015.0, 1020.0]


def test_a_scan_that_finished_after_leaving_is_not_kept(tmp_path):
    rc, p, files, _ = _run_with_network(tmp_path, VENUE, finish_anyway=True)
    assert rc == 1 and p["code"] == "NETWORK_CHANGED" and files == []


def test_live_rechecks_the_network_right_before_each_port_check(tmp_path):
    seq = [HOTSPOT, VENUE]
    net = Net()
    net.detect = lambda: seq.pop(0) if len(seq) > 1 else seq[0]
    net.present = {"172.20.10.5": nb("172.20.10.5")}
    m = make(net, tmp_path)
    m.approve(dev_id("172.20.10.5"))
    m.tick(T0)                                                             # rețeaua: hotspotul; datagramele
    m.tick(T0 + live.READ_AFTER_S)                                         # tura de porturi: rețeaua s-a schimbat
    assert net.probed == [] and m.status == live.PAUSED and m.reason == "WRONG_SSID"


# ---------- 4. același dispozitiv, nu doar același IP ----------

def test_a_different_device_on_the_same_ip_never_confirms_a_fix(tmp_path):
    lab_dir(tmp_path)
    cam = lab_host("172.20.10.14")
    net = Net()
    stranger = nb(cam.ip, mac="DA:A1:19:XX:XX:XX")                        # alt telefon a primit IP-ul camerei
    assert stranger.device_id != cam.device_id
    net.present = {cam.ip: stranger}
    m = make(net, tmp_path, persist=True)
    sweep(m, T0)
    assert m.fixes == 0 and net.probed == []                              # nici nu e al echipei: nu îl atingem
    m.approve(stranger.device_id)                                          # chiar dacă îl aprobi...
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert net.probed and m.fixes == 0                                     # ...nu confirmă problemele camerei
    assert storage.verified_keys(m.known_scan().scan, tmp_path / "data" / "netscan.db") == set()
    assert not any(e.kind == "FIX_CONFIRMED" for e in m.events)


def test_the_same_device_confirms_even_after_a_new_ip(tmp_path):
    lab_dir(tmp_path)
    cam = lab_host("172.20.10.14")
    net = Net()
    net.present = {"172.20.10.9": nb("172.20.10.9", device_id=cam.device_id)}   # aceeași cameră, alt IP
    m = make(net, tmp_path)
    sweep(m, T0)
    assert m.fixes >= 1 and {ip for ip, _ in net.probed} == {"172.20.10.9"}


def test_hosts_without_a_mac_in_the_scan_are_never_confirmed(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "scan_x.xml").write_text("<nmaprun/>")
    host = Host(ip="172.20.10.5", device_id="ip:172.20.10.5", ports=[Port(23, "tcp", "open", "telnet")])
    finding = Finding("scan_x.xml", "172.20.10.5", "ip:172.20.10.5", 23, "TELNET_OPEN", "high", 30, "telnet")
    scan = Scan(file="scan_x.xml", status="ok", score=70, hosts=[host], findings=[finding])
    net = Net()
    seen = nb("172.20.10.5")
    net.present = {"172.20.10.5": seen}
    m = make(net, tmp_path, analyze=lambda path: scan)
    m.approve(seen.device_id)
    sweep(m, T0)
    assert net.probed and m.fixes == 0
    fake = live.LiveDevice(ip="172.20.10.5", mac_masked=None, vendor=None, private_mac=False, first_seen=T0,
                           last_seen=T0, device_id="ip:172.20.10.5")
    m._confirm_fix(m.known_scan(), fake, 23, T0)
    assert m.fixes == 0


def test_same_device_answers_true_false_or_unknown(tmp_path):
    net = Net()
    me = nb("172.20.10.5")
    net.present = {"172.20.10.5": me}
    m = make(net, tmp_path)
    assert m.same_device("172.20.10.5", me.device_id) is None             # protecția nu a văzut încă nimic
    sweep(m, T0)
    assert m.same_device("172.20.10.5", me.device_id) is True
    assert m.same_device("172.20.10.5", dev_id("172.20.10.5", "D0:39:57:XX:XX:XX")) is False
    assert m.same_device("172.20.10.5", "ip:172.20.10.5") is False
    assert m.same_device("172.20.10.6", me.device_id) is None             # nu e online acum
    net.info = VENUE
    m.tick(T0 + live.GATE_EVERY_S + 30)
    assert m.same_device("172.20.10.5", me.device_id) is None             # în afara hotspotului nu știm nimic


# ---------- 5. acordul: un dispozitiv nou primește doar o alertă ----------

def test_new_device_causes_no_probe_and_no_early_rescan(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1")}
    m = make(net, tmp_path)
    progress(tmp_path / "scans", state="waiting_next", job="auto", pid=os.getpid())
    sweep(m, T0)
    net.present["172.20.10.9"] = nb("172.20.10.9")
    net.open["172.20.10.9"] = {23, 3389}
    for i in range(1, 4):
        sweep(m, T0 + i * live.PULSE_EVERY_S)
    assert "NEW_DEVICE" in kinds(m) and net.probed == []
    assert not (tmp_path / "scans" / scan_job.NOW_FILE).exists() and not m.pulse_now
    ev = next(e for e in m.events if e.kind == "NEW_DEVICE")
    assert ev.text_ro.startswith("A apărut un dispozitiv nou: 172.20.10.9")
    assert ev.text_en.startswith("A new device appeared: 172.20.10.9")
    snap = {d["ip"]: d for d in m.snapshot()["devices"]}
    assert snap["172.20.10.9"]["needs_approval"] and not snap["172.20.10.9"]["probed"]
    assert snap["172.20.10.9"]["device_id"] == dev_id("172.20.10.9")
    m._hb_stop.set()


def test_devices_from_the_last_scan_are_checked_without_asking(tmp_path):
    lab_dir(tmp_path)
    net = Net()
    net.present = {"172.20.10.14": lab_nb("172.20.10.14")}
    m = make(net, tmp_path)
    sweep(m, T0)
    dev = m.snapshot()["devices"][0]
    assert net.probed and dev["in_scan"] and dev["probed"] and not dev["approved"] and not dev["needs_approval"]


def test_approve_is_saved_next_to_the_on_setting_and_validated(tmp_path):
    m = make(Net(VENUE), tmp_path, persist=True)
    good = dev_id("172.20.10.9")
    assert m.approve(good)
    for bad in ("ip:172.20.10.9", "../../etc", "", None, "ABCDEF123456", "a" * 13):
        assert not m.approve(bad)
    m._save_setting(True)
    saved = json.loads((tmp_path / "data" / live.SETTINGS_FILE).read_text(encoding="utf-8"))
    assert saved == {"on": True, "approved": [good]}
    assert make(Net(VENUE), tmp_path, persist=True).approved == {good}


# ---------- 6. scanările automate ajung în istoric; „s-a terminat” doar o dată ----------

def test_auto_scan_reaches_the_history_once(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / scan_job.APP_ALIVE_FILE).write_text("viu")
    clock = [1000.0]

    def run(scans_dir, job, writer):
        shutil.copy(LAB / "scan_01_before.xml", scans_dir / "scan_x.xml")
        p = scan_job.Progress(job)
        p.finish("done", file="scan_x.xml")
        writer.write(p.data, force=True)
        return 0

    def sleep(s):
        clock[0] += 60
        if scan_job.read_progress(scans)["state"] == "waiting_next":
            (scans / scan_job.STOP_FILE).write_text("stop")

    scan_job.main(["auto"], scans_dir=scans, run=run, sleep=sleep, now=lambda: clock[0], load_env=False)
    assert scan_job.read_progress(scans)["state"] == "stopped"            # „done” a fost suprascris
    db = tmp_path / "data" / "netscan.db"
    m = make(Net(), tmp_path, persist=True)
    m.full_scan_status()
    m.full_scan_status()
    assert [s.file for s in storage.list_scans(db)] == ["scan_x.xml"]
    assert kinds(m).count("SCAN_DONE") == 1
    again = make(Net(), tmp_path, persist=True)                            # aplicația repornită
    again.full_scan_status()
    assert "SCAN_DONE" not in kinds(again) and len(storage.list_scans(db)) == 1


def test_waiting_next_with_a_file_is_imported(tmp_path):
    scans = lab_dir(tmp_path)
    progress(scans, state="waiting_next", job="auto", pid=os.getpid(), file="scan_01_before.xml")
    m = make(Net(), tmp_path, persist=True)
    assert m.full_scan_status()["state"] == "waiting_next"
    assert [s.file for s in storage.list_scans(tmp_path / "data" / "netscan.db")] == ["scan_01_before.xml"]
    m._hb_stop.set()


# ---------- 7. „Ia pașii de la capăt” permite o nouă confirmare ----------

def test_reset_allows_the_live_fix_to_be_confirmed_again(tmp_path):
    lab_dir(tmp_path)
    net = Net()
    net.present = {"172.20.10.14": lab_nb("172.20.10.14")}
    net.open = {"172.20.10.14": {22, 1883, 2121, 8080}}
    m = make(net, tmp_path, persist=True)
    db = tmp_path / "data" / "netscan.db"
    sweep(m, T0)
    scan = m.known_scan().scan
    first = storage.verified_keys(scan, db)
    assert {k[2] for k in first} == {"TELNET_OPEN", "DB_EXPOSED"} and m.fixes == 2
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert m.fixes == 2                                                    # fără dubluri
    storage.reset_done(scan, db)
    m.forget(scan.file)
    sweep(m, T0 + 2 * live.PULSE_EVERY_S + 2)
    assert storage.verified_keys(scan, db) == first and m.fixes == 4


def test_forget_clears_the_in_memory_confirmations(tmp_path):
    lab_dir(tmp_path)
    net = Net()
    net.present = {"172.20.10.14": lab_nb("172.20.10.14")}
    m = make(net, tmp_path)
    net.open = {"172.20.10.14": {22, 1883, 2121, 8080}}
    sweep(m, T0)
    assert m.fixes == 2 and m._confirmed
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert m.fixes == 2
    m.forget()
    assert not m._confirmed
    sweep(m, T0 + 2 * live.PULSE_EVERY_S + 2)
    assert m.fixes == 4


# ---------- 8. plecat și revenit: fără alerte repetate ----------

def test_leave_and_return_alerts_only_for_new_ports(tmp_path):
    net = Net()
    net.present = {"172.20.10.5": nb("172.20.10.5")}
    net.open = {"172.20.10.5": {23}}
    m = make(net, tmp_path)
    m.approve(dev_id("172.20.10.5"))
    sweep(m, T0)
    assert kinds(m).count("PORT_OPENED") == 1
    away = net.present.pop("172.20.10.5")
    sweep(m, T0 + 20)
    sweep(m, T0 + 40)
    assert kinds(m)[0] == "DEVICE_GONE"
    net.present["172.20.10.5"] = away
    net.open["172.20.10.5"] = {23, 6379}
    sweep(m, T0 + 60)
    opened = [e.port for e in m.events if e.kind == "PORT_OPENED"]
    assert "DEVICE_BACK" in kinds(m) and opened == [6379, 23]             # 23 o singură dată; 6379 e nou


# ---------- 9. pornire / oprire ----------

def test_restart_gen_is_monotonic_and_a_second_start_is_refused(tmp_path):
    m = make(Net(VENUE), tmp_path)
    assert m.start()
    assert not m.start()                                                   # un singur fir
    old = m.gen
    m.stop(remember=False)
    assert m.start() and m.gen > old
    m.stop(remember=False)


def test_known_scan_cache_keeps_at_most_five_entries(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    m = make(Net(), tmp_path, analyze=lambda path: None)
    for i in range(12):
        (scans / f"scan_{i:02}.xml").write_text("<nmaprun/>")
        os.utime(scans / f"scan_{i:02}.xml", (1000 + i, 1000 + i))
        m.known_scan()
    assert len(m._known_cache) <= live.MAX_KNOWN_CACHE == 5


def test_autostart_does_nothing_by_default(tmp_path):
    m = make(Net(VENUE), tmp_path, persist=True)
    m._save_setting(True)
    assert not m.autostart() and not m.running


# ---------- 11. scanarea automată nu trăiește după aplicație ----------

@pytest.mark.parametrize("age_s", [None, 200])
def test_auto_scan_stops_when_the_app_is_gone(tmp_path, age_s):
    scans = tmp_path / "scans"
    scans.mkdir()
    if age_s is not None:
        alive = scans / scan_job.APP_ALIVE_FILE
        alive.write_text("viu")
        os.utime(alive, (time.time() - age_s, time.time() - age_s))
    runs = []
    rc = scan_job.main(["auto"], scans_dir=scans, run=lambda *a: runs.append(1) or 0,
                       sleep=lambda s: pytest.fail("nu trebuia să aștepte"), load_env=False)
    p = scan_job.read_progress(scans)
    assert rc == 0 and runs == [1] and p["state"] == "stopped" and p["code"] == "APP_CLOSED"
    assert p["msg_ro"] == "Am oprit scanarea automată: aplicația s-a închis."
    assert p["msg_en"] == "I stopped automatic scanning: the app was closed."
    assert not (scans / scan_job.LOCK_FILE).exists()


def test_requesting_an_auto_scan_starts_the_heartbeat(tmp_path):
    gate = threading.Event()
    m = make(Net(), tmp_path, launcher=lambda job: (gate.wait(2), elevate.Launch(False, elevate.DENIED))[1])
    assert m.request_full_scan("auto") == "OK"
    try:
        alive = tmp_path / "scans" / scan_job.APP_ALIVE_FILE
        assert alive.exists() and scan_job.app_alive(tmp_path / "scans")
        assert m._hb_thread is not None and m._hb_thread.is_alive()
    finally:
        gate.set()
        m._hb_stop.set()


def test_a_plain_scan_does_not_start_the_heartbeat(tmp_path):
    m = make(Net(), tmp_path, launcher=lambda job: elevate.Launch(False, elevate.DENIED))
    assert m.request_full_scan("scan") == "OK"
    assert not (tmp_path / "scans" / scan_job.APP_ALIVE_FILE).exists()


# ---------- 12. NETSCAN_ALLOWLIST nu poate lărgi ----------

def test_allowlist_cannot_widen_to_the_venue():
    allow = guardrail.build_allowlist("172.20.10.0/28", "10.240.0.0/16")
    d = guardrail.check_target("10.240.5.5", allow)
    assert not d.ok and d.reason_code == guardrail.OUTSIDE_ALLOWLIST
    assert [str(n) for n in allow] == ["172.20.10.0/28"]


def test_live_targets_ignore_a_wider_allowlist(tmp_path):
    net = Net()
    m = make(net, tmp_path, env={**ENV, "NETSCAN_ALLOWLIST": "10.240.0.0/16, 172.20.0.0/16"})
    m.tick(T0)
    (ips, _), = net.poked
    assert len(ips) == 13 and all(ip.startswith("172.20.10.") for ip in ips)


# ---------- 13. ușa-capcană: nu trimite nimic și nu citește nimic ----------

class _Sock:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):                       # orice altă operație pe socket e notată
        def op(*a, **k):
            self.calls.append(name)
            return b""
        return op


class _TrapServer:
    server_address = ("172.20.10.10", 2323)

    def __init__(self):
        self.slots = threading.BoundedSemaphore(1)
        self.seen = []

    def record(self, ip, port):
        self.seen.append((ip, port))


def test_trap_records_and_closes_without_prompt_or_read():
    sock, server = _Sock(), _TrapServer()
    trap._Handler(sock, ("172.20.10.9", 50123), server)
    assert server.seen == [("172.20.10.9", 2323)]
    assert sock.calls == ["shutdown"]                                      # fără sendall/recv
    assert not hasattr(trap, "BANNER") and not hasattr(trap, "MAX_READ")
    import ast
    tree = ast.parse((ROOT / "netscan" / "scan" / "trap.py").read_text(encoding="utf-8"))
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not calls & {"recv", "recv_into", "recvfrom", "send", "sendall", "makefile"}


# ---------- 14. exemplele „ce vede cineva care ascultă” nu imită produse reale ----------

def test_eavesdrop_samples_have_no_real_product_banners():
    for code in eavesdrop.CODES:
        for lang in ("ro", "en"):
            text = eavesdrop.as_text(code, lang)
            assert "vsFTPd" not in text and "BusyBox" not in text
    assert "220 FTP server ready" in eavesdrop.as_text("FTP_CLEARTEXT")
    assert "a login over HTTP" in eavesdrop.get_eavesdrop("HTTP_ADMIN_CLEARTEXT", "en")["caption"]
