"""B: protecția live. Rețeaua, tabela ARP, conexiunile și capcana sunt simulate: testele nu ating rețeaua."""
import errno
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path

import pytest

from netscan.model import Host, Port, Scan
from netscan.scan import elevate, live, local_data, neighbors, scan_job
from netscan.scan.network import NetworkInfo
from netscan.ui import storage

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"
HOTSPOT = NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", gateway="172.20.10.1",
                      ssid="RSH-Ibiza2028", status="OK")
VENUE = NetworkInfo(iface="Wi-Fi", ip="10.240.3.7", cidr="10.240.0.0/16", ssid="UnivBuc Free", status="WRONG_SSID")
FULL_MAC = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
T0 = 1_800_000_000.0


def nb(ip, mac="66:48:42:XX:XX:XX", vendor=None, private=True):
    return neighbors.Neighbor(ip=ip, mac_masked=mac, vendor=vendor, private_mac=private)


class Net:
    """Rețeaua simulată: ce întoarce detect(), cine e în tabela ARP, ce porturi sunt deschise."""

    def __init__(self, info=HOTSPOT):
        self.info, self.present, self.open = info, {}, {}
        self.poked, self.probed = [], []
        self._lock = threading.Lock()

    def detect(self):
        return self.info

    def read(self, info):
        return dict(self.present)

    def poke(self, ips, bind_ip):
        self.poked.append((list(ips), bind_ip))

    def probe(self, ip, port):
        with self._lock:
            self.probed.append((ip, port))
        return "open" if port in self.open.get(ip, ()) else "closed"


class NoPace:
    def wait(self):
        pass


def make(net, tmp_path, **kw):
    kw.setdefault("persist", False)
    kw.setdefault("trap_server", None)
    kw.setdefault("launcher", lambda job: elevate.Launch(True, elevate.STARTED))
    kw.setdefault("read_table", net.read)
    kw.setdefault("probe", net.probe)
    return live.LiveMonitor(scans_dir=tmp_path / "scans", db_path=tmp_path / "data" / "netscan.db",
                            detect=net.detect, poke=net.poke, pacer=NoPace(), **kw)


def sweep(m, t):
    """O tură completă: datagramele, apoi citirea tabelei (și verificarea porturilor, dacă e cazul)."""
    m.tick(t)
    m.tick(t + live.READ_AFTER_S)


def kinds(m):
    return [e.kind for e in m.events]


# ---------- doar hotspotul echipei ----------

def test_off_the_hotspot_nothing_is_touched(tmp_path):
    net, built = Net(VENUE), []
    m = make(net, tmp_path, trap_server=lambda *a: built.append(a))
    for i in range(5):
        sweep(m, T0 + i * 30)
    assert net.poked == [] and net.probed == [] and built == []
    assert m.status == live.PAUSED and m.reason == "WRONG_SSID" and m.snapshot()["devices"] == []


def test_sweep_targets_only_hotspot_addresses_from_the_hotspot_ip(tmp_path):
    net = Net()
    m = make(net, tmp_path)
    m.tick(T0)
    (ips, bind_ip), = net.poked
    assert bind_ip == "172.20.10.10" and len(ips) == 13
    assert all(ip.startswith("172.20.10.") for ip in ips)
    assert {"172.20.10.0", "172.20.10.10", "172.20.10.15"}.isdisjoint(ips)   # rețea, laptopul nostru, broadcast


def test_network_larger_than_a_hotspot_is_not_swept(tmp_path):
    big = NetworkInfo(iface="Wi-Fi", ip="192.168.0.10", cidr="192.168.0.0/16", ssid="RSH-Ibiza2028", status="OK")
    net = Net(big)
    m = make(net, tmp_path)
    sweep(m, T0)
    assert net.poked == [] and m.reason == live.TOO_LARGE


def test_neighbors_outside_the_hotspot_are_never_probed(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1"), "8.8.8.8": nb("8.8.8.8"), "192.168.1.5": nb("192.168.1.5")}
    m = make(net, tmp_path)
    sweep(m, T0)
    assert {ip for ip, _ in net.probed} == {"172.20.10.1"}
    assert [d["ip"] for d in m.snapshot()["devices"]] == ["172.20.10.1"]


# ---------- prezența ----------

def test_baseline_is_quiet_then_a_new_device_is_reported_with_its_ports(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1")}
    m = make(net, tmp_path)
    sweep(m, T0)
    assert m.events == []                                     # ce era deja conectat nu e alertă
    net.present["172.20.10.9"] = nb("172.20.10.9", "D0:39:57:XX:XX:XX", "Liteon", False)
    net.open["172.20.10.9"] = {23}
    sweep(m, T0 + 20)
    assert kinds(m)[:2] == ["PORT_OPENED", "NEW_DEVICE"]      # cele mai noi primele
    assert "172.20.10.9 (Liteon)" in m.events[1].text_ro and "23 (Telnet)" in m.events[0].text_ro
    dev = {d["ip"]: d for d in m.snapshot()["devices"]}["172.20.10.9"]
    assert dev["new"] and dev["open_ports"] == [{"port": 23, "label": "Telnet"}]


def test_device_gone_after_two_missed_sweeps_and_back(tmp_path):
    net = Net()
    net.present = {"172.20.10.1": nb("172.20.10.1"), "172.20.10.2": nb("172.20.10.2")}
    m = make(net, tmp_path)
    sweep(m, T0)
    del net.present["172.20.10.2"]
    sweep(m, T0 + 20)
    assert "DEVICE_GONE" not in kinds(m)                      # o singură tură ratată nu e plecare
    sweep(m, T0 + 40)
    assert kinds(m)[0] == "DEVICE_GONE" and not {d["ip"]: d for d in m.snapshot()["devices"]}["172.20.10.2"]["online"]
    net.present["172.20.10.2"] = nb("172.20.10.2")
    sweep(m, T0 + 60)
    assert "DEVICE_BACK" in kinds(m)


def test_another_device_on_the_same_ip_is_new(tmp_path):
    net = Net()
    net.present = {"172.20.10.2": nb("172.20.10.2", "AA:BB:CC:XX:XX:XX")}
    m = make(net, tmp_path)
    sweep(m, T0)
    net.present = {"172.20.10.2": nb("172.20.10.2", "D0:39:57:XX:XX:XX")}
    sweep(m, T0 + 20)
    assert "NEW_DEVICE" in kinds(m)


# ---------- porturile ----------

def test_ports_changes_between_checks(tmp_path):
    net = Net()
    net.present = {"172.20.10.5": nb("172.20.10.5")}
    m = make(net, tmp_path)
    sweep(m, T0)
    assert m.events == []
    net.open["172.20.10.5"] = {6379}
    sweep(m, T0 + live.PULSE_EVERY_S + 1)
    assert m.events[0].kind == "PORT_OPENED" and "6379 (Redis)" in m.events[0].text_ro
    net.open["172.20.10.5"] = set()
    sweep(m, T0 + 2 * live.PULSE_EVERY_S + 2)
    assert m.events[0].kind == "PORT_CLOSED" and m.events[0].tone == "good"


def test_first_check_is_compared_with_the_last_full_scan(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "scan_x.xml").write_text("<nmaprun/>")
    scan = Scan(file="scan_x.xml", status="ok", score=40, hosts=[
        Host(ip="172.20.10.14", device_id="d", device_type="iot", ports=[
            Port(2121, "tcp", "open", "ftp"), Port(8080, "tcp", "open", "http"), Port(1900, "udp", "open", "upnp")])])
    net = Net()
    net.present = {"172.20.10.14": nb("172.20.10.14")}
    net.open["172.20.10.14"] = {8080, 6379}
    m = make(net, tmp_path, analyze=lambda path: scan)
    sweep(m, T0)
    texts = {e.port: e for e in m.events}
    assert set(texts) == {2121, 6379}                         # 8080 e ca în scanare: fără alertă
    assert texts[2121].kind == "PORT_CLOSED" and "era deschis" in texts[2121].text_ro
    assert texts[6379].kind == "PORT_OPENED" and "nou față de ultima scanare" in texts[6379].text_ro
    assert (2121, ) in {(p,) for _, p in net.probed}          # porturile din scanare se verifică și ele
    dev = m.snapshot()["devices"][0]
    assert dev["in_scan"] and dev["device_type"] == "iot"


def test_a_broken_or_partial_newest_xml_falls_back_to_the_last_valid_scan(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    shutil.copy(LAB / "scan_03_after.xml", scans / "scan_03_after.xml")
    old = time.time() - 100
    os.utime(scans / "scan_03_after.xml", (old, old))
    (scans / "scan_new.xml").write_text("<nmaprun><host><address addr=")   # o scanare încă în lucru
    m = make(Net(), tmp_path)
    assert m.known_scan().file == "scan_03_after.xml"


def test_leaving_the_hotspot_mid_check_stops_the_probes(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "PROBE_WORKERS", 1)
    net = Net()
    net.present = {"172.20.10.5": nb("172.20.10.5")}
    m = make(net, tmp_path)
    m.tick(T0)
    original = net.probe

    def probe(ip, port):
        net.info = VENUE
        m._check_gate(T0 + 5)                                 # rețeaua s-a schimbat după prima conexiune
        return original(ip, port)

    m.probe = probe
    m.tick(T0 + live.READ_AFTER_S)
    assert len(net.probed) == 1 and m.status == live.PAUSED


def test_label_from_the_scan_is_sanitized(tmp_path):
    assert live._label(8080, '<script>alert("x")</script>') == "scriptalertx/script"
    assert live._label(23) == "Telnet" and live._label(31337) == ""


def test_pacer_limits_attempts_per_second():
    clock, slept = [0.0], []
    pacer = live._Pacer(15, clock=lambda: clock[0], sleep=lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s)))
    for _ in range(31):
        pacer.wait()
    assert clock[0] == pytest.approx(2.0, abs=0.01)           # 31 încercări = 2 secunde la 15/s


# ---------- ce se vede și ce se păstrează ----------

def test_snapshot_and_persisted_events_never_contain_a_full_mac(tmp_path):
    net = Net()
    text = "Interface: 172.20.10.10 --- 0xb\n  172.20.10.1  66-48-42-94-c3-64  dynamic\n"
    m = make(net, tmp_path, persist=True,
             read_table=lambda info: neighbors.parse_windows_arp(text, info.ip, info.cidr))
    sweep(m, T0)
    text += "  172.20.10.9  d0-39-57-11-22-33  dynamic\n"
    net.open["172.20.10.9"] = {23}
    sweep(m, T0 + 20)
    dumped = json.dumps(m.snapshot()) + (tmp_path / "data" / "alerts.jsonl").read_text(encoding="utf-8")
    assert not FULL_MAC.search(dumped.replace("XX", "00").replace(":00:00:00", "")) and "94:C3" not in dumped.upper()
    rows = local_data.read_events(local_data.alerts_path(tmp_path / "data" / "netscan.db"))
    assert {r["kind"] for r in rows} <= set(live.PERSISTED_KINDS) and all("mac" not in r for r in rows)


# ---------- ușa-capcană ----------

class FakeTrap:
    instances = []

    def __init__(self, bind_ip, port, ignore, on_attempt):
        self.bind_ip, self.port, self.ignore, self.on_attempt = bind_ip, port, ignore, on_attempt
        self.closed = False
        FakeTrap.instances.append(self)

    def handle_request(self):
        time.sleep(0.01)

    def server_close(self):
        self.closed = True


def test_trap_listens_only_on_the_hotspot_ip_and_stops_when_leaving(tmp_path):
    FakeTrap.instances = []
    net = Net()
    m = make(net, tmp_path, trap_server=FakeTrap)
    m.tick(T0)
    trap_ = FakeTrap.instances[-1]
    assert (trap_.bind_ip, trap_.port) == ("172.20.10.10", 2323) and "172.20.10.10" in trap_.ignore
    assert m.snapshot()["trap_state"] == "listening"
    net.info = VENUE
    m.tick(T0 + live.GATE_EVERY_S)
    for _ in range(100):
        if trap_.closed:
            break
        time.sleep(0.01)
    assert trap_.closed and m.trap_state == ("off", None)


def test_trap_attempt_is_an_urgent_event_and_keeps_only_ip_time_port(tmp_path):
    FakeTrap.instances = []
    m = make(Net(), tmp_path, trap_server=FakeTrap, persist=True)
    m.tick(T0)
    FakeTrap.instances[-1].on_attempt({"ts": T0 + 1, "ip": "172.20.10.9", "port": 2323})
    assert m.events[0].kind == "TRAP" and m.events[0].tone == "urgent" and "172.20.10.9" in m.events[0].text_ro
    rows = local_data.read_events(local_data.trap_path(tmp_path / "data" / "netscan.db"))
    assert rows == [{"ts": T0 + 1, "ip": "172.20.10.9", "port": 2323}]
    m.stop(remember=False)


def test_trap_port_in_use_is_reported(tmp_path):
    def busy(*a):
        raise OSError(errno.EADDRINUSE, "in use")
    m = make(Net(), tmp_path, trap_server=busy)
    m.tick(T0)
    assert m.trap_state == ("error", "BUSY")


# ---------- scanarea completă ----------

def test_full_scan_refused_off_the_hotspot(tmp_path):
    launched = []
    m = make(Net(VENUE), tmp_path, launcher=lambda job: launched.append(job))
    assert m.request_full_scan("scan") == "NOT_ON_HOTSPOT" and launched == []
    assert m.request_full_scan("rm -rf") == "BAD_JOB"


def test_full_scan_launch_once_then_busy_and_denied(tmp_path):
    gate, launched = threading.Event(), []

    def launcher(job):
        launched.append(job)
        gate.wait(2)
        return elevate.Launch(False, elevate.DENIED)

    m = make(Net(), tmp_path, launcher=launcher)
    assert m.request_full_scan("auto") == "OK"
    assert m.full_scan_status()["state"] == "waiting_permission"
    assert m.request_full_scan("scan") == "BUSY"
    gate.set()
    for _ in range(100):
        if m.full_scan_status()["state"] != "waiting_permission":
            break
        time.sleep(0.01)
    assert launched == ["auto"] and m.full_scan_status()["state"] == "denied"
    assert (tmp_path / "scans").is_dir()                      # creat de utilizator, nu de procesul de admin


def test_finished_scan_is_imported_once_with_alerts(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    shutil.copy(LAB / "scan_01_before.xml", scans / "scan_01_before.xml")
    old = time.time() - 100
    os.utime(scans / "scan_01_before.xml", (old, old))
    shutil.copy(LAB / "scan_03_after.xml", scans / "scan_03_after.xml")
    (scans / scan_job.PROGRESS_FILE).write_text(json.dumps({
        "state": "done", "job": "scan", "file": "scan_03_after.xml", "started": time.time(), "percent": 100}))
    m = make(Net(), tmp_path, persist=True)
    db = tmp_path / "data" / "netscan.db"
    assert m.full_scan_status()["state"] == "done"
    m.full_scan_status()
    assert [s.file for s in storage.list_scans(db)] == ["scan_03_after.xml"]
    resolved = {r.get("code") for r in local_data.read_events(local_data.alerts_path(db)) if r["kind"] == "FINDING_RESOLVED"}
    assert resolved == {"TELNET_OPEN", "DB_EXPOSED"} and m.events[0].kind == "SCAN_DONE"


def test_stop_full_scan_writes_the_stop_file_only_when_running(tmp_path):
    m = make(Net(), tmp_path)
    m.stop_full_scan()
    assert not (tmp_path / "scans" / scan_job.STOP_FILE).exists()
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / scan_job.PROGRESS_FILE).write_text(json.dumps(
        {"state": "running", "job": "scan", "pid": os.getpid(), "started": time.time()}))
    m.stop_full_scan()
    assert (tmp_path / "scans" / scan_job.STOP_FILE).exists()


def test_start_is_remembered_and_resumed(tmp_path):
    m = make(Net(VENUE), tmp_path, persist=True)
    m.start()
    m.stop(remember=False)
    again = make(Net(VENUE), tmp_path, persist=True)
    assert again.autostart() and again.running
    again.stop()
    assert not make(Net(VENUE), tmp_path, persist=True).autostart()
