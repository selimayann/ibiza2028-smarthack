"""B: ușa-capcană. Testată pe 127.0.0.1 (nu pe rețea): nu păstrează nimic din ce s-a scris."""
import json
import socket
import threading
import time

import pytest

from netscan.scan import local_data, network, trap


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_trap():
    events = []
    port = free_port()
    srv = trap.TrapServer("127.0.0.1", port, ignore=set(), on_attempt=events.append)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv, port, events
    srv.shutdown()
    srv.server_close()


def connect_and_type(port, text):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        banner = c.recv(256)
        c.sendall(text)
        rest = c.recv(256)
    return banner + rest


def wait_for(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


def test_attempt_recorded_with_only_ip_time_port(running_trap):
    srv, port, events = running_trap
    reply = connect_and_type(port, b"admin\r\nparola-secreta-123\r\n")
    assert b"login:" in reply and b"Login incorrect" in reply
    assert wait_for(lambda: events)
    assert set(events[0]) == {"ts", "ip", "port"} and events[0]["ip"] == "127.0.0.1" and events[0]["port"] == port


def test_nothing_typed_is_ever_stored(tmp_path):
    db = tmp_path / "data" / "netscan.db"
    trap.save_attempt({"ts": time.time(), "ip": "172.20.10.5", "port": 2323, "typed": "parola-secreta"}, db)
    raw = local_data.trap_path(db).read_text(encoding="utf-8")
    assert "parola" not in raw and json.loads(raw) .keys() == {"ts", "ip", "port"}


def test_ignore_list_and_rate_limit():
    events = []
    srv = trap.TrapServer("127.0.0.1", free_port(), ignore={"172.20.10.10"}, on_attempt=events.append,
                          now=lambda: 1000.0)
    try:
        srv.record("172.20.10.10", 2323)            # scannerul nostru: ignorat
        srv.record("172.20.10.5", 2323)
        srv.record("172.20.10.5", 2323)             # același IP în același minut: o singură alertă
        assert [e["ip"] for e in events] == ["172.20.10.5"]
    finally:
        srv.server_close()


def test_never_binds_all_interfaces():
    with pytest.raises(ValueError):
        trap.TrapServer("0.0.0.0", free_port(), ignore=set(), on_attempt=lambda e: None)


def test_refuses_when_not_on_hotspot():
    info = network.NetworkInfo(iface="Wi-Fi", ip="10.240.236.143", cidr="10.240.0.0/16", status=network.WRONG_SSID)
    lines = []
    assert trap.run_trap(confirm=True, out=lines.append, detect=lambda: info) == 2
    assert "Nu deschid" in lines[0]


def test_dry_run_shows_hotspot_ip_and_firewall_rule():
    info = network.NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", status=network.OK)
    lines = []
    assert trap.run_trap(confirm=False, out=lines.append, detect=lambda: info) == 0
    assert "172.20.10.10:2323" in lines[0] and "-Profile Private" in lines[1]


@pytest.mark.parametrize("port", [23, 80, 0, 70000])
def test_port_range_without_admin(port):
    lines = []
    assert trap.run_trap(confirm=True, port=port, out=lines.append) == 2


def test_ignore_list_from_env():
    ips = trap.ignore_list("172.20.10.10", {"NETSCAN_TRAP_IGNORE": "172.20.10.14, nu-e-ip, 8.8.8.8"})
    assert ips == {"172.20.10.10", "172.20.10.14", "8.8.8.8"}


def test_old_attempts_purged_after_7_days(tmp_path):
    path = tmp_path / "trap_attempts.jsonl"
    now = 10 * 86400.0
    local_data.append_events(path, [{"ts": now - 8 * 86400, "ip": "172.20.10.5", "port": 2323},
                                    {"ts": now - 1 * 86400, "ip": "172.20.10.6", "port": 2323}])
    assert local_data.purge_old(path, now=now) == 1
    assert [e["ip"] for e in local_data.read_events(path)] == ["172.20.10.6"]
