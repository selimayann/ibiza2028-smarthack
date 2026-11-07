"""Oneata: runner-ul nmap. Nu rulează nmap și nu atinge rețeaua: totul e pe date false."""
from pathlib import Path

import pytest

from netscan.scan import guardrail, network, runner

INFO_OK = network.NetworkInfo(iface="Wi-Fi", ip="172.20.10.3", cidr="172.20.10.0/28",
                              gateway="172.20.10.1", ssid="RSH-Ibiza2028", status=network.OK)

IFLIST = """\
Starting Nmap 7.993 ( https://nmap.org )
************************INTERFACES************************
DEV    (SHORT)  IP/MASK                     TYPE        UP MTU   MAC
eth0   (eth0)   192.168.56.1/24             ethernet    up 1500  0A:00:27:XX:XX:XX
wlan0  (wlan0)  fe80::1/64                  ethernet    up 1500  4C:23:38:XX:XX:XX
wlan0  (wlan0)  172.20.10.3/28              ethernet    up 1500  4C:23:38:XX:XX:XX
lo0    (lo0)    127.0.0.1/8                 loopback    up 1500

**************************ROUTES**************************
DST/MASK                      DEV    METRIC GATEWAY
0.0.0.0/0                     wlan0  35     172.20.10.1
"""


def plan(target=None, info=INFO_OK, env=None, iflist=IFLIST, ports="22,80,443"):
    return runner.prepare_scan(
        target=target,
        env=env or {},
        detect=lambda: info,
        run=lambda args: iflist,
        nmap_path="nmap",
        top_ports=ports,
        out_path=Path("scans/test.xml"),
    )


def test_build_nmap_args_exact():
    args = runner.build_nmap_args("172.20.10.0/28", "wlan0", "22,80", "scans/x.xml")
    assert args == ["nmap", "-sS", "-sU", "-sV", "--script", "http-title",
                    "-p", "T:22,80,1883,6379,27017,U:53,123,161,1900,5353",
                    "--max-rate", "100", "-e", "wlan0", "-oX", "scans/x.xml", "172.20.10.0/28"]


def test_catalog_extra_ports_reach_command_with_real_top1000():
    """1883 (mqtt), 6379 (redis) și 27017 (mongodb) lipsesc din top 1000; trebuie să fie în -p T:..."""
    top = runner.load_top_ports()
    for p in runner.CATALOG_EXTRA_TCP:
        assert not runner._port_in_list(p, top)          # lista top 1000 rămâne neatinsă
    spec = runner.build_nmap_args("172.20.10.0/28", "eth3", top, "x.xml")[7]
    tcp = spec[2:spec.index(",U:")]
    assert tcp.startswith(top)
    for p in runner.CATALOG_EXTRA_TCP:
        assert runner._port_in_list(p, tcp)


def test_extra_ports_not_duplicated():
    assert runner.tcp_port_spec("22,1883,6000-6400") == "22,1883,6000-6400,27017"


def test_default_target_is_own_subnet(monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    p = plan()
    assert p.ok and p.target == "172.20.10.0/28"
    assert p.args[-1] == "172.20.10.0/28"
    assert p.args[p.args.index("-e") + 1] == "wlan0"   # numele nmap, nu „Wi-Fi”


def test_single_ip_target_is_normalized(monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    p = plan("  172.20.10.14 ")
    assert p.ok and p.args[-1] == "172.20.10.14/32"


@pytest.mark.parametrize("target, code", [
    ("8.8.8.8", guardrail.NOT_PRIVATE),
    ("192.168.1.0/24", guardrail.OUTSIDE_ALLOWLIST),
    ("172.20.10.5; rm -rf /", guardrail.NOT_AN_IP),
    ("-iL targets.txt", guardrail.NOT_AN_IP),
])
def test_guardrail_refusals_never_build_args(target, code):
    p = plan(target)
    assert not p.ok and p.reason_code == code and p.args == []


@pytest.mark.parametrize("status", [network.NO_NETWORK, network.MULTIPLE_NETWORKS, network.WRONG_SSID,
                                    network.SSID_NOT_CONFIGURED, network.PSUTIL_MISSING])
def test_bad_network_refuses_before_guardrail(status):
    info = network.NetworkInfo(iface="Wi-Fi", ip="172.20.10.3", cidr="172.20.10.0/28", status=status)
    p = plan("172.20.10.5", info=info)
    assert not p.ok and p.reason_code == status and p.args == []


def test_extra_allowlist_from_env(monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    assert plan("10.42.0.3", env={"NETSCAN_ALLOWLIST": "10.42.0.0/29"}).ok
    assert not plan("10.42.0.3").ok


def test_missing_ports_file():
    p = runner.prepare_scan(target=None, env={}, detect=lambda: INFO_OK, run=lambda a: IFLIST,
                            nmap_path="nmap", top_ports="", out_path=Path("x.xml"))
    assert p.reason_code == runner.NO_TOP_PORTS


def test_nmap_iface_not_found(monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    p = plan(iflist="")
    assert not p.ok and p.reason_code == runner.NMAP_IFACE_NOT_FOUND


def test_parse_iflist_ignores_routes_and_mac():
    assert runner.parse_nmap_iflist(IFLIST, "172.20.10.3") == "wlan0"
    assert runner.parse_nmap_iflist(IFLIST, "192.168.56.1") == "eth0"
    assert runner.parse_nmap_iflist(IFLIST, "172.20.10.1") is None   # gateway-ul din ROUTES nu e interfață


@pytest.mark.parametrize("text, ok", [("21-23,25,80", True), ("", False), ("22; rm -rf /", False),
                                      ("22,80\n", True), ("22 80", False)])
def test_load_top_ports_validates(tmp_path, text, ok):
    f = tmp_path / "p.txt"
    f.write_text(text, encoding="utf-8")
    assert (runner.load_top_ports(f) is not None) == ok


def test_load_top_ports_missing(tmp_path):
    assert runner.load_top_ports(tmp_path / "nu-exista.txt") is None


def test_repo_top_ports_file_is_valid():
    ports = runner.load_top_ports()
    assert ports is not None
    count = 0
    for part in ports.split(","):
        a, _, b = part.partition("-")
        count += (int(b) - int(a) + 1) if b else 1
    assert count == 1000


def test_execute_refuses_without_admin(monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    monkeypatch.setattr(runner, "is_admin", lambda: False)
    called = []
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: called.append(a))
    p = runner.execute(plan())
    assert p.reason_code == runner.NOT_ADMIN and called == []


def test_execute_never_uses_shell(monkeypatch, tmp_path):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    monkeypatch.setattr(runner, "is_admin", lambda: True)
    p = plan()
    p.out_path = str(tmp_path / "scan.xml")
    seen = {}

    class R:
        returncode = 0

    def fake_run(args, **kw):
        seen.update(kw, args=args)
        Path(p.out_path).write_text("<nmaprun/>")
        return R()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.execute(p, nmap_path="C:/Nmap/nmap.exe").ok
    assert seen["shell"] is False and isinstance(seen["args"], list)
    assert seen["args"][0] == "C:/Nmap/nmap.exe" and seen["args"][-1] == "172.20.10.0/28"


def test_execute_refused_plan_does_nothing(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("nu trebuia rulat"))
    p = plan("8.8.8.8")
    assert runner.execute(p) is p
