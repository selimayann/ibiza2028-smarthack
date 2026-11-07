"""B: prezența dispozitivelor din tabela ARP (protecția live). Fără rețea: textele sunt ieșiri reale, copiate."""
import re

import pytest

from netscan.scan import neighbors
from netscan.scan.network import NetworkInfo

FULL_MAC = re.compile(r"([0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2}")
INFO = NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", gateway="172.20.10.1",
                   ssid="RSH-Ibiza2028", status="OK")

WINDOWS = """
Interface: 172.20.10.10 --- 0xb
  Internet Address      Physical Address      Type
  172.20.10.1           66-48-42-94-c3-64     dynamic
  172.20.10.14          4e-c7-bc-6f-e3-a1     dynamic
  172.20.10.10          aa-bb-cc-dd-ee-ff     dynamic
  172.20.10.15          ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 192.168.56.1 --- 0x7
  Internet Address      Physical Address      Type
  192.168.56.101        08-00-27-aa-bb-cc     dynamic
"""
WINDOWS_RO = """
Interfață: 172.20.10.10 --- 0xb
  Adresă Internet       Adresă fizică         Tip
  172.20.10.3           d0-39-57-11-22-33     dinamic
"""
MACOS = """? (172.20.10.1) at 66:48:42:94:c3:64 on en0 ifscope [ethernet]
? (172.20.10.2) at d8:c0:a6:1:2:3 on en0 ifscope [ethernet]
? (172.20.10.3) at (incomplete) on en0 ifscope [ethernet]
? (172.20.10.15) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (10.0.0.1) at 11:22:33:44:55:66 on en1 ifscope [ethernet]
"""
LINUX = """172.20.10.1 dev wlan0 lladdr 66:48:42:94:c3:64 REACHABLE
172.20.10.3 dev wlan0  FAILED
172.20.10.4 dev wlan0 lladdr d0:39:57:11:22:33 STALE
172.20.10.5 dev wlan0  INCOMPLETE
172.20.10.6 dev wlan0 lladdr 4e:c7:bc:6f:e3:a1 DELAY
"""


def _no_full_mac(found):
    for n in found.values():
        assert n.mac_masked.endswith(":XX:XX:XX") and not FULL_MAC.search(n.mac_masked.replace("XX", ""))


def test_windows_only_the_hotspot_interface_and_real_devices():
    got = neighbors.parse_windows_arp(WINDOWS, "172.20.10.10", "172.20.10.0/28")
    assert set(got) == {"172.20.10.1", "172.20.10.14"}       # fără broadcast, multicast, laptopul nostru, VirtualBox
    assert got["172.20.10.1"].mac_masked == "66:48:42:XX:XX:XX" and got["172.20.10.1"].private_mac
    _no_full_mac(got)


def test_windows_localized_output():
    got = neighbors.parse_windows_arp(WINDOWS_RO, "172.20.10.10", "172.20.10.0/28")
    assert got["172.20.10.3"].mac_masked == "D0:39:57:XX:XX:XX" and not got["172.20.10.3"].private_mac


def test_macos_pads_octets_and_skips_incomplete():
    got = neighbors.parse_macos_arp(MACOS, "172.20.10.10", "172.20.10.0/28")
    assert set(got) == {"172.20.10.1", "172.20.10.2"}
    assert got["172.20.10.2"].mac_masked == "D8:C0:A6:XX:XX:XX"
    _no_full_mac(got)


def test_linux_failed_and_incomplete_are_absent():
    got = neighbors.parse_linux_neigh(LINUX, "172.20.10.10", "172.20.10.0/28")
    assert set(got) == {"172.20.10.1", "172.20.10.4", "172.20.10.6"}
    _no_full_mac(got)


@pytest.mark.parametrize("raw", ["ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00", "01-00-5e-00-00-16", "33:33:00:00:00:01",
                                 "zz-zz-zz-zz-zz-zz", "66-48-42-94-c3"])
def test_mask_mac_rejects_non_devices(raw):
    assert neighbors.mask_mac(raw) is None


@pytest.mark.parametrize("platform, expected", [
    ("windows", ["arp", "-a", "-N", "172.20.10.10"]),
    ("macos", ["arp", "-an", "-i", "Wi-Fi"]),
    ("linux", ["ip", "neigh", "show", "dev", "Wi-Fi"]),
])
def test_read_neighbors_runs_only_the_local_table_command(platform, expected):
    calls = []
    neighbors.read_neighbors(INFO, run=lambda args: calls.append(args) or "", platform=platform)
    assert calls == [expected]


def test_read_neighbors_none_when_the_table_cannot_be_read():
    assert neighbors.read_neighbors(INFO, run=lambda args: None, platform="windows") is None
    assert neighbors.read_neighbors(NetworkInfo(status="NO_NETWORK"), run=lambda a: "", platform="windows") is None


class FakeSock:
    def __init__(self):
        self.bound, self.sent = None, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def bind(self, addr):
        self.bound = addr

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def test_poke_sends_empty_datagrams_from_the_hotspot_ip_only_to_given_addresses():
    sock, slept = FakeSock(), []
    n = neighbors.poke(["172.20.10.1", "nu-e-ip", "172.20.10.14"], "172.20.10.10", make_socket=lambda: sock,
                       sleep=slept.append)
    assert n == 2 and sock.bound == ("172.20.10.10", 0)
    assert sock.sent == [(b"", ("172.20.10.1", 9)), (b"", ("172.20.10.14", 9))]
    assert slept == [0.04, 0.04]                                  # cel mult 25 pe secundă
