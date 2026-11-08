"""Oneata: detectarea rețelei (FR-01). Teste pe text și cu psutil fals: nu ating rețeaua,
rulează la fel pe Windows, Linux și macOS."""
import socket
from collections import namedtuple

import pytest

from netscan.scan import network as n

Addr = namedtuple("Addr", "family address netmask")
Stat = namedtuple("Stat", "isup")


class FakePsutil:
    """ifaces: {nume: (isup, ip, netmask)}"""

    def __init__(self, ifaces):
        self.ifaces = ifaces

    def net_if_addrs(self):
        return {name: [Addr(socket.AF_INET, ip, mask)] for name, (_, ip, mask) in self.ifaces.items()}

    def net_if_stats(self):
        return {name: Stat(up) for name, (up, _, _) in self.ifaces.items()}


def fake_runner(outputs):
    """outputs: {primul argument al comenzii: text}. Comenzile necunoscute „eșuează” (None)."""
    calls = []

    def run(args):
        calls.append(args)
        assert isinstance(args, list)
        return outputs.get(args[0])

    run.calls = calls
    return run


# --- ieșiri reale de comenzi (IP-uri înlocuite) ----------------------------------------------

WIN_ROUTE = """\
===========================================================================
Interface List
 10...........................VirtualBox Host-Only Ethernet Adapter
 11...........................MediaTek Wi-Fi 6 MT7921 Wireless LAN Card
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      172.20.10.1      172.20.10.3     35
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.1.1  Default
===========================================================================
"""

WIN_ROUTE_RO = """\
Tabel rute IPv4
===========================================================================
Rute active:
Destinație rețea        Mască rețea       Gateway       Interfață  Metrică
          0.0.0.0          0.0.0.0      172.20.10.1      172.20.10.3     35
===========================================================================
Rute persistente:
  Niciuna
"""

WIN_NETSH = """\

There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : MediaTek Wi-Fi 6 MT7921 Wireless LAN Card
    GUID                   : 00000000-0000-0000-0000-000000000000
    State                  : connected
    SSID                   : RSH-ibiza2028
    BSSID                  : aa:bb:cc:dd:ee:ff
    Profile                : RSH-ibiza2028
"""

WIN_NETSH_RO = """\

Există 2 interfețe în sistem:

    Nume                   : Wi-Fi 2
    Descriere              : USB Wireless
    Stare                  : deconectat

    Nume                   : Wi-Fi
    Descriere              : MediaTek
    Stare                  : conectat
    SSID                   : RSH-ibiza2028
    BSSID                  : aa:bb:cc:dd:ee:ff
"""

WIN_ADAPTERS = (
    '[{"Name":"Wi-Fi","InterfaceDescription":"MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"},'
    '{"Name":"Ethernet 2","InterfaceDescription":"VirtualBox Host-Only Ethernet Adapter"},'
    '{"Name":"Ethernet","InterfaceDescription":"Realtek PCIe GbE Family Controller"},'
    '{"Name":"vEthernet (WSL (Hyper-V firewall))","InterfaceDescription":"Hyper-V Virtual Ethernet Adapter"}]'
)

# Exact situația de pe laptopul lui Oneata: Wi-Fi + VirtualBox („Ethernet 2”) + WSL, toate „up”.
WIN_IFACES = {
    "Wi-Fi": (True, "172.20.10.3", "255.255.255.240"),
    "Ethernet 2": (True, "192.168.56.1", "255.255.255.0"),
    "vEthernet (WSL (Hyper-V firewall))": (True, "172.25.224.1", "255.255.240.0"),
    "Ethernet": (False, "169.254.40.199", "255.255.0.0"),
    "Loopback Pseudo-Interface 1": (True, "127.0.0.1", "255.0.0.0"),
}

LINUX_ROUTE = """\
default via 172.20.10.1 dev wlp2s0 proto dhcp src 172.20.10.4 metric 600
default via 10.8.0.1 dev tun0 metric 50
"""

MAC_ROUTE = """\
   route to: default
destination: default
       mask: default
    gateway: 172.20.10.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""

MAC_SUMMARY = """\
<dictionary> {
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : RSH-ibiza2028
}
"""


# --- parsere ------------------------------------------------------------------------------------

def test_parse_windows_route_print_ignores_persistent_routes():
    routes = n.parse_windows_route_print(WIN_ROUTE)
    assert routes == [n.DefaultRoute(gateway="172.20.10.1", iface_ip="172.20.10.3", metric=35)]


def test_parse_windows_route_print_romanian():
    assert n.parse_windows_route_print(WIN_ROUTE_RO)[0].iface_ip == "172.20.10.3"


def test_parse_windows_route_on_link():
    text = "          0.0.0.0          0.0.0.0         On-link      172.20.10.3     35\n"
    assert n.parse_windows_route_print(text) == [n.DefaultRoute(gateway=None, iface_ip="172.20.10.3", metric=35)]


def test_parse_linux_ip_route():
    routes = n.parse_linux_ip_route(LINUX_ROUTE)
    assert routes[0] == n.DefaultRoute(gateway="172.20.10.1", iface="wlp2s0", metric=600)
    assert routes[1].iface == "tun0"


def test_parse_macos_route():
    assert n.parse_macos_route_get(MAC_ROUTE) == [n.DefaultRoute(gateway="172.20.10.1", iface="en0")]


@pytest.mark.parametrize("text", ["", "route: writing to routing socket: not in table\n"])
def test_parse_macos_no_route(text):
    assert n.parse_macos_route_get(text) == []


def test_parse_netsh_ssid():
    assert n.parse_windows_netsh_ssid(WIN_NETSH, "Wi-Fi") == "RSH-ibiza2028"
    assert n.parse_windows_netsh_ssid(WIN_NETSH, "Altceva") == "RSH-ibiza2028"  # un singur bloc


def test_parse_netsh_ssid_romanian_two_adapters():
    assert n.parse_windows_netsh_ssid(WIN_NETSH_RO, "Wi-Fi") == "RSH-ibiza2028"
    assert n.parse_windows_netsh_ssid(WIN_NETSH_RO, "Wi-Fi 2") is None
    assert n.parse_windows_netsh_ssid(WIN_NETSH_RO, "Ethernet") is None  # două blocuri, niciunul nu e al lui


def test_parse_netsh_not_wifi():
    assert n.parse_windows_netsh_ssid("The Wireless AutoConfig Service (wlansvc) is not running.\n", "Wi-Fi") is None


def test_parse_iw_link():
    assert n.parse_iw_link("Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: RSH-ibiza2028\n\tfreq: 2437\n") == \
        "RSH-ibiza2028"
    assert n.parse_iw_link("Not connected.\n") is None


def test_parse_macos_ssid():
    assert n.parse_macos_ssid(MAC_SUMMARY) == "RSH-ibiza2028"
    assert n.parse_macos_ssid("Current Wi-Fi Network: RSH-ibiza2028\n") == "RSH-ibiza2028"
    assert n.parse_macos_ssid("  SSID : <redacted>\n") is None


def test_parse_windows_adapters():
    assert n.parse_windows_adapters(WIN_ADAPTERS)["Ethernet 2"].startswith("VirtualBox")
    assert n.parse_windows_adapters('{"Name":"Wi-Fi","InterfaceDescription":"X"}') == {"Wi-Fi": "X"}
    assert n.parse_windows_adapters("nu e json") == {}


@pytest.mark.parametrize(
    "name, desc",
    [
        ("lo", None), ("lo0", None), ("Loopback Pseudo-Interface 1", None),
        ("docker0", None), ("br-1a2b3c", None), ("veth12ab", None), ("virbr0", None),
        ("vEthernet (WSL (Hyper-V firewall))", None), ("vboxnet0", None), ("vmnet8", None),
        ("utun3", None), ("tun0", None), ("tailscale0", None), ("wg0", None), ("awdl0", None),
        ("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter"),
        ("Ethernet 3", "VMware Virtual Ethernet Adapter for VMnet8"),
        ("Local Area Connection* 9", "Microsoft Wi-Fi Direct Virtual Adapter"),
        ("OpenVPN Connect", "TAP-Windows Adapter V9"),
        ("Tailscale", "Tailscale Tunnel"),
    ],
)
def test_virtual_ifaces(name, desc):
    assert n.is_virtual_iface(name, desc)


@pytest.mark.parametrize(
    "name, desc",
    [("Wi-Fi", "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"), ("Ethernet", "Realtek PCIe GbE Family Controller"),
     ("en0", None), ("Ethernet 4", "Apple Mobile Device Ethernet")],
)
def test_physical_ifaces(name, desc):
    assert not n.is_virtual_iface(name, desc)


# --- detect_network ------------------------------------------------------------------------------

ENV = {"NETSCAN_EXPECTED_SSID": "RSH-ibiza2028"}


def windows_runner(**over):
    outputs = {"route": WIN_ROUTE, "powershell": WIN_ADAPTERS, "netsh": WIN_NETSH}
    outputs.update(over)
    return fake_runner(outputs)


def test_windows_hotspot_ok_ignores_virtualbox_and_wsl():
    info = n.detect_network(windows_runner(), FakePsutil(WIN_IFACES), "windows", ENV)
    assert info.status == n.OK, info
    assert (info.iface, info.ip, info.cidr, info.gateway, info.ssid) == \
        ("Wi-Fi", "172.20.10.3", "172.20.10.0/28", "172.20.10.1", "RSH-ibiza2028")
    assert info.scan_allowed and info.warnings == []


def test_windows_without_adapter_descriptions_sees_virtualbox_as_second_network():
    """Dacă Get-NetAdapter nu merge, „Ethernet 2” arată ca fizic: refuzăm (sigur), nu ghicim."""
    info = n.detect_network(windows_runner(powershell=None), FakePsutil(WIN_IFACES), "windows", ENV)
    assert info.status == n.MULTIPLE_NETWORKS and info.other_ifaces == ["Ethernet 2"]


def test_wifi_and_ethernet_is_multiple_networks():
    ifaces = dict(WIN_IFACES, Ethernet=(True, "192.168.1.50", "255.255.255.0"))
    info = n.detect_network(windows_runner(), FakePsutil(ifaces), "windows", ENV)
    assert info.status == n.MULTIPLE_NETWORKS
    assert info.other_ifaces == ["Ethernet"]
    assert not info.scan_allowed


def test_wrong_ssid_refused():
    netsh = WIN_NETSH.replace("RSH-ibiza2028", "Venue Free WiFi")
    info = n.detect_network(windows_runner(netsh=netsh), FakePsutil(WIN_IFACES), "windows", ENV)
    assert info.status == n.WRONG_SSID and not info.scan_allowed


def test_ssid_unreadable_is_warning():
    info = n.detect_network(windows_runner(netsh=None), FakePsutil(WIN_IFACES), "windows", ENV)
    assert info.status == n.OK and n.W_SSID_UNKNOWN in info.warnings


def test_ssid_unreadable_refused_when_required():
    env = dict(ENV, NETSCAN_REQUIRE_SSID="1")
    info = n.detect_network(windows_runner(netsh=None), FakePsutil(WIN_IFACES), "windows", env)
    assert info.status == n.SSID_UNREADABLE and not info.scan_allowed
    assert n.SSID_UNREADABLE in n.MESSAGES


def test_require_ssid_does_not_block_when_ssid_is_readable():
    env = dict(ENV, NETSCAN_REQUIRE_SSID="1")
    info = n.detect_network(windows_runner(), FakePsutil(WIN_IFACES), "windows", env)
    assert info.status == n.OK and info.scan_allowed


@pytest.mark.parametrize("env", [{}, {"NETSCAN_EXPECTED_SSID": ""}, {"NETSCAN_EXPECTED_SSID": "   "}])
def test_expected_ssid_not_configured_refuses(env):
    """Fără numele hotspotului, nu putem deosebi hotspotul de Wi-Fi-ul venue: refuz, nu avertisment."""
    info = n.detect_network(windows_runner(), FakePsutil(WIN_IFACES), "windows", env)
    assert info.status == n.SSID_NOT_CONFIGURED and not info.scan_allowed


def test_no_network():
    ps = FakePsutil({"Loopback Pseudo-Interface 1": (True, "127.0.0.1", "255.0.0.0"),
                     "Wi-Fi": (False, "169.254.1.1", "255.255.0.0")})
    info = n.detect_network(fake_runner({}), ps, "windows", ENV)
    assert info.status == n.NO_NETWORK and info.iface is None


def test_hotspot_without_gateway():
    ps = FakePsutil({"Wi-Fi": (True, "172.20.10.3", "255.255.255.240")})
    info = n.detect_network(windows_runner(route=""), ps, "windows", ENV)
    assert info.status == n.OK and info.gateway is None and n.W_NO_GATEWAY in info.warnings


def test_psutil_missing(monkeypatch):
    monkeypatch.setattr(n, "psutil", None)
    assert n.detect_network(fake_runner({}), None, "windows", ENV).status == n.PSUTIL_MISSING


def test_linux_ignores_vpn_default_route_but_refuses_while_the_vpn_is_on():
    ps = FakePsutil({"lo": (True, "127.0.0.1", "255.0.0.0"), "wlp2s0": (True, "172.20.10.4", "255.255.255.240"),
                     "tun0": (True, "10.8.0.2", "255.255.255.0"), "docker0": (True, "172.17.0.1", "255.255.0.0")})
    run = fake_runner({"ip": LINUX_ROUTE, "iw": "\tSSID: RSH-ibiza2028\n"})
    info = n.detect_network(run, ps, "linux", ENV)
    assert (info.status, info.iface, info.cidr, info.gateway, info.ssid) == \
        (n.VPN_ON, "wlp2s0", "172.20.10.0/28", "172.20.10.1", "RSH-ibiza2028")
    assert info.vpn_ifaces == ["tun0"] and not info.scan_allowed
    ps.ifaces["tun0"] = (False, "10.8.0.2", "255.255.255.0")             # VPN oprit: hotspotul e din nou OK
    assert n.detect_network(run, ps, "linux", ENV).status == n.OK


def test_linux_ssid_fallback_to_nmcli():
    ps = FakePsutil({"wlp2s0": (True, "172.20.10.4", "255.255.255.240")})
    run = fake_runner({"ip": LINUX_ROUTE, "nmcli": "RSH-ibiza2028\n"})
    assert n.detect_network(run, ps, "linux", ENV).ssid == "RSH-ibiza2028"


def test_macos():
    ps = FakePsutil({"lo0": (True, "127.0.0.1", "255.0.0.0"), "en0": (True, "172.20.10.2", "255.255.255.240"),
                     "awdl0": (True, "169.254.3.3", "255.255.0.0")})
    run = fake_runner({"route": MAC_ROUTE, "ipconfig": MAC_SUMMARY})
    info = n.detect_network(run, ps, "macos", ENV)
    assert (info.status, info.iface, info.cidr, info.ssid) == (n.OK, "en0", "172.20.10.0/28", "RSH-ibiza2028")


def test_macos_utun_with_ipv4_is_a_vpn():
    ps = FakePsutil({"lo0": (True, "127.0.0.1", "255.0.0.0"), "en0": (True, "172.20.10.2", "255.255.255.240"),
                     "utun3": (True, "100.100.1.1", "255.255.255.255")})
    run = fake_runner({"route": MAC_ROUTE, "ipconfig": MAC_SUMMARY})
    info = n.detect_network(run, ps, "macos", ENV)
    assert (info.status, info.iface, info.vpn_ifaces) == (n.VPN_ON, "en0", ["utun3"])


# --- VPN pornit lângă hotspot -----------------------------------------------------------------

class FakePsutilV6(FakePsutil):
    """Ca FakePsutil, dar unele interfețe au doar IPv6 (ca utun0..utun3 de pe orice Mac)."""

    def __init__(self, ifaces, v6_only):
        super().__init__(ifaces)
        self.v6_only = set(v6_only)

    def net_if_addrs(self):
        out = super().net_if_addrs()
        for name in self.v6_only:
            out[name] = [Addr(socket.AF_INET6, "fe80::1", "ffff:ffff:ffff:ffff::")]
        return out


WIN_VPN_ADAPTERS = WIN_ADAPTERS[:-1] + (
    ',{"Name":"Tailscale","InterfaceDescription":"Tailscale Tunnel"}'
    ',{"Name":"Ethernet 5","InterfaceDescription":"TAP-Windows Adapter V9"}'
    ',{"Name":"wg-office","InterfaceDescription":"WireGuard Tunnel"}'
    ',{"Name":"Ethernet 6","InterfaceDescription":"Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter"}'
    ',{"Name":"ZeroTier One [8056c2e21c]","InterfaceDescription":"ZeroTier Virtual Port"}]'
)


@pytest.mark.parametrize("name, ip", [
    ("Tailscale", "100.101.102.103"), ("Ethernet 5", "10.8.0.6"), ("wg-office", "10.66.0.2"),
    ("Ethernet 6", "10.200.1.9"), ("ZeroTier One [8056c2e21c]", "10.147.17.4"),
])
def test_windows_vpn_on_the_hotspot_refuses_and_names_the_vpn(name, ip):
    ifaces = dict(WIN_IFACES, **{name: (True, ip, "255.255.255.0")})
    info = n.detect_network(windows_runner(powershell=WIN_VPN_ADAPTERS), FakePsutil(ifaces), "windows", ENV)
    assert info.status == n.VPN_ON and not info.scan_allowed
    assert info.vpn_ifaces == [name] and info.iface == "Wi-Fi" and info.other_ifaces == []
    ro, en = n.describe(info, "ro"), n.describe(info, "en")
    assert f"Ai un VPN pornit ({name})" in ro and "oprește VPN-ul înainte de scanare" in ro
    assert f"You have a VPN turned on ({name})" in en and "Rețeaua: nu scanez aici" in ro
    assert n.status_message(info)[0].startswith(f"Ai un VPN pornit ({name})")


def test_vpn_that_is_down_or_has_no_ipv4_is_ignored():
    ifaces = dict(WIN_IFACES, Tailscale=(False, "100.101.102.103", "255.255.255.255"),
                  **{"wg-office": (True, "", ""), "utun0": (True, "", "")})
    ps = FakePsutilV6(ifaces, v6_only={"utun0", "wg-office"})
    info = n.detect_network(windows_runner(powershell=WIN_VPN_ADAPTERS), ps, "windows", ENV)
    assert info.status == n.OK and info.vpn_ifaces == []


def test_docker_hyperv_virtualbox_are_still_only_ignored_not_vpn():
    ifaces = dict(WIN_IFACES, docker0=(True, "172.17.0.1", "255.255.0.0"),
                  vboxnet0=(True, "192.168.57.1", "255.255.255.0"))
    info = n.detect_network(windows_runner(), FakePsutil(ifaces), "windows", ENV)
    assert info.status == n.OK and info.vpn_ifaces == [] and info.scan_allowed
    for name, desc in [("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter"), ("docker0", None),
                       ("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter")]:
        assert n.is_virtual_iface(name, desc) and not n.is_vpn_iface(name, desc)


def test_vpn_is_a_warning_when_the_network_is_already_refused():
    netsh = WIN_NETSH.replace("RSH-ibiza2028", "Venue Free WiFi")
    ifaces = dict(WIN_IFACES, Tailscale=(True, "100.101.102.103", "255.255.255.255"))
    info = n.detect_network(windows_runner(netsh=netsh, powershell=WIN_VPN_ADAPTERS), FakePsutil(ifaces),
                            "windows", ENV)
    assert info.status == n.WRONG_SSID and n.VPN_ON in info.warnings
    assert "! Ai un VPN pornit (Tailscale)" in n.describe(info, "ro")


def test_vpn_message_without_names_still_reads_well():
    ro, en = n.message(n.VPN_ON)
    assert "%s" not in ro and "%s" not in en and "(VPN)" in ro


def test_never_lists_nearby_wifi_networks():
    """Instrucțiunile interzic listarea rețelelor din jur (ex. `nmcli dev wifi`, `netsh wlan show networks`)."""
    for platform, outputs in [("windows", {"route": WIN_ROUTE, "powershell": WIN_ADAPTERS}),
                              ("linux", {"ip": LINUX_ROUTE}), ("macos", {"route": MAC_ROUTE})]:
        ps = FakePsutil({"Wi-Fi": (True, "172.20.10.3", "255.255.255.240"),
                         "wlp2s0": (True, "172.20.10.4", "255.255.255.240"),
                         "en0": (True, "172.20.10.2", "255.255.255.240")})
        run = fake_runner(outputs)
        n.detect_network(run, ps, platform, ENV)
        for args in run.calls:
            joined = " ".join(args).lower()
            assert "show networks" not in joined and "dev wifi" not in joined and "scan" not in joined


def test_describe_bilingual():
    info = n.detect_network(windows_runner(), FakePsutil(WIN_IFACES), "windows", ENV)
    assert "Rețeaua: hotspotul echipei (scanez doar în 172.20.10.0/28)" in n.describe(info, "ro")
    assert "Network: team hotspot (I only scan inside 172.20.10.0/28)" in n.describe(info, "en")
    refused = n.NetworkInfo(iface="Wi-Fi", ip="10.240.3.7", cidr="10.240.0.0/16", status=n.WRONG_SSID)
    assert "Rețeaua: nu scanez aici" in n.describe(refused, "ro")
    assert "Network: I won't scan here" in n.describe(refused, "en")


def test_cidr_feeds_guardrail():
    from netscan.scan.guardrail import build_allowlist, check_target

    info = n.detect_network(windows_runner(), FakePsutil(WIN_IFACES), "windows", ENV)
    allow = build_allowlist(info.cidr)
    assert check_target("172.20.10.5", allow).ok
    assert not check_target("192.168.56.1", allow).ok  # rețeaua VirtualBox nu e permisă
