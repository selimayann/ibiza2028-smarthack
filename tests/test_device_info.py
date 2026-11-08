"""Oneata/B: FR-03, informațiile despre dispozitive (producător IEEE offline, MAC privat, tip).
Nimic de aici nu are voie să schimbe findings, scorul sau CSV-urile."""
import gzip
from dataclasses import asdict
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_folder
from netscan.model import Host, Port
from netscan.scan import device_info as di

VALIDATION = Path(__file__).parent.parent / "fixtures" / "validation"


def host(ports=(), vendor=None, mac=None, hostname=None, ip="192.168.1.50", dtype="unknown"):
    return Host(ip=ip, device_id="x", mac_masked=mac, vendor=vendor, hostname=hostname,
                device_type=dtype, ports=[Port(p, "tcp", "open") for p in ports])


# --- MAC privat --------------------------------------------------------------------------------

@pytest.mark.parametrize("mac, private", [
    ("02:1A:7D:XX:XX:XX", True), ("06:00:00:XX:XX:XX", True), ("DA:00:00:XX:XX:XX", True),
    ("4E:C7:BC:XX:XX:XX", True), ("50:C7:BF:XX:XX:XX", False), ("B8:27:EB:XX:XX:XX", False),
    ("00:11:32:XX:XX:XX", False), (None, False), ("", False), ("nu e mac", False),
])
def test_private_mac(mac, private):
    assert di.is_private_mac(mac) is private


def test_mac_prefix_formats():
    assert di.mac_prefix("50:c7:bf:XX:XX:XX") == "50C7BF"
    assert di.mac_prefix("50-C7-BF-12-34-56") == "50C7BF"
    assert di.mac_prefix("50C7BF123456") == "50C7BF"
    assert di.mac_prefix("XX:XX") is None


# --- lista IEEE offline ------------------------------------------------------------------------

def test_oui_file_is_in_repo_and_well_formed():
    assert di.OUI_FILE.is_file()
    with gzip.open(di.OUI_FILE, "rt", encoding="utf-8") as f:
        lines = f.read().splitlines()
    assert len(lines) > 30000
    prefixes = [l.split("\t")[0] for l in lines]
    assert prefixes == sorted(prefixes)
    assert all(len(p) == 6 and all(c in "0123456789ABCDEF" for c in p) for p in prefixes)
    assert all("\t" not in l.split("\t", 1)[1] and len(l.split("\t", 1)[1]) <= 80 for l in lines)


@pytest.mark.parametrize("mac, contains", [
    ("50:C7:BF:XX:XX:XX", "TP-LINK"), ("B8:27:EB:XX:XX:XX", "Raspberry Pi"),
    ("C0:56:E3:XX:XX:XX", "Hikvision"), ("24:0A:C4:XX:XX:XX", "Espressif"),
])
def test_lookup_vendor_known(mac, contains):
    assert contains.lower() in di.lookup_vendor(mac).lower()


def test_lookup_vendor_private_or_unknown():
    assert di.lookup_vendor("02:1A:7D:XX:XX:XX") is None        # privat: nu căutăm
    assert di.lookup_vendor(None) is None


def test_no_network_needed(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("FR-03 nu are voie să folosească rețeaua")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    di._oui_table.cache_clear()
    assert di.lookup_vendor("50:C7:BF:XX:XX:XX")


# --- descrierea și tipul -----------------------------------------------------------------------

def test_nmap_vendor_wins():
    info = di.describe(host(vendor="Dell", mac="50:C7:BF:XX:XX:XX"))
    assert (info.vendor, info.vendor_source) == ("Dell", "nmap")


def test_ieee_vendor_when_nmap_has_none_and_retyped():
    info = di.describe(host(ports=[554], mac="C0:56:E3:XX:XX:XX"))
    assert info.vendor_source == "ieee" and "Hikvision" in info.vendor
    assert info.device_type == "camera"


def test_private_mac_without_ports_is_phone_laptop():
    info = di.describe(host(mac="02:1A:7D:XX:XX:XX"))
    assert info.private_mac and info.vendor is None and info.device_type == "phone_laptop"


@pytest.mark.parametrize("ports, dtype", [
    ([631], "printer"), ([9100], "printer"), ([8008], "tv"), ([8009], "tv"),
    ([554], "camera"), ([3389], "pc_windows"), ([445], "pc_windows"),
])
def test_port_types_from_guide(ports, dtype):
    assert di.describe(host(ports=ports)).device_type == dtype


def test_strong_engine_type_is_kept():
    assert di.describe(host(ports=[8008], dtype="iot")).device_type == "iot"
    assert di.describe(host(ports=[631], dtype="camera")).device_type == "camera"


def test_gateway_is_router():
    assert di.describe(host(ip="172.20.10.1", ports=[53]), gateway_ip="172.20.10.1").device_type == "router"
    assert di.describe(host(ip="172.20.10.14"), gateway_ip="172.20.10.1").device_type != "router"


def test_display_host_is_a_copy():
    h = host(mac="C0:56:E3:XX:XX:XX", ports=[554])
    before = asdict(h)
    shown = di.display_host(h)
    assert asdict(h) == before and shown is not h and shown.vendor


# --- nu schimbă regulile -----------------------------------------------------------------------

def test_engine_output_unchanged_on_validation_set():
    """FR-03 e doar afișare: hosturile și findings-urile motorului rămân exact cum erau."""
    scans = analyze_folder(VALIDATION)
    snapshot = [s.to_dict() for s in scans]
    for s in scans:
        for h in s.hosts:
            di.describe(h)
            di.display_host(h, gateway_ip=h.ip)
    assert [s.to_dict() for s in scans] == snapshot


def test_v4_unknown_device_is_private_address():
    v4 = next(s for s in analyze_folder(VALIDATION) if s.file == "V4_legacy.xml")
    h99 = next(h for h in v4.hosts if h.ip == "192.168.1.99")
    assert any(f.code == "UNKNOWN_DEVICE" and f.ip == "192.168.1.99" for f in v4.findings)
    info = di.describe(h99)
    assert info.private_mac and info.vendor is None


# --- un NAS nu e „PC Windows” (are și el SMB pe 445) ----------------------------------------------------

@pytest.mark.parametrize("vendor, hostname", [
    ("Synology Incorporated", None), ("QNAP Systems, Inc.", None), ("Western Digital", None),
    ("BUFFALO.INC", None), ("ASUSTOR Inc.", None), (None, "nas"), (None, "casa-NAS01"), (None, "nas.local"),
])
def test_nas_with_smb_is_a_server(vendor, hostname):
    assert di.describe(host(ports=[445, 139, 5000], vendor=vendor, hostname=hostname)).device_type == "server"
    assert di.describe(host(ports=[445], vendor=vendor, hostname=hostname, dtype="pc_windows")).device_type == "server"


@pytest.mark.parametrize("hostname", ["jonas-laptop", "DESKTOP-NASTASE", "dinastia"])
def test_names_that_only_contain_nas_are_not_a_nas(hostname):
    assert di.describe(host(ports=[445], hostname=hostname)).device_type == "pc_windows"


def test_nas_gateway_is_still_the_router():
    h = host(ip="172.20.10.1", ports=[445], vendor="Synology Incorporated")
    assert di.describe(h, gateway_ip="172.20.10.1").device_type == "router"


# --- Hotspot de pe telefon vs. router adevărat (doar eticheta din UI) ----------------------------------

def test_iphone_hotspot_from_our_real_scan_shape():
    # ca în scanarea noastră: 172.20.10.1, MAC privat, FTP ghicit pe 21, DNS, 62078 (sincronizare iOS)
    h = host(ports=[21, 53, 62078], mac="66:48:42:XX:XX:XX", ip="172.20.10.1", dtype="server")
    assert di.describe(h).device_type == "hotspot_iphone"


def test_iphone_hotspot_when_it_is_the_gateway_elsewhere():
    h = host(ports=[53, 62078], mac="6A:00:00:XX:XX:XX", ip="10.0.0.1")
    assert di.describe(h, gateway_ip="10.0.0.1").device_type == "hotspot_iphone"


def test_iphone_as_a_client_is_not_a_hotspot():
    h = host(ports=[62078], mac="6A:00:00:XX:XX:XX", ip="192.168.1.23")
    assert di.describe(h, gateway_ip="192.168.1.1").device_type == "phone_laptop"


def test_android_hotspot_gateway_with_private_mac_and_no_admin_page():
    h = host(ports=[53], mac="DA:00:00:XX:XX:XX", ip="192.168.43.1")
    assert di.describe(h).device_type == "hotspot_phone"
    g = host(ports=[53], mac="DA:00:00:XX:XX:XX", ip="10.42.0.1")
    assert di.describe(g, gateway_ip="10.42.0.1").device_type == "hotspot_phone"


def test_real_router_stays_router():
    r = host(ports=[53, 80, 443], vendor="TP-Link", mac="50:C7:BF:XX:XX:XX", ip="192.168.1.1", dtype="router")
    assert di.describe(r, gateway_ip="192.168.1.1").device_type == "router"
    # gateway fără producător, dar cu pagină de administrare: router, nu telefon
    a = host(ports=[53, 80], mac="DA:00:00:XX:XX:XX", ip="192.168.0.1")
    assert di.describe(a, gateway_ip="192.168.0.1").device_type == "router"


def test_hotspot_label_does_not_change_findings_or_scores():
    before = [(s.file, s.score, [asdict(f) for f in s.findings]) for s in analyze_folder(VALIDATION)]
    for s in analyze_folder(VALIDATION):
        for h in s.hosts:
            di.display_host(h, gateway_ip=h.ip)
    after = [(s.file, s.score, [asdict(f) for f in s.findings]) for s in analyze_folder(VALIDATION)]
    assert before == after
