"""B: ascultarea pasivă mDNS/SSDP. Pachete construite de mână (și stricate), fără rețea."""
import socket
import struct

import pytest

from netscan.scan import local_data, network, passive
from netscan.scan.eavesdrop import as_text, get_eavesdrop


def name_bytes(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def rr(name: str, rtype: int, rdata: bytes) -> bytes:
    return name_bytes(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def mdns_packet(*records: bytes) -> bytes:
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def txt(**items) -> bytes:
    out = b""
    for k, v in items.items():
        raw = f"{k}={v}".encode()
        out += bytes([len(raw)]) + raw
    return out


CHROMECAST = mdns_packet(
    rr("_googlecast._tcp.local", 12, name_bytes("Chromecast-abc._googlecast._tcp.local")),
    rr("Chromecast-abc._googlecast._tcp.local", 16, txt(fn="Chromecast Sufragerie", md="Chromecast")),
    rr("chromecast-abc.local", 1, socket.inet_aton("172.20.10.5")),
)
PRINTER = mdns_packet(rr("_ipp._tcp.local", 12, name_bytes("HP LaserJet M110._ipp._tcp.local")))
SSDP_NOTIFY = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"LOCATION: http://evil.example.com/desc.xml\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\n"
               b"SERVER: Linux/4.9 UPnP/1.0 Cast/1.0\r\nNTS: ssdp:alive\r\n\r\n")


# --- parsere -------------------------------------------------------------------------------------------

def test_chromecast_friendly_name():
    info = passive.describe_mdns(passive.parse_mdns(CHROMECAST))
    assert info == {"name": "Chromecast Sufragerie", "service": "Google Cast (TV / Chromecast)"}


def test_printer_instance_name():
    assert passive.describe_mdns(passive.parse_mdns(PRINTER)) == {"name": "HP LaserJet M110", "service": "Imprimantă"}


def test_ssdp_ignores_location_link():
    info = passive.parse_ssdp(SSDP_NOTIFY)
    assert info == {"name": "Linux/4.9 UPnP/1.0 Cast/1.0", "service": "TV / Chromecast (DIAL)"}
    assert "evil" not in repr(info)


@pytest.mark.parametrize("data", [
    b"", b"\x00" * 11, b"\xff" * 40, b"garbage" * 2000,
    struct.pack("!HHHHHH", 0, 0, 0, 1, 0, 0) + b"\xc0\x0c",                  # pointer spre el însuși (buclă)
    struct.pack("!HHHHHH", 0, 0, 0, 5000, 0, 0) + b"\x01a\x00",               # prea multe înregistrări
    struct.pack("!HHHHHH", 0, 0, 0, 1, 0, 0) + b"\x3fabc",                    # etichetă trunchiată
])
def test_hostile_mdns_never_crashes(data):
    assert isinstance(passive.parse_mdns(data), list)


def test_hostile_names_are_cleaned():
    evil = mdns_packet(rr("x._http._tcp.local", 16, txt(fn="<script>alert(1)</script>\n\x00" + "A" * 200)))
    name = passive.describe_mdns(passive.parse_mdns(evil))["name"]
    assert "\n" not in name and "\x00" not in name and len(name) <= 60
    # escaparea în HTML e treaba UI-ului (autoescape); aici doar curățăm și tăiem


def test_ssdp_rejects_non_announcements():
    assert passive.parse_ssdp(b"GET / HTTP/1.1\r\n\r\n") is None
    assert passive.parse_ssdp(b"x" * 20000) is None


# --- ascultătorul --------------------------------------------------------------------------------------

def test_listener_only_hotspot_ips_and_writes_changes(tmp_path):
    db = tmp_path / "data" / "netscan.db"
    lines = []
    lst = passive.Listener("172.20.10.0/28", "172.20.10.10", out=lines.append, db_path=db, now=lambda: 5.0)
    assert lst.handle(CHROMECAST, "192.168.1.50", 5353) is None          # nu e din hotspot
    assert lst.handle(CHROMECAST, "172.20.10.10", 5353) is None          # suntem noi
    ev = lst.handle(CHROMECAST, "172.20.10.5", 5353)
    assert ev["name"] == "Chromecast Sufragerie" and "Dispozitiv anunțat: 172.20.10.5" in lines[0]
    assert lst.handle(CHROMECAST, "172.20.10.5", 5353) is None           # același anunț: nu se repetă
    names = passive.load_names(db)
    assert names["172.20.10.5"]["name"] == "Chromecast Sufragerie" and set(names) == {"172.20.10.5"}


def test_refuses_off_hotspot():
    info = network.NetworkInfo(iface="Wi-Fi", ip="10.240.236.143", cidr="10.240.0.0/16", status=network.WRONG_SSID)
    lines = []
    assert passive.run_listen(True, out=lines.append, detect=lambda: info) == 2 and "Nu ascult" in lines[0]


def test_dry_run_sends_nothing(monkeypatch):
    info = network.NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", status=network.OK)
    monkeypatch.setattr(passive, "_open_socket", lambda *a: pytest.fail("dry-run nu deschide socket-uri"))
    lines = []
    assert passive.run_listen(False, out=lines.append, detect=lambda: info) == 0 and "Dry-run" in lines[0]


def test_delete_history_removes_names(tmp_path):
    db = tmp_path / "data" / "netscan.db"
    local_data.append_events(passive.names_path(db), [{"ts": 1.0, "ip": "172.20.10.5", "name": "iPhone-lui-Andrei"}])
    local_data.delete_local_data(db)
    assert not passive.names_path(db).exists()


# --- „ce vede cineva care ascultă” ------------------------------------------------------------------------

@pytest.mark.parametrize("code", ["FTP_CLEARTEXT", "TELNET_OPEN", "HTTP_ADMIN_CLEARTEXT"])
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_eavesdrop_sample(code, lang):
    e = get_eavesdrop(code, lang)
    pw = "parola-ta" if lang == "ro" else "your-password"
    assert pw in e["lines"][e["highlight"]]
    assert ("inventat" in e["caption"]) if lang == "ro" else ("Made-up" in e["caption"])


@pytest.mark.parametrize("code", ["SSH_OPEN", "CAMERA_STREAM_EXPOSED", "NU_EXISTA"])
def test_eavesdrop_only_for_cleartext_codes(code):
    assert get_eavesdrop(code) is None and as_text(code) is None


def test_eavesdrop_has_no_real_ips():
    import re
    for code in ["FTP_CLEARTEXT", "TELNET_OPEN", "HTTP_ADMIN_CLEARTEXT"]:
        assert not re.search(r"\d+\.\d+\.\d+\.\d+", as_text(code))
