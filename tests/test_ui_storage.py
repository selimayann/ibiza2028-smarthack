"""RBRT: istoricul SQLite și diff(). Date sintetice; V6a -> V6b se adaugă când există motorul."""
import json
from pathlib import Path

import pytest

from netscan.model import Finding, Host, Port, Scan
from netscan.ui import storage

SAMPLE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def sample() -> Scan:
    return Scan.from_dict(json.loads(SAMPLE.read_text(encoding="utf-8")))


@pytest.fixture
def db(tmp_path):
    return tmp_path / "h.db"


def test_save_and_load_roundtrip(db):
    scan = sample()
    scan_id = storage.save_scan(scan, db)
    assert storage.get_scan(scan_id, db) == scan


def test_list_ordered_by_started_at(db):
    late = Scan(file="b.xml", status="ok", started_at=200, score=100)
    early = Scan(file="a.xml", status="ok", started_at=100, score=90)
    no_date = Scan(file="c.xml", status="error", error_code="TRUNCATED")
    for s in (late, no_date, early):
        storage.save_scan(s, db)
    assert [s.file for s in storage.list_scans(db)] == ["a.xml", "b.xml", "c.xml"]


def test_previous_scan_id(db):
    a = storage.save_scan(Scan(file="a.xml", status="ok", started_at=1, score=50), db)
    b = storage.save_scan(Scan(file="b.xml", status="ok", started_at=2, score=60), db)
    assert storage.previous_scan_id(b, db) == a
    assert storage.previous_scan_id(a, db) is None


def test_delete_history(db):
    storage.save_scan(sample(), db)
    storage.delete_history(db)
    assert storage.list_scans(db) == []


def test_untrusted_text_stored_verbatim(db):
    """Text ostil din scanare se salvează ca date, nu ca SQL."""
    evil = "x'); DROP TABLE scans; --"
    scan = Scan(file=evil, status="ok", started_at=1, score=100,
                hosts=[Host(ip="10.0.0.5", device_id="ip:10.0.0.5", hostname=evil,
                            ports=[Port(port=80, proto="tcp", state="open", title=evil)])])
    scan_id = storage.save_scan(scan, db)
    loaded = storage.get_scan(scan_id, db)
    assert loaded is not None and loaded.file == evil
    assert loaded.hosts[0].ports[0].title == evil


def _f(dev, port, code, sev="medium", pts=10):
    return Finding(file="x.xml", ip="10.0.0.1", device_id=dev, port=port, code=code,
                   severity=sev, points=pts, evidence="e")


def test_diff_resolved_and_new():
    old = Scan(file="old.xml", status="ok", score=60,
               hosts=[Host(ip="10.0.0.1", device_id="d1", ports=[
                   Port(port=23, proto="tcp", state="open"),
                   Port(port=3306, proto="tcp", state="open")]),
                      Host(ip="10.0.0.2", device_id="d2")],
               findings=[_f("d1", 23, "TELNET_OPEN", "high", 20), _f("d1", 3306, "DB_EXPOSED", "high", 20)])
    new = Scan(file="new.xml", status="ok", score=90,
               hosts=[Host(ip="10.0.0.1", device_id="d1", ports=[
                   Port(port=23, proto="tcp", state="filtered"),
                   Port(port=3306, proto="tcp", state="open"),
                   Port(port=1883, proto="tcp", state="open")]),
                      Host(ip="10.0.0.3", device_id="d3")],
               findings=[_f("d1", 3306, "DB_EXPOSED", "high", 20), _f("d1", 1883, "MQTT_EXPOSED")])
    d = storage.diff(old, new)
    assert [f.code for f in d.resolved_findings] == ["TELNET_OPEN"]
    assert [f.code for f in d.new_findings] == ["MQTT_EXPOSED"]
    assert [h.device_id for h in d.new_devices] == ["d3"]
    assert [h.device_id for h in d.removed_devices] == ["d2"]
    assert d.opened_ports == [("d1", 1883, "tcp")]
    assert d.closed_ports == [("d1", 23, "tcp")]  # filtered nu mai e "open"
    assert (d.score_before, d.score_after) == (60, 90)


def test_diff_identical_is_empty():
    s = sample()
    d = storage.diff(s, s)
    assert not (d.resolved_findings or d.new_findings or d.new_devices or d.removed_devices
                or d.opened_ports or d.closed_ports)


def test_diff_same_code_other_port_is_different_finding():
    old = Scan(file="a", status="ok", score=90, findings=[_f("d1", 80, "HTTP_ADMIN_CLEARTEXT")])
    new = Scan(file="b", status="ok", score=90, findings=[_f("d1", 8080, "HTTP_ADMIN_CLEARTEXT")])
    d = storage.diff(old, new)
    assert len(d.resolved_findings) == 1 and len(d.new_findings) == 1


# ---------- potrivirea dispozitivelor când MAC-ul se schimbă (acord cu Radu) ----------

VAL = Path(__file__).parent.parent / "fixtures" / "validation"


def test_v6a_to_v6b_real_files():
    """V6a și V6b au MAC-uri diferite pentru aceleași dispozitive: potrivire după IP + vendor."""
    from netscan.engine import analyze_file

    d = storage.diff(analyze_file(VAL / "V6a_before.xml"), analyze_file(VAL / "V6b_after.xml"))
    assert len(d.resolved_findings) == 3
    assert d.new_findings == [] and d.persistent_findings == []
    assert d.new_devices == [] and d.removed_devices == []
    assert (d.score_before, d.score_after) == (60, 100)


def _h(dev, ip, vendor, ports=()):
    return Host(ip=ip, device_id=dev, vendor=vendor,
                ports=[Port(port=p, proto="udp" if p == 1900 else "tcp", state="open") for p in ports])


def _fd(dev, ip, port, code, sev, pts):
    return Finding(file="x.xml", ip=ip, device_id=dev, port=port, code=code,
                   severity=sev, points=pts, evidence="e")


def test_one_problem_remains_after_repair():
    """MAC-uri schimbate; după reparare rămâne TELNET: 2 rezolvate, 1 persistentă, 0 noi, scor < 100."""
    old = Scan(file="before.xml", status="ok", score=60,
               hosts=[_h("aaa111", "192.168.1.1", "TP-Link", (80, 1900)), _h("bbb222", "192.168.1.30", "Espressif", (23,))],
               findings=[_fd("aaa111", "192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT", "medium", 10),
                         _fd("aaa111", "192.168.1.1", 1900, "UPNP_EXPOSED", "medium", 10),
                         _fd("bbb222", "192.168.1.30", 23, "TELNET_OPEN", "high", 20)])
    new = Scan(file="after.xml", status="ok", score=80,
               hosts=[_h("ccc333", "192.168.1.1", "TP-Link", (443,)), _h("ddd444", "192.168.1.30", "Espressif", (23,))],
               findings=[_fd("ddd444", "192.168.1.30", 23, "TELNET_OPEN", "high", 20)])
    d = storage.diff(old, new)
    assert sorted(f.code for f in d.resolved_findings) == ["HTTP_ADMIN_CLEARTEXT", "UPNP_EXPOSED"]
    assert [f.code for f in d.persistent_findings] == ["TELNET_OPEN"]
    assert d.new_findings == []
    assert d.new_devices == [] and d.removed_devices == []
    assert d.score_after != 100 and (d.score_before, d.score_after) == (60, 80)
    assert d.closed_ports == [("ccc333", 80, "tcp"), ("ccc333", 1900, "udp")]
    assert d.opened_ports == [("ccc333", 443, "tcp")]


def test_ip_fallback_needs_same_vendor():
    old = Scan(file="a", status="ok", score=100, hosts=[_h("aaa", "10.0.0.5", "TP-Link")])
    new = Scan(file="b", status="ok", score=100, hosts=[_h("bbb", "10.0.0.5", "Samsung")])
    d = storage.diff(old, new)
    assert [h.device_id for h in d.removed_devices] == ["aaa"]
    assert [h.device_id for h in d.new_devices] == ["bbb"]


def test_ip_fallback_vendor_missing_on_one_side_still_matches():
    old = Scan(file="a", status="ok", score=100, hosts=[_h("aaa", "10.0.0.5", None)])
    new = Scan(file="b", status="ok", score=100, hosts=[_h("bbb", "10.0.0.5", "TP-Link")])
    d = storage.diff(old, new)
    assert d.new_devices == [] and d.removed_devices == []


def test_ip_fallback_only_one_to_one():
    """Două dispozitive noi pe același IP: nu se potrivește niciunul."""
    old = Scan(file="a", status="ok", score=100, hosts=[_h("aaa", "10.0.0.5", "TP-Link")])
    new = Scan(file="b", status="ok", score=100,
               hosts=[_h("bbb", "10.0.0.5", "TP-Link"), _h("ccc", "10.0.0.5", "TP-Link")])
    d = storage.diff(old, new)
    assert [h.device_id for h in d.removed_devices] == ["aaa"]
    assert sorted(h.device_id for h in d.new_devices) == ["bbb", "ccc"]


def test_same_device_id_wins_over_ip():
    """Același MAC, IP schimbat: e același dispozitiv; IP-ul liber nu se mai folosește."""
    old = Scan(file="a", status="ok", score=100, hosts=[_h("aaa", "10.0.0.5", "X"), _h("bbb", "10.0.0.6", "X")])
    new = Scan(file="b", status="ok", score=100, hosts=[_h("aaa", "10.0.0.9", "X"), _h("ccc", "10.0.0.6", "X")])
    d = storage.diff(old, new)
    assert d.new_devices == [] and d.removed_devices == []
