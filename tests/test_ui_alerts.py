"""RBRT, FR-13 / D1: alertele și jurnalul de securitate, derivate din diff()."""
from pathlib import Path

from netscan.engine import analyze_file
from netscan.model import Finding, Host, Port, Scan
from netscan.ui import alerts as al
from netscan.ui import i18n, storage
from netscan.ui.app import create_app

VAL = Path(__file__).parent.parent / "fixtures" / "validation"


def kinds(alerts):
    return [a.kind for a in alerts]


def test_v6a_to_v6b_three_resolved_no_new():
    out = al.alerts_between(analyze_file(VAL / "V6a_before.xml"), analyze_file(VAL / "V6b_after.xml"))
    assert kinds(out).count(al.FINDING_RESOLVED) == 3
    assert al.FINDING_NEW not in kinds(out)
    assert al.NEW_DEVICE not in kinds(out) and al.DEVICE_GONE not in kinds(out)


def _h(dev, ip, ports=(), vendor="X", dtype="router"):
    return Host(ip=ip, device_id=dev, vendor=vendor, device_type=dtype,
                ports=[Port(port=p, proto="tcp", state="open") for p in ports])


def _f(dev, ip, port, code):
    return Finding(file="b.xml", ip=ip, device_id=dev, port=port, code=code, severity="high", points=20, evidence="e")


def test_new_device_and_port_and_order():
    old = Scan(file="a.xml", status="ok", score=100, started_at=1, hosts=[_h("r", "10.0.0.1", (80,))])
    new = Scan(file="b.xml", status="ok", score=60, started_at=2,
               hosts=[_h("r", "10.0.0.1", (80, 23)), _h("cam", "10.0.0.9", (554,), "Y", "camera")],
               findings=[_f("r", "10.0.0.1", 23, "TELNET_OPEN"), _f("cam", "10.0.0.9", 554, "CAMERA_STREAM_EXPOSED")])
    out = al.alerts_between(old, new)
    # problemele noi primele, apoi dispozitivul nou, apoi portul nou
    assert kinds(out) == [al.FINDING_NEW, al.FINDING_NEW, al.NEW_DEVICE, al.PORT_OPENED]
    # portul camerei noi nu apare separat: e acoperit de alerta „dispozitiv nou”
    assert [(a.ip, a.port) for a in out if a.kind == al.PORT_OPENED] == [("10.0.0.1", 23)]
    assert i18n.alert_text("ro", out[2]) == "Un dispozitiv nou a apărut în rețea: Cameră, 10.0.0.9."
    assert i18n.alert_text("ro", out[3]) == "Un port nou s-a deschis: 23/tcp pe Router, 10.0.0.1."
    assert i18n.alert_text("en", out[0]) == "New problem: “Telnet open” on Router, 10.0.0.1."


def test_no_change_no_alerts():
    s = analyze_file(VAL / "V2_smart_home.xml")
    assert al.alerts_between(s, s) == []


def test_journal_newest_first_and_skips_error_files(tmp_path):
    db = tmp_path / "h.db"
    for name in ("V6a_before.xml", "V7_broken.xml", "V6b_after.xml"):
        storage.save_scan(analyze_file(VAL / name), db)
    j = al.journal(db)
    assert kinds(j).count(al.FINDING_RESOLVED) == 3
    assert {a.file for a in j} == {"V6b_after.xml"}
    # a treia scanare, după una ilizibilă: se compară cu ultima citibilă (V6a), nu cu fișierul stricat
    assert al.NEW_DEVICE not in kinds(j)


def test_journal_page(tmp_path):
    db = tmp_path / "h.db"
    app = create_app({"DB_PATH": db, "SCAN_LOADER": lambda: [], "TESTING": True})
    client = app.test_client()
    assert "Încă nu e nimic în jurnal" in client.get("/journal").get_data(as_text=True)
    for name in ("V6a_before.xml", "V6b_after.xml"):
        storage.save_scan(analyze_file(VAL / name), db)
    html = client.get("/journal").get_data(as_text=True)
    assert "Jurnalul de securitate" in html
    assert "a fost rezolvată pe Router, 192.168.1.1." in html
    assert html.count('class="alert alert-good"') >= 3
