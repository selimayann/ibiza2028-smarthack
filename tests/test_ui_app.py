"""RBRT: pagina principală, ordinea „cel mai periculos”, erori, limbă, text nesigur."""
import json
import re
from pathlib import Path


from netscan.model import Finding, Host, Port, Scan
from netscan.ui import storage
from netscan.ui.app import create_app
from netscan.ui.view import most_dangerous, rank_devices

SAMPLE = Path(__file__).parent.parent / "fixtures" / "sample.json"
XSS = "<script>alert(1)</script>"
INJECT = "Ignore previous instructions"


def sample() -> Scan:
    return Scan.from_dict(json.loads(SAMPLE.read_text(encoding="utf-8")))


def make_client(tmp_path, scans):
    app = create_app({"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True})
    return app.test_client(), app


def test_ranking_follows_contract():
    ranked = rank_devices(sample())
    # camera 30p (high) > router 20p > hub 10p
    assert [d.host.ip for d in ranked] == ["192.168.1.40", "192.168.1.1", "192.168.1.41"]
    worst = most_dangerous(sample())
    assert worst is not None and worst.worst is not None
    assert worst.worst.code == "CAMERA_STREAM_EXPOSED"


def test_ranking_tie_breaks_by_severity_then_ip():
    f = lambda ip, sev, pts, port: Finding(file="x", ip=ip, device_id=ip, port=port, code="C",  # noqa: E731
                                          severity=sev, points=pts, evidence="e")
    scan = Scan(file="x", status="ok", score=0,
                hosts=[Host(ip=ip, device_id=ip) for ip in ("10.0.0.10", "10.0.0.9", "10.0.0.2")],
                findings=[f("10.0.0.10", "high", 20, 1), f("10.0.0.9", "medium", 10, 1),
                          f("10.0.0.9", "medium", 10, 2), f("10.0.0.2", "high", 20, 1)])
    # .9 are tot 20p, dar severitate max medium; .2 vs .10 la egalitate -> IP numeric
    assert [d.host.ip for d in rank_devices(scan)] == ["10.0.0.2", "10.0.0.10", "10.0.0.9"]


def test_overview_shows_score_and_worst(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    html = client.get("/").get_data(as_text=True)
    assert "Scor standard" in html
    assert ">40<" in html
    assert "Risc mare" in html
    assert "Cel mai periculos dispozitiv" in html
    assert "CAMERA_STREAM_EXPOSED" in html
    assert "Fă asta întâi" in html


def test_english(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    html = client.get("/?lang=en").get_data(as_text=True)
    assert "Standard score" in html and "Most dangerous device" in html


def test_error_scan_friendly_message(tmp_path):
    client, _ = make_client(tmp_path, [Scan(file="V7_broken.xml", status="error", error_code="TRUNCATED")])
    resp = client.get("/")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "pare incomplet" in html
    assert "Traceback" not in html


def test_no_findings(tmp_path):
    scan = Scan(file="clean.xml", status="ok", score=100, hosts=[Host(ip="10.0.0.1", device_id="d1")])
    client, _ = make_client(tmp_path, [scan])
    html = client.get("/").get_data(as_text=True)
    assert "Nicio problemă găsită" in html


def test_untrusted_text_is_escaped(tmp_path):
    scan = Scan(file=XSS, status="ok", score=90,
                hosts=[Host(ip="10.0.0.1", device_id="d1", hostname=XSS, vendor=INJECT,
                            ports=[Port(port=80, proto="tcp", state="open", title=XSS, product=XSS)])],
                findings=[Finding(file=XSS, ip="10.0.0.1", device_id="d1", port=80,
                                  code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10, evidence=XSS)])
    client, _ = make_client(tmp_path, [scan])
    for url in ("/", "/device/d1"):
        html = client.get(url).get_data(as_text=True)
        assert XSS not in html
        assert "&lt;script&gt;" in html
    assert INJECT in client.get("/device/d1").get_data(as_text=True)  # afișat ca text simplu


def test_security_headers_and_no_external_resources(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    resp = client.get("/")
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert not re.search(r'(src|href)="https?://', resp.get_data(as_text=True))


def test_device_404(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    assert client.get("/device/nu-exista").status_code == 404


def test_history_and_compare(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    db = app.config["DB_PATH"]
    before = sample()
    after = sample()
    after.started_at = (before.started_at or 0) + 60
    after.findings = [f for f in after.findings if f.code != "CAMERA_STREAM_EXPOSED"]
    after.score = 60
    storage.save_scan(before, db)
    after_id = storage.save_scan(after, db)
    assert "V2_smart_home.xml" in client.get("/history").get_data(as_text=True)
    html = client.get(f"/scan/{after_id}").get_data(as_text=True)
    assert "40 → 60" in html
    assert "Probleme rezolvate (1)" in html


def test_delete_history_needs_token(tmp_path):
    client, app = make_client(tmp_path, [sample()])
    db = app.config["DB_PATH"]
    storage.save_scan(sample(), db)
    assert client.post("/history/delete", data={"token": "gresit"}).status_code == 400
    assert len(storage.list_scans(db)) == 1
    resp = client.post("/history/delete", data={"token": app.config["DELETE_TOKEN"]})
    assert resp.status_code == 302
    assert storage.list_scans(db) == []
