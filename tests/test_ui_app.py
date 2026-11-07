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
    resp = client.post("/history/delete", data={"token": app.config["FORM_TOKEN"]})
    assert resp.status_code == 302
    assert storage.list_scans(db) == []


# ---------- cu motorul lui Radu, pe Validation Set ----------

def test_ui_on_validation_set_with_engine(tmp_path):
    from netscan.ui.app import load_scans

    scans = load_scans()
    by_file = {s.file: i for i, s in enumerate(scans)}
    client, _ = make_client(tmp_path, scans)
    v1 = client.get(f"/?scan={by_file['V1_home_basic.xml']}").get_data(as_text=True)
    assert ">90<" in v1 and "Bun" in v1
    v2 = client.get(f"/?scan={by_file['V2_smart_home.xml']}").get_data(as_text=True)
    assert ">40<" in v2 and "CAMERA_STREAM_EXPOSED" in v2
    v6b = client.get(f"/?scan={by_file['V6b_after.xml']}").get_data(as_text=True)
    assert "Nicio problemă găsită" in v6b
    v7 = client.get(f"/?scan={by_file['V7_broken.xml']}")
    assert v7.status_code == 200 and "pare incomplet" in v7.get_data(as_text=True)


def test_history_v6a_to_v6b(tmp_path):
    """Testul juriului: V6a -> V6b = 3 findings rezolvate, scorul 60 -> 100."""
    from netscan.engine import analyze_file
    from netscan.ui.app import VALIDATION_DIR

    db = tmp_path / "h.db"
    a = analyze_file(VALIDATION_DIR / "V6a_before.xml")
    b = analyze_file(VALIDATION_DIR / "V6b_after.xml")
    storage.save_scan(a, db)
    b_id = storage.save_scan(b, db)
    d = storage.diff(a, b)
    assert len(d.resolved_findings) == 3 and not d.new_findings
    assert (d.score_before, d.score_after) == (60, 100)
    client, _ = make_client(tmp_path, [])
    html = client.get(f"/scan/{b_id}").get_data(as_text=True)
    assert "60 → 100" in html and "Probleme rezolvate (3)" in html


def test_save_to_history_from_ui(tmp_path):
    from netscan.ui.app import load_scans

    scans = load_scans()
    i_a = next(i for i, s in enumerate(scans) if s.file == "V6a_before.xml")
    i_b = next(i for i, s in enumerate(scans) if s.file == "V6b_after.xml")
    client, app = make_client(tmp_path, scans)
    token = app.config["FORM_TOKEN"]
    assert "Salvează în istoric" in client.get(f"/?scan={i_a}").get_data(as_text=True)
    assert client.post("/history/save", data={"token": "gresit", "scan": i_a}).status_code == 400
    client.post("/history/save", data={"token": token, "scan": i_a})
    resp = client.post("/history/save", data={"token": token, "scan": i_b})
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "60 → 100" in html and "Probleme rezolvate (3)" in html
    # a doua salvare a aceleiași scanări nu o dublează
    client.post("/history/save", data={"token": token, "scan": i_a})
    assert len(storage.list_scans(app.config["DB_PATH"])) == 2
    assert "Salvată în istoric" in client.get(f"/?scan={i_a}").get_data(as_text=True)


def test_history_shows_ip_recognition_note(tmp_path):
    from netscan.engine import analyze_file
    from netscan.ui.app import VALIDATION_DIR

    db = tmp_path / "h.db"
    storage.save_scan(analyze_file(VALIDATION_DIR / "V6a_before.xml"), db)
    b_id = storage.save_scan(analyze_file(VALIDATION_DIR / "V6b_after.xml"), db)
    client, _ = make_client(tmp_path, [])
    html = client.get(f"/scan/{b_id}").get_data(as_text=True)
    assert "Recunoscute după IP (3)" in html


# ---------- FR-10: trendul scorului și porturile în istoric ----------

def _save_validation(db, *names):
    from netscan.engine import analyze_file
    from netscan.ui.app import VALIDATION_DIR

    return [storage.save_scan(analyze_file(VALIDATION_DIR / n), db) for n in names]


def test_history_shows_score_trend(tmp_path):
    client, app = make_client(tmp_path, [])
    db = app.config["DB_PATH"]
    _save_validation(db, "V6a_before.xml", "V6b_after.xml", "V7_broken.xml")
    html = client.get("/history").get_data(as_text=True)
    assert "Scorul standard în timp" in html
    assert "Scorul a crescut de la 60 la 100 în ultimele 2 scanări." in html
    assert html.count('class="trend-dot"') == 2  # V7 (eroare) nu are scor, nu apare pe grafic


def test_trend_needs_two_scans(tmp_path):
    client, app = make_client(tmp_path, [])
    _save_validation(app.config["DB_PATH"], "V6a_before.xml")
    html = client.get("/history").get_data(as_text=True)
    assert "Salvează cel puțin două scanări" in html and "trend-dot" not in html


def test_compare_shows_opened_and_closed_ports(tmp_path):
    client, app = make_client(tmp_path, [])
    _, b_id = _save_validation(app.config["DB_PATH"], "V6a_before.xml", "V6b_after.xml")
    html = client.get(f"/scan/{b_id}").get_data(as_text=True)
    assert "Porturi deschise acum (1)" in html and "443/tcp" in html
    assert "Porturi închise acum (3)" in html and "23/tcp" in html and "1900/udp" in html


def test_device_page_shows_standards(tmp_path):
    from netscan.ui.app import load_scans

    scans = load_scans()
    i = next(n for n, s in enumerate(scans) if s.file == "V6a_before.xml")
    client, _ = make_client(tmp_path, scans)
    worst = most_dangerous(scans[i])
    html = client.get(f"/device/{worst.host.device_id}?scan={i}").get_data(as_text=True)
    assert "Standarde de securitate" in html
    assert "CIS Controls v8" in html and "OWASP IoT Top 10 (2018)" in html
    assert "https://www.cisecurity.org/controls/v8" in html


def test_standards_failure_does_not_break_page(tmp_path, monkeypatch):
    import netscan.explain.standards as st

    monkeypatch.setattr(st, "get_standards", lambda *a, **k: 1 / 0)
    client, _ = make_client(tmp_path, [sample()])
    resp = client.get("/device/e1f2a3b4c5d6")
    assert resp.status_code == 200 and "Standarde de securitate" not in resp.get_data(as_text=True)
