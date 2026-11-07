"""Pașii de reparare se verifică pe date reale: live (un port, doar în rețeaua mea) sau printr-o scanare nouă."""
import socket
from dataclasses import replace

from netscan.engine.scoring import compute_score
from netscan.model import Finding, Host, Port, Scan
from netscan.ui import storage, verify
from netscan.ui.app import create_app
from netscan.ui.view import action_plan, steps_view, verified_by_newer
from tests.test_ui_app import sample


def client_for(tmp_path, scans, probe=None, net=True):
    cfg = {"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True,
           "NET_CHECK": (lambda ip: net)}
    if probe is not None:
        cfg["PORT_PROBE"] = probe
    app = create_app(cfg)
    return app.test_client(), app


def tick(client, app, f, **headers):
    return client.post("/action/done", headers=headers, data={
        "token": app.config["FORM_TOKEN"], "scan": 0, "device_id": f.device_id,
        "port": "" if f.port is None else f.port, "code": f.code})


# ---------- verify.check_finding ----------

def _scan_with(f, proto="tcp"):
    return Scan(file="x.xml", status="ok", started_at=1, score=50,
                hosts=[Host(ip=f.ip, device_id=f.device_id, ports=[Port(port=f.port or 1, proto=proto, state="open")])],
                findings=[f])


F = Finding(file="x.xml", ip="192.168.1.5", device_id="d1", port=23, code="TELNET_OPEN",
            severity="high", points=20, evidence="e")


def test_check_results():
    calls = []
    probe = lambda r: (lambda ip, port: calls.append((ip, port)) or r)
    assert verify.check_finding(_scan_with(F), F, probe("closed"), lambda ip: True).result == verify.VERIFIED
    assert verify.check_finding(_scan_with(F), F, probe("open"), lambda ip: True).result == verify.STILL_OPEN
    assert verify.check_finding(_scan_with(F), F, probe("unknown"), lambda ip: True).result == verify.NO_ANSWER
    old = replace(F, code="OUTDATED_SERVICE")
    assert verify.check_finding(_scan_with(old), old, probe("open"), lambda ip: True).result == verify.STILL_OPEN_VERSION
    assert calls == [("192.168.1.5", 23)] * 4                     # o singură conexiune, la portul problemei
    # fără nicio conexiune: altă rețea, UDP, fără port
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    assert verify.check_finding(_scan_with(F), F, never, lambda ip: False).result == verify.OTHER_NETWORK
    udp = replace(F, port=1900, code="UPNP_EXPOSED")
    assert verify.check_finding(_scan_with(udp, "udp"), udp, never, lambda ip: True).result == verify.UDP
    unk = replace(F, port=None, code="UNKNOWN_DEVICE")
    assert verify.check_finding(_scan_with(unk), unk, never, lambda ip: True).result == verify.NO_PORT


def test_tcp_probe_open_and_closed_on_localhost():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    assert verify.tcp_probe("127.0.0.1", port) == "open"
    srv.close()
    assert verify.tcp_probe("127.0.0.1", port) == "closed"


def test_my_network_check_refuses_when_network_unknown(monkeypatch):
    import netscan.scan.network as network
    monkeypatch.setattr(network, "detect_network", lambda: (_ for _ in ()).throw(OSError("fără rețea")))
    assert verify.target_in_my_network("192.168.1.5") is False


# ---------- pagina ----------

def test_closed_port_is_verified_and_engine_rescores(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    first = action_plan(s)[0]
    resp = tick(client, app, first)
    assert resp.status_code == 302 and "check=ok" in resp.headers["Location"]
    same_port = {f.key() for f in s.findings if f.device_id == first.device_id and f.port == first.port}
    assert storage.verified_keys(s, app.config["DB_PATH"]) == same_port
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    expected = compute_score(f for f in s.findings if f.key() not in same_port)
    assert expected > s.score and f">{expected}<" in html
    assert "Verificat: portul 554" in html and "Scanarea a dat 40" in html


def test_open_port_keeps_step_and_score(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "open")
    first = action_plan(s)[0]
    resp = tick(client, app, first)
    assert "step=1" in resp.headers["Location"]
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "răspunde încă" in html and ">40<" in html and "Pasul 1 din 5" in html
    assert storage.done_keys(s, app.config["DB_PATH"]) == set() == storage.verified_keys(s, app.config["DB_PATH"])


def test_unconfirmable_step_is_only_declared(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], net=False)
    first = action_plan(s)[0]
    html = client.get(tick(client, app, first).headers["Location"]).get_data(as_text=True)
    assert "nu e în rețeaua" in html and ">40<" in html and "Pasul 2 din 5" in html
    assert storage.done_keys(s, app.config["DB_PATH"]) == {first.key()}
    html = client.get("/?step=1").get_data(as_text=True)
    assert "Bifat, dar neconfirmat" in html and "Verifică din nou" in html


def test_cross_site_tick_refused(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    assert tick(client, app, s.findings[0], **{"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert storage.verified_keys(s, app.config["DB_PATH"]) == set()


def test_prev_next_only_browse(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s])
    html = client.get("/").get_data(as_text=True)
    assert "Pasul 1 din 5" in html and 'rel="prev"' not in html and "step=2" in html and "Pasul următor" in html
    html = client.get("/?step=3").get_data(as_text=True)
    assert "Pasul 3 din 5" in html and "step=2" in html and "step=4" in html and "Pasul anterior" in html
    html = client.get("/?step=5").get_data(as_text=True)
    assert 'rel="next"' not in html
    assert "Pasul 1 din 5" in client.get("/?step=99").get_data(as_text=True)
    assert storage.done_keys(s, app.config["DB_PATH"]) == set()       # navigarea nu bifează nimic
    html = client.get("/?check=<script>&checked=1").get_data(as_text=True)
    assert "role=\"status\">" not in html.split("id=\"worst\"", 1)[1].split("do-first", 1)[0]


def test_reset_clears_verified(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    tick(client, app, action_plan(s)[0])
    client.post("/action/reset", data={"token": app.config["FORM_TOKEN"], "scan": 0})
    assert storage.verified_keys(s, app.config["DB_PATH"]) == set()
    assert ">40<" in client.get("/").get_data(as_text=True)


# ---------- o scanare mai nouă confirmă pașii ----------

def test_newer_scan_verifies_missing_problems(tmp_path):
    old = sample()
    gone = action_plan(old)[0]
    new = replace(old, file="after.xml", started_at=old.started_at + 3600,
                  findings=[f for f in old.findings if f.key() != gone.key()])
    by = verified_by_newer(old, [new])
    assert by == {gone.key(): "after.xml"}
    # dispozitiv absent din scanarea nouă = nu știm, nu se confirmă nimic
    empty = replace(new, hosts=[], findings=[])
    assert verified_by_newer(old, [empty]) == {}
    # o scanare mai veche nu confirmă nimic
    assert verified_by_newer(new, [old]) == {}
    view = steps_view(old, set(), set(), by)
    assert view.current.number == 2 and view.verified_count == 1
    assert view.score_now == compute_score(f for f in old.findings if f.key() != gone.key())

    client, _ = client_for(tmp_path, [old, new])
    html = client.get("/?step=1").get_data(as_text=True)
    assert "Verificat de scanarea after.xml" in html


# ---------- cardul „Cel mai periculos dispozitiv” ține cont de pașii verificați ----------

def _worst_card(html):
    return html.split('id="worst"', 1)[1].split("</section>", 1)[0]


def test_worst_card_skips_verified_problems(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    card = _worst_card(client.get("/").get_data(as_text=True))
    assert "CAMERA_STREAM_EXPOSED" in card and "Fără problemele verificate" not in card
    tick(client, app, action_plan(s)[0])                    # camera, port 554: închis -> verificat
    card = _worst_card(client.get("/").get_data(as_text=True))
    assert "CAMERA_STREAM_EXPOSED" not in card and "Fără problemele verificate" in card


def test_all_verified_shows_fixed_card_with_steps(tmp_path):
    """O scanare mai nouă cu aceleași dispozitive și fără probleme confirmă toți pașii (inclusiv UPnP pe UDP)."""
    old = sample()
    new = replace(old, file="after.xml", started_at=old.started_at + 3600, findings=[], score=100)
    client, _ = client_for(tmp_path, [old, new])
    html = client.get("/?scan=0").get_data(as_text=True)
    card = _worst_card(html)
    assert "Toate problemele au fost verificate ca rezolvate" in card and "Revezi pașii" in card
    assert ">100<" in html and "Scanarea a dat 40" in html
    assert "Pasul 1 din 5" in _worst_card(client.get("/?scan=0&step=1").get_data(as_text=True))
    # o scanare care chiar nu a găsit nimic își păstrează textul obișnuit
    assert "Nicio problemă găsită" in _worst_card(client.get("/?scan=1").get_data(as_text=True))
