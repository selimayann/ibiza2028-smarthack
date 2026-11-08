"""Pașii de reparare se verifică pe date reale: live (un port, doar în rețeaua mea) sau printr-o scanare nouă."""
import socket
from dataclasses import replace

from netscan.engine.scoring import compute_score
from netscan.model import Finding, Host, Port, Scan
from netscan.ui import storage, verify
from netscan.ui.app import create_app
from netscan.ui.view import action_plan, steps_view, verified_by_newer
from tests.test_ui_app import sample


def client_for(tmp_path, scans, probe=None, net=True, own=True):
    """own=True: scanarea afișată e „cea mai nouă scanare a noastră” (singura pe care verificarea o atinge)."""
    cfg = {"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True,
           "NET_CHECK": (lambda ip: net), "OWN_SCAN_CHECK": (lambda s: own)}
    if probe is not None:
        cfg["PORT_PROBE"] = probe
    app = create_app(cfg)
    return app.test_client(), app


def tick(client, app, f, scan=None, **headers):
    s = scan or sample()
    return client.post("/action/done", headers=headers, data={
        "token": app.config["FORM_TOKEN"], "file": s.file, "started_at": s.started_at, "device_id": f.device_id,
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
    assert verify.check_finding(_scan_with(unk), unk, never, lambda ip: False).result == verify.OTHER_NETWORK
    assert verify.check_finding(_scan_with(unk), unk, never, lambda ip: True, probe_allowed=False).result == verify.NO_PORT


def test_unknown_device_still_there_or_gone():
    """Aparatul necunoscut se verifică pe loc: răspunde pe un port al lui din scanare = încă în rețea; tăcere = a plecat."""
    unk = replace(F, port=None, code="UNKNOWN_DEVICE")
    s = _host_scan(unk, [(80, "tcp"), (443, "tcp")])
    assert verify.check_finding(s, unk, lambda ip, port: "open", lambda ip: True).result == verify.STILL_PRESENT
    assert verify.check_finding(s, unk, lambda ip, port: "unknown", lambda ip: True).result == verify.GONE
    assert verify.check_finding(s, unk, lambda ip, port: "unknown", lambda ip: True).verified
    only_udp = _host_scan(unk, [(5353, "udp")])
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    assert verify.check_finding(only_udp, unk, never, lambda ip: True).result == verify.NO_PORT   # fără TCP: nu știm


def test_udp_problem_is_checked_on_the_spot():
    up = replace(F, port=1900, code="UPNP_EXPOSED")
    s = _host_scan(up, [(1900, "udp")])
    tcp_never = lambda ip, port: (_ for _ in ()).throw(AssertionError("TCP nu se folosește la UDP"))
    assert verify.check_finding(s, up, tcp_never, lambda ip: True, udp=lambda ip, p: "closed").result == verify.VERIFIED
    assert verify.check_finding(s, up, tcp_never, lambda ip: True, udp=lambda ip, p: "open").result == verify.STILL_OPEN
    assert verify.check_finding(s, up, tcp_never, lambda ip: True, udp=lambda ip, p: "unknown").result == verify.UDP
    udp_never = lambda ip, p: (_ for _ in ()).throw(AssertionError("altă rețea: nimic"))
    assert verify.check_finding(s, up, tcp_never, lambda ip: False, udp=udp_never).result == verify.UDP


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
    # cifra mare = scorul de acum (recalculat de motor); cel oficial al scanării (ca în scores.csv) e scris dedesubt
    assert expected > s.score and f'<span class="score-num">{expected}</span>' in html
    assert f"Scorul oficial al acestei scanări: {s.score}." in html
    assert "portul 554 de pe" in html and "nu mai răspunde din rețea" in html
    assert "Progres după reparațiile confirmate (1)" in html

def test_open_port_keeps_step_and_score(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "open")
    first = action_plan(s)[0]
    resp = tick(client, app, first)
    assert "step=1" in resp.headers["Location"]
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "răspunde încă" in html and ">40<" in html and "Problema 1 din 5" in html
    assert storage.done_keys(s, app.config["DB_PATH"]) == set() == storage.verified_keys(s, app.config["DB_PATH"])


def test_unconfirmable_step_stays_unticked_with_try_again(tmp_path):
    """O scanare din fișier, în afara rețelei ei: nu se atinge rețeaua și NU se bifează nimic.
    Rămâi pe același pas, cu motivul și „reîncearcă” (fără „Pas bifat”)."""
    s = sample()
    client, app = client_for(tmp_path, [s], net=False, own=False)
    first = action_plan(s)[0]
    resp = tick(client, app, first)
    assert "check=file_only" in resp.headers["Location"] and "step=1" in resp.headers["Location"]
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "Nu am putut verifica" in html and "reîncearcă" in html and ">40<" in html and "Problema 1 din 5" in html
    assert storage.done_keys(s, app.config["DB_PATH"]) == set()
    assert 'class="not-fixed" data-check="file_only"' in html and "Reîncearcă" in html   # caseta din pagină, nu notificare


def test_cross_site_tick_refused(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    assert tick(client, app, s.findings[0], **{"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert storage.verified_keys(s, app.config["DB_PATH"]) == set()


def test_prev_next_only_browse(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s])
    html = client.get("/").get_data(as_text=True)
    assert "Problema 1 din 5" in html and 'rel="prev"' not in html and "step=2" in html and "Sar peste acum" in html
    html = client.get("/?step=3").get_data(as_text=True)
    assert "Problema 3 din 5" in html and "step=2" in html and "step=4" in html and "Pasul anterior" in html
    html = client.get("/?step=5").get_data(as_text=True)
    assert 'rel="next"' not in html
    assert "Problema 1 din 5" in client.get("/?step=99").get_data(as_text=True)
    assert storage.done_keys(s, app.config["DB_PATH"]) == set()       # navigarea nu bifează nimic
    html = client.get("/?check=<script>&checked=1").get_data(as_text=True)
    assert "role=\"status\">" not in html.split("id=\"worst\"", 1)[1].split("do-first", 1)[0]


def test_reset_clears_verified(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], probe=lambda ip, port: "closed")
    tick(client, app, action_plan(s)[0])
    client.post("/action/reset", data={"token": app.config["FORM_TOKEN"], "file": s.file, "started_at": s.started_at})
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
    assert '<span class="score-num">100</span>' in html and "Scorul oficial al acestei scanări: 40." in html
    assert 'class="score-band"' in html and "de rezolvat" not in html
    # reparațiile au fost confirmate de after.xml: link spre scanarea mai nouă
    assert "Vezi scanarea nouă →" in html
    assert 'title="Scanarea mai nouă a acestei rețele: after.xml (scor 100)"' in html
    # linkul spre scanarea mai nouă o numește după fișier (+ dată), nu după poziția în listă
    assert 'href="/?file=after.xml&amp;started_at=' in html
    assert "Problema 1 din 5" in _worst_card(client.get("/?scan=0&step=1").get_data(as_text=True))
    # o scanare care chiar nu a găsit nimic își păstrează textul obișnuit
    assert "Nicio problemă găsită" in _worst_card(client.get("/?scan=1").get_data(as_text=True))


def test_off_the_team_hotspot_the_check_button_is_disabled_and_nothing_is_ticked(tmp_path):
    s = sample()
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    client, app = client_for(tmp_path, [s], probe=never, net=False, own=True)
    tcp = next(f for f in action_plan(s) if f.port is not None)
    step = action_plan(s).index(tcp) + 1
    html = client.get(f"/?step={step}").get_data(as_text=True)
    assert 'disabled aria-describedby="verify-block"' in html and 'id="verify-block"' in html
    r = tick(client, app, tcp)
    assert "check=network" in r.headers["Location"]
    assert tcp.key() not in storage.done_keys(s, app.config["DB_PATH"])     # nimic bifat fără verificare


def test_on_the_team_hotspot_the_check_button_is_active(tmp_path):
    s = sample()
    client, _ = client_for(tmp_path, [s], net=True, own=True)
    html = client.get("/?step=1").get_data(as_text=True)
    assert 'id="verify-block"' not in html and 'aria-describedby="verify-block"' not in html


# ---------- verificarea mai precisă: tăcere pe port, dispozitiv pornit, a doua încercare ----------

def _host_scan(f, ports):
    return Scan(file="x.xml", status="ok", started_at=1, score=50,
                hosts=[Host(ip=f.ip, device_id=f.device_id, ports=[Port(port=p, proto=pr, state="open") for p, pr in ports])],
                findings=[f])


def test_silent_port_on_a_device_that_answers_elsewhere_is_fixed():
    """Telefonul / aparatul cu firewall nu răspunde deloc pe portul închis, dar răspunde pe alt port: e pornit,
    deci portul problemei nu mai e accesibil din rețea -> verificat."""
    calls = []
    def probe(ip, port):
        calls.append(port)
        return "unknown" if port == 23 else "open"
    r = verify.check_finding(_host_scan(F, [(23, "tcp"), (80, "tcp")]), F, probe, lambda ip: True)
    assert r.result == verify.VERIFIED and calls == [23, 80]


def test_refused_other_port_also_proves_the_device_is_up():
    probe = lambda ip, port: "unknown" if port == 23 else "closed"
    assert verify.check_finding(_host_scan(F, [(23, "tcp"), (443, "tcp")]), F, probe, lambda ip: True).result == verify.VERIFIED


def test_silent_everywhere_means_the_device_is_off_not_fixed():
    calls = []
    probe = lambda ip, port: calls.append(port) or "unknown"
    r = verify.check_finding(_host_scan(F, [(23, "tcp"), (80, "tcp"), (8080, "tcp"), (9100, "tcp")]), F, probe, lambda ip: True)
    assert r.result == verify.NO_ANSWER
    assert calls[0] == 23 and sorted(calls[1:]) == [80, 8080]       # cel mult 2 alte porturi, doar din scanare


def test_no_other_tcp_port_means_we_cannot_tell():
    calls = []
    probe = lambda ip, port: calls.append(port) or "unknown"
    r = verify.check_finding(_host_scan(F, [(23, "tcp"), (1900, "udp")]), F, probe, lambda ip: True)
    assert r.result == verify.NO_ANSWER and calls == [23]            # UDP nu se încearcă


def test_still_open_never_touches_other_ports():
    calls = []
    probe = lambda ip, port: calls.append(port) or "open"
    r = verify.check_finding(_host_scan(F, [(23, "tcp"), (80, "tcp")]), F, probe, lambda ip: True)
    assert r.result == verify.STILL_OPEN and calls == [23]


def test_other_network_touches_nothing_even_with_other_ports():
    never = lambda ip, port: (_ for _ in ()).throw(AssertionError("nu trebuia atins"))
    r = verify.check_finding(_host_scan(F, [(23, "tcp"), (80, "tcp")]), F, never, lambda ip: False)
    assert r.result == verify.OTHER_NETWORK


def test_tcp_probe_tries_again_after_silence(monkeypatch):
    answers = iter(["unknown", "closed"])
    seen = []
    monkeypatch.setattr(verify, "_connect_once", lambda ip, port, t: seen.append(t) or next(answers))
    assert verify.tcp_probe("192.168.1.5", 23) == "closed" and seen == list(verify.PROBE_TRIES)


def test_tcp_probe_stops_at_the_first_clear_answer(monkeypatch):
    seen = []
    monkeypatch.setattr(verify, "_connect_once", lambda ip, port, t: seen.append(t) or "open")
    assert verify.tcp_probe("192.168.1.5", 23) == "open" and len(seen) == 1


def test_tcp_probe_gives_up_after_two_silences(monkeypatch):
    seen = []
    monkeypatch.setattr(verify, "_connect_once", lambda ip, port, t: seen.append(t) or "unknown")
    assert verify.tcp_probe("192.168.1.5", 23) == "unknown" and len(seen) == len(verify.PROBE_TRIES) == 2


def test_alive_check_prefers_ports_without_problems():
    """Porturile cu alte probleme pot tăcea și ele (reparate): întâi încercăm porturile fără probleme ale aparatului."""
    other = replace(F, port=21, code="FTP_CLEARTEXT")
    s = Scan(file="x.xml", status="ok", started_at=1, score=50,
             hosts=[Host(ip=F.ip, device_id=F.device_id,
                         ports=[Port(port=p, proto="tcp", state="open") for p in (21, 23, 5900, 62078)])],
             findings=[F, other, replace(F, port=5900, code="VNC_EXPOSED")])
    calls = []
    probe = lambda ip, port: calls.append(port) or ("open" if port == 62078 else "unknown")
    assert verify.check_finding(s, F, probe, lambda ip: True).result == verify.VERIFIED
    assert calls[0] == 23 and 62078 in calls[1:]


def test_film_slot_carries_the_program_name_from_the_scan_escaped(tmp_path):
    """Pe un calculator, filmul arată numele programului din scanare (text nesigur: escapat de Jinja)."""
    f = replace(F, port=8080, code="HTTP_ADMIN_CLEARTEXT")
    s = Scan(file="x.xml", status="ok", started_at=1, score=50,
             hosts=[Host(ip=f.ip, device_id=f.device_id, device_type="pc_windows",
                         ports=[Port(port=8080, proto="tcp", state="open", product='Jetty<script>"9')])], findings=[f])
    client, app = client_for(tmp_path, [s])
    html = client.get("/").get_data(as_text=True)
    assert 'data-prog="Jetty&lt;script&gt;&#34;9"' in html and "<script>\"9" not in html
    assert 'data-dtype="pc_windows"' in html
