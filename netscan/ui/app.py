"""Aplicația Flask (RBRT). Vezi docs/roles/D_RBRT_UI_Istoric.md, secțiunea 2.2.

- Ascultă doar pe 127.0.0.1, fără debug.
- Jinja2 cu autoescape; datele din scanare sunt TEXT NESIGUR, niciodată |safe.
- Fără CDN-uri: CSS local în static/.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, url_for
from markupsafe import Markup

from netscan.cli import load_env_file
from netscan.engine import analyze_folder
from netscan.model import Scan
from netscan.scan import live as live_mod
from netscan.ui import extras, i18n, storage, verify
from netscan.ui.alerts import alerts_between, journal
from netscan.ui.explain_stub import get_explanation, get_standards
from netscan.ui.view import (action_plan, ip_key, most_dangerous, rank_devices, score_band, score_trend, steps_view,
                             verified_by_newer)

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = REPO_ROOT / "fixtures" / "sample.json"
VALIDATION_DIR = REPO_ROOT / "fixtures" / "validation"
REPORT_CSS = Path(__file__).resolve().parent / "static" / "report.css"
LOGO_SVG = Path(__file__).resolve().parent / "static" / "brand" / "safeeel-lockup-horizontal-light.svg"
LANG_COOKIE = "lang"
LOCAL_HOSTS = ("127.0.0.1", "localhost")   # serverul ascultă doar pe 127.0.0.1 (IPv4)
SEEN_COOKIE = "journal_seen"   # când a deschis utilizatorul ultima dată Jurnalul (pentru „N alerte noi”)


def load_scan(path: str | Path) -> Scan:
    return Scan.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def scans_dir() -> Path:
    """Folderul cu fișierele nmap XML afișate în UI (implicit Validation Set-ul)."""
    return Path(os.environ.get("NETSCAN_SCANS_DIR") or VALIDATION_DIR)


def load_scans() -> list[Scan]:
    """SURSA DE DATE pentru pagina principală, într-un singur loc: motorul lui Radu."""
    try:
        return analyze_folder(scans_dir())
    except NotADirectoryError:
        return []


USER_SCANS_DIR = REPO_ROOT / "scans"   # scanările tale (din aplicație sau `scan --confirm`)


def load_dashboard_scans() -> list[Scan]:
    """Dashboard-ul arată scanările TALE, cea mai nouă prima. NETSCAN_SCANS_DIR alege alt folder (de ex. lab-ul);
    fără nicio scanare proprie, rămân exemplele (Validation Set)."""
    if os.environ.get("NETSCAN_SCANS_DIR") or not any(USER_SCANS_DIR.glob("*.xml")):
        return load_scans()
    try:
        found = analyze_folder(USER_SCANS_DIR)
    except NotADirectoryError:
        return load_scans()
    return sorted(found, key=lambda s: (s.started_at is not None, s.started_at or 0, s.file), reverse=True)


MAX_QUESTION_LEN = 500
_ASK_LOCK = threading.Lock()
_VERIFY_LOCK = threading.Lock()   # o singură verificare live odată   # modelul local răspunde la o singură întrebare odată (altfel se poate bloca placa video)


def same_site_request() -> bool:
    """Cererea vine din propriul site (sau e tastată direct în bara browserului), nu de pe alt site.
    Browserele moderne trimit Sec-Fetch-Site; dacă lipsește (unelte vechi, teste), o acceptăm."""
    site = request.headers.get("Sec-Fetch-Site")
    return site in (None, "same-origin", "none")


def local_ai_enabled() -> bool:
    """D8: modelul AI local (Ollama pe 127.0.0.1) e pornit doar explicit, cu NETSCAN_LOCAL_LLM=1."""
    try:
        from netscan.scan import local_llm

        return local_llm.is_enabled()
    except Exception:
        return False


def ask_assistant(question: str, scan: Scan | None, lang: str, previous: Scan | None = None):
    """FR-12: asistentul lui Ayan (netscan/scan/assistant.py). Răspunsul e construit din scanare, fără rețea.
    D8: dacă modelul local e pornit, îl reformulează, iar validatorul lui Ayan verifică textul; altfel rămâne
    răspunsul predefinit. Întrebarea e text nesigur: se trimite doar asistentului și nu se afișează ca HTML."""
    question = (question or "").strip()[:MAX_QUESTION_LEN]
    if not question or scan is None:
        return None
    try:
        from netscan.scan.assistant import answer

        llm = None
        if local_ai_enabled():
            try:
                from netscan.scan import local_llm

                llm = local_llm.make_llm()
            except Exception:  # model indisponibil sau adresă nelocală: rămâne textul predefinit
                llm = None
        if llm is None:
            return answer(question, scan, lang=lang, previous=previous)
        with _ASK_LOCK:
            return answer(question, scan, lang=lang, previous=previous, llm=llm)
    except Exception:  # asistentul nu are voie să strice pagina
        return None


# Starea lui Volt (mascota) după răspuns -> (stare, cheia textului, iconița). Starea e scrisă mereu și în text.
REPLY_STATES = {
    "verificat": ("ask_src_llm", "eel"),        # textul AI-ului a trecut validatorul
    "prins": ("ask_src_caught", "shield"),      # validatorul a oprit textul AI-ului: arătăm răspunsul sigur
    "fara-ai": ("ask_src_fallback", "info"),    # AI-ul local e oprit: răspuns construit direct din scanare
}


def reply_state(reply) -> str:
    if getattr(reply, "source", None) == "llm":
        return "verificat"
    return "prins" if getattr(reply, "problems", None) else "fara-ai"


def assistant_ctx(action: str, api: str, scan: Scan | None, scan_index: int | None, question: str, reply,
                  show_changes: bool) -> dict | None:
    """Datele pentru fereastra asistentului (templates/_assistant.html)."""
    if scan is None or scan.status != "ok":
        return None
    return {"action": action, "api": api, "scan_index": scan_index, "question": question, "reply": reply,
            "open": bool(request.args.get("ask")) or bool(question), "llm_on": local_ai_enabled(),
            "file": scan.file, "show_changes": show_changes,
            "state": reply_state(reply) if reply is not None else None}


def create_app(test_config: dict | None = None) -> Flask:
    load_env_file(REPO_ROOT / ".env")  # NETSCAN_SALT, NETSCAN_DB_PATH; nu suprascrie ce e deja setat
    app = Flask(__name__)
    app.config.update(
        SCAN_LOADER=load_dashboard_scans,
        DB_PATH=None,  # None = NETSCAN_DB_PATH sau data/netscan.db
        FORM_TOKEN=secrets.token_urlsafe(32),
        MAX_CONTENT_LENGTH=1024 * 1024,
        # DNS rebinding: o pagină rea poate face ca numele ei să ducă la 127.0.0.1. Acceptăm doar cereri adresate
        # explicit calculatorului local; orice alt Host primește 400 (portul nu contează).
        TRUSTED_HOSTS=list(LOCAL_HOSTS),   # Flask >= 3.1; verificarea proprie only_local_host() acoperă versiunile vechi
        # verificarea pașilor (verify.py): o conexiune TCP, doar spre adrese din rețeaua mea; înlocuibile în teste
        PORT_PROBE=verify.tcp_probe,
        NET_CHECK=verify.target_in_my_network,
    )
    if test_config:
        app.config.update(test_config)
        if app.config.get("TESTING") and "NET_CHECK" not in test_config:
            app.config["NET_CHECK"] = lambda ip: False   # testele nu ating niciodată rețeaua

    # Protecția live (B, netscan/scan/live.py): pornește doar la cererea utilizatorului (sau dacă a lăsat-o pornită,
    # la `run()`), niciodată în teste. În teste, fără LIVE dat explicit: un monitor care „nu e pe hotspot”.
    if app.config.get("LIVE") is None:
        if app.config.get("TESTING"):
            app.config["LIVE"] = live_mod.LiveMonitor(
                scans_dir=Path(app.config["DB_PATH"] or "data/netscan.db").parent / "no-scans",
                db_path=app.config["DB_PATH"], detect=lambda: live_mod.network.NetworkInfo(status="NO_NETWORK"),
                trap_server=None, persist=False, launcher=lambda job: live_mod.elevate.Launch(False, "FAILED"))
        else:
            app.config["LIVE"] = live_mod.LiveMonitor(scans_dir=USER_SCANS_DIR, db_path=app.config["DB_PATH"])

    # ---------- limbă și helperi pentru template-uri ----------

    @app.before_request
    def only_local_host():
        """DNS rebinding: verificare proprie, pe orice versiune de Flask (TRUSTED_HOSTS există doar din 3.1)."""
        host = (request.host or "").rsplit(":", 1)[0] if not (request.host or "").startswith("[") else ""
        if host.lower() not in LOCAL_HOSTS:
            return "400 Bad Request", 400, {"Content-Type": "text/plain; charset=utf-8"}
        return None

    @app.before_request
    def pick_language() -> None:
        g.lang = i18n.normalize_lang(request.args.get("lang") or request.cookies.get(LANG_COOKIE))

    @app.after_request
    def finish(resp):
        if request.endpoint == "journal_page" and resp.status_code == 200:
            resp.set_cookie(SEEN_COOKIE, str(int(time.time())), max_age=60 * 60 * 24 * 365, samesite="Strict", httponly=True)
        if request.args.get("lang") in i18n.LANGS:
            resp.set_cookie(LANG_COOKIE, g.lang, max_age=60 * 60 * 24 * 365, samesite="Strict", httponly=True)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    app.jinja_env.globals["REPLY_STATES"] = REPLY_STATES

    @app.context_processor
    def helpers() -> dict:
        lang = g.get("lang", i18n.DEFAULT_LANG)
        other = "en" if lang == "ro" else "ro"
        if "names" not in g:
            g.names = extras.announced_names()          # numele anunțate (ascultare pasivă), o dată pe cerere
        if "monitor" not in g:
            g.monitor = extras.monitor_events()          # (evenimente, a rulat monitorul?)
        seen = request.cookies.get(SEEN_COOKIE, "0")
        seen = int(seen) if seen.isdigit() else 0
        new_alerts = sum(1 for e in g.monitor[0] if (e.ts or 0) > seen)
        def lang_url() -> str:
            """Aceeași pagină, în cealaltă limbă (păstrează restul parametrilor)."""
            args = {k: (v[:MAX_QUESTION_LEN] if k == "q" else v) for k, v in request.args.items()
                    if k != "lang" and not k.startswith("_")}
            if request.endpoint and request.endpoint != "static" and request.method == "GET":
                return url_for(request.endpoint, **(request.view_args or {}), **args, lang=other)
            return url_for("overview", lang=other)

        return {
            "lang": lang,
            "from_devices": request.args.get("from") == "devices",   # pagina dispozitivului deschisă din „Dispozitive”
            "other_lang": other,
            "lang_url": lang_url,
            "T": lambda key: i18n.t(lang, key),
            "device_type_label": lambda dt: i18n.device_type_label(lang, dt),
            "error_message": lambda code: i18n.error_message(lang, code),
            "explain": lambda code: get_explanation(code, lang),
            "eavesdrop": lambda code: extras.eavesdrop(code, lang),
            "announced": lambda ip: g.names.get(ip),
            "new_alerts": new_alerts,
            "alert_text": lambda a: i18n.alert_text(lang, a),
            "code_name": lambda code: i18n.code_name(lang, code),
            "standards": lambda code: get_standards(code, lang),
            "fmt_time": lambda epoch: _fmt_time(epoch, lang),
            "score_band": score_band,
        }

    # ---------- pagini ----------

    def scans() -> list[Scan]:
        return app.config["SCAN_LOADER"]()

    def pick(scan_list: list[Scan]) -> tuple[Scan | None, int]:
        if not scan_list:
            return None, 0
        idx = request.args.get("scan", default=0, type=int)
        idx = idx if 0 <= idx < len(scan_list) else 0
        name = request.args.get("file", "")[:120]           # „Vezi rezultatul” după o scanare din aplicație
        if name:
            idx = next((i for i, s in enumerate(scan_list) if s.file == name), idx)
        return scan_list[idx], idx

    @app.get("/")
    def overview():
        scan_list = scans()
        scan, idx = pick(scan_list)
        saved_id = storage.find_scan(scan.file, scan.started_at, app.config["DB_PATH"]) if scan else None
        question = request.args.get("q", "")[:MAX_QUESTION_LEN] if same_site_request() else ""
        steps = None
        if scan is not None and scan.status == "ok" and scan.findings:
            db = app.config["DB_PATH"]
            steps = steps_view(scan, storage.done_keys(scan, db), storage.verified_keys(scan, db),
                               verified_by_newer(scan, newer_scans(scan, scan_list)),
                               request.args.get("step", type=int))
        # cardul „Cel mai periculos dispozitiv” nu mai arată problemele verificate ca rezolvate
        remaining = scan
        if steps is not None and steps.fixed_keys:
            remaining = replace(scan, findings=[f for f in scan.findings if f.key() not in steps.fixed_keys])
        check = request.args.get("check")
        checked = request.args.get("checked", type=int)
        if check not in verify.RESULTS or steps is None or not (checked and 1 <= checked <= steps.total):
            check, checked = None, None
        reply = ask_assistant(question, scan, g.lang)
        return render_template(
            "overview.html", scan=scan, scan_list=scan_list, selected=idx, live=live_ctx(),
            steps=steps, check=check, checked=steps.steps[checked - 1] if checked else None,
            show_steps=steps is not None and (request.args.get("step") is not None or not steps.all_resolved),
            assistant=assistant_ctx(url_for("overview"), url_for("api_ask", scan=idx), scan, idx, question, reply, False),
            devices=rank_devices(scan) if scan else [], worst=most_dangerous(remaining) if remaining else None,
            history_id=None, compare=None, saved_id=saved_id, token=app.config["FORM_TOKEN"],
        )

    def newer_scans(scan: Scan, scan_list: list[Scan]) -> list[Scan]:
        """Scanările mai noi decât `scan` (din folder și din istoric), pentru verificarea pașilor."""
        if scan.started_at is None:
            return []
        out = [s for s in scan_list if s is not scan and (s.started_at or 0) > scan.started_at]
        seen = {(s.file, s.started_at) for s in out}
        db = app.config["DB_PATH"]
        for item in storage.list_scans(db):
            if item.status == "ok" and (item.started_at or 0) > scan.started_at and (item.file, item.started_at) not in seen:
                saved = storage.get_scan(item.id, db)
                if saved is not None:
                    out.append(saved)
        return out

    def _form_scan() -> tuple[Scan, int]:
        if not hmac.compare_digest(request.form.get("token", ""), app.config["FORM_TOKEN"]):
            abort(400)
        scan_list = scans()
        idx = request.form.get("scan", default=-1, type=int)
        if not 0 <= idx < len(scan_list):
            abort(400)
        return scan_list[idx], idx

    @app.post("/action/done")
    def action_done():
        """D5: „Am făcut asta” = verifică pasul pe date reale (verify.py). Portul închis -> verificat, iar scorul
        îl recalculează motorul. Portul încă deschis -> rămâne de făcut. Altfel: bifat, dar neconfirmat."""
        if not same_site_request():
            abort(403)
        scan, idx = _form_scan()
        port_raw = request.form.get("port", "")
        key = (request.form.get("device_id", ""), int(port_raw) if port_raw.lstrip("-").isdigit() else None,
               request.form.get("code", ""))
        finding = next((f for f in scan.findings if f.key() == key), None)
        if finding is None:
            abort(400)
        db = app.config["DB_PATH"]
        with _VERIFY_LOCK:
            result = verify.check_finding(scan, finding, app.config["PORT_PROBE"], app.config["NET_CHECK"])
        if result.verified:   # portul e închis: toate problemele de pe acel port al dispozitivului au dispărut
            storage.mark_verified(scan, [f.key() for f in scan.findings
                                         if f.device_id == finding.device_id and f.port == finding.port], db)
        elif result.result not in (verify.STILL_OPEN, verify.STILL_OPEN_VERSION):
            storage.mark_done(scan, key, db)
        number = [f.key() for f in action_plan(scan)].index(key) + 1
        stay = {"step": number} if result.result in (verify.STILL_OPEN, verify.STILL_OPEN_VERSION) else {}
        return redirect(url_for("overview", scan=idx, checked=number, check=result.result, **stay) + "#worst-h")

    @app.post("/action/reset")
    def action_reset():
        scan, idx = _form_scan()
        storage.reset_done(scan, app.config["DB_PATH"])
        return redirect(url_for("overview", scan=idx) + "#worst-h")

    # ---------- protecția live (B): ce se întâmplă acum în hotspot ----------

    LIVE_MESSAGES = ("NOT_ON_HOTSPOT", "BUSY")

    def live_ctx() -> dict:
        """Datele panoului „Rețeaua ta acum”, gata de afișat. Tot ce vine de la dispozitive sau din fișiere e text
        nesigur: îl afișează doar Jinja, cu autoescape."""
        mon = app.config["LIVE"]
        snap, full = mon.snapshot(), mon.full_scan_status()
        lang = g.get("lang", i18n.DEFAULT_LANG)
        en = lang == "en"
        clock = lambda ts: time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""  # noqa: E731
        devices = []
        for d in snap["devices"]:
            if d["in_scan"] and d["device_type"]:
                name = i18n.device_type_label(lang, d["device_type"])
            elif d["private_mac"]:
                name = i18n.t(lang, "live_private")
            else:
                name = d["vendor"] or i18n.t(lang, "live_unknown_device")
            devices.append({**d, "name": name, "since": clock(d["first_seen"]), "left": clock(d["last_seen"]),
                            "not_in_scan": bool(snap["known_file"]) and not d["in_scan"]})
        events = [{"tone": e["tone"], "time": clock(e["ts"]), "text": e["text_en"] if en else e["text_ro"],
                   "kind": e["kind"]} for e in snap["events"][:12]]
        state = full["state"]
        eta = full.get("eta_s")
        found = list(full.get("discovered") or [])
        scan_ctx = {
            "state": state, "job": full.get("job"), "percent": int(full.get("percent") or 0),
            "phase": full.get("phase"), "eta": (f"{int(eta // 60)} min" if eta and eta >= 60 else
                                                f"{int(eta)} s" if eta else ""),
            "found": found[-12:], "found_total": len(found), "file": full.get("file"),
            "message": full.get("msg_en") if en else full.get("msg_ro"),
            "next": clock(full.get("next_at")), "finished": clock(full.get("updated")),
        }
        msg = request.args.get("live_msg", "")
        status = snap["status"]
        active_scan = state in ("waiting_permission", "running", "waiting_next")
        ctx = {
            "status": status, "starting": status == "active" and not snap["baseline_done"],
            "reason": snap["reason_en"] if en else snap["reason_ro"], "ssid": snap["ssid"], "cidr": snap["cidr"],
            "own_ip": snap["own_ip"], "online": snap["online"], "devices": devices, "events": events,
            "last_check": clock(snap["last_sweep"]), "trap_state": snap["trap_state"],
            "trap_code": snap["trap_code"], "trap_port": snap["trap_port"], "known_file": snap["known_file"],
            "scan": scan_ctx, "msg": msg if msg in LIVE_MESSAGES else None,
            "poll_ms": 2000 if (status != "off" or active_scan) else 0,
            "latest": events[0]["text"] if events else "",
        }
        ctx["version"] = hashlib.sha1(json.dumps(ctx, sort_keys=True, default=str).encode()).hexdigest()[:16]
        return ctx

    def _live_form() -> None:
        if not same_site_request():
            abort(403)
        if not hmac.compare_digest(request.form.get("token", ""), app.config["FORM_TOKEN"]):
            abort(400)

    def _live_back(msg: str | None = None):
        args = {"live_msg": msg} if msg else {}
        if request.headers.get("X-Requested-With") == "fetch":
            return redirect(url_for("live_panel", **args))
        return redirect(url_for("overview", **args) + "#live")

    @app.get("/live/panel")
    def live_panel():
        """Doar panoul live (pentru reîmprospătarea din app.js)."""
        resp = app.make_response(render_template("_live_panel.html", live=live_ctx(),
                                                 token=app.config["FORM_TOKEN"]))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.post("/live/start")
    def live_start():
        _live_form()
        app.config["LIVE"].start()
        return _live_back()

    @app.post("/live/stop")
    def live_stop():
        _live_form()
        app.config["LIVE"].stop()
        return _live_back()

    @app.post("/live/scan")
    def live_scan():
        """Scanarea completă: pornește pasul de admin prin fereastra de permisiune a sistemului (elevate.py)."""
        _live_form()
        job = request.form.get("job", "scan")
        if job not in live_mod.elevate.JOBS:
            abort(400)
        code = app.config["LIVE"].request_full_scan(job)
        return _live_back(None if code == "OK" else code)

    @app.post("/live/scan/stop")
    def live_scan_stop():
        _live_form()
        app.config["LIVE"].stop_full_scan()
        return _live_back()

    @app.post("/history/save")
    def history_save():
        """Salvează scanarea afișată în istoric (o singură dată per fișier + dată)."""
        if not hmac.compare_digest(request.form.get("token", ""), app.config["FORM_TOKEN"]):
            abort(400)
        scan_list = scans()
        idx = request.form.get("scan", default=-1, type=int)
        if not 0 <= idx < len(scan_list):
            abort(400)
        scan, db = scan_list[idx], app.config["DB_PATH"]
        scan_id = storage.find_scan(scan.file, scan.started_at, db)
        if scan_id is None:
            scan_id = storage.save_scan(scan, db)
        if request.headers.get("X-Requested-With") == "fetch":  # actualizare parțială: rămânem pe pagina principală
            return redirect(url_for("overview", scan=idx))
        return redirect(url_for("history_scan", scan_id=scan_id))

    @app.get("/devices")
    def inventory():
        """D4: „Ce e conectat la mine?”: toate dispozitivele, inclusiv cele fără probleme, după IP."""
        scan_list = scans()
        scan, idx = pick(scan_list)
        devices = sorted(rank_devices(scan), key=lambda d: ip_key(d.host.ip)) if scan and scan.status == "ok" else []
        return render_template("inventory.html", scan=scan, scan_list=scan_list, selected=idx, devices=devices)

    @app.get("/device/<device_id>")
    def device(device_id: str):
        scan_list = scans()
        scan, idx = pick(scan_list)
        if scan is None:
            abort(404)
        view = next((d for d in rank_devices(scan) if d.host.device_id == device_id), None)
        if view is None:
            abort(404)
        return render_template("device.html", scan=scan, d=view, selected=idx)

    @app.get("/history")
    def history():
        items = storage.list_scans(app.config["DB_PATH"])
        # Pentru coloana „față de anterioara”: scorul ultimei scanări citibile de dinainte (doar afișare, din motor).
        rows, prev = [], None
        for it in items:
            rows.append({"item": it, "prev": prev})
            if it.status == "ok":
                prev = it.score
        return render_template(
            "history.html", items=items, rows=rows, trend=score_trend(items),
            deleted=request.args.get("deleted") == "1",
        )

    def render_report(scan: Scan, back_url: str, download_url: str, download: bool):
        """FR-14: raportul de o pagină pentru furnizorul IT. Doar date din motor; MAC mascat."""
        devices = rank_devices(scan) if scan.status == "ok" else []
        counts = {sev: sum(1 for f in scan.findings if f.severity == sev) for sev in ("high", "medium", "low", "info")}
        html = render_template(
            "report.html", scan=scan, devices=devices, counts=counts, generated=_fmt_time(int(time.time()), g.lang),
            back_url=back_url, download_url=download_url, inline_css=Markup(REPORT_CSS.read_text(encoding="utf-8")) if download else None,  # fișierul nostru, nu date
            # raportul descărcat trebuie să meargă singur, fără server: logo-ul intră în fișier ca data URI
            logo_src=("data:image/svg+xml;base64," + base64.b64encode(LOGO_SVG.read_bytes()).decode("ascii")) if download
            else url_for("static", filename="brand/safeeel-lockup-horizontal-light.svg"),
        )
        if not download:
            return html
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(scan.file).stem)[:60] or "scan"
        return app.response_class(html, mimetype="text/html", headers={
            "Content-Disposition": f'attachment; filename="raport-{name}.html"'})

    @app.get("/report")
    def report():
        scan, idx = pick(scans())
        if scan is None:
            abort(404)
        return render_report(scan, url_for("overview", scan=idx), url_for("report", scan=idx, download=1),
                             request.args.get("download") == "1")

    @app.get("/scan/<int:scan_id>/report")
    def history_report(scan_id: int):
        scan = storage.get_scan(scan_id, app.config["DB_PATH"])
        if scan is None:
            abort(404)
        return render_report(scan, url_for("history_scan", scan_id=scan_id),
                             url_for("history_report", scan_id=scan_id, download=1), request.args.get("download") == "1")

    @app.get("/journal")
    def journal_page():
        g.monitor = extras.monitor_events()
        db = app.config["DB_PATH"]
        by_id = {s.id: s for s in storage.list_scans(db)}
        groups: list[dict] = []
        for a in journal(db):
            if not groups or groups[-1]["scan_id"] != a.scan_id:
                groups.append({"scan_id": a.scan_id, "scan": by_id.get(a.scan_id), "alerts": []})
            groups[-1]["alerts"].append(a)
        events, monitor_ran = g.monitor if "monitor" in g else extras.monitor_events()
        # Legătura spre pagina dispozitivului, dacă IP-ul apare în cea mai nouă scanare citibilă.
        scan_list, known = scans(), {}
        ok = [(i, s) for i, s in enumerate(scan_list) if s.status == "ok"]
        if ok:
            idx, latest = max(ok, key=lambda p: p[1].started_at or 0)
            known = {h.ip: (h.device_id, idx, h.device_type) for h in latest.hosts}
        return render_template("journal.html", groups=groups, events=events, monitor_ran=monitor_ran, known=known)

    @app.get("/history/delete")
    def history_delete_confirm():
        return render_template("history_delete.html", token=app.config["FORM_TOKEN"])

    @app.post("/history/delete")
    def history_delete():
        sent = request.form.get("token", "")
        if not hmac.compare_digest(sent, app.config["FORM_TOKEN"]):
            abort(400)
        storage.delete_history(app.config["DB_PATH"])
        return redirect(url_for("history", deleted=1))

    @app.get("/scan/<int:scan_id>")
    def history_scan(scan_id: int):
        db = app.config["DB_PATH"]
        scan = storage.get_scan(scan_id, db)
        if scan is None:
            abort(404)
        prev_id = storage.previous_scan_id(scan_id, db)
        prev = storage.get_scan(prev_id, db) if prev_id is not None else None
        compare = storage.diff(prev, scan) if prev is not None else None
        alerts = alerts_between(prev, scan, scan_id=scan_id) if prev is not None else None
        question = request.args.get("q", "")[:MAX_QUESTION_LEN] if same_site_request() else ""
        ip_of = {h.device_id: h.ip for h in (prev.hosts if prev else [])} | {h.device_id: h.ip for h in scan.hosts}
        return render_template(
            "overview.html", scan=scan, scan_list=[], selected=0,
            devices=rank_devices(scan), worst=most_dangerous(scan),
            history_id=scan_id, compare=compare, ip_of=ip_of, alerts=alerts,
            assistant=assistant_ctx(url_for("history_scan", scan_id=scan_id), url_for("api_ask", history=scan_id),
                                    scan, None, question, ask_assistant(question, scan, g.lang, previous=prev), True),
        )

    @app.get("/api/ask")
    def api_ask():
        """Răspunsul asistentului ca JSON, pentru fereastra de chat (app.js îl pune în pagină doar cu textContent)."""
        if not same_site_request():
            return {"ok": False, "text": i18n.t(g.lang, "ai_error")}, 403
        question = request.args.get("q", "")[:MAX_QUESTION_LEN]
        prev = None
        if request.args.get("history") is not None:
            db = app.config["DB_PATH"]
            hid = request.args.get("history", type=int)
            scan = storage.get_scan(hid, db) if hid is not None else None
            prev_id = storage.previous_scan_id(hid, db) if scan is not None else None
            prev = storage.get_scan(prev_id, db) if prev_id is not None else None
        else:
            scan, _ = pick(scans())
        reply = ask_assistant(question, scan, g.lang, previous=prev)
        if reply is None:
            return {"ok": False, "text": i18n.t(g.lang, "ai_error")}, 200
        state = reply_state(reply)
        key, icon = REPLY_STATES[state]
        return {
            "ok": True, "text": reply.text, "source": reply.source, "state": state,
            "source_label": i18n.t(g.lang, key), "source_icon": icon,
        }

    @app.errorhandler(400)
    @app.errorhandler(404)
    def not_found(err):
        try:
            return render_template("message.html", message_key="not_found"), err.code
        except Exception:  # ex. Host respins (DNS rebinding): fără linkuri, doar un mesaj simplu
            return "400 Bad Request", err.code, {"Content-Type": "text/plain; charset=utf-8"}

    @app.errorhandler(500)
    def server_error(err):  # fără stack trace în pagină
        return render_template("message.html", message_key="no_data"), 500

    return app


def _fmt_time(epoch: int | None, lang: str = "ro") -> str:
    """Data pe înțeles: „1 nov. 2026, 11:09” (RO) / „1 Nov 2026, 11:09” (EN)."""
    if epoch is None:
        return "—"
    d = datetime.fromtimestamp(epoch)
    return f"{d.day} {i18n.month_short(lang, d.month)} {d.year}, {d:%H:%M}"


def run(port: int = 5000) -> None:
    """Pornește UI-ul local. Doar 127.0.0.1, fără debug. Dacă utilizatorul a lăsat protecția live pornită, o reia
    (ea însăși așteaptă hotspotul echipei înainte să atingă rețeaua)."""
    app = create_app()
    app.config["LIVE"].autostart()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
