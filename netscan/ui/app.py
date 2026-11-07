"""Aplicația Flask (RBRT). Vezi docs/roles/D_RBRT_UI_Istoric.md, secțiunea 2.2.

- Ascultă doar pe 127.0.0.1, fără debug.
- Jinja2 cu autoescape; datele din scanare sunt TEXT NESIGUR, niciodată |safe.
- Fără CDN-uri: CSS local în static/.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, url_for

from netscan.cli import load_env_file
from netscan.engine import analyze_folder
from netscan.model import Scan
from netscan.ui import i18n, storage
from netscan.ui.alerts import alerts_between, journal
from netscan.ui.explain_stub import get_explanation, get_standards
from netscan.ui.view import action_plan, current_action, ip_key, most_dangerous, rank_devices, score_band, score_trend

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = REPO_ROOT / "fixtures" / "sample.json"
VALIDATION_DIR = REPO_ROOT / "fixtures" / "validation"
REPORT_CSS = Path(__file__).resolve().parent / "static" / "report.css"
LANG_COOKIE = "lang"


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


MAX_QUESTION_LEN = 500


def ask_assistant(question: str, scan: Scan | None, lang: str, previous: Scan | None = None):
    """FR-12: asistentul lui Ayan (netscan/scan/assistant.py). Răspunde doar din scanare, fără rețea.
    Întrebarea e text nesigur: se trimite doar asistentului și nu se afișează ca HTML."""
    question = (question or "").strip()[:MAX_QUESTION_LEN]
    if not question or scan is None:
        return None
    try:
        from netscan.scan.assistant import answer

        return answer(question, scan, lang=lang, previous=previous)
    except Exception:  # asistentul nu are voie să strice pagina
        return None


def create_app(test_config: dict | None = None) -> Flask:
    load_env_file(REPO_ROOT / ".env")  # NETSCAN_SALT, NETSCAN_DB_PATH; nu suprascrie ce e deja setat
    app = Flask(__name__)
    app.config.update(
        SCAN_LOADER=load_scans,
        DB_PATH=None,  # None = NETSCAN_DB_PATH sau data/netscan.db
        FORM_TOKEN=secrets.token_urlsafe(32),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    # ---------- limbă și helperi pentru template-uri ----------

    @app.before_request
    def pick_language() -> None:
        g.lang = i18n.normalize_lang(request.args.get("lang") or request.cookies.get(LANG_COOKIE))

    @app.after_request
    def finish(resp):
        if request.args.get("lang") in i18n.LANGS:
            resp.set_cookie(LANG_COOKIE, g.lang, max_age=60 * 60 * 24 * 365, samesite="Strict", httponly=True)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.context_processor
    def helpers() -> dict:
        lang = g.get("lang", i18n.DEFAULT_LANG)
        other = "en" if lang == "ro" else "ro"
        def lang_url() -> str:
            """Aceeași pagină, în cealaltă limbă (păstrează restul parametrilor)."""
            args = {k: (v[:MAX_QUESTION_LEN] if k == "q" else v) for k, v in request.args.items() if k != "lang"}
            if request.endpoint and request.endpoint != "static" and request.method == "GET":
                return url_for(request.endpoint, **(request.view_args or {}), **args, lang=other)
            return url_for("overview", lang=other)

        return {
            "lang": lang,
            "other_lang": other,
            "lang_url": lang_url,
            "T": lambda key: i18n.t(lang, key),
            "device_type_label": lambda dt: i18n.device_type_label(lang, dt),
            "error_message": lambda code: i18n.error_message(lang, code),
            "explain": lambda code: get_explanation(code, lang),
            "alert_text": lambda a: i18n.alert_text(lang, a),
            "code_name": lambda code: i18n.code_name(lang, code),
            "standards": lambda code: get_standards(code, lang),
            "fmt_time": _fmt_time,
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
        return scan_list[idx], idx

    @app.get("/")
    def overview():
        scan_list = scans()
        scan, idx = pick(scan_list)
        saved_id = storage.find_scan(scan.file, scan.started_at, app.config["DB_PATH"]) if scan else None
        question = request.args.get("q", "")[:MAX_QUESTION_LEN]
        step, plan_total, all_done = None, 0, False
        if scan is not None and scan.status == "ok" and scan.findings:
            done = storage.done_keys(scan, app.config["DB_PATH"])
            step, plan_total = current_action(scan, done), len(action_plan(scan))
            all_done = step is None
        return render_template(
            "overview.html", scan=scan, scan_list=scan_list, selected=idx,
            step=step, plan_total=plan_total, all_done=all_done,
            question=question, reply=ask_assistant(question, scan, g.lang),
            devices=rank_devices(scan) if scan else [], worst=most_dangerous(scan) if scan else None,
            history_id=None, compare=None, saved_id=saved_id, token=app.config["FORM_TOKEN"],
        )

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
        """D5: bifează pasul curent. Cheia trebuie să fie a unei probleme din scanare; scorul nu se schimbă."""
        scan, idx = _form_scan()
        port_raw = request.form.get("port", "")
        key = (request.form.get("device_id", ""), int(port_raw) if port_raw.lstrip("-").isdigit() else None,
               request.form.get("code", ""))
        if key not in {f.key() for f in scan.findings}:
            abort(400)
        storage.mark_done(scan, key, app.config["DB_PATH"])
        return redirect(url_for("overview", scan=idx) + "#worst-h")

    @app.post("/action/reset")
    def action_reset():
        scan, idx = _form_scan()
        storage.reset_done(scan, app.config["DB_PATH"])
        return redirect(url_for("overview", scan=idx) + "#worst-h")

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
        return render_template(
            "history.html", items=items, trend=score_trend(items),
            deleted=request.args.get("deleted") == "1",
        )

    def render_report(scan: Scan, back_url: str, download_url: str, download: bool):
        """FR-14: raportul de o pagină pentru furnizorul IT. Doar date din motor; MAC mascat."""
        devices = rank_devices(scan) if scan.status == "ok" else []
        counts = {sev: sum(1 for f in scan.findings if f.severity == sev) for sev in ("high", "medium", "low", "info")}
        html = render_template(
            "report.html", scan=scan, devices=devices, counts=counts, generated=_fmt_time(int(time.time())),
            back_url=back_url, download_url=download_url, inline_css=REPORT_CSS.read_text(encoding="utf-8") if download else None,
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
        db = app.config["DB_PATH"]
        by_id = {s.id: s for s in storage.list_scans(db)}
        groups: list[dict] = []
        for a in journal(db):
            if not groups or groups[-1]["scan_id"] != a.scan_id:
                groups.append({"scan_id": a.scan_id, "scan": by_id.get(a.scan_id), "alerts": []})
            groups[-1]["alerts"].append(a)
        return render_template("journal.html", groups=groups)

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
        question = request.args.get("q", "")[:MAX_QUESTION_LEN]
        ip_of = {h.device_id: h.ip for h in (prev.hosts if prev else [])} | {h.device_id: h.ip for h in scan.hosts}
        return render_template(
            "overview.html", scan=scan, scan_list=[], selected=0,
            devices=rank_devices(scan), worst=most_dangerous(scan),
            history_id=scan_id, compare=compare, ip_of=ip_of, alerts=alerts,
            question=question, reply=ask_assistant(question, scan, g.lang, previous=prev),
        )

    @app.errorhandler(400)
    @app.errorhandler(404)
    def not_found(err):
        return render_template("message.html", message_key="not_found"), err.code

    @app.errorhandler(500)
    def server_error(err):  # fără stack trace în pagină
        return render_template("message.html", message_key="no_data"), 500

    return app


def _fmt_time(epoch: int | None) -> str:
    if epoch is None:
        return "—"
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


def run(port: int = 5000) -> None:
    """Pornește UI-ul local. Doar 127.0.0.1, fără debug."""
    create_app().run(host="127.0.0.1", port=port, debug=False)
