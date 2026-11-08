"""„Toate verificările” (/results): pentru FIECARE verificare din folderul afișat, același răspuns ca pe Acasă, pe
scurt: o propoziție-verdict, cel mai periculos dispozitiv și primul pas. Sus, un rezumat într-o propoziție. Pentru
tehnician: findings.csv / scores.csv pentru tot folderul, scrise de funcția motorului (ca `netscan analyze`).

UI-ul nu calculează nimic: verdictul vine din view.verdict_view (aceeași funcție ca pe Acasă), adică din scorul,
severitățile și punctele motorului.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Blueprint, Response, abort, current_app, g, render_template

from netscan.engine.export import write_results
from netscan.ui import i18n
from netscan.ui.view import verdict_view

bp = Blueprint("results", __name__)

TEXTS = {
    "ro": {
        "title": "Toate verificările",
        "lead": "Pentru fiecare verificare a rețelei: scorul, ce a găsit și cel mai periculos dispozitiv. Deschide una ca să vezi ce faci întâi.",
        "summary": "Ai %s verificări: %s.",
        "s_poor": "%s au nevoie de atenție", "s_fair": "%s se pot îmbunătăți", "s_good": "%s au scor bun",
        "s_error": "%s nu s-au putut citi",
        "and": " și ",
        "error_title": "Fișierul nu a putut fi citit.",
        "error_body": "Nu am ghicit nimic din el. Restul verificărilor au fost analizate normal.",
        "worst": "Cel mai periculos:", "first": "Fă asta întâi:", "score": "Scor", "of": "din 100",
        "open": "Deschide verificarea", "no_date": "fără dată",
        "tech": "Pentru tehnician: rezultatele în format standard",
        "tech_body": "Aceleași fișiere ca comanda python -m netscan analyze, pentru toate verificările de mai sus.",
        "export_findings": "Descarcă findings.csv", "export_scores": "Descarcă scores.csv",
        "empty": "Nu există încă nicio verificare pe acest calculator.", "back": "Înapoi la Acasă",
    },
    "en": {
        "title": "All checks",
        "lead": "For every check of your network: the score, what it found and the most dangerous device. Open one to see what to do first.",
        "summary": "You have %s checks: %s.",
        "s_poor": "%s need attention", "s_fair": "%s could be better", "s_good": "%s have a good score",
        "s_error": "%s could not be read",
        "and": " and ",
        "error_title": "The file could not be read.",
        "error_body": "I didn't guess anything from it. The other checks were analysed normally.",
        "worst": "Most dangerous:", "first": "Do this first:", "score": "Score", "of": "out of 100",
        "open": "Open the check", "no_date": "no date",
        "tech": "For a technician: the results in the standard format",
        "tech_body": "The same files as the python -m netscan analyze command, for all the checks above.",
        "export_findings": "Download findings.csv", "export_scores": "Download scores.csv",
        "empty": "There are no checks on this computer yet.", "back": "Back to Home",
    },
}
BAND_ICON = {"good": "good", "fair": "fair", "poor": "high"}


def _lang() -> str:
    return "en" if g.get("lang") == "en" else "ro"


def check_cards(scans: list, lang: str = "ro") -> list[dict]:
    """Un card pe verificare, în ordinea în care le arată și Acasă (lista de alegere)."""
    cards = []
    for s in scans:
        if s.status != "ok" or s.score is None:
            cards.append({"file": s.file, "started_at": s.started_at, "ok": False})
            continue
        v = verdict_view(s, lang=lang)
        key = v.get("verdict_key") or ("verdict_clean" if v["clean"] else f"verdict_{v['band']}")
        cards.append({"file": s.file, "started_at": s.started_at, "ok": True, "score": s.score, "band": v["band"],
                      "verdict": i18n.t(lang, key), "counts": v["counts_text"], "worst_name": v["worst_name"],
                      "worst_problem": i18n.code_name(lang, v["first_code"]) if v["first_code"] else None,
                      "first_step": v["first_step"]})
    return cards


def summary_text(cards: list[dict], lang: str = "ro") -> str:
    t = TEXTS[lang]
    n = {"poor": 0, "fair": 0, "good": 0, "error": 0}
    for c in cards:
        n[c["band"] if c["ok"] else "error"] += 1
    parts = [t[f"s_{k}"] % v for k, v in n.items() if v]
    joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + t["and"] + parts[-1]
    return t["summary"] % (len(cards), joined)


@bp.get("/results")
def results_page():
    lang = _lang()
    cards = check_cards(current_app.config["SCAN_LOADER"](), lang)
    return render_template("results.html", R=TEXTS[lang], cards=cards, band_icon=BAND_ICON,
                           summary=summary_text(cards, lang) if cards else "")


@bp.get("/results/<name>.csv")
def results_csv(name: str):
    """findings.csv / scores.csv pentru toate verificările din folder, scrise de motor (descărcare)."""
    if name not in ("findings", "scores"):
        abort(404)
    scans = current_app.config["SCAN_LOADER"]()
    with tempfile.TemporaryDirectory() as tmp:
        f_path, s_path = write_results(scans, tmp)
        data = Path(f_path if name == "findings" else s_path).read_bytes()
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}.csv"', "Cache-Control": "no-store"})
