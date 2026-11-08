"""Aplicația Flask (RBRT). Vezi docs/roles/D_RBRT_UI_Istoric.md, secțiunea 2.2.

- Ascultă doar pe 127.0.0.1, fără debug.
- Jinja2 cu autoescape; datele din scanare sunt TEXT NESIGUR, niciodată |safe.
- Fără CDN-uri: CSS local în static/.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from netscan.cli import load_env_file
from netscan.engine import analyze_file, analyze_folder
from netscan.engine.parser import MAX_BYTES
from netscan.engine.parser import _DEFAULT_SALT as DEFAULT_SALT   # doar comparat: „cheia echipei sau cea implicită?”
from netscan.scan.device_info import phone_hotspot
from netscan.model import Scan
from netscan.scan import live as live_mod
from netscan.ui import extras, guide, i18n, storage, verify
from netscan.ui.alerts import alerts_between, fold_port_alerts, journal
from netscan.ui.explain_stub import get_explanation, get_harm, get_standards
from netscan.ui.view import (action_plan, csv_view, evidence_text, ip_key, most_dangerous, order_devices, proof_of,
                             proof_view, rank_devices, remaining_scan, score_band, score_trend, steps_view, summary_of,
                             verdict_view, verified_by_newer, worst_device)

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = REPO_ROOT / "fixtures" / "sample.json"
VALIDATION_DIR = REPO_ROOT / "fixtures" / "validation"
LANG_COOKIE = "lang"
LOCAL_HOSTS = ("127.0.0.1", "localhost")   # serverul ascultă doar pe 127.0.0.1 (IPv4)
MASKED_MAC = re.compile(r"^([0-9A-Fa-f]{2}:){3}XX:XX:XX$")   # pe /trust arătăm doar un MAC deja mascat
SEEN_COOKIE = "journal_seen"   # când a deschis utilizatorul ultima dată Jurnalul (pentru „N alerte noi”)


def glossary_terms(text: str, lang: str) -> list[dict]:
    """Termenii din glosar (netscan/explain) care apar în `text`. Lipsă sau eroare: nimic de afișat."""
    try:
        from netscan.explain import get_glossary_terms_for

        terms = get_glossary_terms_for(text, lang) or []
        return [t for t in terms if isinstance(t, dict) and t.get("term") and t.get("definition")]
    except Exception:
        return []


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


_OWN_INDEX: dict[tuple, int | None] = {}     # (nume, mtime_ns, mărime) -> started_at (None = fișier ilizibil)
_OWN_INDEX_LOCK = threading.Lock()


def _own_scan_times(folder: Path) -> dict[str, int | None]:
    """started_at pentru fiecare scanare din folderul nostru (cu cache după nume, dată și mărime)."""
    from netscan.engine import analyze_file

    out: dict[str, int | None] = {}
    try:
        files = [p for p in folder.glob("*.xml") if p.is_file()]
    except OSError:
        return out
    keep = set()
    for p in files:
        try:
            st = p.stat()
        except OSError:
            continue
        key = (p.name, st.st_mtime_ns, st.st_size)
        keep.add(key)
        with _OWN_INDEX_LOCK:
            known = key in _OWN_INDEX
            value = _OWN_INDEX.get(key)
        if not known:
            try:
                scan = analyze_file(p)
                value = scan.started_at if scan.status == "ok" else None
            except Exception:
                value = None
            with _OWN_INDEX_LOCK:
                _OWN_INDEX[key] = value
        out[p.name] = value
    with _OWN_INDEX_LOCK:
        for key in [k for k in _OWN_INDEX if k[0] in out and k not in keep]:
            del _OWN_INDEX[key]
    return out


def own_newest_scan(scan: Scan | None, own_dir: str | Path | None = None, env: dict | None = None) -> bool:
    """E scanarea afișată CEA MAI NOUĂ scanare scrisă de scanerul nostru (scans/)? Doar atunci aplicația are voie
    să bată la ușa unui dispozitiv sau să lipească numele anunțate. Validation / Test Set / lab, un folder ales cu
    NETSCAN_SCANS_DIR sau o scanare mai veche: nu (sunt doar fișiere analizate)."""
    env = os.environ if env is None else env
    if scan is None or scan.status != "ok" or not scan.file or Path(scan.file).name != scan.file:
        return False
    own = Path(own_dir or USER_SCANS_DIR)
    other = (env.get("NETSCAN_SCANS_DIR") or "").strip()
    try:
        if other and Path(other).resolve() != own.resolve():
            return False
    except OSError:
        return False
    times = _own_scan_times(own)
    if scan.file not in times or times[scan.file] is None:
        return False
    newest = max(((t is not None, t or 0, name) for name, t in times.items() if t is not None), default=None)
    return newest is not None and newest[2] == scan.file and newest[1] == scan.started_at


MAX_QUESTION_LEN = 500
VERIFY_NET_MAX_AGE_S = 5      # la „Verifică”: rețeaua trebuie citită în ultimele 5 s (altfel o recitim)
NETWORK_TTL_S = 15           # rețeaua curentă (citită din sistem) se recitește cel mult o dată la 15 s
LIVE_MSG_TTL_S = 60          # un mesaj al panoului live rămâne vizibil un minut (nu dispare la următorul refresh)
URGENT_WINDOW_S = 600        # alertele urgente din ultimele 10 minute apar într-un banner mic sus
UPLOAD_ERRORS = frozenset(set(i18n.ERROR_MESSAGES["ro"]) - {"_default"}) | {"NO_FILE", "OLDER"}   # coduri afișabile la încărcare
UPLOAD_SLACK = 1024 * 1024   # peste limita fișierului: câmpurile formularului (jeton etc.)
_ASK_LOCK = threading.Lock()
_VERIFY_LOCK = threading.Lock()   # o singură verificare live odată   # modelul local răspunde la o singură întrebare odată (altfel se poate bloca placa video)


def current_user() -> str | None:
    """Utilizatorul de sistem sub care rulează aplicația (istoricul e al lui, pe acest calculator). None dacă
    sistemul nu îl spune. Text de la sistem: se escapează în template, ca orice altceva."""
    try:
        return getpass.getuser().strip()[:60] or None
    except Exception:  # fără nume de utilizator în mediu (ex. cont de serviciu): pagina merge și fără
        return None


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


def assistant_ctx(action: str, api: str, scan: Scan | None, ref: dict | None, question: str, reply,
                  show_changes: bool) -> dict | None:
    """Datele pentru fereastra asistentului (templates/_assistant.html). `ref` = {"file", "started_at"} al
    scanării (linkurile și formularele o păstrează după fișier, nu după poziția în listă); None în istoric."""
    if scan is None or scan.status != "ok":
        return None
    from urllib.parse import urlencode

    ref = dict(ref or {})
    return {"action": action, "api": api, "ref": ref, "question": question, "reply": reply,
            # fără JavaScript: pagina se reîncarcă cu fereastra deschisă (aceeași scanare, după fișier + dată)
            "open_url": f"{action}?{urlencode({**ref, 'ask': 1})}#chat",
            "open": bool(request.args.get("ask")) or bool(question), "llm_on": local_ai_enabled(),
            "file": scan.file, "started_at": scan.started_at, "show_changes": show_changes,
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
        USER_SCANS_DIR=USER_SCANS_DIR,   # scanările scrise de scanerul nostru (doar pe ele le verificăm live)
        OWN_SCAN_CHECK=None,             # (scan) -> e cea mai nouă scanare a noastră? None = own_newest_scan
        # () -> NetworkInfo: rețeaua curentă, doar CITITĂ din sistem (rute, numele Wi-Fi), fără pachete în rețea.
        # None = detect-ul monitorului live (în teste: „fără rețea”). Rezultatul se păstrează NETWORK_TTL_S secunde.
        NETWORK_DETECT=None,
    )
    if test_config:
        app.config.update(test_config)
        if app.config.get("TESTING") and "NET_CHECK" not in test_config:
            app.config["NET_CHECK"] = lambda ip: False   # testele nu ating niciodată rețeaua
        if app.config.get("TESTING") and "USER_SCANS_DIR" not in test_config:
            # testele nu ating niciodată scans/ din repo (nici la citire, nici la „Șterge istoricul”)
            app.config["USER_SCANS_DIR"] = Path(app.config["DB_PATH"] or "data/netscan.db").parent / "no-scans"
    if app.config.get("OWN_SCAN_CHECK") is None:
        app.config["OWN_SCAN_CHECK"] = lambda s: own_newest_scan(s, app.config["USER_SCANS_DIR"])
    # Mesajul panoului live (cod + momentul), păstrat LIVE_MSG_TTL_S secunde; nu intră în versiunea panoului.
    live_msg_state: dict = {"code": None, "ts": 0.0}
    net_cache: dict = {"info": None, "ts": None}
    net_lock = threading.Lock()

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

    def current_network(max_age: float = NETWORK_TTL_S):
        """Rețeaua de acum (NetworkInfo) sau None dacă nu s-a putut citi. Doar citește setările sistemului (ruta
        implicită, numele Wi-Fi): nu pornește nimic și nu trimite nimic în rețea. Păstrată NETWORK_TTL_S secunde
        (max_age mai mic = o citire mai proaspătă, de ex. chiar înainte de verificarea unui pas)."""
        with net_lock:
            if net_cache["ts"] is not None and time.monotonic() - net_cache["ts"] < max_age:
                return net_cache["info"]
        detect = app.config.get("NETWORK_DETECT") or getattr(app.config["LIVE"], "detect", None)
        info = None
        if detect is not None:
            try:
                info = detect()
            except Exception:   # o eroare la citirea rețelei nu are voie să strice pagina
                info = None
        with net_lock:
            net_cache.update(info=info, ts=time.monotonic())
        return info

    def router_ip(scan: Scan | None) -> str | None:
        """IP-ul routerului (la noi, telefonul cu hotspotul): gateway-ul rețelei de ACUM, dar doar dacă suntem pe
        hotspotul echipei și scanarea afișată e cea mai nouă scanare a noastră. Doar o etichetă: tipul
        dispozitivului (al motorului) rămâne neschimbat."""
        if scan is None or scan.status != "ok" or not app.config["OWN_SCAN_CHECK"](scan):
            return None
        info = current_network()
        if info is None or not getattr(info, "scan_allowed", False) or not getattr(info, "gateway", None):
            return None
        return info.gateway

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
            g.names = {}   # numele anunțate apar doar lângă scanarea lor (vezi names_for), altfel nimic
        if "monitor" not in g:
            g.monitor = extras.monitor_events(app.config["DB_PATH"])          # (evenimente, a rulat monitorul?)
        seen = request.cookies.get(SEEN_COOKIE, "0")
        seen = int(seen) if seen.isdigit() else 0
        new_alerts = sum(1 for e in g.monitor[0] if (e.ts or 0) > seen)
        def lang_url() -> str:
            """Aceeași pagină, în cealaltă limbă (păstrează restul parametrilor). Un ?scan=<poziție> vechi devine
            fișierul + data scanării afișate, ca linkul să rămână corect dacă lista se schimbă."""
            args = {k: (v[:MAX_QUESTION_LEN] if k == "q" else v) for k, v in request.args.items()
                    if k != "lang" and not k.startswith("_")}
            picked = g.get("picked")
            if "scan" in args and picked is not None and picked.file:
                args.pop("scan")
                args.update(scan_ref(picked))
            if request.endpoint and request.endpoint != "static" and request.method == "GET":
                return url_for(request.endpoint, **(request.view_args or {}), **args, lang=other)
            return url_for("overview", lang=other)

        return {
            "lang": lang,
            "from_devices": request.args.get("from") == "devices",   # pagina dispozitivului deschisă din „Dispozitive”
            "from_journal": request.args.get("from") == "journal",   # comparația deschisă din „Jurnal”
            "other_lang": other,
            "lang_url": lang_url,
            "T": lambda key: i18n.t(lang, key),
            "device_type_label": lambda dt: i18n.device_type_label(lang, dt),
            # hotspot de pe telefon vs. router adevărat, din datele scanării (doar etichete; CSV-urile și scorul nu se schimbă)
            "hotspot_kind": lambda h: phone_hotspot(h, h.vendor, g.get("router_ip")),
            "device_type_the": lambda dt: i18n.device_type_the(lang, dt),
            "error_message": lambda code: i18n.error_message(lang, code),
            "explain": lambda code: get_explanation(code, lang),
            "harm": lambda code: get_harm(code, lang),
            "eavesdrop": lambda code: extras.eavesdrop(code, lang),
            "announced": lambda ip: g.names.get(ip),
            "guide_plan": guide.guide_for,
            "guide_icon": guide.device_icon,
            "new_alerts": new_alerts,
            "alert_text": lambda a, short=False: i18n.alert_text(lang, a, custom_names(), short),
            "alert_device": lambda a: i18n.alert_device(lang, a, custom_names()),
            "custom_name": lambda device_id: custom_names().get(device_id),
            "proof_sentence": lambda proof: i18n.proof_sentence(lang, proof),
            "code_name": lambda code: i18n.code_name(lang, code),
            "standards": lambda code: get_standards(code, lang),
            "fmt_time": lambda epoch: _fmt_time(epoch, lang),
            "score_band": score_band,
            "evidence_text": lambda f: evidence_text(f, lang),   # dovada motorului, pe limba paginii (doar afișare)
            "scan_ref_of": scan_ref,   # scan_ref_of(s) -> {"file", "started_at"} pentru url_for(..., **ref)
            "router_ip": g.get("router_ip"),   # eticheta „Routerul (telefonul cu hotspotul)”, vezi router_ip()
            "plural": lambda n, key: i18n.count_phrase(lang, n, key + "_one", key),
        }

    def scan_ref(scan: Scan | None) -> dict:
        """Identitatea stabilă a unei scanări pentru formulare și linkuri: fișierul (+ data), nu poziția în listă."""
        if scan is None:
            return {}
        ref = {"file": scan.file}
        if scan.started_at is not None:
            ref["started_at"] = scan.started_at
        return ref

    def names_for(scan: Scan | None) -> dict:
        """Numele anunțate (ascultare pasivă) doar pentru cea mai nouă scanare a noastră și doar cele auzite în
        ±6 h de ea. Pe Validation / lab / o scanare veche: niciun nume (IP-urile se refolosesc)."""
        if scan is None or scan.status != "ok" or not app.config["OWN_SCAN_CHECK"](scan):
            return {}
        return extras.names_near(extras.announced_names(), scan.started_at)

    # ---------- pagini ----------

    def scans() -> list[Scan]:
        return app.config["SCAN_LOADER"]()

    def _find(scan_list: list[Scan], name: str, started: str | None) -> int | None:
        """Poziția scanării cu acest fișier (și această dată, dacă e dată). None = nu mai e în listă."""
        if not name:
            return None
        for i, s in enumerate(scan_list):
            if s.file == name and (started in (None, "") or str(s.started_at) == started):
                return i
        return None

    def custom_names() -> dict[str, str]:
        """Numele date de utilizator ({device_id: nume}), citite o dată pe cerere. O bază ilizibilă nu strică pagina."""
        if "custom_names" not in g:
            try:
                g.custom_names = storage.device_names(app.config["DB_PATH"])
            except Exception:
                g.custom_names = {}
        return g.custom_names

    def summary_sentence(scan: Scan, worst, all_fixed: bool = False) -> i18n.SummaryParts:
        """Fraza de sub verdict (cu ce să începi). `scan` și `worst` sunt cele ale cardului de dedesubt (fără
        problemele confirmate ca rezolvate), ca fraza și cardul să spună același lucru. Vine pe bucăți
        (înainte, nume, după), ca template-ul să pună numele în <strong> escapat, fără |safe."""
        summary = summary_of(scan, worst, all_fixed)
        label = step = None
        if summary.device is not None and summary.finding is not None:
            host = summary.device.host
            # numele anunțate doar unde le arată și pagina (g.names = names_for(scan): cea mai nouă scanare a noastră)
            announced = (g.get("names") or {}).get(host.ip)
            # aceeași ordine ca în pagină: numele dat de utilizator, apoi cel anunțat de dispozitiv, apoi tipul
            label = (custom_names().get(host.device_id) or (announced["name"] if announced else None)
                     or i18n.device_type_label(g.lang, host.device_type))
            steps = get_explanation(summary.finding.code, g.lang).get("steps") or []
            step = steps[0] if steps else None
        return i18n.summary_parts(g.lang, summary, label, step, with_counts=False)
    def pick(scan_list: list[Scan]) -> tuple[Scan | None, int]:
        """Scanarea cerută prin GET: după fișier (+ dată), ca linkurile să rămână corecte când apare o scanare
        nouă. ?scan=<poziție> merge încă (linkuri vechi), doar la citire."""
        if not scan_list:
            return None, 0
        idx = request.args.get("scan", default=0, type=int)
        idx = idx if 0 <= idx < len(scan_list) else 0
        name = request.args.get("file", "")[:200]           # „Vezi rezultatul” după o scanare din aplicație
        found = _find(scan_list, name, request.args.get("started_at", "")[:20] or None)
        if found is None and name:
            found = _find(scan_list, name, None)
        if found is not None:
            idx = found
        g.picked = scan_list[idx]
        return scan_list[idx], idx

    def check_text(check: str | None, finding) -> str | None:
        """Rezultatul verificării unui pas, ca propoziție gata de afișat (i18n, RO și EN)."""
        if not check or finding is None:
            return None
        return i18n.t(g.lang, "verify_" + check) % verify.message_args(check, finding.ip, finding.port)

    @app.get("/")
    def overview():
        scan_list = scans()
        scan, idx = pick(scan_list)
        g.names = names_for(scan)
        g.router_ip = router_ip(scan)
        db = app.config["DB_PATH"]
        saved_id = storage.find_scan(scan.file, scan.started_at, db) if scan else None
        question = request.args.get("q", "")[:MAX_QUESTION_LEN] if same_site_request() else ""
        steps = None
        accepted: set = set()
        if scan is not None and scan.status == "ok" and scan.findings:
            accepted = storage.accepted_keys(scan, db)
            steps = steps_view(scan, storage.done_keys(scan, db), storage.verified_keys(scan, db),
                               verified_by_newer(scan, newer_scans(scan, scan_list)),
                               request.args.get("step", type=int), accepted=accepted)
        fixed = steps.fixed_keys if steps is not None else set()
        # reparațiile confirmate de o scanare mai nouă: link spre acea scanare (cea mai nouă), după fișier + dată
        newer_hint = None
        if steps is not None:
            by_files = {s.verified_by for s in steps.steps if s.verified_by not in (None, "live")}
            found = [s for s in scan_list if s.file in by_files and s.status == "ok"]
            if found:
                s_new = max(found, key=lambda s: s.started_at or 0)
                newer_hint = {"ref": scan_ref(s_new), "file": s_new.file, "score": s_new.score}
        check = request.args.get("check")
        checked = request.args.get("checked", type=int)
        if check not in verify.RESULTS or steps is None or not (checked and 1 <= checked <= steps.total):
            check, checked = None, None
        checked_step = steps.steps[checked - 1] if checked else None
        reply = ask_assistant(question, scan, g.lang)
        ok = scan is not None and scan.status == "ok"
        # Scorul standard (cel mare) e MEREU scan.score, al motorului. Scorul după reparațiile confirmate e separat.
        score_std = scan.score if ok else None
        score_now = steps.score_now if steps is not None else score_std
        notice = request.args.get("notice")
        worst = worst_device(scan, fixed) if ok else None
        # După ce a bifat ceva, utilizatorul vede pasul următor: „Verifică din nou” (fișier nou sau scanare mai nouă).
        recheck = None
        if ok and steps is not None and (steps.declared_count or steps.verified_count):
            newer = newest_after(scan, scan_list)
            recheck = {"newer_ref": newer[0] if newer else None, "newer_file": newer[1].file if newer else None}
        # Se poate verifica pasul de acum? Doar pe cea mai nouă scanare a noastră, pe un port TCP, și doar dacă laptopul
        # e chiar în hotspotul echipei. Altfel butonul „Verifică” e dezactivat, cu motivul lângă el (nu bate la nicio ușă).
        verify_block = None
        if steps is not None and getattr(steps, "current", None) is not None and ok and not app.config["OWN_SCAN_CHECK"](scan):
            verify_block = {"file": True}   # scanare veche / din fișier: adresele de atunci pot fi acum alte dispozitive
        elif steps is not None and getattr(steps, "current", None) is not None and ok:
            f_now = steps.current.finding
            h_now = next((h for h in scan.hosts if h.device_id == f_now.device_id), None)
            if f_now.port is not None and verify._tcp_port(h_now, f_now.port):
                try:   # pe pagină: rețeaua citită în ultimele 15 s (la click, verificarea o recitește, pentru siguranță)
                    net_check = app.config["NET_CHECK"]
                    if net_check is verify.target_in_my_network:
                        reachable = verify.target_in_my_network(f_now.ip, detect=current_network)
                    else:
                        reachable = bool(net_check(f_now.ip))
                except Exception:
                    reachable = False
                if not reachable:
                    info = current_network()
                    verify_block = {"ssid": getattr(info, "ssid", None) if info else None}
        upload_error = request.args.get("upload_error")
        if upload_error not in UPLOAD_ERRORS:
            upload_error = None
        return render_template(
            "overview.html", scan=scan, scan_list=scan_list, selected=idx, live=live_ctx(),
            steps=steps, check=check, checked=checked_step,
            check_text=check_text(check, checked_step.finding if checked_step else None),
            recheck=recheck, upload_error=upload_error, verify_block=verify_block,
            expected_ssid=os.environ.get("NETSCAN_EXPECTED_SSID") or "RSH-Ibiza2028",
            show_steps=steps is not None and (request.args.get("step") is not None or not steps.all_resolved),
            assistant=assistant_ctx(url_for("overview"), url_for("api_ask", **scan_ref(scan)), scan, scan_ref(scan),
                                    question, reply, False),
            summary=summary_sentence(remaining_scan(scan, fixed) if ok else scan, worst,
                                     bool(steps and steps.verified_count)) if scan is not None else None,
            devices=order_devices(scan, fixed) if ok else (rank_devices(scan) if scan else []),
            worst=worst,
            fixed_keys=fixed, accepted_keys=accepted,
            score_std=score_std, score_now=score_now,
            score_now_differs=score_now is not None and score_std is not None and score_now != score_std,
            verdict=verdict_view(scan, fixed, accepted, g.lang) if ok else None,
            csv=csv_view(scan), scan_ref=scan_ref(scan), own_scan=bool(ok and app.config["OWN_SCAN_CHECK"](scan)),
            notice=i18n.t(g.lang, notice) if notice == "scan_list_changed" else None,
            history_id=None, compare=None, saved_id=saved_id, token=app.config["FORM_TOKEN"],
            newer_hint=newer_hint,
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

    class ScanGone(Exception):
        """Scanarea din formular nu mai e în listă (de ex. a apărut una nouă sau fișierul a fost șters)."""

    @app.errorhandler(ScanGone)
    def scan_gone(_err):
        if request.headers.get("X-Requested-With") == "fetch":
            return i18n.t(g.get("lang", i18n.DEFAULT_LANG), "scan_list_changed"), 409, {
                "Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("overview", notice="scan_list_changed"))

    # ---------- „Verifică din nou”: o scanare nouă (fișier încărcat sau deja existentă) și dovada înainte/după ----------

    def ensure_saved(scan: Scan) -> int:
        """Id-ul scanării în istoric; o salvează dacă încă nu e (aceeași pereche fișier + dată nu se dublează)."""
        db = app.config["DB_PATH"]
        found = storage.find_scan(scan.file, scan.started_at, db)
        return found if found is not None else storage.save_scan(scan, db)

    def folder_ref(scan: Scan) -> str:
        """Referința unei scanări din folder, după identitatea ei (fișier + dată), nu după poziția în listă."""
        return f"f:{scan.file}" + (f"|{scan.started_at}" if scan.started_at is not None else "")

    def newest_after(scan: Scan, scan_list: list[Scan]) -> tuple[str, Scan] | None:
        """Cea mai nouă scanare citibilă de după `scan`, ca referință: "f:<fișier>|<dată>" (din folder) sau
        "h<id>" (din istoric)."""
        if scan.started_at is None:
            return None
        found: list[tuple[int, str, Scan]] = []
        for s in scan_list:
            if s.status == "ok" and (s.started_at or 0) > scan.started_at:
                found.append((s.started_at, folder_ref(s), s))
        seen = {(s.file, s.started_at) for _, _, s in found}
        db = app.config["DB_PATH"]
        for item in storage.list_scans(db):
            if item.status == "ok" and (item.started_at or 0) > scan.started_at and (item.file, item.started_at) not in seen:
                saved = storage.get_scan(item.id, db)
                if saved is not None:
                    found.append((item.started_at, f"h{item.id}", saved))
        if not found:
            return None
        _, ref, newest = max(found, key=lambda t: t[0])
        return ref, newest

    def resolve_ref(ref: str, scan_list: list[Scan]) -> Scan | None:
        """Scanarea numită de o referință "f:<fișier>|<dată>" / "h<id>". Orice altceva: None."""
        ref = (ref or "")[:260]
        match = re.fullmatch(r"h(\d{1,9})", ref)
        if match:
            return storage.get_scan(int(match.group(1)), app.config["DB_PATH"])
        if not ref.startswith("f:"):
            return None
        name, sep, started = ref[2:].rpartition("|")
        if not sep or not started.isdigit():
            name, started = ref[2:], None
        idx = _find(scan_list, name, started)
        return scan_list[idx] if idx is not None else None
    def _form_scan() -> tuple[Scan, int]:
        """Scanarea pe care a văzut-o utilizatorul: după fișier (+ data), NICIODATĂ după poziția în listă (lista se
        poate schimba între afișare și clic, iar acțiunea ar ajunge pe altă scanare)."""
        if not hmac.compare_digest(request.form.get("token", ""), app.config["FORM_TOKEN"]):
            abort(400)
        name = request.form.get("file", "")[:200]
        if not name:
            abort(400)
        scan_list = scans()
        idx = _find(scan_list, name, request.form.get("started_at", "")[:20] or None)
        if idx is None:
            raise ScanGone()
        g.form_scans = scan_list   # pentru pasul următor după „Am făcut asta” (fără o a doua analiză a folderului)
        return scan_list[idx], idx

    def _form_key() -> tuple:
        port_raw = request.form.get("port", "")
        return (request.form.get("device_id", ""), int(port_raw) if port_raw.lstrip("-").isdigit() else None,
                request.form.get("code", ""))

    @app.post("/action/done")
    def action_done():
        """D5: „Am făcut asta” = verifică pasul pe date reale (verify.py). Portul închis -> verificat, iar scorul
        îl recalculează motorul. Portul încă deschis -> rămâne de făcut. Altfel: bifat, dar neconfirmat.
        Se bate la ușă doar pentru cea mai nouă scanare a NOASTRĂ (scans/), doar dacă pe IP e același dispozitiv și
        doar în hotspotul echipei; pentru fișiere analizate (Validation, Test Set, lab) nu se atinge rețeaua."""
        if not same_site_request():
            abort(403)
        scan, _ = _form_scan()
        key = _form_key()
        finding = next((f for f in scan.findings if f.key() == key), None)
        if finding is None:
            abort(400)
        db = app.config["DB_PATH"]
        probe_allowed = bool(app.config["OWN_SCAN_CHECK"](scan))
        same = getattr(app.config["LIVE"], "same_device", None)
        with _VERIFY_LOCK:
            net_check = app.config["NET_CHECK"]
            if net_check is verify.target_in_my_network:   # rețeaua citită în ultimele VERIFY_NET_MAX_AGE_S secunde
                net_check = lambda ip: verify.target_in_my_network(ip, detect=lambda: current_network(VERIFY_NET_MAX_AGE_S))  # noqa: E731
            result = verify.check_finding(scan, finding, app.config["PORT_PROBE"], net_check,
                                          probe_allowed=probe_allowed, same_device=same)
        if result.verified:   # portul e închis: toate problemele de pe acel port al dispozitivului au dispărut
            storage.mark_verified(scan, [f.key() for f in scan.findings
                                         if f.device_id == finding.device_id and f.port == finding.port], db)
        elif result.result not in (verify.STILL_OPEN, verify.STILL_OPEN_VERSION, verify.OTHER_NETWORK):
            storage.mark_done(scan, key, db)   # în altă rețea nu bifăm nimic: nu s-a verificat nimic
        number = [f.key() for f in action_plan(scan)].index(key) + 1
        if result.result in (verify.STILL_OPEN, verify.STILL_OPEN_VERSION, verify.OTHER_NETWORK):
            stay = {"step": number}
        else:
            # Mergem ÎNAINTE: primul pas încă de făcut DUPĂ cel bifat (apoi, circular, unul sărit mai devreme).
            # Înainte, pagina sărea înapoi la primul pas sărit, deși mesajul era despre pasul tocmai bifat.
            # Fără niciun pas rămas: fără `step`, ca pagina să arate „Ai trecut prin toți pașii”.
            sv = steps_view(scan, storage.done_keys(scan, db), storage.verified_keys(scan, db),
                            verified_by_newer(scan, newer_scans(scan, g.get("form_scans") or [scan])),
                            accepted=storage.accepted_keys(scan, db))
            todo = [s.number for s in sv.steps if s.status == "todo"] if sv else []
            nxt = next((n for n in todo if n > number), todo[0] if todo else None)
            stay = {"step": nxt} if nxt else {}
        return redirect(url_for("overview", **scan_ref(scan), checked=number, check=result.result, **stay)
                        + "#worst-h")

    @app.post("/action/accept")
    def action_accept():
        """„Accept riscul”: utilizatorul știe de ce e așa (e dispozitivul lui). Problema rămâne în raport și pe pagina
        dispozitivului, marcată ca acceptată; scorul NU se schimbă (e al motorului). Trecem la pasul următor."""
        if not same_site_request():
            abort(403)
        scan, _ = _form_scan()
        key = _form_key()
        if key not in {f.key() for f in scan.findings}:
            abort(400)
        storage.mark_accepted(scan, key, app.config["DB_PATH"])
        return redirect(url_for("overview", **scan_ref(scan)) + "#worst-h")

    @app.post("/scan/upload")
    def scan_upload():
        """„Verifică din nou” cu un fișier nmap XML nou: îl analizează motorul, ambele scanări intră în istoric și
        se arată dovada înainte/după. Fișierul nu e păstrat (doar rezultatul), iar fără rețea."""
        if not same_site_request():
            abort(403)
        request.max_content_length = MAX_BYTES + UPLOAD_SLACK   # doar pentru această cerere (restul rămân la 1 MB)
        before, _ = _form_scan()
        upload = request.files.get("scanfile")
        data = upload.read(MAX_BYTES + 1) if upload is not None else b""
        back = lambda code: redirect(url_for("overview", **scan_ref(before), upload_error=code) + "#recheck-h")  # noqa: E731
        if not data:
            return back("NO_FILE")
        # Același motor ca pentru fișierele din folder (analyze_file): defusedxml, limită de mărime, erori ca valori.
        # Fișierul stă doar cât durează analiza, într-un folder temporar, sub un nume curățat.
        name = secure_filename(upload.filename or "") or "scan.xml"
        if not name.lower().endswith(".xml"):
            name += ".xml"
        with tempfile.TemporaryDirectory(prefix="netscan-upload-") as tmp:
            path = Path(tmp) / name
            path.write_bytes(data)
            after = analyze_file(path)
        if after.status != "ok":
            return back(after.error_code or "INVALID_XML")
        if before.status == "ok" and None not in (before.started_at, after.started_at) \
                and after.started_at < before.started_at:
            return back("OLDER")
        before_id, after_id = ensure_saved(before), ensure_saved(after)
        return redirect(url_for("history_scan", scan_id=after_id, vs=before_id) + "#proof-h")

    @app.post("/compare")
    def compare_scans():
        """„Vezi înainte și după” pentru o scanare mai nouă care există deja (în folder sau în istoric)."""
        if not same_site_request():
            abort(403)
        before, _ = _form_scan()
        after = resolve_ref(request.form.get("after", ""), scans())
        if after is None or after.status != "ok" or before.status != "ok":
            abort(400)
        before_id, after_id = ensure_saved(before), ensure_saved(after)
        return redirect(url_for("history_scan", scan_id=after_id, vs=before_id) + "#proof-h")

    @app.post("/action/reset")
    def action_reset():
        """„Ia pașii de la capăt”: șterge bifele, confirmările și riscurile acceptate ale scanării, iar protecția
        live uită confirmările ei pentru această scanare (ca o reparație să poată fi confirmată din nou)."""
        if not same_site_request():
            abort(403)
        scan, _ = _form_scan()
        storage.reset_done(scan, app.config["DB_PATH"])
        forget = getattr(app.config["LIVE"], "forget", None)
        if forget is not None:
            forget(scan.file)
        return redirect(url_for("overview", **scan_ref(scan)) + "#worst-h")

    # ---------- protecția live (B): ce se întâmplă acum în hotspot ----------

    LIVE_MESSAGES = ("NOT_ON_HOTSPOT", "BUSY", "CONSENT_REQUIRED")

    def set_live_msg(code: str | None) -> None:
        live_msg_state["code"] = code if code in LIVE_MESSAGES else None
        live_msg_state["ts"] = time.time()

    def current_live_msg() -> str | None:
        """Mesajul panoului: cel salvat la ultima acțiune (cel mult LIVE_MSG_TTL_S secunde) sau ?live_msg=."""
        code, ts = live_msg_state.get("code"), live_msg_state.get("ts") or 0.0
        if code and time.time() - ts <= LIVE_MSG_TTL_S:
            return code
        arg = request.args.get("live_msg", "")
        return arg if arg in LIVE_MESSAGES else None

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
            if d.get("is_gateway"):
                name = i18n.t(lang, "live_gateway")
            elif d["in_scan"] and d["device_type"] and d["device_type"] != "unknown":
                name = i18n.device_type_label(lang, d["device_type"])
            elif d["vendor"]:
                name = i18n.t(lang, "live_device_by") % d["vendor"]
            elif d["private_mac"]:
                name = i18n.t(lang, "live_private")
            else:
                name = i18n.t(lang, "live_unknown_device")
            doors = [{"port": p["port"], **i18n.port_meaning(lang, p["port"], p["label"])} for p in d["open_ports"]]
            device_id = d.get("device_id")
            needs = bool(d.get("needs_approval"))
            devices.append({**d, "name": name, "since": clock(d["first_seen"]), "left": clock(d["last_seen"]),
                            "not_in_scan": bool(snap["known_file"]) and not d["in_scan"], "doors": doors,
                            "to_check": sum(1 for x in doors if x["check"]), "device_id": device_id,
                            "needs_approval": needs,
                            # butonul „Da, e al nostru” doar pentru un id real al motorului (nu „ip:…”)
                            "can_approve": needs and live_mod.valid_device_id(device_id)})
        events = [{"tone": e["tone"], "time": clock(e["ts"]), "text": e["text_en"] if en else e["text_ro"],
                   "kind": e["kind"]} for e in snap["events"][:12]]
        now = time.time()
        urgent = sum(1 for e in snap["events"]
                     if e.get("tone") == "urgent" and (e.get("ts") or 0) >= now - URGENT_WINDOW_S)
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
        status = snap["status"]
        active_scan = state in ("waiting_permission", "running", "waiting_next")
        ctx = {
            "status": status, "starting": status == "active" and not snap["baseline_done"],
            "reason": snap["reason_en"] if en else snap["reason_ro"], "ssid": snap["ssid"], "cidr": snap["cidr"],
            "own_ip": snap["own_ip"], "online": snap["online"], "devices": devices, "events": events,
            "last_check": clock(snap["last_sweep"]), "trap_state": snap["trap_state"],
            "trap_code": snap["trap_code"], "trap_port": snap["trap_port"], "known_file": snap["known_file"],
            "scan": scan_ctx,
            "gateway": snap.get("gateway"), "fixes": snap.get("fixes", 0),
            "poll_ms": 2000 if (status != "off" or active_scan) else 0,
            "latest": events[0]["text"] if events else "",
            "paused_for_scan": bool(snap.get("paused_for_scan")),
            "needs_approval": [{"device_id": d["device_id"], "ip": d["ip"], "name": d["name"]}
                               for d in devices if d["can_approve"]],
            "has_urgent": urgent,
            "trap_note": i18n.t(lang, "trap_note"),
            "trap_wanted": bool(getattr(mon, "trap_wanted", False)),
        }
        # Versiunea (pentru reîmprospătarea din app.js) nu include mesajul: altfel panoul s-ar înlocui doar pentru
        # că mesajul a expirat, iar utilizatorul și-ar pierde locul.
        ctx["version"] = hashlib.sha1(json.dumps(ctx, sort_keys=True, default=str).encode()).hexdigest()[:16]
        ctx["msg"] = current_live_msg()
        return ctx

    def _live_form() -> None:
        if not same_site_request():
            abort(403)
        if not hmac.compare_digest(request.form.get("token", ""), app.config["FORM_TOKEN"]):
            abort(400)

    def _live_back(msg: str | None = None):
        set_live_msg(msg)                      # rămâne vizibil LIVE_MSG_TTL_S secunde (sau până la acțiunea următoare)
        args = {"live_msg": msg} if msg else {}
        if request.headers.get("X-Requested-With") == "fetch":
            return redirect(url_for("live_panel", **args))
        return redirect(url_for("overview", **args) + "#live")

    def _consent_given() -> bool:
        """Consimțământul explicit (echivalentul lui --confirm din linia de comandă): căsuța bifată în formular."""
        return request.form.get("confirm") == "1"

    @app.get("/live/panel")
    def live_panel():
        """Doar panoul live (pentru reîmprospătarea din app.js)."""
        resp = app.make_response(render_template("_live_panel.html", live=live_ctx(),
                                                 token=app.config["FORM_TOKEN"]))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.post("/live/start")
    def live_start():
        """Pornește protecția live DOAR cu consimțământul bifat (confirm=1); altfel nu face nimic și cere bifa."""
        _live_form()
        if not _consent_given():
            return _live_back("CONSENT_REQUIRED")
        # Ușa-capcană: o bifă separată, nebifată implicit. Fără ea, protecția live nu ascultă pe niciun port.
        app.config["LIVE"].start(trap=request.form.get("trap") == "1")
        return _live_back()

    @app.post("/live/stop")
    def live_stop():
        _live_form()
        app.config["LIVE"].stop()
        return _live_back()

    @app.post("/live/scan")
    def live_scan():
        """Scanarea completă: pornește pasul de admin prin fereastra de permisiune a sistemului (elevate.py), doar
        cu consimțământul bifat (confirm=1)."""
        _live_form()
        job = request.form.get("job", "scan")
        if job not in live_mod.elevate.JOBS:
            abort(400)
        if not _consent_given():
            return _live_back("CONSENT_REQUIRED")
        code = app.config["LIVE"].request_full_scan(job)
        return _live_back(None if code == "OK" else code)

    @app.post("/live/approve")
    def live_approve():
        """„Da, e al nostru”: utilizatorul confirmă că un dispozitiv nou din hotspot e al echipei; abia apoi
        protecția live îi verifică porturile. Doar id-uri reale ale motorului (12 caractere hex)."""
        _live_form()
        device_id = request.form.get("device_id", "")[:64]
        if not live_mod.valid_device_id(device_id) or not app.config["LIVE"].approve(device_id):
            abort(400)
        return _live_back()

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
        scan, _ = _form_scan()
        db = app.config["DB_PATH"]
        scan_id = storage.find_scan(scan.file, scan.started_at, db)
        if scan_id is None:
            scan_id = storage.save_scan(scan, db)
        if request.headers.get("X-Requested-With") == "fetch":  # actualizare parțială: rămânem pe pagina principală
            return redirect(url_for("overview", **scan_ref(scan)))
        return redirect(url_for("history_scan", scan_id=scan_id))

    def progress_keys(scan: Scan | None, scan_list: list[Scan]) -> tuple[set, set]:
        """(problemele confirmate ca rezolvate, riscurile acceptate) pentru o scanare din listă."""
        if scan is None or scan.status != "ok" or not scan.findings:
            return set(), set()
        db = app.config["DB_PATH"]
        fixed = storage.verified_keys(scan, db) | set(verified_by_newer(scan, newer_scans(scan, scan_list)))
        return fixed, storage.accepted_keys(scan, db) - fixed

    @app.get("/devices")
    def inventory():
        """D4: „Ce e conectat la mine?”: toate dispozitivele, inclusiv cele fără probleme, după IP."""
        scan_list = scans()
        scan, idx = pick(scan_list)
        g.names = names_for(scan)
        g.router_ip = router_ip(scan)
        fixed, accepted = progress_keys(scan, scan_list)
        devices = sorted(rank_devices(scan), key=lambda d: ip_key(d.host.ip)) if scan and scan.status == "ok" else []
        return render_template("inventory.html", scan=scan, scan_list=scan_list, selected=idx, devices=devices,
                               fixed_keys=fixed, accepted_keys=accepted, scan_ref=scan_ref(scan), csv=csv_view(scan),
                               dev_ref={**scan_ref(scan), "from": "devices"})   # pagina dispozitivului știe că vii din „Dispozitive”

    @app.get("/device/<device_id>")
    def device(device_id: str):
        scan_list = scans()
        scan, idx = pick(scan_list)
        if scan is None:
            abort(404)
        g.names = names_for(scan)
        g.router_ip = router_ip(scan)
        view = next((d for d in rank_devices(scan) if d.host.device_id == device_id), None)
        if view is None:
            abort(404)
        fixed, accepted = progress_keys(scan, scan_list)
        # „Fă asta întâi”: numărul pasului ghidat (de pe Acasă) pentru prima problemă nerezolvată a dispozitivului
        plan = [f.key() for f in action_plan(scan)] if scan.status == "ok" else []
        first = next((f for f in view.findings if f.key() not in fixed), None)
        first_step = plan.index(first.key()) + 1 if first is not None and first.key() in plan else None
        # „Cuvinte noi”: termenii din glosar care apar în explicațiile și pașii afișați pe pagină
        shown = []
        for f in view.findings:
            ex = get_explanation(f.code, g.lang)
            shown += [ex.get("text") or "", *(ex.get("steps") or [])]
        name_status = request.args.get("name")
        return render_template("device.html", scan=scan, d=view, selected=idx, fixed_keys=fixed,
                               accepted_keys=accepted, scan_ref=scan_ref(scan), first_step=first_step,
                               first_finding=first, words=glossary_terms(" ".join(shown), g.lang),
                               token=app.config["FORM_TOKEN"],
                               name_status=name_status if name_status in ("saved", "cleared", "too_long") else None,
                               name_max=storage.DEVICE_NAME_MAX)

    @app.post("/device/<device_id>/name")
    def device_name_save(device_id: str):
        """Numele dat dispozitivului, salvat pe device_id. Gol = șterge numele. Prea lung = refuzat, nu tăiat."""
        if not same_site_request():
            abort(403)
        scan, _ = _form_scan()   # verifică și jetonul formularului; scanarea după fișier + dată
        if not any(h.device_id == device_id for h in scan.hosts):
            abort(404)             # nu salvăm nume pentru dispozitive care nu există în scanare
        db = app.config["DB_PATH"]
        raw = "" if request.form.get("action") == "clear" else request.form.get("name", "")
        try:
            saved = storage.set_device_name(device_id, raw, db)
        except ValueError:
            status = "too_long"
        else:
            status = "saved" if saved else "cleared"
        back = {"from": "devices"} if request.form.get("from") == "devices" else {}
        return redirect(url_for("device", device_id=device_id, **scan_ref(scan), name=status, **back) + "#name-h")

    @app.get("/trust")
    def trust():
        """„Ce știe SafeEel despre tine”: ce e salvat local, unde, cum sunt ascunse MAC-urile, limitele de siguranță
        și rețeaua de acum. Doar CITEȘTE: nu pornește nimic (nici protecția live, nici scanări) și nu trimite nimic
        în rețea; rețeaua e citită din setările calculatorului (current_network)."""
        db = app.config["DB_PATH"] or storage.db_path()
        counts = storage.stored_counts(db)
        events, _ran = extras.monitor_events(app.config["DB_PATH"])
        own_dir = Path(app.config["USER_SCANS_DIR"])
        try:
            raw = sum(1 for p in own_dir.glob("*.xml") if p.is_file())
        except OSError:
            raw = 0
        mac = counts.mac_example if counts.mac_example and MASKED_MAC.match(counts.mac_example) else None
        info = current_network()
        lang = g.lang
        net = None
        if info is not None:
            allowed = bool(getattr(info, "scan_allowed", False))
            status = getattr(info, "status", None)
            reason = live_mod.network.MESSAGES.get(status or "", ("", ""))[1 if lang == "en" else 0]
            net = {"allowed": allowed, "ssid": info.ssid, "cidr": info.cidr, "gateway": info.gateway,
                   "reason": reason}
        salt = (os.environ.get("NETSCAN_SALT") or "").strip()
        return render_template(
            "trust.html", counts=counts, n_alerts=sum(1 for e in events if e.kind != "TRAP"),
            n_trap=sum(1 for e in events if e.kind == "TRAP"), n_raw=raw, mac_example=mac,
            db_dir=str(Path(db).resolve().parent), scans_dir=str(own_dir.resolve()),
            own_salt=bool(salt) and salt != DEFAULT_SALT, net=net)

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
            # None = nu s-a cerut ștergerea scanărilor brute; True = șterse; False = nu s-au putut șterge
            deleted_raw={"1": True, "0": False}.get(request.args.get("raw", "")),
            owner=current_user(),   # al cui e istoricul; când e gol, poate fi alt utilizator sau alt folder
            db_file=str(Path(app.config["DB_PATH"] or storage.db_path()).resolve()),
        )

    def render_report(scan: Scan, back_url: str, fixed: set = frozenset(), accepted: set = frozenset(), compare=None,
                      prev: Scan | None = None):
        """FR-14: raportul de o pagină pentru furnizorul IT. Doar date din motor; MAC mascat. PDF = Tipărește.
        Problemele apar în aceeași ordine ca pașii de pe pagina Acasă (dispozitivul cel mai riscant primul, apoi
        problemele lui, cea mai gravă prima); `rows` le numerotează exact ca pașii."""
        devices = rank_devices(scan) if scan.status == "ok" else []
        counts = {sev: sum(1 for f in scan.findings if f.severity == sev) for sev in ("high", "medium", "low", "info")}
        rows = [{"n": i, "finding": f, "device": d.host,
                 "status": "fixed" if f.key() in fixed else "accepted" if f.key() in accepted else "todo"}
                for i, (d, f) in enumerate(((d, f) for d in devices for f in d.findings), 1)]
        return render_template(
            "report.html", scan=scan, devices=devices, counts=counts, generated=_fmt_time(int(time.time()), g.lang),
            rows=rows, fixed_keys=set(fixed), accepted_keys=set(accepted), csv=csv_view(scan),
            verdict=verdict_view(scan, fixed, accepted, g.lang) if scan.status == "ok" else None,
            score_std=scan.score if scan.status == "ok" else None, compare=compare,
            proof=proof_view(prev, scan, compare) if (compare is not None and prev is not None) else None,
            back_url=back_url, logo_src=url_for("static", filename="brand/safeeel-lockup-horizontal-light.svg"),
        )

    @app.get("/report")
    def report():
        scan_list = scans()
        scan, _ = pick(scan_list)
        if scan is None:
            abort(404)
        g.names = names_for(scan)
        fixed, accepted = progress_keys(scan, scan_list)
        return render_report(scan, url_for("overview", **scan_ref(scan)), fixed, accepted)

    @app.get("/scan/<int:scan_id>/report")
    def history_report(scan_id: int):
        db = app.config["DB_PATH"]
        scan = storage.get_scan(scan_id, db)
        if scan is None:
            abort(404)
        prev_id = storage.previous_scan_id(scan_id, db)
        prev = storage.get_scan(prev_id, db) if prev_id is not None else None
        compare = storage.diff(prev, scan) if prev is not None and scan.status == "ok" else None
        return render_report(scan, url_for("history_scan", scan_id=scan_id), compare=compare,
                             prev=prev if compare is not None else None)

    @app.get("/journal")
    def journal_page():
        g.monitor = extras.monitor_events(app.config["DB_PATH"])
        db = app.config["DB_PATH"]
        by_id = {s.id: s for s in storage.list_scans(db)}
        groups: list[dict] = []
        for a in journal(db):
            if not groups or groups[-1]["scan_id"] != a.scan_id:
                groups.append({"scan_id": a.scan_id, "scan": by_id.get(a.scan_id), "alerts": []})
            groups[-1]["alerts"].append(a)
        for grp in groups:   # porturile care sunt chiar portul unei probleme noi/rezolvate: pliate dedesubt
            grp["alerts"], grp["folded"] = fold_port_alerts(grp["alerts"])
        events, monitor_ran = g.monitor if "monitor" in g else extras.monitor_events(app.config["DB_PATH"])
        # Legătura spre pagina dispozitivului, dacă IP-ul apare în cea mai nouă scanare citibilă.
        scan_list, known = scans(), {}
        ok = [(i, s) for i, s in enumerate(scan_list) if s.status == "ok"]
        if ok:
            idx, latest = max(ok, key=lambda p: p[1].started_at or 0)
            known = {h.ip: (h.device_id, scan_ref(latest), h.device_type) for h in latest.hosts}
        return render_template("journal.html", groups=groups, events=events, monitor_ran=monitor_ran, known=known)

    @app.get("/history/delete")
    def history_delete_confirm():
        return render_template("history_delete.html", token=app.config["FORM_TOKEN"], delete_raw_default=True)

    @app.post("/history/delete")
    def history_delete():
        """NFR-02: șterge istoricul. Cu delete_raw=1 (bifat implicit în pagină) șterge și scanările brute din
        scans/ (*.xml, *.xml.part, .scan_progress.json; niciodată fixtures/). Protecția live își uită confirmările."""
        sent = request.form.get("token", "")
        if not hmac.compare_digest(sent, app.config["FORM_TOKEN"]):
            abort(400)
        if not same_site_request():
            abort(403)
        storage.delete_history(app.config["DB_PATH"])
        raw = None
        if request.form.get("delete_raw") == "1":
            try:
                storage.delete_raw_scans(app.config["USER_SCANS_DIR"])
                raw = 1
            except (OSError, ValueError):
                raw = 0
        forget = getattr(app.config["LIVE"], "forget", None)
        if forget is not None:
            forget()
        return redirect(url_for("history", deleted=1, raw=raw))

    @app.get("/scan/<int:scan_id>")
    def history_scan(scan_id: int):
        db = app.config["DB_PATH"]
        scan = storage.get_scan(scan_id, db)
        if scan is None:
            abort(404)
        # „Înainte”: cea cerută explicit (?vs=<id>, după „Verifică din nou”) sau ultima citibilă de dinainte
        prev = None
        vs = request.args.get("vs", type=int)
        if vs is not None and vs != scan_id:
            prev = storage.get_scan(vs, db)
            if prev is not None and prev.status != "ok":
                prev = None
        if prev is None:
            prev_id = storage.previous_scan_id(scan_id, db)
            prev = storage.get_scan(prev_id, db) if prev_id is not None else None
        compare = storage.diff(prev, scan) if prev is not None and scan.status == "ok" else None
        # Dovada: ce a dispărut de pe dispozitive văzute din nou (reparat) e separat de ce a dispărut pentru că
        # dispozitivul nu a mai fost văzut (nu înseamnă reparat). Fraza („Ai închis N uși”) numără doar reparatele.
        proof = proof_view(prev, scan, compare) if compare is not None else None
        door = proof_of(prev, scan, compare) if compare is not None else None
        proof_line = None
        if proof is not None and door is not None:
            proof_line = i18n.proof_sentence(g.lang, replace(door, resolved=[x["finding"] for x in proof["fixed"]]))
        alerts = alerts_between(prev, scan, scan_id=scan_id) if prev is not None and scan.status == "ok" else None
        # niciun dispozitiv comun = scanarea anterioară e din altă rețea: comparația nu spune mare lucru
        same_network = prev is None or bool(storage.match_devices(prev, scan))
        question = request.args.get("q", "")[:MAX_QUESTION_LEN] if same_site_request() else ""
        ip_of = {h.device_id: h.ip for h in (prev.hosts if prev else [])} | {h.device_id: h.ip for h in scan.hosts}
        ok = scan.status == "ok"
        worst = most_dangerous(scan)
        # „Deschide această verificare”: aceeași scanare pe Acasă, dacă e încă în folderul afișat
        live_copy = next((s for s in scans() if s.file == scan.file and s.started_at == scan.started_at), None)
        return render_template(
            "overview.html", scan=scan, scan_list=[], selected=0,
            scan_file_ref=scan_ref(live_copy) if live_copy is not None else None,
            devices=rank_devices(scan), worst=worst,
            summary=summary_sentence(scan, worst),
            score_std=scan.score if ok else None, score_now=scan.score if ok else None, score_now_differs=False,
            verdict=verdict_view(scan, set(), set(), g.lang) if ok else None, fixed_keys=set(), accepted_keys=set(),
            csv=csv_view(scan), proof=proof, proof_line=proof_line,
            history_id=scan_id, compare=compare, ip_of=ip_of, alerts=alerts, same_network=same_network,
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

    from netscan.ui.results import bp as results_bp   # „Rezultate pe tot folderul” (/results)
    app.register_blueprint(results_bp)
    return app


def _fmt_time(epoch: int | None, lang: str = "ro") -> str:
    """Data pe înțeles: „1 nov. 2026, 11:09” (RO) / „1 Nov 2026, 11:09” (EN)."""
    if epoch is None:
        return "—"
    d = datetime.fromtimestamp(epoch)
    return f"{d.day} {i18n.month_short(lang, d.month)} {d.year}, {d:%H:%M}"


def run(port: int = 5000) -> None:
    """Pornește UI-ul local. Doar 127.0.0.1, fără debug. Protecția live NU pornește singură: doar din butonul ei,
    cu consimțământul bifat."""
    app = create_app()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
