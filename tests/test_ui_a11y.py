"""RBRT, NFR-08: pe ecran niciun text sub 16px. Verifică regulile CSS din afara @media print."""
import re
from pathlib import Path

STATIC = Path(__file__).parent.parent / "netscan" / "ui" / "static"


def _screen_rules(css: str) -> str:
    """Scoate blocurile @media print (pe hârtie textul poate fi mai mic, ca raportul să încapă pe o pagină)."""
    out, i = [], 0
    for m in re.finditer(r"@media\s+print\s*\{", css):
        out.append(css[i:m.start()])
        depth, j = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            j += 1
        i = j
    out.append(css[i:])
    return "".join(out)


def _too_small(value: str) -> bool:
    v = value.strip()
    if v.startswith("max("):          # max(1rem, ...) nu scade sub 16px
        return "1rem" not in v and "16px" not in v
    m = re.match(r"([\d.]+)(rem|em|px)$", v)
    if not m:
        return False
    n, unit = float(m.group(1)), m.group(2)
    return n < 16 if unit == "px" else n < 1


def test_no_screen_text_below_16px():
    bad = []
    for name in ("style.css", "report.css"):
        css = _screen_rules((STATIC / name).read_text(encoding="utf-8"))
        css = re.sub(r"@media\s*\(max-width[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}", "", css)  # pe telefon, graficul are mărimi proprii
        for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            for val in re.findall(r"font-size\s*:\s*([^;]+)", body):
                if _too_small(val) and ".trend-" not in sel:  # textul din grafic e scalat cu SVG-ul; verificat în browser
                    bad.append(f"{name}: {sel.strip()} -> {val.strip()}")
    assert bad == [], bad

# ---------- pagina Acasă calmă (WS-C): ordinea, un singur buton principal, fără coduri pe drumul principal ----------
import json as _json  # noqa: E402

from netscan.engine.parser import analyze_file  # noqa: E402
from netscan.model import Scan  # noqa: E402
from netscan.ui import storage  # noqa: E402
from netscan.ui.app import create_app  # noqa: E402

ROOT = Path(__file__).parent.parent
V2 = ROOT / "fixtures" / "validation" / "V2_smart_home.xml"
SAMPLE = ROOT / "fixtures" / "sample.json"
STYLE = (STATIC / "style.css").read_text(encoding="utf-8")


class _OffLive:
    """Protecția live oprită (fără rețea): doar ce trebuie pentru panou."""
    def snapshot(self):
        return {"status": "off", "devices": [], "events": [], "baseline_done": False, "reason_ro": "", "reason_en": "",
                "ssid": None, "cidr": None, "own_ip": None, "online": 0, "last_sweep": None, "trap_state": "off",
                "trap_code": None, "trap_port": None, "known_file": None}

    def full_scan_status(self):
        return {"state": "idle", "job": None, "percent": 0.0, "discovered": [], "phase": None, "eta_s": None}


def _client(tmp_path, scans, live=None):
    app = create_app({"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True,
                      "NET_CHECK": lambda ip: False, "LIVE": live or _OffLive()})
    return app.test_client(), app


def _main(html: str) -> str:
    return html[html.index("<main"):html.index("</main>")]


def _outside_details(html: str) -> str:
    return re.sub(r"<details\b.*?</details>", "", _main(html), flags=re.S)


def _home(tmp_path, lang="ro"):
    c, app = _client(tmp_path, [analyze_file(str(V2))])
    return c.get(f"/?lang={lang}").get_data(as_text=True)


def test_home_answer_comes_before_live_protection(tmp_path):
    html = _home(tmp_path)
    text = re.sub(r"<[^>]+>", " ", html)
    first_step = text.index("Fă asta întâi")
    assert text.index("Cel mai periculos") < text.index("Pornește protecția live")
    assert first_step < text.index("Pornește protecția live")
    assert html.index('id="verdict-h"') < html.index('id="score"') < html.index('id="worst"') < html.index('id="live"')


def test_home_has_one_primary_button_and_no_codes_on_the_main_path(tmp_path):
    html = _home(tmp_path)
    main = _outside_details(html)
    assert main.count("button-primary") == 1
    assert "CAMERA_STREAM_EXPOSED" in html                 # e în pagină (detalii tehnice + CSV)…
    visible = re.sub(r"<[^>]+>", " ", main)                 # textul văzut (fără câmpurile ascunse ale formularelor)
    assert "CAMERA_STREAM_EXPOSED" not in visible          # …dar doar în <details>
    assert "findings.csv" in html and "scores.csv" in html


def test_home_first_heading_is_h1_and_no_level_is_skipped(tmp_path):
    for lang in ("ro", "en"):
        html = _home(tmp_path, lang)
        levels = [int(n) for n in re.findall(r"<h([1-6])\b", html)]
        assert levels[0] == 1 and levels.count(1) == 1
        assert all(b - a <= 1 for a, b in zip(levels, levels[1:])), levels


def test_big_number_is_the_engine_score_and_severity_has_words(tmp_path):
    scan = analyze_file(str(V2))
    html = _home(tmp_path)
    assert f'<span class="score-num">{scan.score}</span>' in html
    assert "Risc ridicat" in html and "#i-high" in html    # pictogramă + cuvânt, nu doar culoare
    assert "Detalii despre scor" in html


def test_live_panel_off_is_compact_with_required_consent(tmp_path):
    html = _home(tmp_path)
    live = _main(html)[_main(html).index('id="live"'):]
    assert live.count('name="confirm" value="1" required') == 2    # pornirea + formularul de scanare
    assert 'name="job" value="scan"' in live and 'name="job" value="auto"' in live
    assert "button-primary" not in live
    assert 'role="status"' not in live                              # anunțurile le face #live-announce
    assert '<div class="live-scan' not in live and 'aria-labelledby="scan-h"' in live


def test_status_messages_can_take_focus(tmp_path):
    c, app = _client(tmp_path, [Scan.from_dict(_json.loads(SAMPLE.read_text(encoding="utf-8")))])
    token = app.config["FORM_TOKEN"]
    scan = Scan.from_dict(_json.loads(SAMPLE.read_text(encoding="utf-8")))
    c.post("/history/save", data={"token": token, "file": scan.file, "started_at": scan.started_at},
           headers={"X-Requested-With": "fetch"})
    html = c.get("/").get_data(as_text=True)
    assert re.search(r'<p class="saved" role="status" tabindex="-1">', html)
    page = c.get("/?checked=1&check=file_only").get_data(as_text=True)
    assert re.search(r'<p class="verify-msg[^"]*" role="status" tabindex="-1">', page)


def test_history_chart_is_a_group_and_rows_newest_first(tmp_path):
    c, app = _client(tmp_path, [])
    db = app.config["DB_PATH"]
    a = Scan.from_dict(_json.loads(SAMPLE.read_text(encoding="utf-8")))
    b = Scan.from_dict(_json.loads(SAMPLE.read_text(encoding="utf-8")))
    b.started_at = (a.started_at or 0) + 3600
    storage.save_scan(a, db)
    b_id = storage.save_scan(b, db)
    html = c.get("/history").get_data(as_text=True)
    assert 'role="img"' not in html and 'class="trend-chart"' in html and 'role="group"' in html
    rows = re.findall(r'href="/scan/(\d+)" title=', html)
    assert rows[0] == str(b_id)
    assert c.get(f"/scan/{b_id}").get_data(as_text=True).count("<h1") == 1


def test_journal_empty_state_has_no_cli_command(tmp_path):
    c, _ = _client(tmp_path, [])
    html = c.get("/journal").get_data(as_text=True)
    assert "python -m netscan" not in html
    assert re.search(r"<h3 class=\"empty-title\">", html)


def test_device_page_summary_jump_list_and_technical_details(tmp_path):
    scan = analyze_file(str(ROOT / "fixtures" / "lab" / "scan_01_before.xml"))
    c, _ = _client(tmp_path, [scan])
    worst = max({f.device_id for f in scan.findings}, key=lambda d: sum(f.points for f in scan.findings if f.device_id == d))
    html = c.get(f"/device/{worst}").get_data(as_text=True)
    assert "Probleme:" in html and "Fă asta întâi" in html and '<details class="problem card"' in html
    main = _outside_details(html)
    for f in scan.findings:
        if f.device_id == worst:
            assert f.code not in main                         # codul catalogului doar „Pentru tehnician”
    assert "Pentru tehnician" in html


def test_report_has_legend_and_severity_words(tmp_path):
    c, _ = _client(tmp_path, [analyze_file(str(V2))])
    html = c.get("/report").get_data(as_text=True)
    assert "Ce înseamnă etichetele" in html and "Risc ridicat" in html and "Doar de știut" in html


def test_css_contrast_targets_and_reduced_motion():
    assert "--line-strong: #7D8A9C" in STYLE
    assert ".chat-suggest button { min-height: 2.75rem" in STYLE
    assert ".row-links a, .rt-name a, .scan-line a" in STYLE and "min-height: 2.75rem" in STYLE
    assert "prefers-reduced-motion: reduce" in STYLE
    assert ".verify-msg:focus-visible" in STYLE and ".saved:focus-visible" in STYLE
    assert "border-bottom: 2px solid var(--ink)" not in STYLE        # fără linii groase de formular


def test_app_js_guards_live_poll_and_keyboard_picker():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "liveSeq" in js and "seq === liveSeq" in js
    assert "keyboardPick" in js and "pointerdown" in js
    assert "#live-h" in js and "#step-now" in js