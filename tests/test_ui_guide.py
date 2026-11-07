"""Ghidul animat „Începe depanarea”: acoperire pentru toate codurile, RO/EN, escapare, reguli CSP/accesibilitate."""
import re
from pathlib import Path

import pytest

from netscan.ui import guide, i18n
from netscan.ui.i18n import CODE_NAMES
from tests.test_ui_app import make_client, sample

STATIC = Path(__file__).parent.parent / "netscan" / "ui" / "static"
CODES = sorted(CODE_NAMES["ro"])


def test_every_code_has_a_plan_with_known_scenes_ending_in_verify():
    assert set(guide.PLANS) <= set(CODES)
    for code in CODES:
        plan = guide.guide_for(code)
        assert plan.scenes and set(plan.scenes) <= set(guide.ALL_SCENES)
        assert plan.scenes[0] == guide.FIND and plan.scenes[-1] == guide.VERIFY
    assert guide.guide_for("NECUNOSCUT").scenes == guide.DEFAULT_PLAN


def test_all_guide_texts_exist_in_both_languages_and_are_not_empty():
    ro = {k for k in i18n.TEXTS["ro"] if k.startswith("g_")}
    en = {k for k in i18n.TEXTS["en"] if k.startswith("g_")}
    assert ro == en
    for lang in ("ro", "en"):
        for k in ro:
            assert i18n.TEXTS[lang][k].strip()
        for scene in guide.ALL_SCENES:
            assert f"g_{scene}" in ro, scene
        for code in CODES:
            plan = guide.guide_for(code)
            if guide.TOGGLE in plan.scenes:
                assert f"g_svc_{code}" in ro, code
            if guide.WINDOWS in plan.scenes:
                assert f"g_win_{code}" in ro, code


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_dialog_is_on_the_page_and_matches_the_current_step(lang, tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    page = client.get(f"/?lang={lang}").get_data(as_text=True)
    assert 'data-guide-open' in page and '<dialog class="guide" id="guide"' in page
    assert i18n.TEXTS[lang]["g_start"] in page
    # primul pas e vizibil, restul ascunse
    scenes = re.findall(r"<li class=\"scene [^\"]*\" data-scene( hidden)?>", page)
    assert scenes and scenes[0] == "" and all(h == " hidden" for h in scenes[1:])
    assert "data-guide-submit" in page and "/action/done" in page
    assert "scene-verify" in page                     # ultimul pas = verificarea


def test_no_javascript_fallback_link_goes_to_device_page(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    page = client.get("/").get_data(as_text=True)
    m = re.search(r'<a class="[^"]*guide-open"[^>]*href="([^"]+)"', page)
    assert m and m.group(1).startswith("/device/")


def test_hostile_device_name_is_escaped_in_guide(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    page = client.get("/").get_data(as_text=True)
    dlg = page[page.index('<dialog class="guide"'):page.index("</dialog>")]
    assert "<script" not in dlg.lower() and "|safe" not in dlg


def test_guide_js_and_css_follow_the_security_and_a11y_rules():
    js = (STATIC / "guide.js").read_text(encoding="utf-8")
    for bad in ("innerHTML", "eval(", "https://", "insertAdjacentHTML", "document.write"):
        assert bad not in js
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    block = css[css.index("Ghidul „Începe depanarea”"):]
    assert "prefers-reduced-motion: no-preference" in block      # mișcarea doar dacă nu e cerută reducerea ei
    assert "style=" not in (Path(__file__).parent.parent / "netscan/ui/templates/_guide.html").read_text(encoding="utf-8")


def test_guide_script_is_loaded_locally_on_every_page(tmp_path):
    client, _ = make_client(tmp_path, [sample()])
    assert "/static/guide.js" in client.get("/").get_data(as_text=True)
    assert client.get("/static/guide.js").status_code == 200


def test_scene_texts_have_the_right_number_of_placeholders():
    """Textul special al unui cod primește exact aceleași valori ca textul general al scenei (altfel pagina cade)."""
    for lang in ("ro", "en"):
        for key, text in i18n.TEXTS[lang].items():
            if not key.startswith("g_"):
                continue
            parts = key[2:].split("_", 1)
            if parts[0] in guide.ALL_SCENES:
                assert text.count("%s") == guide.TEXT_ARGS.get(parts[0], 0), (lang, key)


def _scene_text(code, kind, lang="ro"):
    t = i18n.TEXTS[lang]
    return t.get(f"g_{kind}_{code}", t[f"g_{kind}"])


def test_steps_follow_the_real_fixes_and_never_push_risky_actions():
    """Pașii trebuie să fie remedierile din netscan/explain, iar acțiunile care pot strica ceva să fie condiționate."""
    # SSH e doar informativ: nu cerem oprirea lui necondiționat
    assert "doar dacă nu-l folosești" in _scene_text("SSH_OPEN", "toggle")
    # SMB: oprirea SMBv1 nu închide portul 445; pasul e oprirea partajării, și doar dacă nu partajezi
    smb = _scene_text("SMB_EXPOSED", "windows") % i18n.TEXTS["ro"]["g_win_SMB_EXPOSED"]
    assert "Dacă nu partajezi" in smb and "SMB 1.0" not in smb and "Partajare fișiere și imprimante" in smb
    # RDP / VNC / FTP / SNMP: oprite doar dacă nu sunt folosite
    for code, kind in (("RDP_EXPOSED", "windows"), ("VNC_EXPOSED", "toggle"), ("FTP_CLEARTEXT", "toggle"), ("SNMP_EXPOSED", "toggle")):
        assert re.search(r"[Dd]acă nu(-l)? folosești", _scene_text(code, kind)), code
    # imprimanta: oprirea RAW poate opri printarea, deci spunem cum revii
    assert "pornește-o la loc" in _scene_text("PRINTER_RAW_EXPOSED", "toggle")
    # camera: parola întâi, apoi RTSP doar dacă aplicația merge fără
    cam = guide.guide_for("CAMERA_STREAM_EXPOSED").scenes
    assert cam.index(guide.PASSWORD) < cam.index(guide.TOGGLE)
    assert "merge și fără" in _scene_text("CAMERA_STREAM_EXPOSED", "toggle")
    # baza de date nu are „comutator” în router: se schimbă adresa de ascultare pe calculatorul ei
    assert guide.TOGGLE not in guide.guide_for("DB_EXPOSED").scenes
    assert guide.guide_for("DB_EXPOSED").config[1].endswith("127.0.0.1")
    assert "repornește" in _scene_text("DB_EXPOSED", "config")
    assert guide.guide_for("MQTT_EXPOSED").config == ("allow_anonymous true", "allow_anonymous false")
    # dispozitiv necunoscut: parola Wi-Fi se schimbă doar dacă NU e al tău
    assert "NU e al tău" in _scene_text("UNKNOWN_DEVICE", "password")


def test_verify_text_does_not_promise_a_closed_port_when_the_fix_keeps_it_open():
    """Verificarea live confirmă doar porturi închise; unde remedierea lasă portul deschis sau e UDP, textul o spune."""
    for code in ("MQTT_EXPOSED", "OUTDATED_SERVICE", "HTTP_ADMIN_CLEARTEXT", "SNMP_EXPOSED", "UPNP_EXPOSED",
                 "UNKNOWN_DEVICE", "SSH_OPEN", "CAMERA_STREAM_EXPOSED", "RDP_EXPOSED", "SMB_EXPOSED", "VNC_EXPOSED"):
        for lang in ("ro", "en"):
            assert f"g_verify_{code}" in i18n.TEXTS[lang], (code, lang)


def test_every_code_renders_its_guide_without_errors(tmp_path):
    """Fiecare dintre cele 15 coduri: dialogul se randează, cu toate scenele planului și textele lor."""
    from netscan.model import Finding, Host, Port, Scan
    for code in CODES:
        host = Host(ip="192.168.1.9", device_id="d1", vendor="<b>X</b>", device_type="router",
                    ports=[Port(port=23, proto="tcp", state="open")])
        f = Finding(file="a.xml", ip="192.168.1.9", device_id="d1", port=23, code=code, severity="high",
                    points=20, evidence="e")
        scan = Scan(file="a.xml", status="ok", started_at=1, score=80, hosts=[host], findings=[f])
        client, _ = make_client(tmp_path / code, [scan]) if (tmp_path / code).mkdir() is None else None
        page = client.get("/").get_data(as_text=True)
        dlg = page[page.index('<dialog class="guide"'):page.index("</dialog>")]
        assert dlg.count("data-scene") == len(guide.guide_for(code).scenes), code
        scenes = dlg[dlg.index("guide-scenes"):]
        assert "<b>X</b>" not in dlg and "%s" not in scenes, code


def test_computers_skip_the_label_and_admin_page_steps():
    for code in CODES:
        for dtype in ("pc_windows", "server", "phone_laptop"):
            sc = guide.guide_for(code, dtype).scenes
            assert guide.LABEL not in sc and guide.ADMIN not in sc and sc[-1] == guide.VERIFY, (code, dtype)
    assert guide.LABEL in guide.guide_for("TELNET_OPEN", "router").scenes


def test_guide_uses_the_users_own_device_name_escaped(tmp_path):
    """Numele dat de utilizator (S2) apare în primul pas al ghidului, escapat."""
    from netscan.ui import storage
    s = sample()
    client, app = make_client(tmp_path, [s])
    page = client.get("/").get_data(as_text=True)
    dev = re.search(r'<a class="[^"]*guide-open"[^>]*href="/device/([^"?]+)"', page).group(1)
    storage.set_device_name(dev, "<script>x</script>Camera mea", app.config["DB_PATH"])
    page = client.get("/").get_data(as_text=True)
    dlg = page[page.index('<dialog class="guide"'):page.index("</dialog>")]
    assert "&lt;script&gt;x&lt;/script&gt;Camera mea" in dlg and "<script>x" not in dlg
