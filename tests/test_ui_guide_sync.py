"""Regresii pe „Acasă”: ghidul animat urmează pasul afișat, iar „Am făcut asta, verifică” merge înainte.

Bugurile (văzute în browser, cu JavaScript):
- după „Sar peste acum” / „Am făcut asta” (actualizare parțială a lui #worst), <dialog id="guide"> rămânea cel al
  pasului vechi: animația era pentru altă problemă, iar „Am făcut asta, verifică” din ghid bifa ALT pas; butonul lui
  rămânea apoi blocat pe „Verific…”;
- dacă pagina se încărcase fără ghid (toți pașii bifați), după „Revezi pașii” primul clic pe „Arată-mi cum, pas cu
  pas” ducea la pagina dispozitivului, în loc să deschidă animația;
- după „Am făcut asta” pe pasul 2 (cu pasul 1 sărit), pagina sărea ÎNAPOI la pasul 1.
Partea de server se testează aici; partea din browser e în app.js (syncGuide), verificată cu Chrome headless.
"""
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from netscan.ui import storage
from netscan.ui.view import action_plan
from tests.test_ui_app import sample
from tests.test_ui_steps import client_for, tick

STATIC = Path(__file__).parent.parent / "netscan" / "ui" / "static"


def _slot(page: str) -> str:
    """Conținutul lui #guide-slot (locul stabil al ghidului, înlocuit de app.js împreună cu #worst)."""
    start = page.index('<div id="guide-slot">')
    return page[start:page.index("<footer", start)]


def _step_key(page: str) -> str:
    """Cheia pasului afișat în #worst (formularul „Am făcut asta, verifică” al pasului)."""
    worst = page[page.index('id="worst"'):]
    form = worst[worst.index('action="/action/done"'):]
    get = lambda n: re.search(rf'name="{n}" value="([^"]*)"', form).group(1)  # noqa: E731
    return f"{get('device_id')}|{get('port')}|{get('code')}"


def test_guide_lives_in_a_stable_slot_and_belongs_to_the_shown_step(tmp_path):
    client, _ = client_for(tmp_path, [sample()], net=False)
    for url in ("/", "/?step=2", "/?step=4"):
        page = client.get(url).get_data(as_text=True)
        slot = _slot(page)
        key = re.search(r'<dialog class="guide" id="guide"[^>]*data-key="([^"]+)"', slot).group(1)
        assert key == _step_key(page), url
        # și formularul de verificare din ghid trimite exact pasul afișat
        guide_form = slot[slot.index("data-guide-submit"):]
        code = re.search(r'name="code" value="([^"]+)"', guide_form).group(1)
        assert key.endswith("|" + code)


def test_slot_exists_even_without_a_guide_so_a_partial_update_can_fill_it(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], net=True, own=False)   # fișier analizat: bifat, neconfirmat
    for f in action_plan(s):
        tick(client, app, f)
    page = client.get("/").get_data(as_text=True)
    assert "do-first-done" in page and '<div id="guide-slot">' in page and 'id="guide"' not in page
    # „Revezi pașii” (step=1): răspunsul are ghidul în același loc, pe care app.js îl pune în pagină
    page = client.get("/?step=1").get_data(as_text=True)
    assert 'data-guide-open' in page and '<dialog class="guide" id="guide"' in _slot(page)


def test_done_moves_forward_not_back_to_a_skipped_step(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], net=True, own=False)   # fișier analizat: doar bifat, nu confirmat (pe altă rețea pasul rămâne, vezi PR #8)
    plan = action_plan(s)
    # pasul 1 sărit, pasul 2 bifat -> pasul 3 (nu înapoi la 1)
    loc = tick(client, app, plan[1]).headers["Location"]
    assert "checked=2" in loc and "step=3" in loc
    page = client.get(loc).get_data(as_text=True)
    assert "Pasul 3 din 5" in page and _step_key(page).endswith("|" + plan[2].code)
    # ultimul pas bifat -> circular, primul rămas de făcut (pasul 1, cel sărit)
    for f in plan[2:]:
        loc = tick(client, app, f).headers["Location"]
    assert "step=1" in loc
    # nimic rămas: fără `step`, ca pagina să spună că ai trecut prin toți pașii
    loc = tick(client, app, plan[0]).headers["Location"]
    assert "step" not in parse_qs(urlparse(loc).query)
    assert "do-first-done" in client.get(loc).get_data(as_text=True)
    assert storage.done_keys(s, app.config["DB_PATH"]) == {f.key() for f in plan}


def test_done_on_analysed_file_does_not_change_the_score(tmp_path):
    s = sample()
    client, app = client_for(tmp_path, [s], net=True, own=False)   # fișier analizat: nu se atinge rețeaua
    loc = tick(client, app, action_plan(s)[0]).headers["Location"]
    assert "check=file_only" in loc and "step=2" in loc
    page = client.get(loc).get_data(as_text=True)
    assert f'<span class="score-num">{s.score}</span>' in page and "Pasul 2 din 5" in page


def test_app_js_keeps_the_guide_in_sync_with_partial_updates():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    sync = js[js.index("const syncGuide"):js.index("async function swap")]
    assert 'getElementById("guide-slot")' in sync and "replaceWith" in sync and "dataset.key" in sync
    assert 'syncGuide(doc)' in js[js.index("async function swap"):]
    guide = (STATIC / "guide.js").read_text(encoding="utf-8")
    assert "if (dlg.open) dlg.close();" in guide           # showModal() pe un dialog deschis ar arunca eroare
    for bad in ("innerHTML", "eval(", "insertAdjacentHTML", "document.write"):
        assert bad not in js and bad not in guide
