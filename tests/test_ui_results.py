"""„Toate verificările”: pentru fiecare verificare, același verdict ca pe Acasă (din motor) + CSV-urile motorului."""
from dataclasses import replace

from netscan.engine import analyze_folder
from netscan.ui.app import VALIDATION_DIR, create_app
from netscan.ui.results import check_cards, summary_text

XSS = "<script>alert(1)</script>"


def _client(tmp_path, scans):
    app = create_app({"SCAN_LOADER": lambda: scans, "DB_PATH": tmp_path / "h.db", "TESTING": True})
    return app.test_client()


def test_cards_answer_the_home_question_for_every_check():
    cards = {c["file"]: c for c in check_cards(analyze_folder(VALIDATION_DIR))}
    v2 = cards["V2_smart_home.xml"]
    assert (v2["score"], v2["band"]) == (40, "poor") and v2["verdict"] == "Rețeaua ta are nevoie de atenție."
    assert v2["worst_name"] == "Cameră" and v2["first_step"]
    assert cards["V6b_after.xml"]["verdict"] == "Nu am găsit probleme în rețeaua ta."
    assert not cards["V7_broken.xml"]["ok"]


def test_summary_sentence():
    text = summary_text(check_cards(analyze_folder(VALIDATION_DIR)))
    assert text.startswith("Ai 8 verificări:") and "nu s-au putut citi" in text


def test_page_and_csv_download(tmp_path):
    c = _client(tmp_path, analyze_folder(VALIDATION_DIR))
    html = c.get("/results").get_data(as_text=True)
    assert "Toate verificările" in html and html.count('class="check-card') == 8
    assert "file=V2_smart_home.xml" in html and "Fișierul nu a putut fi citit." in html
    for name in ("findings", "scores"):
        resp = c.get(f"/results/{name}.csv")
        assert resp.status_code == 200 and resp.data == (VALIDATION_DIR / f"expected_{name}.csv").read_bytes()
    assert c.get("/results/x.csv").status_code == 404
    assert "All checks" in c.get("/results?lang=en").get_data(as_text=True)


def test_untrusted_file_names_are_escaped(tmp_path):
    scans = analyze_folder(VALIDATION_DIR)
    scans[0] = replace(scans[0], file=XSS)
    html = _client(tmp_path, scans).get("/results").get_data(as_text=True)
    assert XSS not in html and "&lt;script&gt;" in html
