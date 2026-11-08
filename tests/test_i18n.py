"""WS-D: textele UI pe înțeles (netscan/ui/i18n.py). Paritate RO/EN, aceleași „%s”, vocabular unic, plural corect."""
from __future__ import annotations

import re

import pytest

from netscan.scan.ai_check import CATALOG
from netscan.ui import i18n

NEW_KEYS = [
    "verdict_poor", "verdict_fair", "verdict_good", "verdict_clean", "verdict_counts_lead", "verdict_worst",
    "verdict_first", "score_label", "score_after_line", "how_score", "details_tech", "more_options",
    "for_technician", "csv_view_title", "about_check", "consent_live", "consent_scan", "live_msg_CONSENT_REQUIRED",
    "scan_list_changed", "live_needs_approval", "approve_btn", "unknown_btn", "live_paused_for_scan",
    "live_section_off", "verify_file_only", "verify_other_device", "receipt_ok", "proof_headline",
    "proof_headline_same", "proof_headline_down", "proof_fixed", "proof_not_seen", "proof_still", "proof_new",
    "proof_limits_title", "proof_limits_body", "delete_raw_label", "delete_raw_done", "trap_note",
    "sev_csv_high", "sev_csv_medium", "sev_csv_low", "sev_csv_info", "new_words", "harm_label",
]

# Cheile folosite în template-uri și cod cu un număr fix de argumente (app.py, overview.html, …).
PLACEHOLDERS = {
    "verdict_part_high": 1, "verdict_part_medium": 1, "verdict_part_low": 1, "verdict_only_info": 1,
    "verdict_worst": 1, "score_after_line": 1, "verify_other_device": 1, "receipt_ok": 3,
    "proof_headline": 4, "proof_headline_same": 3, "proof_headline_down": 4, "proof_fixed": 1,
    "proof_not_seen": 1, "proof_still": 1, "proof_new": 1, "verify_ok": 2, "steps_tally": 3,
    "steps_all_done_hint": 2, "risk_points": 1, "inv_summary": 3, "inv_summary_short": 2, "j_bad": 1, "j_good": 1,
    "j_info": 1, "score_after": 2, "verify_udp": 2, "verify_noanswer": 2, "verify_network": 1, "verify_noport": 1,
}


def test_ro_and_en_have_the_same_keys():
    assert set(i18n.TEXTS["ro"]) == set(i18n.TEXTS["en"])
    for table in (i18n.ERROR_MESSAGES, i18n.DEVICE_TYPES, i18n.CODE_NAMES, i18n.ALERT_TEXTS):
        assert set(table["ro"]) == set(table["en"])


def test_same_placeholders_in_both_languages():
    for key, ro in i18n.TEXTS["ro"].items():
        en = i18n.TEXTS["en"][key]
        assert ro.count("%s") == en.count("%s"), key
        assert re.findall(r"\{\w+\}", ro) == re.findall(r"\{\w+\}", en), key


@pytest.mark.parametrize("key, n", sorted(PLACEHOLDERS.items()))
def test_placeholder_count_used_by_the_code(key, n):
    for lang in i18n.LANGS:
        text = i18n.t(lang, key)
        assert text.count("%s") == n, (lang, key)
        text % tuple(["x"] * n)                           # se poate formata, fără alte „%” rătăcite


@pytest.mark.parametrize("key", NEW_KEYS)
def test_new_keys_exist_in_both_languages(key):
    assert i18n.TEXTS["ro"][key].strip() and i18n.TEXTS["en"][key].strip()


def test_exact_texts_asked_for():
    ro = i18n.TEXTS["ro"]
    assert ro["verdict_poor"] == "Rețeaua ta are nevoie de atenție."
    assert i18n.verdict_counts_text("ro", 1, 1, 1) ==         "Probleme găsite: 1 cu risc ridicat, 1 cu risc mediu și 1 cu risc scăzut."
    assert ro["score_label"] == "Scorul rețelei (standard)"
    assert ro["consent_live"] == ("Confirm că în hotspot sunt doar dispozitivele noastre și că avem voie "
                                  "să le verificăm.")
    assert ro["approve_btn"] == "Da, e al nostru" and ro["unknown_btn"] == "Nu-l cunosc"
    assert ro["proof_limits_title"] == "Ce NU dovedește această pagină"


def test_navigation_names():
    assert [i18n.t("ro", k) for k in ("nav_overview", "nav_devices", "nav_journal", "nav_history")] == \
        ["Acasă", "Dispozitive", "Alerte", "Progres"]
    assert [i18n.t("en", k) for k in ("nav_overview", "nav_devices", "nav_journal", "nav_history")] == \
        ["Home", "Devices", "Alerts", "Progress"]


@pytest.mark.parametrize("lang", i18n.LANGS)
def test_no_dashboard_or_rezumat_anywhere(lang):
    for key, text in i18n.TEXTS[lang].items():
        assert "Dashboard" not in text and "Rezumat" not in text, key


def test_one_severity_vocabulary_and_csv_values():
    assert [i18n.t("ro", f"sev_{s}") for s in ("high", "medium", "low", "info")] == \
        ["Risc ridicat", "Risc mediu", "Risc scăzut", "Doar de știut"]
    assert [i18n.t("en", f"sev_{s}") for s in ("high", "medium", "low", "info")] == \
        ["High risk", "Medium risk", "Low risk", "Just so you know"]
    for lang in i18n.LANGS:
        assert [i18n.t(lang, f"sev_csv_{s}") for s in ("high", "medium", "low", "info")] == \
            ["high", "medium", "low", "info"]


@pytest.mark.parametrize("lang", i18n.LANGS)
def test_code_names_cover_the_catalog_short_with_plain_words(lang):
    names = i18n.CODE_NAMES[lang]
    assert set(names) == set(CATALOG)
    for code, name in names.items():
        assert len(name) <= i18n.CODE_NAME_MAX, (code, name)
        assert code not in name and "expus" not in name.lower() and "exposed" not in name.lower()
        # acronimul, dacă există, stă doar între paranteze, după numele simplu
        outside = re.sub(r"\([^)]*\)", "", name)
        assert not re.search(r"\b[A-Z]{3,}\b", outside), (code, name)
    assert i18n.code_name(lang, "NU_EXISTA") == "NU_EXISTA"


def test_code_names_examples():
    assert i18n.code_name("ro", "TELNET_OPEN") == "Intrare veche, fără lacăt (Telnet)"
    assert i18n.code_name("en", "TELNET_OPEN") == "Old login without a lock (Telnet)"
    assert i18n.code_name("ro", "DB_EXPOSED") == "Bază de date deschisă în rețea"


@pytest.mark.parametrize("n, ro", [(0, "0 puncte"), (1, "1 punct"), (2, "2 puncte"), (19, "19 puncte"),
                                   (20, "20 de puncte"), (40, "40 de puncte"), (100, "100 de puncte"),
                                   (101, "101 puncte"), (119, "119 puncte"), (120, "120 de puncte")])
def test_count_words_romanian_de(n, ro):
    assert i18n.count_words("ro", n, "punct", "puncte") == ro


def test_count_words_english():
    assert i18n.count_words("en", 1, "point", "points") == "1 point"
    assert i18n.count_words("en", 40, "point", "points") == "40 points"


def test_count_phrase_uses_singular_key_and_de():
    assert i18n.count_phrase("ro", 1, "risk_points_one", "risk_points_many") == "1 punct de risc"
    assert i18n.count_phrase("ro", 5, "risk_points_one", "risk_points_many") == "5 puncte de risc"
    assert i18n.count_phrase("ro", 40, "risk_points_one", "risk_points_many") == "40 de puncte de risc"
    assert i18n.count_phrase("en", 40, "risk_points_one", "risk_points_many") == "40 risk points"
    # o cheie cu eticheta înainte („Puncte de risc: %s”) nu primește „de”
    assert i18n.count_phrase("ro", 40, "risk_points_one", "risk_points") == "Puncte de risc: 40"


@pytest.mark.parametrize("lang", i18n.LANGS)
def test_count_texts_need_no_plural_agreement(lang):
    """Textele cu un număr variabil pun eticheta înainte, ca să nu existe „40 puncte” sau „1 verificați”."""
    for key in ("risk_points", "steps_tally", "j_bad", "j_good", "j_info", "inv_summary", "inv_summary_short"):
        assert not i18n.t(lang, key).startswith("%s"), key
    assert i18n.t("ro", "risk_points") % 40 == "Puncte de risc: 40"


def test_receipt_texts_are_plain_and_honest():
    assert i18n.t("ro", "verify_ok") % (554, "192.168.1.40") == (
        "Dovadă: am bătut o singură dată la ușa 554 de pe 192.168.1.40 și nu a răspuns nimeni, deci pasul e "
        "confirmat. (1 conexiune, nimic altceva trimis.)")
    assert "1 connection, nothing else sent" in i18n.t("en", "receipt_ok")
    for lang in i18n.LANGS:                                # scurte și fără jargon
        assert len(i18n.t(lang, "verify_note")) <= 140 and "UDP" not in i18n.t(lang, "verify_note")
        assert len(i18n.t(lang, "steps_all_done_hint")) <= 80


@pytest.mark.parametrize("lang", i18n.LANGS)
def test_no_unexplained_tech_in_main_texts(lang):
    texts = i18n.TEXTS[lang]
    assert "127.0.0.1" not in texts["footer_local"]
    assert "IEEE" not in texts["vendor_ieee"] and "nmap" not in texts["scan_hint"]
    assert "TCP" not in texts["scan_phase_tcp"]
    assert "Dashboard" not in texts["scan_hint"]
