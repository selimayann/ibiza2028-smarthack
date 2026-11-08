"""WS-D: glosarul afișat în UI („Cuvinte noi”) și vocabularul unic de severitate."""
from __future__ import annotations

import pytest

from netscan.explain import LANGS, get_explanation, get_glossary, get_glossary_terms_for
from netscan.explain.plain import jargon_in, sentences
from netscan.scan.ai_check import CATALOG


def _terms(text, lang):
    return [d["term"] for d in get_glossary_terms_for(text, lang)]


def test_finds_terms_by_name_stem_and_alias():
    assert _terms("Actualizează firmware-ul routerului.", "ro") == ["Firmware", "Router"]
    assert "Criptare" in _terms("Pornește criptarea conexiunilor.", "ro")      # rădăcina „cript” din plain.JARGON
    assert "Adresă IP" in _terms("Caută IP-ul în listă.", "ro")
    assert "VPN" in _terms("Use a VPN (an encrypted tunnel).", "en")
    assert _terms("", "ro") == [] and _terms("Pisica doarme.", "ro") == []


def test_short_stems_are_whole_words_only():
    assert "Adresă IP" not in _terms("Ipoteza e greșită.", "ro")
    assert "TLS" not in _terms("Atlas", "en")


def test_case_and_diacritics_do_not_matter():
    assert _terms("REȚEA PENTRU OASPEȚI", "ro") == _terms("retea pentru oaspeti", "ro") == ["Rețea pentru oaspeți"]


@pytest.mark.parametrize("lang", LANGS)
def test_same_shape_as_get_glossary_and_no_duplicates(lang):
    full = {d["term"]: d["definition"] for d in get_glossary(lang)}
    found = get_glossary_terms_for("SSH SSH, firewall, port, porturi", lang)
    assert len({d["term"] for d in found}) == len(found)
    assert all(full[d["term"]] == d["definition"] for d in found)


@pytest.mark.parametrize("code", sorted(CATALOG))
@pytest.mark.parametrize("lang", LANGS)
def test_every_jargon_word_in_an_explanation_gets_a_definition(code, lang):
    """FR-07 vizibil: fiecare termen tehnic din explicație și pași apare în lista „Cuvinte noi” de sub ea."""
    e = get_explanation(code, lang)
    text = " ".join([e["text"], *e["steps"]])
    shown = {d["term"].lower() for d in get_glossary_terms_for(text, lang)}
    assert shown, code
    for s in sentences(text):
        assert jargon_in(s, lang) == []                    # restul e explicat chiar în frază


def test_severity_definition_uses_the_ui_words():
    ro = {d["term"]: d["definition"] for d in get_glossary("ro")}["Severitate"]
    en = {d["term"]: d["definition"] for d in get_glossary("en")}["Severity"]
    assert "risc ridicat" in ro and "doar de știut" in ro
    assert "high risk" in en and "just so you know" in en
