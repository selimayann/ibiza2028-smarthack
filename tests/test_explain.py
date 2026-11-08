"""Teste pentru explicațiile predefinite RO/EN (Oneata)."""

from __future__ import annotations

import re

import pytest

from netscan.explain import LANGS, fallback_text, get_explanation, get_glossary
from netscan.explain.templates_en import TEMPLATES as EN
from netscan.explain.templates_ro import TEMPLATES as RO
from netscan.model import Scan
from netscan.scan.ai_check import CATALOG, check_llm_text
from netscan.ui.explain_stub import get_explanation as ui_get_explanation

CASES = [(code, lang) for code in sorted(CATALOG) for lang in LANGS]


def _sentences(text: str) -> int:
    return len([s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s])


def test_both_languages_cover_exactly_the_catalog():
    assert set(RO) == set(CATALOG)
    assert set(EN) == set(CATALOG)


@pytest.mark.parametrize("code,lang", CASES)
def test_shape(code, lang):
    e = get_explanation(code, lang)
    assert set(e) == {"text", "steps"}
    assert isinstance(e["text"], str) and e["text"].strip()
    assert 1 <= len(e["steps"]) <= 5
    assert all(isinstance(s, str) and s.strip() for s in e["steps"])


@pytest.mark.parametrize("code,lang", CASES)
def test_max_two_sentences(code, lang):
    assert _sentences(get_explanation(code, lang)["text"]) <= 2


@pytest.mark.parametrize("code,lang", CASES)
def test_fallback_passes_ai_check_on_any_scan(code, lang):
    # Textul predefinit nu are voie să pomenească porturi, IP-uri, coduri, CVE-uri, MAC-uri sau linkuri
    # care nu sunt în scanare: verificat pe o scanare goală, deci nu pomenește niciunul.
    empty = Scan(file="x.xml", status="ok")
    result = check_llm_text(fallback_text(code, lang), empty)
    assert result.ok, result.problems


@pytest.mark.parametrize("code,lang", CASES)
def test_no_digits_that_look_like_ports(code, lang):
    e = get_explanation(code, lang)
    for s in [e["text"], *e["steps"]]:
        assert not re.search(r"\b\d{2,5}\b", s), s


def test_ro_and_en_have_same_number_of_steps():
    for code in CATALOG:
        assert len(RO[code]["steps"]) == len(EN[code]["steps"]), code


def test_unknown_code_and_lang_fall_back():
    e = get_explanation("NOT_A_CODE", "ro")
    assert e["text"] and e["steps"]
    assert get_explanation("TELNET_OPEN", "de") == get_explanation("TELNET_OPEN", "ro")
    assert get_explanation("TELNET_OPEN", "EN") == get_explanation("TELNET_OPEN", "en")


def test_returned_steps_are_a_copy():
    get_explanation("SSH_OPEN", "ro")["steps"].append("x")
    assert "x" not in get_explanation("SSH_OPEN", "ro")["steps"]


def test_ui_uses_real_explanations_not_stub():
    assert ui_get_explanation("MQTT_EXPOSED", "ro") == get_explanation("MQTT_EXPOSED", "ro")


def test_vnc_ro_states_the_same_fact_as_en():
    """VNC arată ecranul ACESTUI dispozitiv altcuiva (nu ecranul altcuiva)."""
    assert RO["VNC_EXPOSED"]["text"].startswith("VNC îi arată altcuiva din rețea ecranul acestui dispozitiv")
    assert "altcuiva din rețea și" not in RO["VNC_EXPOSED"]["text"]


def test_unknown_device_matches_catalog_rule_no_maker_and_no_name():
    assert "nici numele, nici producătorul" in RO["UNKNOWN_DEVICE"]["text"]
    assert "servicii deschise" not in RO["UNKNOWN_DEVICE"]["text"]


@pytest.mark.parametrize("lang", LANGS)
def test_steps_are_doable_without_admin_jargon(lang):
    """Pași pe care îi poate face un părinte: fără „adresa locală”, „community strings”, „client”."""
    banned = ("adresa locală", "local address", "community string", "client", "Network Level Authentication")
    for code in CATALOG:
        for step in get_explanation(code, lang)["steps"]:
            assert not any(b.lower() in step.lower() for b in banned), (code, step)


def test_mqtt_ro_and_en_say_the_same_thing():
    assert "turning the lights on" not in EN["MQTT_EXPOSED"]["text"]
    assert "hub" in EN["MQTT_EXPOSED"]["steps"][0] and "centralei" in RO["MQTT_EXPOSED"]["steps"][0]


def test_smb_first_step_says_where():
    assert "Setări → Rețea și internet" in RO["SMB_EXPOSED"]["steps"][0]
    assert "Settings → Network & internet" in EN["SMB_EXPOSED"]["steps"][0]
    assert RO["SMB_EXPOSED"]["steps"][3] == "Instalează toate actualizările sistemului."


def test_outdated_first_step_points_to_the_evidence():
    assert "„Dovadă”" in RO["OUTDATED_SERVICE"]["steps"][0] and '"Evidence"' in EN["OUTDATED_SERVICE"]["steps"][0]


@pytest.mark.parametrize("lang", LANGS)
def test_glossary(lang):
    g = get_glossary(lang)
    assert len(g) >= 10
    assert all(d["term"] and d["definition"] for d in g)
    assert len({d["term"] for d in g}) == len(g)
