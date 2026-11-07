"""Testul automat de limbaj simplu (nu e un test cu oameni): pe toate cele 15 coduri, RO și EN,
pe explicație, pași și rândul „ce poate face cineva rău intenționat”. Raportul: scripts/plain_language_report.py."""
from __future__ import annotations

import pytest

from netscan.explain import LANGS, get_harm
from netscan.explain.plain import (LIX_MAX, MAX_SENTENCE_WORDS, jargon_in, lix, measure,
                                   step_starts_with_action, words)
from netscan.scan.ai_check import CATALOG

CASES = [(code, lang) for code in sorted(CATALOG) for lang in LANGS]


@pytest.mark.parametrize("code,lang", CASES)
def test_no_unexplained_jargon(code, lang):
    assert measure(code, lang).jargon == []


@pytest.mark.parametrize("code,lang", CASES)
def test_short_sentences(code, lang):
    assert measure(code, lang).long_sentences == []


@pytest.mark.parametrize("code,lang", CASES)
def test_steps_start_with_an_action(code, lang):
    assert measure(code, lang).bad_steps == []


@pytest.mark.parametrize("code,lang", CASES)
def test_lix_under_threshold(code, lang):
    assert measure(code, lang).lix <= LIX_MAX[lang]


@pytest.mark.parametrize("code,lang", CASES)
def test_every_code_says_what_an_attacker_could_do(code, lang):
    harm = get_harm(code, lang)
    assert harm and len(words(harm)) <= MAX_SENTENCE_WORDS and harm.count(".") == 1


# ---------- verificatorul însuși prinde textele proaste ----------

def test_checker_catches_bad_text():
    assert jargon_in("Configurează banner-ul pe protocolul TCP.", "ro") == ["protocol", "TCP", "banner"]
    assert jargon_in("The exploit uses UDP.", "en") == ["UDP", "exploit"]
    assert jargon_in("Port is a door.", "en") == []                      # în glosar
    assert jargon_in("Bannerul e textul cu care se prezintă un program.", "ro") == []   # explicat în frază
    assert not step_starts_with_action("Telefoanele noi își ascund adresa.", "ro")
    assert step_starts_with_action("Dacă îl folosești, oprește-l.", "ro")
    assert step_starts_with_action("If you use it, turn it off.", "en")


def test_lix_formula():
    # 6 cuvinte, 2 propoziții, 2 cuvinte lungi (peste 6 litere): 6/2 + 100*2/6 = 36,33
    assert round(lix(["Pisica doarme. Calculatorul funcționează bine acum."]), 2) == round(6 / 2 + 100 * 2 / 6, 2)
