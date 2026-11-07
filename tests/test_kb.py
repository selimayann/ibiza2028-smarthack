"""B: baza de cunoștințe a asistentului (RAG), din docs/knowledge_base.pdf. Fără rețea, fără model AI."""
import hashlib
import json
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_file
from netscan.explain import get_explanation
from netscan.scan import assistant as a
from netscan.scan import kb, local_llm
from netscan.scan.ai_check import check_llm_text
from netscan.scan.build_kb import EXPECTED_IDS

ROOT = Path(__file__).parent.parent
V2 = analyze_file(str(ROOT / "fixtures" / "validation" / "V2_smart_home.xml"))
CATALOG = ["TELNET_OPEN", "RDP_EXPOSED", "VNC_EXPOSED", "DB_EXPOSED", "CAMERA_STREAM_EXPOSED", "OUTDATED_SERVICE",
           "FTP_CLEARTEXT", "HTTP_ADMIN_CLEARTEXT", "SMB_EXPOSED", "MQTT_EXPOSED", "UPNP_EXPOSED", "SNMP_EXPOSED",
           "PRINTER_RAW_EXPOSED", "UNKNOWN_DEVICE", "SSH_OPEN"]


# --- datele -----------------------------------------------------------------------------------------------

def test_json_complete():
    data = kb.load()
    assert [e["id"] for e in data["entries"]] == EXPECTED_IDS          # 56 de intrări, în ordine
    assert len(data["rules"]) == 7 and len(data["ethics"]) == 6
    for e in data["entries"]:
        assert all(e[k] for k in ("category", "tags", "q_ro", "a_ro", "q_en", "a_en")), e["id"]
        assert len(e["steps_ro"]) == len(e["steps_en"]), e["id"]


def test_json_in_sync_with_pdf():
    """Dacă cineva schimbă PDF-ul fără să ruleze build_kb, testul pică."""
    pdf = ROOT / "docs" / "knowledge_base.pdf"
    assert kb.load()["sha256"] == hashlib.sha256(pdf.read_bytes()).hexdigest()


@pytest.mark.parametrize("i, code", list(enumerate(CATALOG, 1)))
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_catalog_entries_match_the_app(i, code, lang):
    """Documentul spune „textul și pașii sunt cei din aplicație”: verificăm că așa rămâne."""
    e = kb.get(f"D{i}")
    assert code in e["q_ro"]
    ex = get_explanation(code, lang)
    assert (e["a_en"] if lang == "en" else e["a_ro"]).startswith(ex["text"])
    assert (e["steps_en"] if lang == "en" else e["steps_ro"]) == ex["steps"]


def test_bot_notes_never_shown_to_user():
    for e in kb.load()["entries"]:
        if e["note"]:
            assert e["note"] not in kb.answer_text(e, "ro") and e["note"] not in kb.answer_text(e, "en")


# --- căutarea ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("q, expected", [
    ("Cred că am fost hackuit", "F10"), ("I think I was hacked", "F10"),
    ("Pot bloca un dispozitiv din aplicație?", "B8"), ("Can I block a device?", "B8"),
    ("Cum actualizez routerul?", "F3"), ("Mi-au blocat fișierele și cer bani", "F11"),
    ("My files are locked, they want money", "F11"), ("Scanarea îmi strică ceva?", "A7"),
    ("Pot afla cine folosește telefonul?", "B2"), ("Pot vedea ce site-uri deschide fratele meu?", "B7"),
    ("Cât de des să scanez?", "F8"), ("Merge fără internet?", "A9"), ("Ce înseamnă ERROR?", "A10"),
    ("Cum intru în pagina routerului?", "F2"), ("Ce e rețeaua pentru oaspeți?", "F4"),
])
def test_search_finds_the_right_entry(q, expected):
    assert kb.search(q, 1)[0].id == expected


def test_search_nothing_for_unrelated():
    assert kb.search("Care e capitala Franței?") == []


# --- în asistent ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("q, ref, word", [
    ("Cred că am fost hackuit", "F10", "antivirus"),
    ("Pot bloca un dispozitiv din aplicație?", "B8", "router"),
    ("Cum actualizez routerul?", "F3", "Firmware"),
    ("Ce e rețeaua pentru oaspeți?", "F4", "separată"),
])
def test_assistant_answers_from_kb(q, ref, word):
    r = a.answer(q, V2)
    assert r.intent == a.INTENT_KB and r.refs == [ref] and word in r.text and r.source == "fallback"


def test_assistant_answers_from_kb_in_english():
    r = a.answer("I think I was hacked, what do I do?", V2, lang="en")
    assert r.refs == ["F10"] and "antivirus" in r.text


@pytest.mark.parametrize("q, intent", [
    ("Care e cel mai periculos dispozitiv?", a.INTENT_DANGEROUS),
    ("Ce fac întâi?", a.INTENT_FIRST),
    ("Care e scorul?", a.INTENT_SCORE),
    ("Ce e la 192.168.1.40?", a.INTENT_DEVICE),
    ("Ce înseamnă telnet?", a.INTENT_CODE),
])
def test_scan_questions_still_answered_from_scan(q, intent):
    r = a.answer(q, V2)
    assert r.intent == intent and r.refs == []


def test_refusals_stay_refusals_with_kb_text():
    r = a.answer("Cum ghicesc parola Wi-Fi a vecinului?", V2)
    assert r.intent == a.INTENT_SCOPE and r.text.startswith("Nu te pot ajuta")


def test_unrelated_still_out_of_scope():
    r = a.answer("Care e capitala Franței?", V2)
    assert r.intent == a.INTENT_UNKNOWN and "nu poate răspunde" in r.text


@pytest.mark.parametrize("eid", sorted(a.KB_PREFERRED))
def test_kb_answers_pass_the_validator(eid):
    """Dacă modelul local copiază un fragment din bază, validatorul nu trebuie să-l respingă pe nedrept."""
    for lang in ("ro", "en"):
        assert check_llm_text(kb.answer_text(kb.get(eid), lang), V2).ok, (eid, lang)


# --- RAG pentru modelul local -----------------------------------------------------------------------------

def test_llm_gets_kb_context_and_answer_is_checked():
    seen = []
    def llm(ctx):
        seen.append(ctx)
        return "Schimbă parola Wi-Fi de pe un dispozitiv curat și rulează un antivirus."
    r = a.answer("Cred că am fost hackuit", V2, llm=llm)
    assert seen and seen[0]["knowledge"][0]["id"] == "F10"
    assert r.source == "llm" and r.refs == ["F10"]
    prompt = local_llm.build_prompt(seen[0])
    assert "[F10]" in prompt and "FRAGMENTE DIN BAZA DE CUNOȘTINȚE" in prompt and len(prompt) < 4000
    assert "question_untrusted" not in prompt                         # întrebarea nu ajunge la model


def test_llm_hallucination_with_kb_still_rejected():
    r = a.answer("Cred că am fost hackuit", V2, llm=lambda ctx: "Sună la 0721 234 567 sau intră pe http://x.ro.")
    assert r.source == "fallback" and r.refs == ["F10"] and "antivirus" in r.text
