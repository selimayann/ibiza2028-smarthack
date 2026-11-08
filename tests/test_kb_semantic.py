"""Căutarea după sens pentru RAG (bge-m3 prin Ollama local), cu BM25 ca rezervă. Fără rețea: embedder simulat."""
import pytest

from netscan.scan import assistant as a
from netscan.scan import kb, local_llm


def fake_embed_towards(entry_id):
    """Un „model” care pune orice întrebare exact pe vectorul unei intrări: aceea trebuie să iasă prima."""
    target = kb.vectors()[entry_id]
    return lambda texts: [list(target) for _ in texts]


def test_embeddings_file_in_sync_with_the_knowledge_base():
    """Dacă se schimbă baza de cunoștințe sau termenii din kb.py, rulează `python -m netscan.scan.build_kb_embeddings`."""
    vecs = kb.vectors()
    assert vecs is not None, "kb_embeddings.json lipsește sau e vechi: python -m netscan.scan.build_kb_embeddings"
    assert set(vecs) == {e["id"] for e in kb.load()["entries"]}


def test_meaning_wins_over_words():
    # cuvintele duc spre altceva (BM25), sensul spre F2: combinația îl pune pe F2 primul
    hits = kb.hybrid_search("cum ajung in meniul routerului", 2, embed=fake_embed_towards("F2"))
    assert hits[0].id == "F2"


@pytest.mark.parametrize("embed", [None, lambda texts: (_ for _ in ()).throw(OSError("Ollama oprit"))])
def test_without_ollama_it_is_plain_bm25(embed):
    q = "Cum actualizez routerul?"
    assert [h.id for h in kb.hybrid_search(q, 3, embed)] == [h.id for h in kb.search(q, 3)]


def test_stale_vectors_are_not_used(monkeypatch, tmp_path):
    bad = tmp_path / "kb_embeddings.json"
    bad.write_text('{"model": "bge-m3", "fingerprint": "vechi", "vectors": {}}', encoding="utf-8")
    monkeypatch.setattr(kb, "EMBED_FILE", bad)
    kb.vectors.cache_clear()
    try:
        assert kb.vectors() is None
        q = "Cât de des să scanez?"
        assert [h.id for h in kb.hybrid_search(q, 2, embed=lambda t: [[1.0] * 3])] == [h.id for h in kb.search(q, 2)]
    finally:
        monkeypatch.undo()
        kb.vectors.cache_clear()


def test_embedder_off_by_default_and_only_local():
    assert local_llm.make_embedder(env={}) is None
    with pytest.raises(local_llm.NotLocalError):
        local_llm.make_embedder(env={"NETSCAN_LOCAL_LLM": "1", "NETSCAN_LOCAL_LLM_URL": "http://example.com:11434"})


def test_rag_context_uses_the_local_embedder(monkeypatch):
    monkeypatch.setattr(local_llm, "default_embedder", lambda: fake_embed_towards("F4"))
    ctx = a._kb_context("ce e asta cu reteaua aia separata", "ro")
    assert ctx and ctx[0]["id"] == "F4"


# --- răspunsul de bază, intenția și sursa (problemele găsite cu modelul real) ---------------------------------

def test_what_is_http_gives_the_definition_and_the_scan_problem():
    from netscan.engine.parser import analyze_file
    from pathlib import Path
    v4 = analyze_file(str(Path(__file__).parent.parent / "fixtures" / "validation" / "V4_legacy.xml"))
    for q, lang in (("ce inseamna http", "ro"), ("ce inseamna https", "ro"), ("what is http", "en")):
        text, intent = a.fallback_answer(q, v4, lang)
        assert intent == "glossary" and text.startswith("HTTP / HTTPS")
        assert "192.168.1.1 (port 80)" in text.splitlines()[1]
    assert a.fallback_answer("ce e telnet", v4, "ro")[1] == "code"      # telnet rămâne problema din scanare


def test_why_lost_points_is_the_score_explanation():
    from netscan.engine.parser import analyze_file
    from pathlib import Path
    v4 = analyze_file(str(Path(__file__).parent.parent / "fixtures" / "validation" / "V4_legacy.xml"))
    assert a.fallback_answer("de ce am pierdut puncte", v4, "ro")[1] == "score_how"


def test_refusal_texts_are_never_a_second_rag_fragment():
    ctx = kb.context("ce e retea pentru oaspeti", "ro", embed=fake_embed_towards("F4"))
    assert ctx[0]["id"] == "F4" and all(kb.get(c["id"])["category"] != "Etică" for c in ctx[1:])


def test_unknown_question_uses_meaning_with_a_threshold(monkeypatch):
    monkeypatch.setattr(local_llm, "default_embedder", lambda: fake_embed_towards("F2"))
    assert a.kb_answer("cum ajung in meniul routerului", a.INTENT_UNKNOWN, "ro")[1] == "F2"
    far = [0.0] * len(next(iter(kb.vectors().values())))
    far[0] = 1.0                                   # un vector care nu seamănă cu nicio intrare: sub SIM_MIN
    monkeypatch.setattr(local_llm, "default_embedder", lambda: (lambda texts: [far for _ in texts]))
    if max(sum(x * y for x, y in zip(kb._unit(far), v)) for v in kb.vectors().values()) < kb.SIM_MIN:
        assert a.kb_answer("spune-mi o reteta de clatite", a.INTENT_UNKNOWN, "ro") is None


def test_timeout_is_not_shown_as_a_caught_ai_mistake():
    from netscan.ui.app import reply_label, reply_state
    slow = a.Answer("text", "fallback", "first", ["LLM_ERROR"])
    caught = a.Answer("text", "fallback", "first", ["PORT"])
    assert reply_state(slow) == "fara-ai" and reply_label(slow)[0] == "ask_src_slow"
    assert reply_state(caught) == "prins" and reply_label(caught)[0] == "ask_src_caught"
