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
