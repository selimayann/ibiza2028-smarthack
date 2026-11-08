"""Calculează vectorii (bge-m3, prin Ollama local) pentru intrările din baza de cunoștințe și îi scrie în
netscan/scan/data/kb_embeddings.json, cu amprenta textelor. Se rulează din nou când se schimbă baza de cunoștințe
(după build_kb.py) sau termenii din kb.py; altfel testul test_kb_embeddings_in_sync pică.

    ollama pull bge-m3
    python -m netscan.scan.build_kb_embeddings

Totul rămâne pe laptop: Ollama doar pe 127.0.0.1 (local_llm.check_local_url).
"""
from __future__ import annotations

import json
import sys

from netscan.scan import kb, local_llm


def build(embed=None) -> dict:
    embed = embed or local_llm.make_embedder(force=True, timeout=600)   # prima încărcare a modelului durează
    entries = kb.load()["entries"]
    vecs = embed([kb.doc_text(e) for e in entries])
    return {
        "model": kb.EMBED_MODEL,
        "fingerprint": kb.fingerprint(kb.EMBED_MODEL),
        "vectors": {e["id"]: [round(float(x), 6) for x in v] for e, v in zip(entries, vecs)},
    }


def main() -> int:
    try:
        data = build()
    except OSError as exc:
        print(f"Ollama nu răspunde pe 127.0.0.1 (pornește `ollama serve` și `ollama pull {kb.EMBED_MODEL}`): {exc}",
              file=sys.stderr)
        return 1
    kb.EMBED_FILE.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    kb.vectors.cache_clear()
    print(f"Scris {kb.EMBED_FILE} ({len(data['vectors'])} intrări, model {data['model']}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
