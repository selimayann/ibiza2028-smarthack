"""Baza de cunoștințe a asistentului (RAG), căutare locală (B).

- Datele: netscan/scan/data/knowledge_base.json, generat din docs/knowledge_base.pdf (build_kb.py).
- Căutarea: BM25 pe cuvinte, fără diacritice, în RO și EN; întrebarea și etichetele contează mai mult decât
  textul. Locală, deterministă, fără internet și fără model de embeddings.
- Folosirea: (1) fără AI, asistentul răspunde direct cu intrarea găsită când scanarea nu e întrebată;
  (2) cu modelul local, intrările găsite sunt contextul (RAG), iar textul modelului trece prin validator.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

KB_FILE = Path(__file__).with_name("data") / "knowledge_base.json"

# cuvinte foarte comune, care nu ajută la căutare
STOPWORDS = frozenset("""
a ai al ale am ar as au ca care ce cea cel cele cei cu da daca de deci din dupa e ea el eu este fi fie
i ii il in ia imi iti la le li lui ma mai mea meu mi mie mult ne nu o pe pentru poate pot prin sa sau se
si sunt ta tau te ti tu un una unei unui va vor
the a an and or of to in on for is are be it its my me i you your do does can how what which who why
with this that there from at by as not no
""".split())

W_QUESTION, W_TAGS, W_TEXT = 3.0, 3.0, 1.0
K1, B = 1.4, 0.75


@dataclass(frozen=True)
class Hit:
    id: str
    score: float
    entry: dict


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def tokens(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9_]+", _norm(text))
    out = []
    for w in words:
        if w in STOPWORDS or len(w) < 2:
            continue
        out.append(w)
        if len(w) > 5:                       # „hackuit” ~ „hack”, „actualizez” ~ „actualizare”: rădăcină grosieră
            out.append(w[:5])
    return out


# În intrările din catalog (D1-D15), explicația și pașii sunt cei din aplicație (netscan/explain), sursa unică:
# dacă textele se rescriu (ex. testul de limbaj simplu), asistentul nu rămâne cu varianta veche din PDF.
# Restul răspunsului din PDF (gravitatea, „Apare când scanarea vede: ...”) rămâne neschimbat.
_TAIL = {"ro": " Gravitate:", "en": " Severity:"}


def _sync_catalog(data: dict) -> dict:
    from netscan.explain import get_explanation
    from netscan.scan.ai_check import CATALOG

    for e in data.get("entries", []):
        if e.get("category") != "Catalog":
            continue
        code = next((t for t in e.get("tags", []) if t in CATALOG), None)
        if code is None:
            continue
        for lang, tail in _TAIL.items():
            ex = get_explanation(code, lang)
            answer = e.get("a_" + lang, "")
            rest = answer[answer.index(tail):] if tail in answer else ""
            e["a_" + lang] = ex["text"] + rest
            e["steps_" + lang] = ex["steps"]
    return data


@lru_cache(maxsize=1)
def load() -> dict:
    try:
        data = json.loads(KB_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"entries": [], "rules": [], "ethics": []}
    return _sync_catalog(data)


@lru_cache(maxsize=1)
def _index():
    docs = []
    for e in load()["entries"]:
        bag: dict[str, float] = {}
        fields = ((e["q_ro"] + " " + e["q_en"], W_QUESTION), (" ".join(e["tags"]) + " " + e["id"], W_TAGS),
                  (e["a_ro"] + " " + e["a_en"], W_TEXT))
        length = 0.0
        for text, w in fields:
            for t in tokens(text):
                bag[t] = bag.get(t, 0.0) + w
                length += w
        docs.append((e, bag, length))
    n = len(docs) or 1
    avg = sum(d[2] for d in docs) / n
    df: dict[str, int] = {}
    for _, bag, _ in docs:
        for t in bag:
            df[t] = df.get(t, 0) + 1
    idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
    return docs, idf, avg


def search(question: str, k: int = 3) -> list[Hit]:
    """Cele mai potrivite intrări, cu scor BM25 (0 = nicio potrivire)."""
    docs, idf, avg = _index()
    q = list(dict.fromkeys(tokens(question)))
    hits = []
    for e, bag, length in docs:
        s = 0.0
        for t in q:
            tf = bag.get(t)
            if tf:
                s += idf.get(t, 0.0) * tf * (K1 + 1) / (tf + K1 * (1 - B + B * length / avg))
        if s > 0:
            hits.append(Hit(e["id"], round(s, 3), e))
    hits.sort(key=lambda h: (-h.score, h.id))
    return hits[:k]


def get(entry_id: str) -> Optional[dict]:
    return next((e for e in load()["entries"] if e["id"] == entry_id), None)


def answer_text(entry: dict, lang: str = "ro") -> str:
    """Răspunsul unei intrări, cu pașii numerotați (fără nota pentru bot, care nu se arată utilizatorului)."""
    en = lang == "en"
    text = entry["a_en"] if en else entry["a_ro"]
    steps = entry["steps_en"] if en else entry["steps_ro"]
    if steps:
        text += "\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
    return text


def context(question: str, lang: str = "ro", k: int = 2, max_chars: int = 1600) -> list[dict]:
    """Fragmentele pentru modelul local (RAG): [{"id", "question", "text", "note"}], tăiate la max_chars în total."""
    out, used = [], 0
    for h in search(question, k):
        text = answer_text(h.entry, lang)
        if used + len(text) > max_chars:
            text = text[: max(0, max_chars - used)]
        if not text:
            break
        used += len(text)
        out.append({"id": h.id, "question": h.entry["q_en" if lang == "en" else "q_ro"], "text": text,
                    "note": h.entry.get("note", "")})
    return out


def rules() -> list[str]:
    return list(load().get("rules", []))
