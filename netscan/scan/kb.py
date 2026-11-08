"""Baza de cunoștințe a asistentului (RAG), căutare locală (B).

- Datele: netscan/scan/data/knowledge_base.json, generat din docs/knowledge_base.pdf (build_kb.py).
- Căutarea: BM25 pe cuvinte, fără diacritice, în RO și EN; întrebarea și etichetele contează mai mult decât
  textul. Locală, deterministă, fără internet și fără model de embeddings.
- Folosirea: (1) fără AI, asistentul răspunde direct cu intrarea găsită când scanarea nu e întrebată;
  (2) cu modelul local, intrările găsite sunt contextul (RAG), iar textul modelului trece prin validator.
- Căutarea după sens (doar cu AI-ul local pornit): vectorii intrărilor (bge-m3, calculați o dată de
  build_kb_embeddings.py) stau în data/kb_embeddings.json; întrebarea primește vectorul ei de la Ollama local.
  Rezultatul combină sensul (de SEM_WEIGHT ori mai important) cu BM25. Fără Ollama sau fără fișier: doar BM25.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

KB_FILE = Path(__file__).with_name("data") / "knowledge_base.json"
EMBED_FILE = Path(__file__).with_name("data") / "kb_embeddings.json"
EMBED_MODEL = "bge-m3"
SEM_WEIGHT = 3.0         # măsurat pe 98 de întrebări realiste: sensul de 3 ori mai important decât BM25
RRF_K = 30

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
W_SYNONYM = 0.6          # cuvintele adăugate prin sinonime contează mai puțin decât cele scrise de utilizator

# Cuvinte în plus pentru intrările din catalog (D1-D15): numele pe înțeles din aplicație (RO/EN), serviciile și
# porturile obișnuite. Oamenii nu scriu „OUTDATED_SERVICE”, ci „software vechi” sau „portul 9100”.
CATALOG_TERMS: dict[str, str] = {
    "TELNET_OPEN": "telnet port 23 intrare veche fara lacat old door without lock remote login",
    "RDP_EXPOSED": "rdp remote desktop desktop la distanta 3389 windows",
    "VNC_EXPOSED": "vnc 5900 ecran la distanta remote screen",
    "DB_EXPOSED": "baza de date database mysql postgresql postgres redis mongodb 3306 5432 6379 27017",
    "CAMERA_STREAM_EXPOSED": "camera rtsp 554 imagine video supraveghere stream webcam",
    "OUTDATED_SERVICE": "program vechi software vechi versiune veche outdated old software old version firmware vechi defecte cunoscute",
    "FTP_CLEARTEXT": "ftp 21 transfer fisiere necriptat file transfer unencrypted",
    "HTTP_ADMIN_CLEARTEXT": "admin http fara https necriptata unencrypted",
    "SMB_EXPOSED": "smb 445 139 partajare fisiere file sharing windows share samba",
    "MQTT_EXPOSED": "mqtt 1883 mosquitto mesagerie iot smart home casa inteligenta",
    "UPNP_EXPOSED": "upnp 1900 deschide porturi singur opens ports automatically",
    "SNMP_EXPOSED": "snmp 161 public community",
    "PRINTER_RAW_EXPOSED": "imprimanta printer 9100 jetdirect tiparire print",
    "UNKNOWN_DEVICE": "necunoscut nerecunoscut unknown unrecognized strain intrus",
    "SSH_OPEN": "ssh 22 acces la distanta securizat secure shell",
}

# Sinonime pentru întrebare (fără diacritice, litere mici): cuvintele obișnuite ale oamenilor, legate de cele din
# baza de cunoștințe. Fiecare grup: orice cuvânt din grup aduce și celelalte (cu greutatea W_SYNONYM).
SYNONYM_GROUPS: tuple[tuple[str, ...], ...] = (
    ("wifi", "retea", "network", "hotspot"),
    ("producator", "manufacturer", "vendor", "brand", "marca"),
    ("software", "program", "programul", "firmware", "versiune", "version"),
    ("vechi", "veche", "old", "outdated", "invechit"),
    ("imprimanta", "printer"),
    ("televizor", "tv", "dispozitiv", "device", "aparat"),
    ("recunosc", "recognize", "recognise", "necunoscut", "unknown", "strain"),
    ("vreme", "vremea", "meteo", "weather"),
    ("parola", "password", "parole", "passwords"),
    ("birou", "office", "serviciu", "scoala", "hotel", "cafenea", "vecin", "altcuiva", "alta"),
    ("spart", "sparge", "hackuit", "hacked", "atacat", "compromis", "hack"),
    ("sigur", "siguranta", "safe", "secure", "protejat"),
    ("intru", "login", "logare", "setari", "settings"),
)


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
        extra = " ".join(CATALOG_TERMS.get(t, "") for t in e["tags"])
        fields = ((e["q_ro"] + " " + e["q_en"], W_QUESTION), (" ".join(e["tags"]) + " " + e["id"] + " " + extra, W_TAGS),
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


@lru_cache(maxsize=1)
def _synonyms() -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for group in SYNONYM_GROUPS:
        for w in group:
            out[w] = tuple(x for x in group if x != w)
    return out


def _query_terms(question: str) -> dict[str, float]:
    """Cuvintele întrebării (greutate 1) plus sinonimele lor (greutate W_SYNONYM), fără dubluri."""
    terms: dict[str, float] = {}
    syn = _synonyms()
    words = re.findall(r"[a-z0-9_]+", _norm(question))
    for t in tokens(question):
        terms[t] = 1.0
    for w in words:
        for other in syn.get(w, ()):
            for t in tokens(other):
                terms.setdefault(t, W_SYNONYM)
    return terms


def search(question: str, k: int = 3) -> list[Hit]:
    """Cele mai potrivite intrări, cu scor BM25 (0 = nicio potrivire)."""
    docs, idf, avg = _index()
    q = _query_terms(question)
    hits = []
    for e, bag, length in docs:
        s = 0.0
        for t, qw in q.items():
            tf = bag.get(t)
            if tf:
                s += qw * idf.get(t, 0.0) * tf * (K1 + 1) / (tf + K1 * (1 - B + B * length / avg))
        if s > 0:
            hits.append(Hit(e["id"], round(s, 3), e))
    hits.sort(key=lambda h: (-h.score, h.id))
    return hits[:k]


# --- căutarea după sens (embeddings) ------------------------------------------------------------------------

def doc_text(e: dict) -> str:
    """Textul din care se face vectorul unei intrări: întrebările, etichetele, termenii din catalog, începutul
    răspunsurilor (RO și EN)."""
    extra = " ".join(CATALOG_TERMS.get(t, "") for t in e["tags"])
    return " | ".join([e["q_ro"], e["q_en"], ", ".join(e["tags"]), extra, e["a_ro"][:300], e["a_en"][:300]])


def fingerprint(model: str = EMBED_MODEL) -> str:
    """Amprenta textelor indexate: dacă baza de cunoștințe sau termenii se schimbă, vectorii trebuie refăcuți."""
    h = hashlib.sha256(model.encode())
    for e in load()["entries"]:
        h.update(b"\0" + e["id"].encode() + b"\0" + doc_text(e).encode())
    return h.hexdigest()


def _unit(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


@lru_cache(maxsize=1)
def vectors() -> Optional[dict[str, list[float]]]:
    """Vectorii intrărilor, doar dacă fișierul se potrivește cu baza de cunoștințe de acum; altfel None (BM25)."""
    try:
        data = json.loads(EMBED_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("fingerprint") != fingerprint(data.get("model", "")) or data.get("model") != EMBED_MODEL:
        return None
    vecs = data.get("vectors") or {}
    if {e["id"] for e in load()["entries"]} != set(vecs):
        return None
    return {i: _unit(v) for i, v in vecs.items()}


def hybrid_search(question: str, k: int = 3, embed=None) -> list[Hit]:
    """Căutarea pentru RAG: după sens (vectorul întrebării de la `embed`) combinat cu BM25, prin RRF ponderat.
    `embed(texts) -> list[vector]` vine de la Ollama local; dacă lipsește, cade sau nu are fișierul: doar BM25."""
    vecs = vectors() if embed is not None else None
    if vecs is None:
        return search(question, k)
    try:
        qv = _unit(embed([question])[0])
    except Exception:  # Ollama oprit / model lipsă: căutarea obișnuită
        return search(question, k)
    entries = {e["id"]: e for e in load()["entries"]}
    sem = sorted(vecs, key=lambda i: -sum(a * b for a, b in zip(qv, vecs[i])))
    bm = [h.id for h in search(question, len(entries))]
    score: dict[str, float] = {}
    for pos, i in enumerate(bm):
        score[i] = score.get(i, 0.0) + 1.0 / (RRF_K + pos + 1)
    for pos, i in enumerate(sem):
        score[i] = score.get(i, 0.0) + SEM_WEIGHT / (RRF_K + pos + 1)
    ranked = sorted(score, key=lambda i: (-score[i], i))[:k]
    return [Hit(i, round(score[i], 4), entries[i]) for i in ranked]


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


def context(question: str, lang: str = "ro", k: int = 2, max_chars: int = 1600, embed=None) -> list[dict]:
    """Fragmentele pentru modelul local (RAG): [{"id", "question", "text", "note"}], tăiate la max_chars în total.
    Cu `embed` (Ollama local), căutarea e după sens + BM25; fără, doar BM25."""
    out, used = [], 0
    for h in hybrid_search(question, k, embed):
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
