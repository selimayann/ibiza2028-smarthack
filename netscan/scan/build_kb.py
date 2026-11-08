"""Generează baza de cunoștințe pentru asistent (RAG) din docs/knowledge_base.pdf.

    pip install pypdf                       # doar pentru acest script, nu pentru aplicație
    python -m netscan.scan.build_kb [docs/knowledge_base.pdf]

Rezultat: netscan/scan/data/knowledge_base.json (intrările A1…G6, regulile botului și ghidul de etică).
Aplicația citește doar JSON-ul; PDF-ul rămâne sursa editată de echipă. Glosarul (secțiunea E) nu se
preia de aici: asistentul îl ia direct din netscan/explain/glossary.py (aceleași texte).

HOTSPOT_ADDITIONS: ramura „hotspot de telefon” la intrările despre schimbarea parolei Wi-Fi / scoaterea unui
dispozitiv (rețeaua echipei e hotspotul unui telefon, nu un router). Se aplică după citirea PDF-ului, ca o
regenerare să nu le piardă.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

SRC = Path("docs/knowledge_base.pdf")
OUT = Path(__file__).with_name("data") / "knowledge_base.json"
EXPECTED_IDS = ([f"A{i}" for i in range(1, 11)] + [f"B{i}" for i in range(1, 10)] + [f"C{i}" for i in range(1, 6)]
                + [f"D{i}" for i in range(1, 16)] + [f"F{i}" for i in range(1, 12)] + [f"G{i}" for i in range(1, 7)])

_HEADER = re.compile(r"^netscan · Knowledge Base \(RAG\) · Ibiza2028( pagina \d+)?$")
_PAGE = re.compile(r"^pagina \d+$")
_ENTRY = re.compile(r"^\[([A-G]\d+)\]\s+(.*)$")
_SECTION = re.compile(r"^[A-H]\.\s+[A-ZĂÂÎȘȚ]")   # „B. Dispozitive…”; nu „0. Nu coboară…” din text
BULLETS = ("•", "")
_STEP = re.compile(r"^(\d+)\.\s+(.*)$")

HOTSPOT_RO = ("Dacă rețeaua e hotspotul unui telefon, parola se schimbă din telefon: pe iPhone, Setări → Hotspot "
              "personal → Parolă Wi-Fi; pe Android, Setări → Conexiuni → Hotspot mobil.")
HOTSPOT_EN = ("If the network is a phone's hotspot, change the password on the phone: on iPhone, Settings → Personal "
              "Hotspot → Wi-Fi Password; on Android, Settings → Connections → Mobile Hotspot.")
# id -> (unde): "step_after:<n>" = pas nou după pasul n (de la 1); "answer" = propoziție adăugată la răspuns
HOTSPOT_ADDITIONS = {"B3": "step_after:3", "B8": "answer"}
HOTSPOT_TAGS = ["hotspot", "parola hotspot", "scot dispozitiv"]


def apply_hotspot_additions(entries: list[dict]) -> list[dict]:
    """Adaugă ramura de hotspot (RO+EN) în intrările din HOTSPOT_ADDITIONS. Idempotent."""
    for e in entries:
        where = HOTSPOT_ADDITIONS.get(e["id"])
        if where is None or HOTSPOT_RO in e["a_ro"] or HOTSPOT_RO in e["steps_ro"]:
            continue
        if where == "answer":
            e["a_ro"] = f"{e['a_ro']} {HOTSPOT_RO}"
            e["a_en"] = f"{e['a_en']} {HOTSPOT_EN}"
        else:
            n = int(where.split(":", 1)[1])
            e["steps_ro"].insert(n, HOTSPOT_RO)
            e["steps_en"].insert(n, HOTSPOT_EN)
        e["tags"] = e["tags"] + [t for t in HOTSPOT_TAGS if t not in e["tags"]]
    return entries


def _lines(pdf: Path) -> list[str]:
    from pypdf import PdfReader
    out = []
    for page in PdfReader(str(pdf)).pages:
        for line in (page.extract_text() or "").splitlines():
            line = line.strip()
            if line and not _HEADER.match(line) and not _PAGE.match(line):
                out.append(line)
    return out


def _join(parts: list[str]) -> str:
    return " ".join(" ".join(parts).split())


def _bullets(lines: list[str]) -> list[str]:
    items, cur = [], []
    for line in lines:
        if line[:1] in BULLETS:          # pypdf extrage „•” uneori ca 
            if cur:
                items.append(_join(cur))
            cur = [line[1:].strip()]
        elif cur:
            cur.append(line)
    if cur:
        items.append(_join(cur))
    return items


def _section(lines: list[str], start: str, end: str) -> list[str]:
    i = next(k for k, l in enumerate(lines) if l.startswith(start))
    j = next(k for k, l in enumerate(lines) if k > i and l.startswith(end))
    return lines[i + 1:j]


def _parse_entry(eid: str, block: list[str]) -> dict:
    title, i = [block[0]], 1
    while i < len(block) and not block[i].startswith("Categorie:"):
        title.append(block[i]); i += 1
    meta = []
    while i < len(block) and block[i] != "RO":
        meta.append(block[i]); i += 1
    meta_txt = _join(meta)
    m = re.match(r"Categorie:\s*(.*?)\s*·\s*Etichete:\s*(.*)$", meta_txt)
    category, tags = (m.group(1), [t.strip() for t in m.group(2).split(",") if t.strip()]) if m else ("", [])
    i += 1  # „RO”

    def read_text(stop):
        buf = []
        nonlocal i
        while i < len(block) and not stop(block[i]):
            buf.append(block[i]); i += 1
        return buf

    def read_steps(stop):
        steps, cur = [], []
        nonlocal i
        while i < len(block) and not stop(block[i]):
            sm = _STEP.match(block[i])
            if sm:
                if cur:
                    steps.append(_join(cur))
                cur = [sm.group(2)]
            else:
                cur.append(block[i])
            i += 1
        if cur:
            steps.append(_join(cur))
        return steps

    is_en = lambda l: l.startswith("EN ·")  # noqa: E731
    is_note = lambda l: l.startswith("Notă pentru bot")  # noqa: E731
    a_ro = read_text(lambda l: l == "Pași:" or is_en(l))
    steps_ro = []
    if i < len(block) and block[i] == "Pași:":
        i += 1
        steps_ro = read_steps(is_en)
    q_en = [block[i][len("EN ·"):].strip()]; i += 1
    # titlul EN poate continua pe rândul următor doar dacă nu se termină în „?” sau „.”
    while i < len(block) and not q_en[-1].rstrip().endswith(("?", ".", ")")):
        q_en.append(block[i]); i += 1
    a_en = read_text(lambda l: l == "Steps:" or is_note(l))
    steps_en = []
    if i < len(block) and block[i] == "Steps:":
        i += 1
        steps_en = read_steps(is_note)
    note = ""
    if i < len(block) and is_note(block[i]):
        note = _join(block[i:]).split(":", 1)[1].strip()
    return {"id": eid, "category": category, "tags": tags,
            "q_ro": _join(title), "a_ro": _join(a_ro), "steps_ro": steps_ro,
            "q_en": _join(q_en), "a_en": _join(a_en), "steps_en": steps_en, "note": note}


def build(pdf: Path = SRC, out: Path = OUT) -> int:
    lines = _lines(pdf)
    rules = _bullets(_section(lines, "0. Cum folosește botul", "A. Despre produs"))
    ethics = _bullets(_section(lines, "H. Ce promitem", "Index al intrărilor"))
    body_end = next(k for k, l in enumerate(lines) if l.startswith("H. Ce promitem"))
    entries, cur_id, cur = [], None, []
    for line in lines[:body_end]:
        m = _ENTRY.match(line)
        if m:
            if cur_id:
                entries.append(_parse_entry(cur_id, cur))
            cur_id, cur = m.group(1), [m.group(2)]
        elif cur_id and (_SECTION.match(line) or line.startswith("E. Glosar")):
            entries.append(_parse_entry(cur_id, cur))
            cur_id, cur = None, []
        elif cur_id:
            cur.append(line)
    if cur_id:
        entries.append(_parse_entry(cur_id, cur))
    ids = [e["id"] for e in entries]
    if ids != EXPECTED_IDS:
        raise SystemExit(f"intrări neașteptate: {ids}")
    entries = apply_hotspot_additions(entries)
    data = {"source": str(pdf).replace("\\", "/"), "sha256": hashlib.sha256(pdf.read_bytes()).hexdigest(),
            "rules": rules, "ethics": ethics, "entries": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return len(entries)


if __name__ == "__main__":  # pragma: no cover
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else SRC
    print(f"{build(src)} intrări scrise în {OUT}")
