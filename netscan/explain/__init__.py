"""Explicații și pași de reparare (Oneata). Texte predefinite RO/EN = fallback-ul fără LLM.

Interfața folosită de UI (netscan/ui/explain_stub.py):
    get_explanation(code, lang) -> {"text": str, "steps": [str, ...]}   # 1-5 pași, primul = „Fă asta întâi”

Ce poate face cineva rău intenționat (un rând scurt, RO/EN), separat ca să nu se schimbe forma de mai sus:
    get_harm(code, lang) -> str

Pentru ai_check.choose_text() (textul de rezervă când textul LLM nu trece verificarea):
    fallback_text(code, lang) -> str

Textele nu depind de scanare și nu conțin numere de port, IP-uri sau coduri: „code decides, the model words”.
"""

from __future__ import annotations

from netscan.explain.glossary import get_glossary
from netscan.explain.standards import get_standards
from netscan.explain.templates_en import TEMPLATES as _EN
from netscan.explain.templates_ro import TEMPLATES as _RO

__all__ = ["LANGS", "fallback_text", "get_explanation", "get_glossary", "get_harm", "get_standards"]

LANGS = ("ro", "en")
_TEMPLATES = {"ro": _RO, "en": _EN}

_GENERIC = {
    "ro": {
        "text": "Am găsit o problemă de securitate pe acest dispozitiv. Verifică dacă serviciul e chiar necesar "
                "și protejează-l.",
        "steps": [
            "Oprește serviciul dacă nu îl folosești.",
            "Dacă îl folosești, pune o parolă puternică și actualizează dispozitivul.",
        ],
    },
    "en": {
        "text": "We found a security problem on this device. Check whether the service is really needed and "
                "protect it.",
        "steps": [
            "Turn off the service if you don't use it.",
            "If you use it, set a strong password and update the device.",
        ],
    },
}


def _lang(lang: str | None) -> str:
    lang = (lang or "").lower()
    return lang if lang in LANGS else "ro"


def get_explanation(code: str, lang: str = "ro") -> dict:
    """Explicația pentru un cod din catalog: {"text": str, "steps": [str]}. Cod necunoscut → text generic."""
    lang = _lang(lang)
    entry = _TEMPLATES[lang].get(code) or _GENERIC[lang]
    return {"text": entry["text"], "steps": list(entry["steps"])}


_GENERIC_HARM = {
    "ro": "Cineva din rețea ar putea folosi problema ca să ajungă la dispozitiv.",
    "en": "Someone on the network could use this problem to reach the device.",
}


def get_harm(code: str, lang: str = "ro") -> str:
    """Un rând: ce poate face cineva rău intenționat, fără exagerări. Cod necunoscut → text generic."""
    lang = _lang(lang)
    entry = _TEMPLATES[lang].get(code)
    return entry["harm"] if entry and entry.get("harm") else _GENERIC_HARM[lang]


def fallback_text(code: str, lang: str = "ro") -> str:
    """Explicația și pașii într-un singur text (pentru ai_check.choose_text)."""
    e = get_explanation(code, lang)
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(e["steps"], 1))
    return f"{e['text']}\n{steps}"
