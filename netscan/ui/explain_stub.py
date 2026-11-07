"""Stub provizoriu pentru explicații, până livrează Ayan textele din netscan/explain/.

Forma propusă echipei: get_explanation(code, lang) -> {"text": str, "steps": [str, ...]} (1-5 pași).
Când există funcția reală, UI-ul o folosește pe aceea; altfel cade pe acest stub.
"""
from __future__ import annotations


def _stub(code: str, lang: str) -> dict:
    if lang == "en":
        return {
            "text": f"Problem {code}. The full explanation will be added soon.",
            "steps": [f"Close or protect the service behind {code}."],
        }
    return {
        "text": f"Problema {code}. Explicația completă va fi adăugată în curând.",
        "steps": [f"Închide sau protejează serviciul din spatele {code}."],
    }


def get_explanation(code: str, lang: str) -> dict:
    try:  # funcția reală a lui Ayan, când apare
        from netscan.explain import get_explanation as real  # type: ignore[attr-defined]
    except ImportError:
        return _stub(code, lang)
    try:
        result = real(code, lang)
        if isinstance(result, dict) and result.get("text") and result.get("steps"):
            return result
    except Exception:  # explicațiile nu au voie să strice pagina
        pass
    return _stub(code, lang)
