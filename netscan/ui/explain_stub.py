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


def get_standards(code: str, lang: str) -> dict:
    """Trimiterile la standarde de la Oneata (D3), gata de afișat. Lipsă sau eroare → nimic de afișat."""
    try:
        from netscan.explain import standards as st

        refs = st.get_standards(code, lang)
        lang = lang if lang in ("ro", "en") else "ro"
        groups = []
        for key, names in (("cis", st.CIS_NAME), ("owasp_iot", st.OWASP_NAME)):
            items = [r for r in refs.get(key, []) if r.get("id") and r.get("title")]
            if items:
                groups.append({"name": names[lang], "url": st.SOURCES.get(key), "refs": items})
        return {"groups": groups}
    except Exception:  # standardele sunt un bonus: nu au voie să strice pagina
        return {"groups": []}


def get_harm(code: str, lang: str) -> str:
    """Un rând „ce poate face cineva rău intenționat” (netscan/explain, get_harm). Lipsă sau eroare → nimic."""
    try:
        from netscan.explain import get_harm as real

        text = real(code, lang)
        return text if isinstance(text, str) else ""
    except Exception:  # e un plus: nu are voie să strice pagina
        return ""
