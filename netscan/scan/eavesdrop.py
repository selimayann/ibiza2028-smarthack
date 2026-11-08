"""„Ce vede cineva care ascultă” (B), după momentul „aha” din Wireshark (Follow stream / credențiale în clar).

Pentru problemele necriptate (FTP_CLEARTEXT, TELNET_OPEN, HTTP_ADMIN_CLEARTEXT) arătăm cum arată o logare
pentru cineva care ascultă rețeaua: numele și parola trec la vedere.

Important: e un EXEMPLU INVENTAT, scris de noi. Nu capturăm și nu citim traficul nimănui (n-ar respecta
confidențialitatea și regula „fără log-uri”); parola din exemplu e un text generic („parola-ta”).
"""
from __future__ import annotations

from typing import Optional

LANGS = ("ro", "en")

# (protocolul, liniile pe care le-ar vedea cineva care ascultă; {pw} = parola generică)
_SAMPLES: dict[str, tuple[str, tuple[str, ...]]] = {
    "FTP_CLEARTEXT": ("FTP", (
        "220 FTP server ready",
        "USER admin",
        "331 Please specify the password.",
        "PASS {pw}",
        "230 Login successful.",
    )),
    "TELNET_OPEN": ("Telnet", (
        "login: admin",
        "Password: {pw}",
        "Welcome",
        "# ",
    )),
    "HTTP_ADMIN_CLEARTEXT": ("HTTP", (
        "POST /login HTTP/1.1",
        "Host: router",
        "Content-Type: application/x-www-form-urlencoded",
        "",
        "user=admin&password={pw}",
    )),
}

_TEXTS = {
    "ro": {
        "title": "Ce vede cineva care ascultă rețeaua",
        "password": "parola-ta",
        "caption": ("Așa arată o logare pe {proto} pentru oricine ascultă rețeaua: numele și parola trec la vedere, "
                    "ca pe o carte poștală. Exemplu inventat: noi nu ascultăm traficul tău."),
        "fix": "După reparare, aceeași logare ar arăta ca un șir de caractere amestecate, pe care nu-l poate citi nimeni.",
    },
    "en": {
        "title": "What someone listening on the network sees",
        "password": "your-password",
        "caption": ("This is what a login over {proto} looks like to anyone listening on the network: the username and "
                    "password travel in plain sight, like a postcard. Made-up example: we don't listen to your traffic."),
        "fix": "After the fix, the same login would look like scrambled characters that nobody can read.",
    },
}

CODES = frozenset(_SAMPLES)


def get_eavesdrop(code: str, lang: str = "ro") -> Optional[dict]:
    """{"title", "protocol", "lines": [...], "caption", "fix", "highlight": index} sau None dacă nu se aplică.
    `highlight` = rândul cu parola (UI-ul îl poate evidenția)."""
    if code not in _SAMPLES:
        return None
    lang = lang if lang in LANGS else "ro"
    t = _TEXTS[lang]
    proto, raw = _SAMPLES[code]
    lines = [line.format(pw=t["password"]) for line in raw]
    highlight = next(i for i, line in enumerate(raw) if "{pw}" in line)
    return {"title": t["title"], "protocol": proto, "lines": lines, "caption": t["caption"].format(proto=proto),
            "fix": t["fix"], "highlight": highlight}


def as_text(code: str, lang: str = "ro") -> Optional[str]:
    """Varianta text (pentru CLI și asistent)."""
    e = get_eavesdrop(code, lang)
    if e is None:
        return None
    body = "\n".join(f"    {line}" + ("    ← " + ("parola, la vedere" if lang == "ro" else "the password, in plain sight")
                                        if i == e["highlight"] else "")
                     for i, line in enumerate(e["lines"]) if line)
    return f"{e['title']} ({e['protocol']}):\n{body}\n{e['caption']}"
