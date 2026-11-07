"""Legătura UI-ului cu funcțiile lui Ayan (B): monitorul, ușa-capcană, „ce vede cineva care ascultă” și numele
anunțate de dispozitive. Totul e doar CITIT și afișat: UI-ul nu calculează nimic și nu trimite nimic în rețea.

Toate datele de aici sunt TEXT NESIGUR (scris de dispozitive sau din fișiere locale): în template-uri doar cu
autoescape, niciodată |safe. Dacă un modul lipsește sau dă eroare, UI-ul merge mai departe fără secțiunea lui.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

NAME_MAX = 60   # numele anunțate se taie la 60 de caractere (cerința lui Ayan)

# Tipurile de evenimente ale monitorului; „TRAP” e o încercare de intrare prinsă de ușa-capcană.
WATCH_KINDS = ("NEW_DEVICE", "DEVICE_GONE", "PORT_OPENED", "PORT_CLOSED", "FINDING_NEW", "FINDING_RESOLVED", "SCORE")
URGENT = {"FINDING_NEW", "NEW_DEVICE", "TRAP"}           # cer atenție: accent vizual
GOOD = {"FINDING_RESOLVED", "PORT_CLOSED"}               # calm, verde + bifă


def _clean_ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _clean_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


@dataclass
class Event:
    kind: str                # una din WATCH_KINDS sau „TRAP”
    ts: int | None
    ip: str | None
    port: int | None
    proto: str | None
    code: str | None
    severity: str | None
    text_ro: str
    text_en: str

    @property
    def tone(self) -> str:
        if self.kind in URGENT:
            return "urgent"
        if self.kind in GOOD:
            return "good"
        return "info"


def _read(path_fn: str) -> list[dict]:
    try:
        from netscan.scan import local_data

        rows = local_data.read_events(getattr(local_data, path_fn)())
        return [r for r in (rows or []) if isinstance(r, dict)]
    except Exception:
        return []


def watch_events() -> list[Event] | None:
    """Alertele monitorului (`python -m netscan watch`). None = monitorul n-a rulat (nu există date)."""
    try:
        from netscan.scan import local_data  # noqa: F401
    except Exception:
        return None
    rows = _read("alerts_path")
    events = []
    for r in rows:
        kind = _text(r.get("kind"), 32).upper()
        if kind not in WATCH_KINDS:
            continue
        events.append(Event(kind=kind, ts=_clean_int(r.get("ts")), ip=_clean_ip(r.get("ip")),
                            port=_clean_int(r.get("port")), proto=_text(r.get("proto"), 8) or None,
                            code=_text(r.get("code"), 40) or None, severity=_text(r.get("severity"), 8) or None,
                            text_ro=_text(r.get("text_ro")), text_en=_text(r.get("text_en"))))
    return events if rows else None


def trap_events() -> list[Event]:
    """Încercările de intrare prinse de ușa-capcană: doar {ts, ip, port}. Textul îl scrie UI-ul."""
    out = []
    for r in _read("trap_path"):
        ip = _clean_ip(r.get("ip"))
        if ip is None:
            continue
        out.append(Event(kind="TRAP", ts=_clean_int(r.get("ts")), ip=ip, port=_clean_int(r.get("port")),
                         proto=None, code=None, severity=None, text_ro="", text_en=""))
    return out


def monitor_events() -> tuple[list[Event], bool]:
    """Monitorul + capcana, cele mai noi primele. Al doilea element: dacă monitorul a rulat vreodată."""
    watch = watch_events()
    events = (watch or []) + trap_events()
    events.sort(key=lambda e: (e.ts or 0), reverse=True)
    return events, watch is not None or bool(events)


def eavesdrop(code: str, lang: str) -> dict | None:
    """„Ce vede cineva care ascultă” pentru FTP/Telnet/HTTP în clar (exemplu inventat). None pentru alte coduri."""
    try:
        from netscan.scan.eavesdrop import get_eavesdrop

        d = get_eavesdrop(code, lang)
    except Exception:
        return None
    if not isinstance(d, dict) or not d.get("lines"):
        return None
    lines = [_text(x, 200) for x in list(d.get("lines") or [])[:30]]
    hl = _clean_int(d.get("highlight"))
    return {"title": _text(d.get("title"), 120), "protocol": _text(d.get("protocol"), 20), "lines": lines,
            "highlight": hl if hl is not None and 0 <= hl < len(lines) else None,
            "caption": _text(d.get("caption")), "fix": _text(d.get("fix"))}


def announced_names() -> dict[str, dict]:
    """Numele anunțate de dispozitive (ascultare pasivă): {ip: {"name", "service"}}. Text nesigur, tăiat la 60."""
    try:
        from netscan.scan.passive import load_names

        raw = load_names() or {}
    except Exception:
        return {}
    out = {}
    for ip, info in raw.items():
        ip = _clean_ip(ip)
        if ip is None or not isinstance(info, dict):
            continue
        name = _text(info.get("name"), NAME_MAX)
        if name:
            out[ip] = {"name": name, "service": _text(info.get("service"), NAME_MAX) or None}
    return out
