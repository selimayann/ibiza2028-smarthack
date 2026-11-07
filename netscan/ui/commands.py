"""Comenzile CLI ale lui RBRT: ui, diff, delete-history. cli.py doar le apelează."""
from __future__ import annotations

import sys

from netscan.model import Scan
from netscan.ui import i18n, storage
from netscan.ui.storage import ScanDiff

_TXT = {
    "ro": {
        "ui_start": "Interfața pornește la http://127.0.0.1:{port}  (Ctrl+C ca să o oprești)",
        "not_file": "Eroare: '{path}' nu există sau nu e fișier.",
        "cannot_read": "{file}: {msg}",
        "score": "Scor standard: {a} → {b}",
        "resolved": "Probleme rezolvate",
        "new": "Probleme noi",
        "new_dev": "Dispozitive noi",
        "gone_dev": "Dispozitive dispărute",
        "opened": "Porturi deschise acum",
        "closed": "Porturi închise acum",
        "none": "niciuna",
        "saved": "Salvate în istoric (id {a} și {b}). Le vezi în UI la „Istoric”.",
        "confirm": "Ștergi definitiv tot istoricul de pe acest calculator? Scrie DA ca să confirmi: ",
        "confirm_word": "DA",
        "deleted": "Istoricul a fost șters.",
        "cancelled": "Anulat. Istoricul nu a fost atins.",
    },
    "en": {
        "ui_start": "The interface is starting at http://127.0.0.1:{port}  (Ctrl+C to stop it)",
        "not_file": "Error: '{path}' does not exist or is not a file.",
        "cannot_read": "{file}: {msg}",
        "score": "Standard score: {a} → {b}",
        "resolved": "Resolved problems",
        "new": "New problems",
        "new_dev": "New devices",
        "gone_dev": "Devices gone",
        "opened": "Newly open ports",
        "closed": "Newly closed ports",
        "none": "none",
        "saved": "Saved to history (ids {a} and {b}). See them in the UI under “History”.",
        "confirm": "Permanently delete all history on this computer? Type YES to confirm: ",
        "confirm_word": "YES",
        "deleted": "History deleted.",
        "cancelled": "Cancelled. History was not touched.",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    return _TXT[i18n.normalize_lang(lang)][key].format(**kw)


def cmd_ui(port: int = 5000, lang: str = "ro") -> int:
    from netscan.ui.app import run

    print(_t(lang, "ui_start", port=port))
    run(port=port)
    return 0


def format_diff(d: ScanDiff, lang: str = "ro") -> str:
    none = _t(lang, "none")
    lines = [_t(lang, "score", a=d.score_before, b=d.score_after), ""]

    def section(title: str, items: list[str]) -> None:
        lines.append(f"{title} ({len(items)}):")
        lines.extend(f"  - {i}" for i in items) if items else lines.append(f"  {none}")

    port = lambda f: "-" if f.port is None else str(f.port)  # noqa: E731
    section(_t(lang, "resolved"), [f"{f.code}  {f.ip}  port {port(f)}" for f in d.resolved_findings])
    section(_t(lang, "new"), [f"{f.code}  {f.ip}  port {port(f)}" for f in d.new_findings])
    section(_t(lang, "new_dev"), [f"{h.ip}  {i18n.device_type_label(lang, h.device_type)}" for h in d.new_devices])
    section(_t(lang, "gone_dev"), [f"{h.ip}  {i18n.device_type_label(lang, h.device_type)}" for h in d.removed_devices])
    section(_t(lang, "opened"), [f"{p}/{proto}  ({dev})" for dev, p, proto in d.opened_ports])
    section(_t(lang, "closed"), [f"{p}/{proto}  ({dev})" for dev, p, proto in d.closed_ports])
    return "\n".join(lines)


def cmd_diff(old_path: str, new_path: str, lang: str = "ro", save: bool = False) -> int:
    from pathlib import Path

    from netscan.engine import analyze_file

    scans: list[Scan] = []
    for p in (old_path, new_path):
        if not Path(p).is_file():
            print(_t(lang, "not_file", path=p), file=sys.stderr)
            return 2
        scans.append(analyze_file(p))
    old, new = scans
    for s in (old, new):
        if s.status == "error":
            print(_t(lang, "cannot_read", file=s.file, msg=i18n.error_message(lang, s.error_code)), file=sys.stderr)
            return 2
    print(f"{old.file} → {new.file}")
    print(format_diff(storage.diff(old, new), lang))
    if save:
        a, b = storage.save_scan(old), storage.save_scan(new)
        print()
        print(_t(lang, "saved", a=a, b=b))
    return 0


def cmd_delete_history(lang: str = "ro", yes: bool = False) -> int:
    if not yes:
        try:
            answer = input(_t(lang, "confirm"))
        except EOFError:
            answer = ""
        if answer.strip().upper() != _t(lang, "confirm_word"):
            print(_t(lang, "cancelled"))
            return 1
    storage.delete_history()
    print(_t(lang, "deleted"))
    return 0
