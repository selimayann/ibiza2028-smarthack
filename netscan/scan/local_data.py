"""Datele locale ale monitorului (alerte) și ale ușii-capcană (încercări) (B). NFR-02.

- Stau lângă baza cu istoricul (folderul lui NETSCAN_DB_PATH, implicit data/), care nu intră în git.
- Format JSON Lines, câte un eveniment pe rând. Fără MAC, fără parole, fără ce a scris cineva.
- `delete_local_data()` e apelat de „Șterge istoricul” (netscan/ui/storage.delete_history).
- Încercările de la capcană mai vechi de RETENTION_DAYS se șterg automat.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable, Optional

ALERTS_FILE = "alerts.jsonl"
TRAP_FILE = "trap_attempts.jsonl"
RETENTION_DAYS = 7
MAX_EVENTS = 5000


def data_dir(db_path: Optional[str | Path] = None) -> Path:
    db = Path(db_path or os.environ.get("NETSCAN_DB_PATH") or "data/netscan.db")
    return db.parent


def alerts_path(db_path=None) -> Path:
    return data_dir(db_path) / ALERTS_FILE


def trap_path(db_path=None) -> Path:
    return data_dir(db_path) / TRAP_FILE


def append_events(path: Path, events: Iterable[dict]) -> None:
    events = list(events)
    if not events:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")


def read_events(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-MAX_EVENTS:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def purge_old(path: Path, days: int = RETENTION_DAYS, now: Optional[float] = None) -> int:
    """Păstrează doar evenimentele din ultimele `days` zile (și cel mult MAX_EVENTS). Întoarce câte au rămas."""
    if not path.exists():
        return 0
    limit = (now if now is not None else time.time()) - days * 86400
    keep = [e for e in read_events(path) if isinstance(e.get("ts"), (int, float)) and e["ts"] >= limit]
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in keep), encoding="utf-8")
    tmp.replace(path)
    return len(keep)


def delete_local_data(db_path=None) -> None:
    """Șterge alertele, încercările de la capcană și numele anunțate (butonul „Șterge istoricul”)."""
    for p in (alerts_path(db_path), trap_path(db_path), data_dir(db_path) / "device_names.jsonl"):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
