"""Pregătirea demo-ului (RBRT): pune cele 3 scanări din lab în istoricul UI-ului.

Utilizare (din rădăcina proiectului):
    python scripts/demo_load_history.py                    # folderul fixtures/lab, baza implicită
    python scripts/demo_load_history.py --folder <folder>  # alt folder cu fișiere nmap XML
    python scripts/demo_load_history.py --db <fișier.db>   # altă bază (altfel NETSCAN_DB_PATH sau data/netscan.db)

Ce face:
- analizează fișierele *.xml din folder cu același motor ca UI-ul (doar citește fișiere, fără rețea);
- salvează în istoric fiecare scanare citibilă care nu e deja acolo (aceeași pereche fișier + dată nu se dublează),
  deci poate fi rulat de câte ori vrei;
- citește `.env` ca UI-ul (NETSCAN_SALT trebuie să fie același, altfel device_id din istoric diferă de cel din folder);
- nu șterge și nu modifică nimic din ce e deja în istoric.

Coduri de ieșire: 0 = gata, 2 = folderul nu există sau n-are nicio scanare citibilă.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from netscan.cli import load_env_file  # noqa: E402
from netscan.engine import analyze_folder  # noqa: E402
from netscan.ui import storage  # noqa: E402

DEFAULT_FOLDER = REPO / "fixtures" / "lab"


def load_history(folder: Path, db_path: Path | str | None = None) -> list[tuple[str, int, bool]]:
    """Salvează scanările citibile din `folder` în istoric. Întoarce (fișier, id, era_deja_acolo) pentru fiecare.
    Ridică NotADirectoryError dacă folderul nu există."""
    rows: list[tuple[str, int, bool]] = []
    scans = [s for s in analyze_folder(folder) if s.status == "ok"]
    for scan in sorted(scans, key=lambda s: (s.started_at is None, s.started_at or 0, s.file)):
        existing = storage.find_scan(scan.file, scan.started_at, db_path)
        scan_id = existing if existing is not None else storage.save_scan(scan, db_path)
        rows.append((scan.file, scan_id, existing is not None))
    return rows


def main(argv: list[str] | None = None, stream=sys.stdout) -> int:
    parser = argparse.ArgumentParser(description="Pune scanările din lab în istoricul UI-ului.")
    parser.add_argument("--folder", type=Path, default=DEFAULT_FOLDER, help="folderul cu fișiere nmap XML")
    parser.add_argument("--db", type=Path, default=None, help="baza de date (implicit NETSCAN_DB_PATH sau data/netscan.db)")
    args = parser.parse_args(argv)

    load_env_file(REPO / ".env")   # ca UI-ul: același NETSCAN_SALT și același NETSCAN_DB_PATH
    try:
        rows = load_history(args.folder, args.db)
    except NotADirectoryError:
        print(f"Eroare: '{args.folder}' nu este un folder.", file=sys.stderr)
        return 2
    if not rows:
        print(f"Eroare: nu am găsit nicio scanare citibilă în '{args.folder}'.", file=sys.stderr)
        return 2
    for name, scan_id, existed in rows:
        print(f"{name}: {'era deja în istoric' if existed else 'salvată'} (id {scan_id})", file=stream)
    where = args.db or storage.db_path()
    print(f"Istoric: {Path(where).resolve()} ({len(storage.list_scans(args.db))} scanări)", file=stream)
    return 0


if __name__ == "__main__":
    sys.exit(main())
