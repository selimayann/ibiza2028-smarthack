"""Generează lista offline de producători (FR-03) din registrul oficial IEEE.

    python -m netscan.scan.build_oui <oui.csv descărcat de pe standards-oui.ieee.org/oui/oui.csv>

Rezultat: netscan/scan/data/oui.tsv.gz, câte o linie „AABBCC<TAB>Producător”, sortată, gzip determinist.
Se rulează doar când vrem să actualizăm lista; tool-ul nu descarcă nimic și nu folosește rețeaua.
Numele producătorilor sunt text din afară: păstrăm doar caractere tipăribile, pe un rând, scurtate.
"""
from __future__ import annotations

import csv
import gzip
import io
import re
import sys
from pathlib import Path

OUT = Path(__file__).with_name("data") / "oui.tsv.gz"
MAX_NAME = 80
_HEX6 = re.compile(r"[0-9A-F]{6}")


def clean_name(name: str) -> str:
    name = "".join(ch if ch.isprintable() else " " for ch in name)
    return " ".join(name.replace("\t", " ").split())[:MAX_NAME]


def build(src: Path, out: Path = OUT) -> int:
    rows: dict[str, str] = {}
    with src.open(encoding="utf-8", errors="replace", newline="") as f:
        for rec in csv.DictReader(f):
            if (rec.get("Registry") or "").strip() != "MA-L":
                continue
            prefix = (rec.get("Assignment") or "").strip().upper()
            name = clean_name(rec.get("Organization Name") or "")
            if _HEX6.fullmatch(prefix) and name:
                rows[prefix] = name
    text = "".join(f"{p}\t{rows[p]}\n" for p in sorted(rows))
    out.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
        gz.write(text.encode("utf-8"))
    out.write_bytes(buf.getvalue())
    return len(rows)


if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    print(f"{build(Path(sys.argv[1]))} prefixe scrise în {OUT}")
