# Scanările din lab

Făcute de tool (`python -m netscan scan --confirm`) pe laptopul-scanner, în hotspotul `RSH-Ibiza2028`, pe 7 nov. 2026:

- `scan_01_before.xml` — toate serviciile pornite
- `scan_02.xml` — aceeași scanare, pentru verificarea stabilității
- `scan_03_after.xml` — după oprirea redis și a telnet-ului fals

Fișierele sunt exact cum le-a scris nmap: **nu edita conținutul lor.** `SHA256SUMS.txt` vine de la laptopul-scanner;
verificare: `sha256sum -c SHA256SUMS.txt` (și `tests/test_lab_scans.py`). Liniile se termină cu CRLF (Windows),
de aceea `.gitattributes` le marchează `-text`, ca git să nu le modifice.

MAC-urile din fișiere sunt **randomizate** de sistemul de operare (adresă privată, bitul „administrat local” setat),
nu adresele hardware. Findings așteptate: [docs/lab.md](../../docs/lab.md).
