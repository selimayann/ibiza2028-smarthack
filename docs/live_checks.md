# Foaia pentru verificările live (jurizare)

> Ordinea juriului (ghidul, secțiunea 10). Pentru fiecare: cine o arată, comanda exactă, ce trebuie să vadă juriul
> și ce a dat **rularea locală din 7 nov., 21:49** (pe branch-ul `scan-demo`, fără scanare live).
> Pregătirea laptopului: [demo.md](demo.md). Toate comenzile se rulează din folderul repo-ului.

## 1. Re-rulare pe un fișier din Test Set (Oneata)

Juriul alege un fișier din Test Set; rezultatul trebuie să fie **identic** cu ce am încărcat.

```
git checkout final
python scripts/preflight.py <folder-cu-fișierul-ales> --out rerun
```
Preflight-ul (Oneata) rulează `python -m netscan analyze` de două ori, în procese separate, compară `findings.csv` și
`scores.csv` byte cu byte și afișează scorul per fișier și SHA-256. Apoi se compară rândurile din `rerun/` cu cele
ale acelui fișier din CSV-urile încărcate (procedura completă: [workflow.md](workflow.md)).

- **Rulat local** (Validation Set, commit 66d0c5d): `Cele două rulări sunt identice byte cu byte.`, cod de ieșire 0;
  scoruri V1 90, V2 40, V3 45, V4 25, V5 50, V6a 60, V6b 100, V7 ERROR (TRUNCATED); CSV-urile sunt **identice cu
  baremul** oficial (`fixtures/validation/expected_*.csv`).

## 2. Sarcina hands-on în UI (Radu)

Un jurat găsește singur cel mai periculos dispozitiv și prima reparație.

```
start.bat            (Windows, dublu-click; din terminal: .\start.bat)
start.command        (macOS)
```
Se deschide `http://127.0.0.1:5055/`. Juriul trebuie să vadă cardul **„Cel mai periculos dispozitiv”** cu pasul „Fă asta întâi”.

- **Rulat local** (V2): `Cel mai periculos dispozitiv · Cameră 192.168.1.40 · Ridicat · Imaginea camerei expusă ·
  CAMERA_STREAM_EXPOSED · Port 554 · Imaginile camerei video pot fi văzute direct din rețea…`
- `start.bat` verificat: UI-ul răspunde (HTTP 200) și ascultă **doar pe 127.0.0.1:5055**.

## 3. Explicații pentru 3 coduri (RBRT)

Explicația și reparația pentru trei findings numite de juriu: în UI (pagina dispozitivului / problema) sau:
```
python -m netscan ask fixtures/validation/V2_smart_home.xml "Ce înseamnă CAMERA_STREAM_EXPOSED?"
```
La FTP_CLEARTEXT, TELNET_OPEN și HTTP_ADMIN_CLEARTEXT apare și „Ce vede cineva care ascultă” (exemplu inventat).

- **Rulat local:** `Am găsit CAMERA_STREAM_EXPOSED pe camera 192.168.1.40 (port 554). Imaginile camerei video pot fi văzute
  direct din rețea…`; `Am găsit HTTP_ADMIN_CLEARTEXT pe routerul 192.168.1.1 (port 80), camera 192.168.1.40 (port 80)…`;
  la TELNET_OPEN (absent din V2): `Scanarea nu a găsit TELNET_OPEN în această rețea.` + explicația și pașii.

## 4. Guardrail (Ayan)

Laptopul e pe `RSH-Ibiza2028`. Juriul încearcă un IP public și rețeaua venue; tool-ul refuză.

```
python -m netscan scan 8.8.8.8
python -m netscan scan <subnetul venue>        # notat la fața locului; azi: Wi-Fi-ul venue „UnivBuc Free” = 10.240.0.0/16
python -m netscan scan 172.20.10.14            # acceptat, dar doar dry-run (arată comanda nmap, nu scanează)
```
Mesajele de refuz așteptate (cod de ieșire 2):

| Țintă | Mesaj |
|---|---|
| `8.8.8.8` | `Nu scanez această adresă: este o adresă publică, din afara rețelei tale.` |
| subnetul venue (ex. `10.240.0.0/16`) | `Nu scanez această adresă: nu face parte din rețeaua ta (172.20.10.0/28).` |
| `router.local`, `8.8.8.8; rm -rf /` | `Nu scanez această adresă: nu este o adresă IP …` (fără DNS) |
| laptopul conectat la Wi-Fi-ul venue, orice țintă | `Ești conectat la altă rețea Wi-Fi decât hotspotul echipei, așa că nu scanez.` |

- **Rulat local:** mesajele de mai sus, din `check_target` cu allowlist-ul hotspotului `172.20.10.0/28`
  (`8.8.8.8` → NOT_PRIVATE, `10.240.0.0/16` → OUTSIDE_ALLOWLIST, `172.20.10.14` → acceptat).
  Laptopul fiind pe Wi-Fi-ul venue, `python -m netscan scan 8.8.8.8` a refuzat chiar mai devreme: `Ești conectat la altă rețea Wi-Fi decât hotspotul echipei, așa că nu scanez.` (exit 2).

## 5. Fișier stricat (Ayan)

```
python -m netscan analyze <folder cu V7_broken.xml> --out broken
```
Juriul trebuie să vadă un mesaj clar, fără crash, iar restul folderului se analizează în continuare.

- **Rulat local:** `V7_broken.xml: EROARE (TRUNCATED)`, cod de ieșire 0, `scores.csv` = `V7_broken.xml,ERROR`,
  0 rânduri în `findings.csv`. În UI: mesaj prietenos per tipul de eroare, fără stack trace.
- Alte fișiere stricate testate automat (`fixtures/traps/`): gol, XML care nu e nmap, XXE, „billion laughs”, trunchiat.

## 6. Istoric înainte/după din lab (0 → 30)

```
python -m netscan diff fixtures/lab/scan_01_before.xml fixtures/lab/scan_03_after.xml
```
În UI: `NETSCAN_SCANS_DIR=fixtures/lab`, „Salvează” pe `scan_01_before.xml`, apoi pe `scan_03_after.xml` → comparația.

- **Rulat local:** `Scor standard: 0 → 30`; `Probleme rezolvate (2): TELNET_OPEN 172.20.10.14 port 2323, DB_EXPOSED 172.20.10.14 port 6379`.

## 7. Fără secrete: gitleaks (Ayan)

gitleaks nu e în repo: se descarcă de pe GitHub (release-ul oficial, cu verificarea checksum-ului).
```
gitleaks git --log-opts="--all" --redact -v .     # istoricul tuturor commit-urilor
gitleaks dir --redact .                            # fișierele de pe disc
```
- **Rulat local** (gitleaks 8.30.1): istoricul `no leaks found`; fișierele (cod, documentație, fixtures, lab,
  scripturile de pornire, `.env.example`) `no leaks found`. `.env` (local) e în `.gitignore`.

## Separat: MAC-urile mascate

MAC-ul real e aruncat în parser; peste tot rămân doar primii 3 octeți (`AA:BB:CC:XX:XX:XX`) și un hash cu salt (`device_id`).

- **UI:** pagina dispozitivului, rândul „MAC (mascat)”. **Rulat local:** `50:C7:BF:XX:XX:XX`, `C0:56:E3:XX:XX:XX`… și
  **niciun MAC complet** în paginile generate.
- **Baza de date (istoricul):**
  ```
  python -c "import sqlite3; print(sqlite3.connect('data/netscan.db').execute('SELECT ip, mac_masked FROM hosts').fetchall())"
  ```
  **Rulat local** (cu cele 2 scanări din lab): `('172.20.10.1', '66:48:42:XX:XX:XX'), ('172.20.10.14', '4E:C7:BC:XX:XX:XX')`;
  căutând în tot fișierul bazei: **niciun MAC complet** (sursa nmap XML avea 4).
- **CSV-urile de predare:** nu conțin MAC-uri (0 găsite în `findings.csv` al lab-ului).
