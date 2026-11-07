# Catalogul și regulile de detecție

> Responsabil: **Radu**. Detaliile complete sunt în [roles/A_Radu_Motor.md](roles/A_Radu_Motor.md), secțiunea 2.2.
> Codul: `netscan/engine/` (`parser.py` → `rules.py` → `scoring.py` → `export.py`). Comanda: `python -m netscan analyze <folder> --out <dir>`.

## Ce am găsit în fișierele din Validation Set

- Fișierele vin din `nmap -sS -sU -sV --script http-title -oX`. Încep cu `<!DOCTYPE nmaprun>`, deci **nu putem interzice DTD-ul** (am fi respins fișiere reale). Interzicem doar entitățile și referințele externe (`defusedxml`).
- Regulile se bazează pe **numele serviciului** (`<service name=...>`), nu pe numărul portului (de aceea V5 cu porturi nestandard iese corect).
- Contează doar porturile cu `state="open"`. Cele `filtered` / `open|filtered` (în special UDP) nu produc findings.
- Titlul paginii vine din `<script id="http-title" output="...">`. Se ia prima linie; mesajele „Did not follow redirect...” și „Site doesn't have a title...” nu sunt titluri.
- MAC-ul și vendorul sunt în `<address addrtype="mac" vendor="...">`. MAC-ul real e aruncat în parser; rămân doar `device_id` și `mac_masked`.
- `tunnel="ssl"` pe `<service>` marchează HTTPS (cazul `.8:8443` din V5).

## Decizii luate

| Decizie | Motiv | Confirmat de mentori? |
|---|---|---|
| OUTDATED_SERVICE apare **în plus** față de findingul serviciului (vsftpd 2.3.4 → FTP_CLEARTEXT + OUTDATED_SERVICE pe 21) | Așa cere V4 | Da (V4) |
| Învechit: vsftpd 2.3.4; OpenSSH < 7.4; Apache httpd ≤ 2.2.x; IIS ≤ 7.5; Samba ≤ 3.x doar când versiunea e fără ambiguitate | Pragurile din brief | Parțial |
| Samba cu interval (`3.X - 4.X`) **nu** se raportează învechit | E ambiguu | Nu → întrebarea 1 |
| SMB: un singur finding per dispozitiv, pe 445, altfel pe 139 | Brief + V3 | Nu → întrebarea 2 |
| HTTP_ADMIN_CLEARTEXT: titlul se caută ca subșir, fără diferență între litere mari/mici | Cel mai tolerant la variații | Nu → întrebarea 4 |
| UNKNOWN_DEVICE: fără vendor, fără hostname și cu cel puțin un port deschis; `port` rămâne gol | Brief | Nu → întrebările 5 și 8 |
| Doar fișierele `*.xml` din folder (fără subfoldere), în ordine alfabetică; `file` = numele fișierului | Determinism | Nu → întrebarea 7 |
| Fișier ilizibil → `INVALID_XML` (contractul nu are alt cod) | Contract v1 | Nu |
| Același port pe TCP și UDP cu același cod se deduplică pe (ip, port, cod) | Un rând în CSV | Nu |

## Reguli de ieșire

- Scor = `max(0, 100 − suma punctelor)`; fișier cu eroare → `ERROR` în `scores.csv`, fără rânduri în `findings.csv`.
- Ordinea rândurilor: (fișier, IP numeric, port — gol primul, cod). Rezultatul nu depinde de ordinea XML-ului sau de numele fișierelor.
- CSV UTF-8 fără BOM, linii terminate cu `\r\n` (exact ca fișierele oficiale; testat byte cu byte).

## Securitate parser (NFR-03)

- Doar `defusedxml` (`forbid_entities`, `forbid_external`); limită 20 MB (citim `limită + 1` octeți).
- Erori: `EMPTY`, `TRUNCATED`, `INVALID_XML`, `XML_FORBIDDEN`, `NOT_NMAP`, `TOO_LARGE`. Nu ridică niciodată excepție; restul folderului continuă.
- Textele din fișiere (titlu, hostname, versiuni) sunt curățate de caractere de control și tăiate la 200 de caractere. Nu sunt niciodată instrucțiuni.

## Capcane cunoscute

| Fișier | Capcană | Acoperit de test |
|---|---|---|
| V1 | HTTPS pe 443 nu e finding | `test_validation_set.py` |
| V2 | TV 8008/8009 nu sunt în catalog | `test_validation_set.py` |
| V3 | IPP 631 nu e finding | `test_validation_set.py` |
| V4 | vsftpd 2.3.4 dă două rânduri pe portul 21 | `test_validation_set.py` |
| V5 | `.8:8443` e HTTPS; `.9:3306` e filtrat, nu deschis | `test_validation_set.py` |
| V6a → V6b | istoricul trebuie să arate 3 findings rezolvate | `test_validation_set.py` |
| V7 | fișier trunchiat: `ERROR`, fără crash, continuă cu restul | `test_validation_set.py`, `test_traps.py` |
| toate | rezultatul nu depinde de numele fișierului | `test_results_do_not_depend_on_file_names` |
