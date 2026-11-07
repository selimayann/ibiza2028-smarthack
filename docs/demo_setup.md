# Laptopul de demo: pregătirea interfeței (UI)

> Pașii exacți ca interfața să fie gata pentru jurizare. Rețeaua, AI-ul local, lab-ul și cele 7 verificări live sunt în [demo.md](demo.md); aici e doar ce ține de UI. Test: un jurat, fără ajutor, trebuie să răspundă din UI la „Care dispozitiv e cel mai periculos și ce fac întâi?”.

## 1. O singură dată: fișierul `.env`

În rădăcina proiectului, `.env` (copie după `.env.example`) trebuie să aibă:

```
NETSCAN_SALT=<orice text lung, ales o dată>
NETSCAN_SCANS_DIR=fixtures/lab
```

- `NETSCAN_SCANS_DIR=fixtures/lab` face ca UI-ul să arate cele 3 scanări din lab (`scan_01_before.xml`, `scan_02.xml`, `scan_03_after.xml`).
- **Nu schimba `NETSCAN_SALT` după ce ai încărcat istoricul.** Din el se face `device_id`; dacă se schimbă, numele date dispozitivelor și bifele nu se mai potrivesc. Dacă totuși l-ai schimbat: șterge istoricul (`python -m netscan delete-history --yes`) și repetă pasul 2.
- Baza de date e `data/netscan.db`, **relativ la folderul din care pornești comenzile**. Rulează toate comenzile de mai jos din rădăcina proiectului, ca să fie aceeași bază.

## 2. Încarcă cele 3 scanări din lab în istoric

```powershell
cd <folderul proiectului>
python scripts/demo_load_history.py
```

Rezultat așteptat (id-urile pot diferi dacă istoricul avea deja scanări):

```
scan_01_before.xml: salvată (id 1)
scan_02.xml: salvată (id 2)
scan_03_after.xml: salvată (id 3)
Istoric: <calea>\data\netscan.db (3 scanări)
```

Scriptul poate fi rulat de câte ori vrei: ce e deja în istoric nu se dublează și nu se modifică. Folosește doar fișierele din lab; nu folosește rețeaua.

## 3. Pornește UI-ul

```powershell
python -m netscan ui --port 5000
```

Lasă terminalul deschis (nu-l închide și nu apăsa Ctrl+C). UI-ul ascultă doar pe `127.0.0.1`.

## 4. Pagina deschisă

În Edge sau Chrome, o singură filă, deschide:

**http://127.0.0.1:5000/?scan=2**

E scanarea `scan_03_after.xml` (cea mai nouă). Jurații văd direct: fraza „Rețeaua ta are o problemă gravă și 6 mai mici. Începe cu …”, scorul standard 30, cardul „Cel mai periculos dispozitiv” cu „Fă asta întâi”.

> De ce nu `scan_01`? Pagina unei scanări vechi ține cont de scanările mai noi (din folder și din istoric): arată scorul recalculat (30) cu nota „Scanarea a dat 0”. E corect, dar pentru primul contact cu juratul e mai limpede o pagină fără ce să fie „deja rezolvat”.

**Drumul de arătat, pe rând** (aproximativ 2 minute):

1. Pagina deschisă: fraza de sus → dispozitivul → „Fă asta întâi”.
2. „Vezi toți pașii de reparare” (pagina dispozitivului). Aici se poate da și un nume dispozitivului.
3. **Istoric** → deschide `scan_03_after.xml`: cardul **Dovada: înainte și după**, scor 0 → 30, „Ai închis 2 uși”, ce a fost rezolvat și ce a rămas.
4. (Varianta cu bucla, dacă e timp) `http://127.0.0.1:5000/?scan=0`: panoul „Ai reparat ceva? Verifică din nou” cu butonul „Vezi înainte și după”; sau încarcă un fișier nou cu „Verifică din nou”.

## 5. Fereastra

- Browserul **maximizat** (nu pe tot ecranul cu F11), **zoom 100%**. Mărimea de lucru: **1366 × 768** sau mai mare; capturile din `docs/screenshots/` sunt făcute la 1366 × 1000.
- Închide celelalte file și bara de favorite. Păstrează comutatorul RO / EN vizibil (sus, dreapta).
- Dacă proiectorul sau ecranul e mic: **nu micșora zoom-ul sub 100%**, textul trebuie să rămână de cel puțin 16 px. Mărește mai bine (110–125%).

## 6. Notificările oprite (Windows 11)

1. **Setări → Sistem → Notificări → Nu deranja: Pornit** (sau Focus: Alarme doar).
2. Închide Teams, Slack, WhatsApp, Outlook și orice alt program care poate afișa ferestre.
3. **Setări → Sistem → Alimentare și baterie → Ecran și repaus: Niciodată** cât timp e la priză (pune-le la loc după jurizare). Economisirea bateriei oprită.
4. Aplicația nu cere permisiuni de notificare în browser; dacă apare vreo cerere de la alt site, refuz-o și închide fila.

## 7. Verificare rapidă, înainte de a intra la juriu

- [ ] `http://127.0.0.1:5000/?scan=2` arată fraza de sus, scorul **30** și cardul „Cel mai periculos dispozitiv”.
- [ ] **Istoric** arată cele 3 scanări; la `scan_03_after.xml`, cardul „Dovada” spune **0 → 30** și „Ai închis 2 uși”.
- [ ] Comutatorul **EN** merge și textele sunt în engleză; revino pe **RO**.
- [ ] Sub „Istoric” scrie „Istoric pentru utilizatorul … pe acest calculator”. Dacă istoricul apare gol: ești în alt folder sau alt utilizator de Windows (mesajul de pe pagină spune și unde caută).
- [ ] `pytest` trece (în terminal separat, nu în cel cu UI-ul).

## 8. Capturile de ecran (planul B al pitch-ului)

Trei capturi, făcute cu UI-ul real pe scanările din lab, în `docs/screenshots/`:

| Fișier | Pagina |
|---|---|
| [01_pagina_principala.png](screenshots/01_pagina_principala.png) | `/?scan=2`: fraza-rezumat, scorul, cel mai periculos dispozitiv |
| [02_dispozitiv.png](screenshots/02_dispozitiv.png) | pagina dispozitivului: formularul pentru nume, problemele, pașii de reparare |
| [03_inainte_dupa.png](screenshots/03_inainte_dupa.png) | `/scan/3?vs=1`: Dovada, 0 → 30 |

Dacă UI-ul se schimbă și vrei să le refaci (Edge, fără să atingi `data/`; baza de date separată, doar pentru capturi):

```powershell
$env:NETSCAN_DB_PATH = "$env:TEMP\demo-capturi.db"; $env:NETSCAN_SCANS_DIR = "fixtures/lab"; $env:NETSCAN_SALT = "demo-salt"
python scripts/demo_load_history.py
Start-Process python -ArgumentList "-m","netscan","ui","--port","5055"
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
& $edge --headless=new --hide-scrollbars --window-size=1366,1000 --screenshot="$PWD\docs\screenshots\01_pagina_principala.png" "http://127.0.0.1:5055/?scan=2"
& $edge --headless=new --hide-scrollbars --window-size=1366,1000 --screenshot="$PWD\docs\screenshots\03_inainte_dupa.png" "http://127.0.0.1:5055/scan/3?vs=1"
# pagina dispozitivului: ia linkul din pagina principală (primul /device/...?scan=2) și fă captura la fel
```

Ține calea capturii **absolută**: cu cale relativă Edge nu scrie fișierul. Oprește serverul după (`Get-Process python | Stop-Process` doar dacă nu rulează nimic altceva).
