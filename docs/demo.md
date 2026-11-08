# Pregătirea demo-ului și a jurizării

> Lista de verificat pe laptopul de demo, în ordine. Jurizarea (ghidul, secțiunea 10): 7 minute pitch + 8 minute verificări live.

## 1. Cu 15 minute înainte

- [ ] **Rețeaua:** laptopul e conectat **doar** la `RSH-Ibiza2028` (fără cablu). Rețeaua e setată ca **Private** în Windows.
- [ ] **VPN oprit** (Tailscale, WireGuard, OpenVPN, AnyConnect, ZeroTier…). Cu un VPN pornit, tool-ul refuză scanarea și protecția live: `Ai un VPN pornit (…). … oprește VPN-ul înainte de scanare.`
- [ ] **Adaptoarele virtuale dezactivate** (VirtualBox Host-Only, WSL/Hyper-V). Tool-ul le ignoră oricum; WSL își poate reface adaptorul după repornire; verifică:
  `Get-NetAdapter -IncludeHidden | Where-Object InterfaceDescription -match "VirtualBox|Hyper-V Virtual Ethernet"` → `Disabled`.
- [ ] **`.env`** are `NETSCAN_EXPECTED_SSID=RSH-Ibiza2028`, `NETSCAN_REQUIRE_SSID=1`, `NETSCAN_SALT`, iar pentru AI-ul local `NETSCAN_LOCAL_KEEP_ALIVE=3h`.
- [ ] `python -m netscan network` → `Rețea Wi-Fi: RSH-Ibiza2028`, `Stare: OK` și `Rețeaua: hotspotul echipei (scanez doar în 172.20.10.0/28)` (cod de ieșire 0).
- [ ] **Bază de date curată pentru demo:** `NETSCAN_DB_PATH=data/demo.db` în `.env` (un fișier nou, fără scanări sau pași vechi), sau „Șterge istoricul meu” din Progres.
- [ ] **Valorile implicite:** protecția live **oprită** la deschiderea aplicației; ușa-capcană **nebifată** (o bifăm doar dacă o arătăm).
- [ ] `pytest` trece.

## 2. AI-ul local (dacă îl arătăm)

- [ ] Ollama pornit (iconița din bara de sistem) și ascultă doar pe `127.0.0.1:11434`.
- [ ] **Încălzirea modelului** (prima încărcare poate depăși 30 s): `ollama run qwen2.5:7b "salut"`.
  Cu `NETSCAN_LOCAL_KEEP_ALIVE=3h` rămâne încărcat 3 ore după fiecare întrebare (ocupă ~5 GB RAM: închide programele de care nu ai nevoie).
- [ ] Probă: `python -m netscan ask fixtures/validation/V2_smart_home.xml "Ce fac întâi?" --local-ai` → `[AI local, verificat de validator]` în câteva secunde.
- [ ] Demo validator: `python -m netscan ask fixtures/validation/V2_smart_home.xml x --verify-text "Închide portul 23 pe 192.168.1.99 și sună la 0721 234 567."` → `RESPINS`.

## 3. Lab-ul și funcțiile de supraveghere

- [ ] Laptopul-țintă pornit cu serviciile din `docs/lab.md` (redis, mosquitto, nginx, telnet și FTP false, SSH).
- [ ] **Ușa-capcană (doar dacă o arătăm):** regula de firewall doar pe Private (comanda o afișează `python -m netscan trap`), apoi în aplicație bifa „Pornește și ușa-capcană” la pornirea protecției live (sau, din terminal, `python -m netscan trap --confirm`).
  Demo: de pe laptopul-țintă, `telnet <IP-laptop-demo> 2323` → alerta apare live. Capcana nu citește nimic: notează doar IP, ora și portul și închide.
- [ ] (Opțional) `python -m netscan listen --confirm` și `python -m netscan watch --every 10 --confirm` (terminal de Administrator); apoi, în terminalul normal, `python -m netscan import-scans` ca alertele și scanările să apară în UI.
- [ ] **UI:** `NETSCAN_SCANS_DIR=fixtures/lab` (pentru istoricul înainte/după al lab-ului) și `python -m netscan ui`. Pașii exacți (istoric încărcat, pagina deschisă, fereastra, notificări oprite, capturi pentru planul B): [demo_setup.md](demo_setup.md).

## 3a. Demo-ul în aplicație, pas cu pas

1. `start.bat` → **Acasă**: „Pe scurt” (verdict, scor, *Risc ridicat / mediu / scăzut / Doar de știut*) și **„Fă asta întâi”**.
2. Jos pe Acasă: bifează consimțământul („în hotspot sunt doar dispozitivele noastre…”), apoi **„Pornește protecția live”**. Fără bifă nu pornește nimic.
3. Laptopul-țintă apare ca dispozitiv nou: alertă, dar nu îl atingem. Apasă **„Da, e al nostru”** → de acum îi verificăm porturile riscante.
4. Bifează consimțământul de scanare și **„Scanează acum”** → fereastra UAC → „Da”. Cât rulează, verificările live așteaptă (scanarea folosește `--min-rate 80 --max-rate 100`). La final rezultatul apare pe Acasă și în Progres.
5. Pe laptopul-țintă oprește un serviciu (secțiunea 3b), apoi „Am făcut asta” → „Verificat”, scorul îl recalculează motorul.
6. **Progres** → **„Vezi dovada”** la scanarea nouă: ce s-a reparat, ce a rămas, ce e nou.
7. (Opțional) asistentul: „Cum scot un dispozitiv din rețea?” → pașii siguri (parola hotspotului: iPhone Setări → Hotspot personal → Parolă Wi-Fi; Android Setări → Conexiuni → Hotspot mobil) și „SafeEel nu deconectează niciodată singur un dispozitiv”.

## 3b. „Am făcut asta” și scorul (de ce la unii se schimbă, la alții nu)

Butonul nu crede utilizatorul pe cuvânt (`netscan/ui/verify.py`): încearcă **o singură conexiune TCP** la portul problemei. Cifra mare rămâne **scorul standard al scanării** (ca în `scores.csv`); dedesubt apare „După reparațiile confirmate (N): X din 100”, recalculat de motor, **doar** pentru pașii confirmați. Altfel pasul e „bifat, neconfirmat” și scorul rămâne, intenționat.

| Situația | Ce scrie aplicația | „După reparațiile confirmate” |
|---|---|---|
| Laptopul e pe `RSH-Ibiza2028`, `.env` are `NETSCAN_EXPECTED_SSID=RSH-Ibiza2028`, scanarea e din rețeaua noastră (lab, `172.20.10.x`) și portul **refuză** conexiunea | „Verificat: portul … nu mai răspunde” | **apare / crește** |
| Aceleași condiții, dar portul **acceptă** conexiunea (serviciul încă rulează) | „răspunde încă, pasul rămâne de făcut” | nu apare |
| `NETSCAN_EXPECTED_SSID` lipsește din `.env`, laptopul nu e pe hotspot, sau scanarea e din altă rețea (de ex. Validation Set, `192.168.1.x`) | „nu e în rețeaua la care e conectat acum laptopul” | nu apare |
| Dispozitivul nu răspunde deloc (oprit, firewall care ignoră) | „nu a răspuns deloc … neconfirmat” | nu apare |
| Port UDP sau problemă fără port (UNKNOWN_DEVICE) | „nu îl pot verifica de aici” | nu apare (doar la o scanare nouă) |

Verificat pe 7 nov. (Oneata), pe hotspot: FTP pe `172.20.10.14:2121` din `scan_03_after.xml` → fără `NETSCAN_EXPECTED_SSID`: „nu e în rețeaua ta”; cu el: „verificat” (lab-ul era oprit); o problemă din V1 (`192.168.1.1`) → „nu e în rețeaua ta”.

- **O scanare mai nouă a aceleiași rețele** confirmă și ea reparațiile (dispozitivul e acolo, problema nu): pe scanarea veche apare „După reparațiile confirmate” și linkul „Există o scanare mai nouă … Vezi scanarea nouă →”. Scorul scanării vechi nu se schimbă (de ex. `scan_01_before` rămâne 0).
- **Pe Windows:** refuzul unui port închis vine după ~2 s. Timpul de verificare e 3 s din commit-ul `886dcee`; pe un `main` mai vechi (1,5 s) pasul ieșea mereu „fără răspuns”. Dați `git pull` înainte de demo.
- **Pentru demo:** laptopul de demo pe hotspot, cu `NETSCAN_EXPECTED_SSID` în `.env`, UI cu `NETSCAN_SCANS_DIR=fixtures/lab`. Laptopul-țintă pe hotspot, cu lab-ul **pornit**. Pe laptopul-țintă se oprește un serviciu (de ex. `docker compose -f lab/docker-compose.yml stop redis`), apoi în UI „Am făcut asta” la DB_EXPOSED → „Verificat”, iar sub scor apare „După reparațiile confirmate (1): …”. Cu lab-ul oprit de tot, toți pașii ies „verificat” din prima (nu mai e nimic de arătat).

## 4. Cele 7 verificări live, în ordinea juriului

| # | Verificarea | Ce rulăm / arătăm |
|---|---|---|
| 1 | Re-rulare | `python -m netscan analyze <folderul Test Set> --out out` pe commit-ul cu tag-ul `final`; fișierele identice cu cele încărcate |
| 2 | Sarcina hands-on | UI, pagina Acasă: „Pe scurt” (cel mai periculos) și „Fă asta întâi” |
| 3 | Explicații | UI sau `ask "Ce înseamnă <cod>?"`; la FTP/Telnet/HTTP apare și „Ce vede cineva care ascultă” |
| 4 | Guardrail | `python -m netscan scan 8.8.8.8` și `python -m netscan scan 192.168.1.0/24` → refuz; `scan 172.20.10.14` → doar dry-run (în UI: consimțământul de pe Acasă și pagina „Ce știe SafeEel despre tine”) |
| 5 | Fișier stricat | `fixtures/validation/V7_broken.xml` → ERROR, fără crash (UI și `analyze`) |
| 6 | Istoric | UI: salvează `scan_01_before.xml`, apoi `scan_03_after.xml`; **Progres** → „Vezi dovada” → scor 0 → 30, 2 probleme rezolvate (sau `python -m netscan diff`) |
| 7 | Fără secrete | `gitleaks git` și `gitleaks dir` pe repo → „no leaks found” |

## 5. După jurizare

- [ ] În aplicație: „Oprește protecția live” (oprește și capcana și scanarea automată).
- [ ] Oprește `trap`, `listen`, `watch` (Ctrl+C) și șterge regula de firewall: `Remove-NetFirewallRule -DisplayName netscan-trap`.
- [ ] Eliberează memoria: `ollama stop qwen2.5:7b`.
- [ ] Laptopul-țintă: `docker compose -f lab/docker-compose.yml down`, Ctrl+C pe serviciile false, `sudo systemctl stop sshd`.
- [ ] Dacă e nevoie, reactivează adaptoarele virtuale (Administrator): `Enable-NetAdapter -Name "Ethernet 2","vEthernet (WSL (Hyper-V firewall))"`.
- [ ] Oprește hotspotul.
