# Pregătirea demo-ului și a jurizării

> Lista de verificat pe laptopul de demo, în ordine. Jurizarea (ghidul, secțiunea 10): 7 minute pitch + 8 minute verificări live.

## 1. Cu 15 minute înainte

- [ ] **Rețeaua:** laptopul e conectat **doar** la `RSH-Ibiza2028` (fără cablu, fără VPN). Rețeaua e setată ca **Private** în Windows.
- [ ] **Adaptoarele virtuale dezactivate** (VirtualBox Host-Only, WSL/Hyper-V). WSL își poate reface adaptorul după repornire; verifică:
  `Get-NetAdapter -IncludeHidden | Where-Object InterfaceDescription -match "VirtualBox|Hyper-V Virtual Ethernet"` → `Disabled`.
- [ ] **`.env`** are `NETSCAN_EXPECTED_SSID=RSH-Ibiza2028`, `NETSCAN_SALT`, iar pentru AI-ul local `NETSCAN_LOCAL_KEEP_ALIVE=3h`.
- [ ] `python -m netscan network` → `Rețea Wi-Fi: RSH-Ibiza2028`, `Scanare live: permisă`.
- [ ] `pytest` trece.

## 2. AI-ul local (dacă îl arătăm)

- [ ] Ollama pornit (iconița din bara de sistem) și ascultă doar pe `127.0.0.1:11434`.
- [ ] **Încălzirea modelului** (prima încărcare poate depăși 30 s): `ollama run qwen2.5:7b "salut"`.
  Cu `NETSCAN_LOCAL_KEEP_ALIVE=3h` rămâne încărcat 3 ore după fiecare întrebare (ocupă ~5 GB RAM: închide programele de care nu ai nevoie).
- [ ] Probă: `python -m netscan ask fixtures/validation/V2_smart_home.xml "Ce fac întâi?" --local-ai` → `[AI local, verificat de validator]` în câteva secunde.
- [ ] Demo validator: `python -m netscan ask fixtures/validation/V2_smart_home.xml x --verify-text "Închide portul 23 pe 192.168.1.99 și sună la 0721 234 567."` → `RESPINS`.

## 3. Lab-ul și funcțiile de supraveghere

- [ ] Laptopul-țintă pornit cu serviciile din `docs/lab.md` (redis, mosquitto, nginx, telnet și FTP false, SSH).
- [ ] **Ușa-capcană:** regula de firewall doar pe Private (comanda o afișează `python -m netscan trap`), apoi `python -m netscan trap --confirm`.
  Demo: de pe laptopul-țintă, `telnet <IP-laptop-demo> 2323` → alerta apare live.
- [ ] (Opțional) `python -m netscan listen --confirm` și `python -m netscan watch --every 10 --confirm` (terminal de Administrator); apoi, în terminalul normal, `python -m netscan import-scans` ca alertele și scanările să apară în UI.
- [ ] **UI:** `NETSCAN_SCANS_DIR=fixtures/lab` (pentru istoricul înainte/după al lab-ului) și `python -m netscan ui`.

## 3b. „Am făcut asta” și scorul (de ce la unii se schimbă, la alții nu)

Butonul nu crede utilizatorul pe cuvânt (`netscan/ui/verify.py`): încearcă **o singură conexiune TCP** la portul problemei. Scorul se recalculează (de motor) **doar** dacă pasul e confirmat. Altfel pasul e „bifat, neconfirmat” și scorul rămâne, intenționat.

| Situația | Ce scrie aplicația | Scorul |
|---|---|---|
| Laptopul e pe `RSH-Ibiza2028`, `.env` are `NETSCAN_EXPECTED_SSID=RSH-Ibiza2028`, scanarea e din rețeaua noastră (lab, `172.20.10.x`) și portul **refuză** conexiunea | „Verificat: portul … nu mai răspunde” | **se schimbă** |
| Aceleași condiții, dar portul **acceptă** conexiunea (serviciul încă rulează) | „răspunde încă, pasul rămâne de făcut” | nu se schimbă |
| `NETSCAN_EXPECTED_SSID` lipsește din `.env`, laptopul nu e pe hotspot, sau scanarea e din altă rețea (de ex. Validation Set, `192.168.1.x`) | „nu e în rețeaua la care e conectat acum laptopul” | nu se schimbă |
| Dispozitivul nu răspunde deloc (oprit, firewall care ignoră) | „nu a răspuns deloc … neconfirmat” | nu se schimbă |
| Port UDP sau problemă fără port (UNKNOWN_DEVICE) | „nu îl pot verifica de aici” | nu se schimbă (doar la o scanare nouă) |

Verificat pe 7 nov. (Oneata), pe hotspot: FTP pe `172.20.10.14:2121` din `scan_03_after.xml` → fără `NETSCAN_EXPECTED_SSID`: „nu e în rețeaua ta”; cu el: „verificat” (lab-ul era oprit); o problemă din V1 (`192.168.1.1`) → „nu e în rețeaua ta”.

- **Pe Windows:** refuzul unui port închis vine după ~2 s. Timpul de verificare e 3 s din commit-ul `886dcee`; pe un `main` mai vechi (1,5 s) pasul ieșea mereu „fără răspuns”. Dați `git pull` înainte de demo.
- **Pentru demo:** laptopul de demo pe hotspot, cu `NETSCAN_EXPECTED_SSID` în `.env`, UI cu `NETSCAN_SCANS_DIR=fixtures/lab`. Laptopul-țintă pe hotspot, cu lab-ul **pornit**. Pe laptopul-țintă se oprește un serviciu (de ex. `docker compose -f lab/docker-compose.yml stop redis`), apoi în UI „Am făcut asta” la DB_EXPOSED → „Verificat” și scorul crește. Cu lab-ul oprit de tot, toți pașii ies „verificat” din prima (nu mai e nimic de arătat).

## 4. Cele 7 verificări live, în ordinea juriului

| # | Verificarea | Ce rulăm / arătăm |
|---|---|---|
| 1 | Re-rulare | `python -m netscan analyze <folderul Test Set> --out out` pe commit-ul cu tag-ul `final`; fișierele identice cu cele încărcate |
| 2 | Sarcina hands-on | UI: cardul „Cel mai periculos dispozitiv — Fă asta întâi” |
| 3 | Explicații | UI sau `ask "Ce înseamnă <cod>?"`; la FTP/Telnet/HTTP apare și „Ce vede cineva care ascultă” |
| 4 | Guardrail | `python -m netscan scan 8.8.8.8` și `python -m netscan scan 192.168.1.0/24` → refuz; `scan 172.20.10.14` → doar dry-run |
| 5 | Fișier stricat | `fixtures/validation/V7_broken.xml` → ERROR, fără crash (UI și `analyze`) |
| 6 | Istoric | UI: salvează `scan_01_before.xml`, apoi `scan_03_after.xml` → scor 0 → 30, 2 probleme rezolvate (sau `python -m netscan diff`) |
| 7 | Fără secrete | `gitleaks git` și `gitleaks dir` pe repo → „no leaks found” |

## 5. După jurizare

- [ ] Oprește `trap`, `listen`, `watch` (Ctrl+C) și șterge regula de firewall: `Remove-NetFirewallRule -DisplayName netscan-trap`.
- [ ] Eliberează memoria: `ollama stop qwen2.5:7b`.
- [ ] Laptopul-țintă: `docker compose -f lab/docker-compose.yml down`, Ctrl+C pe serviciile false, `sudo systemctl stop sshd`.
- [ ] Dacă e nevoie, reactivează adaptoarele virtuale (Administrator): `Enable-NetAdapter -Name "Ethernet 2","vEthernet (WSL (Hyper-V firewall))"`.
- [ ] Oprește hotspotul.
