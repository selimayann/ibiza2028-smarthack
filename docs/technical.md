# Pagina tehnică · Secure Networks, Simply Explained

> Echipa **Ibiza2028** · R Systems Hackathon 2026 · Detalii: [README](../README.md), [lab.md](lab.md), [rules.md](rules.md), [questions.md](questions.md).

## Ce face
`netscan` citește scanări nmap XML (offline) și scanează live **doar** hotspotul echipei. Aplică exact catalogul oficial de 15 coduri, calculează scorul standard `max(0, 100 − puncte)` și explică fiecare problemă în română și engleză (max. 2 propoziții, 1–5 pași). Păstrează istoricul și arată înainte/după. **Codul decide, modelul formulează, codul verifică:** findings, severități și scoruri vin doar din reguli deterministe.

## Arhitectura
```
scan --confirm (singurul pas cu drepturi de admin)  ─┐
fișiere nmap XML (Validation / Test Set, lab) ───────┴─> parser sigur (defusedxml, 20 MB)
  -> model (Scan / Host / Port / Finding, docs/contract.md) -> motor de reguli (catalogul exact) -> scor
  -> findings.csv + scores.csv (FR-15) · SQLite local (istoric, diff) · explicații RO/EN · UI web pe 127.0.0.1
```
| Modul | Ce face |
|---|---|
| `netscan/scan/` | FR-01 detectarea rețelei · FR-02 guardrail · runner nmap · FR-03 producător și tip · validatorul AI · protecția live și scanarea din aplicație |
| `netscan/engine/` | parser, cele 15 reguli, scor, export CSV |
| `netscan/explain/` | textele RO/EN pentru cele 15 coduri, glosar |
| `netscan/ui/` | Flask + Jinja2 (autoescape), SQLite, diff, „cel mai periculos dispozitiv + ce fac întâi” |

Stack: Python 3.11+, defusedxml, Flask, SQLite, psutil, pytest (470 de teste). Instalare: `pip install -e ".[dev]"`.

## Scanarea live: doar rețeaua noastră
1. **Interfața:** cea cu ruta implicită; interfețele virtuale (Docker, WSL/Hyper-V, VirtualBox, VPN) sunt ignorate, inclusiv un adaptor VirtualBox numit „Ethernet 2” (după descriere). Două rețele fizice active → refuz.
2. **Rețeaua Wi-Fi** trebuie să fie `NETSCAN_EXPECTED_SSID` (`RSH-Ibiza2028`); dacă nu e setată sau diferă → refuz.
3. **Ținta** (`check_target`): doar IPv4 privat din subnetul hotspotului. Refuz: IP public, `100.64.0.0/10`, subnet mai mare, rețeaua venue, hostname (fără DNS), injecții. Mesaje RO/EN.
4. **nmap:** listă de argumente, fără shell; ținta normalizată de guardrail; `-e <interfață>`; `--max-rate 100`; fără `--confirm` doar dry-run.
5. **Nimic nu iese din hotspot:** `-n` (fără DNS invers) și portul 53 fără sonde de versiune (`--versiondb` cu `Exclude T:53,U:53`), ca telefonul să nu trimită mai departe interogările DNS.

Comanda: `nmap -n -sS -sU -sV --script http-title -p T:<top 1000>,1883,6379,27017,U:53,123,161,1900,5353 --max-rate 100 -e <if> --versiondb <copie> -oX scans/<dată>.xml <țintă>`. Porturile 1883, 6379 și 27017 (mqtt, redis, mongodb) sunt în catalog, dar nu în top 1000 nmap.

## Lab-ul
Hotspot iPhone `RSH-Ibiza2028` (`172.20.10.0/28`), laptop-scanner (Windows, nmap 7.993 + Npcap 1.90), laptop-țintă (Fedora): redis, mosquitto 1.6, nginx cu „Admin Login” (Docker), telnet și FTP false în Python (nu execută nimic, orice login eșuează), SSH. 3 scanări făcute cu tool-ul: înainte, repetată (identică), după oprirea redis și a telnet-ului. **8 coduri diferite; scor 0 → 30** (DB_EXPOSED și TELNET_OPEN rezolvate). Pași și findings așteptate: [lab.md](lab.md).

## Cifre
- **Validation Set:** 24/24 de rânduri și 8/8 scoruri identice cu baremul (V7 = ERROR); două rulări identice byte cu byte.
- **Analiză:** 0,27 s pentru cele 8 fișiere. **Scanare live:** 3 min 25 s pentru /28 cu 2 dispozitive.
- **Securitate:** gitleaks pe istoric și pe fișiere: fără secrete. MAC real aruncat în parser (doar `AA:BB:CC:XX:XX:XX` și hash cu salt local). SQL parametrizat, autoescape, buton „șterge istoricul”.

## Presupuneri (confirmate de mentori, vezi questions.md)
Doar `state="open"`; decizia după numele serviciului, nu după port; `upnp`/`snmp` doar pe UDP; HTTP_ADMIN = `http` exact, fără `tunnel="ssl"`, titlu cu cuvintele cheie ca subșir, fără diferență de litere. `mosquitto version X` = MQTT_EXPOSED. `method="table"` contează ca `probed`. Samba `3.X - 4.X` nu e învechit; Samba învechit → SMB_EXPOSED + OUTDATED_SERVICE o singură dată, pe 445 (altfel 139). MAC fără producător = „fără producător” la UNKNOWN_DEVICE. Coloana `file` = doar numele fișierului.

## Supraveghere fără agenți
- **Monitorul (`watch`, FR-13):** scanare periodică a hotspotului (minimum 10 min), cu verificarea rețelei și a țintei la fiecare ciclu și alerte RO/EN în terminal la dispozitiv nou/plecat, port nou/închis, problemă nouă/rezolvată, scor schimbat (din `diff()`). **NFR-04:** pasul privilegiat (`scan --confirm`, ciclul lui `watch`) scrie doar XML; istoricul și alertele le scrie `import-scans`, ca utilizator normal (sub `sudo` sau alt cont de admin, baza ar ajunge altundeva sau ar rămâne a lui root).
- **Ușa-capcană (`trap`):** Telnet fals pe IP-ul din hotspot (idee de honeypot, ca OpenCanary): orice conexiune e o alertă. Păstrează doar IP, oră, port, local, 7 zile; nu păstrează nimic din ce s-a scris; nu răspunde spre cine a încercat.
- **Protecția live (Dashboard, `netscan/scan/live.py`):** rulează în aplicație, ca utilizator normal, doar după „Pornește protecția live” și doar cât timp verificările de la scanare (SSID, o singură rețea, guardrail) trec; le reface la ~10 s și intră singură în pauză altfel. Straturi: **prezența** la ~20 s (o datagramă UDP goală pe fiecare adresă din hotspot, legată de IP-ul din hotspot, ≤25/s, apoi tabela ARP a sistemului; Windows reverifică intrările vechi, deci plecările se văd în ~40 s), **porturile riscante** în fiecare minut (conexiune TCP închisă imediat, ≤10/s, porturile din catalog + cele din ultima scanare; prima verificare se compară cu ultima scanare), **ușa-capcană** pe IP-ul din hotspot. Nu decide probleme și nu calculează scor: le dă motorul, din scanarea completă.
- **Scanarea completă din aplicație (`elevate.py`, `scan_job.py`):** butonul pornește `python -I netscan/scan/_elevated.py scan|auto` prin fereastra de permisiune a sistemului (UAC / parola de admin / pkexec); comanda e fixă, procesul de admin refăce toate verificările și rulează exact comanda nmap de mai sus, plus `-v --stats-every 5s` (doar afișarea progresului). **NFR-04:** scrie doar în `scans/` (XML, copia bazei de sonde, `.scan_progress.json`, blocarea); aplicația citește progresul ca date nesigure și aduce scanarea terminată în istoric, ca utilizator normal.
- **Ascultarea pasivă (`listen`):** abonare la anunțurile mDNS/SSDP doar pe interfața hotspotului (permisă de ghid), parser cu limite stricte pentru pachete ostile, fără cereri și fără deschiderea link-urilor din anunțuri.
- **„Ce vede cineva care ascultă”:** pentru codurile necriptate, un exemplu inventat de logare la vedere (momentul „aha” din Wireshark), fără captură reală de trafic.
- Față de o platformă cu agenți (de ex. Wazuh): vedem toate dispozitivele, inclusiv camere și telefoane pe care nu se poate instala nimic, dar nu vedem ce e în interiorul lor (log-uri, fișiere, viruși).

## Limitări
- Porturile UDP `open|filtered` nu sunt raportate: nmap nu poate deosebi un port deschis de unul filtrat.
- Telefoanele și laptopurile moderne au **MAC aleatoriu** (fără producător), deci ies UNKNOWN_DEVICE după regula exactă; UI-ul le arată ca „adresă privată”.
- Producătorul din lista IEEE și tipul ghicit sunt doar pentru afișare; „gateway = router” se știe doar la scanarea live, nu dintr-un XML.
- Regulile urmează ce raportează nmap: dacă nmap identifică greșit un serviciu, și noi îl vedem greșit.
- **Durata:** cu `--max-rate 100`, UDP și detecția de versiuni, o rețea /24 cu multe dispozitive poate depăși 5 minute (NFR-07); nu am avut un /24 pe care avem voie să-l scanăm.
- nmap pe Windows nu se scanează pe sine: laptopul-scanner nu apare în rezultate.
- Dacă sistemul nu permite citirea numelui Wi-Fi (de ex. macOS recent), tool-ul doar avertizează.
- XML-urile din lab sunt în `fixtures/lab/`, neatinse; MAC-urile din ele sunt randomizate (adrese private), nu cele hardware.

## Folosirea LLM-ului
**Nu folosim AI online:** mentorii au confirmat că nu avem voie (întrebarea 13), din cauza regulii „fără alte rețele”. Toate explicațiile vin din textele predefinite RO/EN, iar tool-ul merge complet fără internet.

**AI local, opțional (D8, permis de mentori, întrebarea 14):** `ask --local-ai` cere unui model Qwen rulat cu Ollama pe laptop să reformuleze răspunsul construit de cod. Cererea merge doar spre `127.0.0.1` (orice altă adresă e refuzată, proxy-urile sunt ignorate), modelul primește doar textul deja construit, iar rezultatul trece prin validator; dacă e respins sau Ollama nu rulează, se afișează răspunsul predefinit. `ask --verify-text` arată live validatorul pe un text inventat.

Guvernanța rămâne în cod, pregătită pentru un model rulat local, fără internet:
- un model ar putea doar să formuleze: nu decide findings, severități sau scoruri;
- ar primi doar date structurate, fără MAC, cu titlurile de pagini marcate ca text nesigur (`ai_check.prompt_context`);
- **validatorul** (`ai_check.check_llm_text`) respinge orice IP, port, cod de finding, CVE sau număr de telefon care nu există în scanare, plus MAC-uri și link-uri; atunci se afișează textul predefinit.

**Baza de cunoștințe (RAG):** 56 de intrări RO/EN din `docs/knowledge_base.pdf`, căutate local cu BM25 (fără embeddings, fără internet). Fără AI, răspund direct la întrebările generale („am fost hackuit”, „pot bloca un dispozitiv?”); cu modelul local, sunt contextul lui. Scanarea are întâietate la întrebările despre rețea, iar refuzurile rămân refuzuri. Un test verifică că textele celor 15 coduri din document sunt identice cu cele din aplicație.

**Asistentul (FR-12)**, `netscan/scan/assistant.py`, comanda `ask`: răspunde cu texte predefinite RO/EN, construite din scanare, la ~20 de tipuri de întrebări: cel mai periculos dispozitiv, ce fac întâi, pasul următor, planul complet de reparații, toate problemele, porturile deschise, un cod sau un IP anume, scorul și cum se calculează, cât de grave sunt problemele, „e sigură rețeaua?” (cu limitele scanării), dispozitivele fără probleme, „ce s-a schimbat”, termeni din glosar („ce e un port?”), adresa privată, ce face aplicația, unde ajung datele; refuză politicos cererile despre alte rețele. Altfel spune clar că scanarea nu poate răspunde. Răspunsurile sunt construite de cod, fără niciun model AI; validatorul e testat cu texte „inventate” (porturi, IP-uri, CVE-uri, telefoane) care sunt respinse.
