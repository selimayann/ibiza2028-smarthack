# Direcția produsului

> Se lucrează la ea **doar după ce nucleul trece verificarea mentorului** (cerințele Must FR-01…FR-11 și FR-15).
> Wazuh apare doar aici și în pitch, ca termen de comparație. Nu folosim numele sau logo-ul lui în produs, UI sau README.

## Într-o propoziție

**Un „centru de securitate” pentru oameni netehnici:** vede ce e conectat la rețeaua ta, observă ce se schimbă de la o scanare la alta și îți spune, pe rând și pe înțelesul tău, ce să repari întâi.

## Wazuh vs. noi

| | Wazuh | Noi |
|---|---|---|
| **Pentru cine** | Firme, echipe de securitate, analiști SOC | Familii, oameni fără pregătire tehnică |
| **Cum vede rețeaua** | Agenți instalați pe fiecare dispozitiv trimit log-uri și date de sistem la un server central | O scanare nmap a rețelei proprii (hotspotul echipei), din afară, fără să instalăm nimic pe dispozitive |
| **Ce dă utilizatorului** | Dashboard-uri cu mii de alerte, nivele de regulă, termeni tehnici; are nevoie de un expert care să le citească | Un scor, cel mai periculos dispozitiv, o singură acțiune pe rând, explicată în RO/EN în max. 2 propoziții |
| **Instalare** | Server (manager, indexer, dashboard) + un agent pe fiecare dispozitiv | `pip install` pe un singur laptop; nimic pe celelalte dispozitive |

## Ce preluăm și ce NU

| Idee de la Wazuh | Preluăm? | Cum / de ce |
|---|---|---|
| Inventarul dispozitivelor | **Da** | „Ce e conectat la mine?”: lista dispozitivelor din scanare, cu tipul ghicit (FR-03), vendor, porturi. Fără agenți: doar ce se vede din rețea. |
| Monitorizare în timp și alerte la schimbări | **Da** | Din `diff()`-ul existent între două scanări: dispozitiv nou/dispărut, port nou deschis/închis, problemă nouă/rezolvată, scris ca un „jurnal de securitate” în limbaj simplu. |
| Maparea pe standarde (Wazuh mapează pe PCI DSS, GDPR, CIS etc.) | **Da** | Fiecare dintre cele 15 coduri → CIS Controls v8 și OWASP IoT Top 10 (bonus în brief), afișat lângă explicație. |
| Prioritizarea după gravitate | **Da** | O singură acțiune recomandată pe rând, în ordinea de risc din contract (puncte ↓, severitate ↓, IP ↑). |
| Agenți pe dispozitive | **Nu** | Brief-ul cere scanarea rețelei proprii; o familie nu instalează agenți pe televizor sau cameră. |
| Colectarea log-urilor | **Nu** | În afara brief-ului și o problemă de confidențialitate; noi nu citim nimic de pe dispozitive. |
| Reparații automate (active response) | **Nu** | Riscant și în afara brief-ului: tool-ul doar explică; omul repară. |
| Server central, indexer, dashboard-uri multiple | **Nu** | Prea complex pentru publicul nostru; totul rulează local, pe `127.0.0.1`. |
| Alerte în jargon, în volum mare | **Nu** | Exact problema pe care o rezolvăm: puține mesaje, în limbaj simplu, cu un singur pas următor. |

## Funcțiile direcției

| # | Funcție | Responsabil | Cerința din brief | Prioritate |
|---|---|---|---|---|
| D1 | **Jurnalul de securitate și alertele la schimbări** (din `diff()`): dispozitiv nou, port nou, problemă nouă sau rezolvată, în limbaj simplu, RO/EN | RBRT | FR-13 | După nucleu |
| D2 | **Asistentul care răspunde doar din scanare**: întrebări în limbaj simplu; orice port, IP, cod sau CVE care nu există în scanare → răspunsul e respins și se folosește textul predefinit | Ayan (AI și siguranță: `netscan/scan/assistant.py` + validatorul `netscan/scan/ai_check.py`) | FR-12 | După nucleu |
| D3 | **Maparea pe CIS Controls v8 și OWASP IoT Top 10** pentru fiecare dintre cele 15 coduri, afișată lângă explicație | Oneata (explicații: `netscan/explain/standards.py`) | Bonus | Dacă rămâne timp |
| D4 | **Inventarul „ce e conectat la mine?”**: pagina cu toate dispozitivele (tip, producător, MAC mascat, porturi), inclusiv cele fără probleme | RBRT (UI), pe datele FR-03 de la Ayan (`netscan/scan/device_info.py`: producător IEEE offline, MAC privat, tip) | FR-03 + FR-11 (Must, deja în nucleu); direcția doar le pune pe o pagină „inventar” | După nucleu (mare parte există deja în UI) |
| D5 | **O singură acțiune pe rând, ordonată după risc**: „Fă asta acum”, apoi următoarea după ce o bifezi | RBRT (UI), Oneata (textul pasului) | FR-11 (UI simplu) și criteriul „Ease of use” (20%): „cel mai periculos dispozitiv și ce fac întâi” | După nucleu |
| D6 | **Raportul „servicii văzute care nu sunt în catalog”**: ce servicii deschise a văzut motorul și n-au dat niciun finding; ajută la verificarea Test Set-ului | Radu | Nu e cerință, dar e în procedura de rulare a Test Set-ului de la ora 20 (ghid, secțiunea 9) | **Înainte de ora 20** |
| D7 | **Raportul de o pagină pentru furnizorul IT** (HTML/PDF): scor, dispozitive, findings, pașii de reparare | RBRT | FR-14 (Should/Could) | După nucleu (în ghid: orele 16–20) |
| D9 | **Monitorul periodic (`watch`)**: scanare la interval doar pe hotspot, alerte la dispozitiv sau port nou, probleme noi sau rezolvate, scor; varianta fără agenți a supravegherii continue | Ayan | FR-13 | După nucleu (**făcut**) |
| D10 | **Ușa-capcană (`trap`)**: Telnet fals pe laptop; alertă când cineva din hotspot încearcă să intre; doar IP, oră, port, fără conținut | Ayan | Inovație (10%) | După nucleu (**făcut**) |
| D11 | **Ascultarea pasivă (`listen`)**: numele anunțate de dispozitive (mDNS/SSDP), fără să trimită nimic; inspirat din Wireshark | Ayan | FR-03 (nume) + FR-13 (dispozitiv nou) | După nucleu (**făcut**) |
| D12 | **„Ce vede cineva care ascultă”**: exemplu inventat de logare în clar la FTP/Telnet/HTTP, lângă explicație | Ayan (date), RBRT (UI) | Explicații (15%) | După nucleu (**făcut** în asistent) |
| D13 | **Baza de cunoștințe pentru asistent (RAG)**: 56 de întrebări RO/EN, căutare locală BM25; răspuns direct fără AI, context pentru modelul local | Ayan | FR-12 + Explicații (15%) | După nucleu (**făcut**) |
| D8 | **Model AI local (Qwen, rulat cu Ollama pe laptop, fără internet)**: reformulează răspunsurile asistentului; validatorul respinge orice IP, port, cod, CVE sau telefon inventat și se revine la textul predefinit. Scopul: demonstrația live a validatorului anti-halucinații | Ayan | FR-12 + Inovație (10%; ghidul, secțiunea 6) | După nucleu; **confirmat de mentori** (întrebarea 14: da) |

> **FR-10 (Istoric) e cerință Must**, deci face parte din nucleu, nu din direcție: dispozitive noi/dispărute, porturi deschise/închise, findings rezolvate (V6a → V6b: 3), trendul scorului. D1 (alertele, FR-13) se construiește peste el.

Reguli pentru toate funcțiile:
- **Motorul, catalogul, scorul și CSV-urile nu se schimbă.** Funcțiile direcției doar citesc ce produce motorul.
- **Fără agenți, fără log-uri, fără reparații automate.** Doar scanarea hotspotului echipei.
- Tot ce vine din scanare (titluri, hostname-uri, bannere) e **text nesigur**: escapat în UI, marcat ca date în prompturi.
- Tot ce e text pentru utilizator: RO și EN, max. 2 propoziții, fără jargon (sau cu termenul explicat în glosar).
- **Nimic nu iese din hotspot** (regula organizatorilor). D2 trebuie să meargă și fără internet, cu răspunsuri predefinite construite din scanare. AI online: **nu** (mentorii, întrebarea 13). Un model **local** (D8) e permis (mentorii, întrebarea 14), oprit implicit, pornit explicit pentru demo.

## Propuneri de contract

> **Doar propuneri. Nu sunt aplicate.** `docs/contract.md`, `netscan/model.py` și `fixtures/sample.json` se schimbă doar după ce echipa e de acord, toate trei în același commit.

**P1 · Tipul `Alert` (pentru D1), derivat din `ScanDiff`**
```
Alert
  kind: "NEW_DEVICE" | "DEVICE_GONE" | "PORT_OPENED" | "PORT_CLOSED" | "FINDING_NEW" | "FINDING_RESOLVED"
  scan_id: int                 # scanarea în care s-a observat schimbarea
  started_at: int | null       # momentul scanării (ordonează jurnalul)
  device_id: str
  ip: str
  port: int | null
  proto: "tcp" | "udp" | null
  code: str | null             # doar la FINDING_*
  severity: "high" | "medium" | "low" | "info" | null   # doar la FINDING_*; vine din motor
```
- Se calculează din `diff(old, new)`; nu adaugă nimic nou în motor.
- Varianta minimă: `Alert` rămâne intern în `netscan/ui/` și nu intră în contract. Intră în contract doar dacă îl folosesc și alte părți (de exemplu asistentul de la D2).
- Ordinea în jurnal: `started_at` ↓, apoi `FINDING_NEW` > `NEW_DEVICE` > `PORT_OPENED` > `FINDING_RESOLVED` > `PORT_CLOSED` > `DEVICE_GONE`, apoi IP numeric ↑.

**P2 · Maparea pe standarde (pentru D3)**: fără schimbare de contract
- Un fișier nou, `netscan/explain/standards.py` (Oneata), cu un dicționar static `cod → {"cis": [...], "owasp_iot": [...]}` și o funcție `get_standards(code, lang)`.
- RBRT îl citește direct în UI. `get_explanation()` rămâne compatibil (doar chei noi, dacă e cazul), deci UI-ul existent nu se strică.
- Punctul de pornire din ghid (secțiunea 11), de verificat în sursele oficiale: majoritatea codurilor → OWASP „servicii de rețea nesigure” și CIS 4.8 (dezactivarea serviciilor inutile); OUTDATED_SERVICE → „componente nesigure sau învechite”; TELNET / FTP / HTTP în clar → „transfer și stocare nesigure a datelor”; UPNP → „setări implicite nesigure”; UNKNOWN_DEVICE → inventarul dispozitivelor.

**P3 · Raportul de servicii din afara catalogului (pentru D6)**: fără schimbare de contract
- Lista se afișează la `analyze` (ghidul: „programul afișează și o listă «servicii văzute care nu sunt în catalog»”) și, la cerere, se scrie într-un fișier separat, de exemplu `unmatched_services.csv` (`file,ip,port,proto,service`).
- **Nu** modifică `findings.csv` și `scores.csv` (FR-15).

**P4 · Răspunsul asistentului (pentru D2)**: fără schimbare de contract
- Intern în `netscan/scan/assistant.py` (Ayan): `Answer(text, source: "llm" | "fallback", problems: [str])`, construit cu `ai_check.check_llm_text()` și `choose_text()` din același folder.
- RBRT îl afișează; forma lui `Answer` se stabilește între Ayan și RBRT.

**P5 · Modelul local (pentru D8)**: fără schimbare de contract
- Fișier nou `netscan/scan/local_llm.py` (Ayan): o funcție `llm(context) -> str` pentru parametrul `llm` din `assistant.answer()`, care cheamă Ollama doar pe `127.0.0.1` (cu timeout, fără dependențe noi).
- Oprit implicit; pornit doar cu o variabilă explicită, de exemplu `NETSCAN_LOCAL_LLM=1` (și numele modelului în `NETSCAN_LOCAL_MODEL`). Fără ea, totul rămâne pe textele predefinite.

## Fraza de pitch

> „Instrumente ca Wazuh protejează firmele, dar cer un server, agenți pe fiecare dispozitiv și un expert care să citească alertele. Noi am făcut versiunea pentru oricine: o scanare, un scor, o reparație pe rând, explicată pe înțelesul tuturor.”
