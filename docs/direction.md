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
| D4 | **Inventarul „ce e conectat la mine?”**: pagina cu toate dispozitivele (tip, vendor, MAC mascat, porturi), inclusiv cele fără probleme | RBRT (folosește `netscan/engine/devices.py` de la Radu) | FR-03 (tipul dispozitivului); restul de verificat în brief | După nucleu (mare parte există deja în UI) |
| D5 | **O singură acțiune pe rând, ordonată după risc**: „Fă asta acum”, apoi următoarea după ce o bifezi | RBRT (UI), Ayan (textul pasului) | De verificat în brief (FR-10 sau FR-14) | După nucleu |
| D6 | **Raportul „servicii văzute care nu sunt în catalog”**: ce servicii deschise a văzut motorul și n-au dat niciun finding; ajută la verificarea Test Set-ului | Radu | Nu e cerință; sprijină acuratețea pe Test Set | Dacă rămâne timp |

Reguli pentru toate funcțiile:
- **Motorul, catalogul, scorul și CSV-urile nu se schimbă.** Funcțiile direcției doar citesc ce produce motorul.
- **Fără agenți, fără log-uri, fără reparații automate.** Doar scanarea hotspotului echipei.
- Tot ce vine din scanare (titluri, hostname-uri, bannere) e **text nesigur**: escapat în UI, marcat ca date în prompturi.
- Tot ce e text pentru utilizator: RO și EN, max. 2 propoziții, fără jargon (sau cu termenul explicat în glosar).
- **Nimic nu iese din hotspot** (regula organizatorilor). D2 trebuie să meargă și fără internet, cu răspunsuri predefinite construite din scanare. Apelul la un LLM se activează doar dacă mentorii confirmă că e permis.

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

**P3 · Raportul de servicii din afara catalogului (pentru D6)**: fără schimbare de contract
- Fișier separat, de exemplu `unmatched_services.csv` (`file,ip,port,proto,service`), scris **doar la cerere** (o opțiune nouă la `analyze`).
- **Nu** modifică `findings.csv` și `scores.csv` (FR-15).

**P4 · Răspunsul asistentului (pentru D2)**: fără schimbare de contract
- Intern în `netscan/scan/assistant.py` (Ayan): `Answer(text, source: "llm" | "fallback", problems: [str])`, construit cu `ai_check.check_llm_text()` și `choose_text()` din același folder.
- RBRT îl afișează; forma lui `Answer` se stabilește între Ayan și RBRT.

## Fraza de pitch

> „Instrumente ca Wazuh protejează firmele, dar cer un server, agenți pe fiecare dispozitiv și un expert care să citească alertele. Noi am făcut versiunea pentru oricine: o scanare, un scor, o reparație pe rând, explicată pe înțelesul tuturor.”
