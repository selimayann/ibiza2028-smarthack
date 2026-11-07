# Cum lucrăm

## Branch-uri

| Branch | Cine | Ce atinge |
|---|---|---|
| `engine` | Radu | `netscan/engine/`, `fixtures/validation/`, `fixtures/traps/`, `docs/rules.md`, `tests/test_validation_set.py`, `tests/test_traps.py` |
| `scan` | Oneata | `netscan/scan/`, `tests/test_guardrail.py`, `README.md`, `docs/questions.md`, `.gitignore`, `.env.example` |
| `explain` | Ayan | `lab/`, `fixtures/lab/`, `docs/lab.md`, apoi `netscan/explain/` |
| `ui` | RBRT | `netscan/ui/` |

- Fiecare lucrează pe branch-ul lui și face merge în `main` **doar ce merge** (testele trec).
- Commit-uri mici și dese, cu mesaje clare: `engine: regula SMB o dată pe dispozitiv`.
- Înainte de merge: `git pull origin main` pe branch-ul tău, rezolvă conflictele, rulează `pytest`.
- `main` trebuie să ruleze mereu. Dacă strici `main`, repari imediat.

## Fișiere comune

`docs/contract.md`, `netscan/model.py`, `netscan/cli.py`, `fixtures/sample.json`, `pyproject.toml`

- Se modifică **doar după ce anunți echipa**.
- Contractul, `model.py` și `sample.json` se schimbă **în același commit**.
- Fiecare adaugă comanda lui în `cli.py`, fără să le atingă pe ale celorlalți.

## Sincronizări până la ora 3

| Moment | Cine | Ce |
|---|---|---|
| 0:00 – 0:45 | toți | repo, contract, `model.py`, `sample.json`, întrebări pentru mentori |
| ~1:30 | Radu ↔ RBRT | `analyze` merge pe V1/V2; RBRT îl conectează în UI în locul lui `sample.json` |
| ~1:45 | Oneata → Ayan | lista top 1000 porturi TCP |
| ~2:30 | Oneata | validatorul de țintă legat în comanda `scan` (dry-run) |
| **3:00** | toți | verificarea comună (mai jos) |

## Verificarea de la ora 3

1. `python -m netscan analyze fixtures/validation/` rulează fără crash și scrie cele două CSV-uri; V7 dă `ERROR`.
2. `check_target` refuză un IP public și acceptă un IP din subnetul hotspotului.
3. UI-ul afișează date (din `sample.json` sau din motor).
4. Cele 3 scanări din lab sunt în `fixtures/lab/`, iar `analyze` pe `scan_03_after.xml` arată mai puține findings decât pe `scan_01_before.xml`.

## Direcția (după verificarea mentorului)

Detalii: [direction.md](direction.md). **Nu începe nimeni** până nu trece nucleul verificarea mentorului: cerințele Must (FR-01…FR-11, FR-15) merg, iar `pytest` trece pe `main`. O cerință Must lipsă plafonează nota tehnică la 50%, deci nucleul are mereu prioritate.

| Ordine | Cine | Ce | Branch | Fișiere |
|---|---|---|---|---|
| 1 | RBRT | D1: jurnalul de securitate și alertele la schimbări (FR-13), din `diff()` | `ui` | `netscan/ui/` |
| 2 | Ayan | D2: AI și siguranță: asistentul care răspunde doar din scanare, cu validatorul (FR-12) | `scan` | `netscan/scan/assistant.py` (nou), `netscan/scan/ai_check.py` |
| 3 | RBRT | D4 + D5: inventarul complet (pe datele FR-03) și „o singură acțiune pe rând” (FR-11, Ease of use) | `ui` | `netscan/ui/` |
| 3b | RBRT | D7: raportul de o pagină pentru furnizorul IT (FR-14) | `ui` | `netscan/ui/` |
| 4 | Oneata | D3: explicații: maparea celor 15 coduri pe CIS Controls v8 și OWASP IoT Top 10 (bonus) | `explain` | `netscan/explain/standards.py` (nou) |
| 5 | Radu | D6: raportul „servicii văzute care nu sunt în catalog”, **gata înainte de ora 20** (e în procedura Test Set-ului) | `engine` | `netscan/engine/` (fără schimbări la reguli, scor sau CSV-uri) |
| 6 | Ayan | D8: model AI local (Qwen cu Ollama, fără internet) pentru demo-ul validatorului; permis de mentori (întrebarea 14) | `scan` | `netscan/scan/local_llm.py` (nou) |

- **Ce nu se schimbă:** motorul de reguli, catalogul, scorul, `findings.csv` și `scores.csv`. Findings, severități și scoruri vin doar din cod.
- **Fără** agenți pe dispozitive, colectare de log-uri sau reparații automate.
- **Contractul:** dacă o funcție cere un câmp sau un tip nou, se scrie în `docs/direction.md`, la „Propuneri de contract”, și se aplică doar după acordul echipei (contract, `model.py` și `sample.json` în același commit).
- **Rolurile în direcție:** Ayan = AI și siguranță (rolul B, `netscan/scan/`), Oneata = explicații (rolul C, `netscan/explain/`). Fiecare lucrează în folderul lui; orice modificare în folderul altcuiva se anunță înainte.
- **Sincronizări:** RBRT ↔ Ayan când alertele și asistentul apar în UI; RBRT ↔ Oneata când maparea e gata de afișat.
- Merge în `main` doar ce merge, ca până acum. Înainte de upload-ul Test Set-ului, nimic din direcție nu trebuie să atingă `analyze`.

## Ziua Test Set (ora 20)

Obiectiv: rezultatul încărcat e exact cel pe care îl reproduce oricine pe commit-ul cu tag-ul `final`. Fără improvizații: se urmează pașii în ordine. Scriptul: `scripts/preflight.py` (rulează `analyze` de două ori, în procese separate, compară `findings.csv` și `scores.csv` byte cu byte, scrie hash-urile și raportul de servicii din afara catalogului).

| Pas | Cine | Ce |
|---|---|---|
| 1 | Oneata | Copiază Test Set-ul într-un folder local, în afara repo-ului (de ex. `~/testset/`), și notează SHA-256 pentru fiecare XML: `sha256sum ~/testset/*.xml > ~/testset_sha256.txt`. Fișierele XML nu se deschid în editor și nu se modifică. |
| 2 | Oneata | Pe `main` actualizat și fără modificări locale: `python scripts/preflight.py ~/testset --out results/`. Dacă scrie „OPRIT”, nu se încarcă nimic: rezultatul depinde de rulare (bug în motor, Radu). |
| 3 | Ayan | Citește „Servicii văzute care nu sunt în catalog” (și `results/unmatched_services.csv`). Pentru fiecare serviciu: e în catalog sub alt nume? Decizia: **doar bug-uri clare**, cu test (o capcană nouă în `fixtures/traps/` + rezultatul ei în `tests/expected_traps.py`) și cu acordul lui Radu. Un caz ambiguu nu se „repară”: se scrie în `docs/questions.md` și se întreabă mentorii. |
| 3b | RBRT | Verifică scorurile din ieșirea preflight: fiecare fișier are un scor sau `ERROR`; un scor de 0 sau 100 se verifică cu ochiul în `findings.csv`. |
| 4 | Oneata | **Doar dacă s-a schimbat cod:** commit + push pe `main`, apoi `pytest` complet, apoi pasul 2 din nou (ieșirea veche nu se mai folosește). |
| 5 | Oneata + Radu | Upload `results/findings.csv`, `results/scores.csv` și captura UI-ului. Radu face captura: `NETSCAN_SCANS_DIR=~/testset python -m netscan ui`. |
| 6 | Oneata | **Imediat după upload:** `git tag final <commit-ul din hashes.txt>` și `git push origin final`. Hash-urile din `results/hashes.txt` se copiază pe grup (și în descrierea tag-ului, dacă vrem: `git tag -a final -m "<hash-uri>"`). Commit-ul din `hashes.txt` nu trebuie să aibă „+modificări necomise”. |
| 7 | toți | După tag nu se mai schimbă nimic în `netscan/` sau `pyproject.toml`. La verificarea live (re-rularea), juriul rulează `analyze` pe commit-ul `final`: rezultatul trebuie să aibă exact hash-urile notate. |

Reguli:
- Nicio excepție pe nume de fișiere, nicio regulă schimbată ca să „iasă” un rezultat. Doar bug-uri clare, cu test, înainte de upload.
- Test Set-ul și `results/` nu se pun în repo fără acordul echipei.

**Repetiția pe Validation Set** (7 nov., Oneata, pe commit-ul `1714b3e`): pașii 1, 2, 4 (pytest + preflight din nou) și hash-ul commit-ului au durat **7,5 s** pe mașină (preflight: 0,18 s; `pytest` complet: 7,1 s). Rezultatul a fost identic byte cu byte cu `expected_findings.csv` și `expected_scores.csv` (24 de rânduri, V7 = `ERROR`). Pașii făcuți de oameni (citirea raportului, upload, captura, tag-ul) nu sunt cronometrați aici: se cronometrează la repetiția cu toată echipa.

## Când ceva nu e clar

Nu inventa o regulă. Scrie întrebarea în `docs/questions.md`, spune-i echipei, iar Oneata o duce la mentori. „Nu înțeleg încă” e o propoziție productivă aici.

## Pull request (checklist)

- [ ] Ce am schimbat, în 1–2 propoziții
- [ ] `pytest` trece
- [ ] N-am atins fișierele comune fără să anunț
- [ ] Nicio cheie, parolă sau MAC real
- [ ] Datele din scanare tratate ca text nesigur (escapate / parametrizate)
