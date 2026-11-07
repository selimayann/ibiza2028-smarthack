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

## Când ceva nu e clar

Nu inventa o regulă. Scrie întrebarea în `docs/questions.md`, spune-i echipei, iar Oneata o duce la mentori. „Nu înțeleg încă” e o propoziție productivă aici.

## Pull request (checklist)

- [ ] Ce am schimbat, în 1–2 propoziții
- [ ] `pytest` trece
- [ ] N-am atins fișierele comune fără să anunț
- [ ] Nicio cheie, parolă sau MAC real
- [ ] Datele din scanare tratate ca text nesigur (escapate / parametrizate)
