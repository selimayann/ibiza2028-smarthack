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

## Când ceva nu e clar

Nu inventa o regulă. Scrie întrebarea în `docs/questions.md`, spune-i echipei, iar Oneata o duce la mentori. „Nu înțeleg încă” e o propoziție productivă aici.

## Pull request (checklist)

- [ ] Ce am schimbat, în 1–2 propoziții
- [ ] `pytest` trece
- [ ] N-am atins fișierele comune fără să anunț
- [ ] Nicio cheie, parolă sau MAC real
- [ ] Datele din scanare tratate ca text nesigur (escapate / parametrizate)
