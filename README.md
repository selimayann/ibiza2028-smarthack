# ibiza2028-smarthack

**R Systems Hackathon 2026 · Secure Networks, Simply Explained**

Un tool care scanează **doar** rețeaua echipei (hotspotul nostru), aplică exact catalogul oficial de 15 findings, calculează scorul standard și explică fiecare problemă în română și engleză, cu pași concreți de reparare și istoric înainte/după.

> Regula de bază: **codul decide, modelul formulează, codul verifică.** Findings, severități și scoruri vin doar din reguli deterministe, niciodată din LLM.

## Echipa

| Persoană | Cine | Rol | Folder principal | Branch | Instrucțiuni |
|---|---|---|---|---|---|
| A | **Radu** | Motor: parser, reguli, scor, export CSV | `netscan/engine/` | `engine` | [A_Radu_Motor.md](docs/roles/A_Radu_Motor.md) |
| B | **Oneata** | Siguranță, scanare live, AI | `netscan/scan/` | `scan` | [B_Oneata_Siguranta_Scanare_AI.md](docs/roles/B_Oneata_Siguranta_Scanare_AI.md) |
| C | **Ayan** | Lab (orele 0–3), apoi explicații RO/EN | `lab/`, `netscan/explain/` | `explain` | [C_Ayan_Lab_Explicatii.md](docs/roles/C_Ayan_Lab_Explicatii.md) |
| D | **RBRT** | UI și istoric | `netscan/ui/` | `ui` | [D_RBRT_UI_Istoric.md](docs/roles/D_RBRT_UI_Istoric.md) |

**Radu și RBRT lucrează în pereche** (UI-ul afișează exact ce produce motorul). Oneata ajută la lab până merge rețeaua.

## Cum începe fiecare

1. Clonează repo-ul și creează-ți branch-ul (vezi tabelul).
2. Deschide Claude Code în repo și scrie: „Citește `docs/roles/<fișierul tău>` și lucrează după el.”
3. Citește [docs/workflow.md](docs/workflow.md) (reguli de git și sincronizări) și [docs/contract.md](docs/contract.md) (forma datelor).

## Structura

```
ibiza2028-smarthack/
├── docs/
│   ├── contract.md        contractul de date (toți)
│   ├── workflow.md        cum lucrăm: branch-uri, sincronizări, reguli
│   ├── rules.md           catalogul + capcane (Radu)
│   ├── lab.md             lab-ul (Ayan)
│   ├── questions.md       întrebări pentru mentori + răspunsuri (Oneata)
│   └── roles/             instrucțiunile pentru Claude-ul fiecăruia
├── fixtures/
│   ├── sample.json        exemplu în forma contractului (toți)
│   ├── validation/        Validation Set V1…V7 (Radu)
│   ├── lab/               scanările noastre din hotspot (Ayan)
│   └── traps/             XML-uri de capcană (Radu + Ayan)
├── netscan/
│   ├── cli.py             analyze · network · scan · ui · diff · delete-history
│   ├── model.py           contractul, în cod (Radu + RBRT)
│   ├── engine/            Radu
│   ├── scan/              Oneata
│   ├── explain/           Ayan
│   └── ui/                RBRT
├── lab/                   Ayan: docker-compose, nginx, servicii false
└── tests/
```

## Setup

Necesită Python 3.11+ și nmap (pe Windows, cu Npcap).

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env             # completează valorile local; .env nu intră în git
```

## Comenzi (se implementează pe parcurs)

```
python -m netscan analyze <folder>     # findings.csv + scores.csv, fără rețea
python -m netscan network              # interfața, subnetul și gateway-ul detectate
python -m netscan scan <țintă>         # dry-run; scanează doar cu --confirm
python -m netscan ui                   # interfața web locală
python -m netscan diff <a> <b>         # diferența dintre două scanări
python -m netscan delete-history       # șterge istoricul local
```

## Reguli care nu se negociază

- Scanăm **doar** hotspotul nostru (`RSH-<nume-echipă>`). Orice altceva = descalificare (Art. 360 Cod Penal).
- Nicio cheie, parolă sau token în repo. Configurare doar prin variabile de mediu.
- MAC-urile reale nu apar în nicio ieșire.
- Rezultatele (`findings.csv`, `scores.csv`) le produce doar tool-ul; nu se editează de mână.
- După upload-ul Test Set-ului nu se mai schimbă nimic; commit-ul acela primește tag-ul `final`.
