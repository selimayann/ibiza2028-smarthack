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
pytest
```

În `.env` sunt obligatorii pentru scanarea live: `NETSCAN_EXPECTED_SSID` (numele hotspotului, ex. `RSH-Ibiza2028`) și `NETSCAN_SALT` (un text lung, aleatoriu, de ex. `python -c "import secrets; print(secrets.token_hex(32))"`). Tool-ul citește singur `.env` din folderul curent.

**Windows**
- Folosiți Python-ul oficial (python.org sau Microsoft Store). Python-ul din MSYS2 (`C:\msys64\...`, cel găsit des primul de Git Bash) nu poate instala `psutil`. Verificare: `python -c "import sysconfig; print(sysconfig.get_platform())"` trebuie să afișeze `win-amd64`.
- nmap de pe [nmap.org/download](https://nmap.org/download.html) și Npcap de pe [npcap.com](https://npcap.com). Scanarea live (`scan --confirm`) cere terminal deschis **ca Administrator**; restul comenzilor nu.
- Rețeaua hotspotului trebuie setată ca **Private** (Setări → Network & internet → Wi-Fi → rețeaua → Network profile type).

## Comenzi (se implementează pe parcurs)

```
python -m netscan analyze <folder>     # findings.csv + scores.csv, fără rețea
python -m netscan network              # interfața, subnetul și gateway-ul detectate
python -m netscan scan <țintă>         # dry-run; scanează doar cu --confirm
python -m netscan ui                   # interfața web locală
python -m netscan diff <a> <b>         # diferența dintre două scanări
python -m netscan delete-history       # șterge istoricul local
```

### Scanarea live, pas cu pas (`network`, `scan`)

```
python -m netscan network                    # ce rețea vede tool-ul și dacă scanarea e permisă
python -m netscan scan                       # dry-run pe tot subnetul: arată comanda nmap, nu scanează
python -m netscan scan 172.20.10.14          # dry-run pe un singur dispozitiv
python -m netscan scan 172.20.10.14 --confirm   # scanează (Administrator / sudo); XML-ul ajunge în scans/
python -m netscan scan --lang en             # mesajele în engleză
```

Înainte de orice scanare, tool-ul verifică în ordine:
1. **Rețeaua** (`network`): o singură rețea fizică activă (Wi-Fi și cablu în același timp → refuz), interfețele virtuale (Docker, WSL, VirtualBox, VPN) sunt ignorate, iar numele Wi-Fi trebuie să fie `NETSCAN_EXPECTED_SSID`.
2. **Ținta** (`check_target`): doar adrese IPv4 din subnetul hotspotului (plus `NETSCAN_ALLOWLIST`). Refuză IP-uri publice, `100.64.0.0/10`, subneturi mai mari decât al nostru, rețele private străine (venue), nume de dispozitive (fără DNS) și orice text care nu e o adresă.
3. **Comanda nmap** e o listă de argumente (fără shell), cu `--max-rate 100` și ținta normalizată de guardrail.

## Reguli care nu se negociază

- Scanăm **doar** hotspotul nostru (`RSH-<nume-echipă>`). Orice altceva = descalificare (Art. 360 Cod Penal).
- Nicio cheie, parolă sau token în repo. Configurare doar prin variabile de mediu.
- MAC-urile reale nu apar în nicio ieșire.
- Rezultatele (`findings.csv`, `scores.csv`) le produce doar tool-ul; nu se editează de mână.
- După upload-ul Test Set-ului nu se mai schimbă nimic; commit-ul acela primește tag-ul `final`.
