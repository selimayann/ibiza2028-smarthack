# Rezumat tehnic · SafeEel (echipa Ibiza2028)

> R Systems Hackathon 2026 · Secure Networks, Simply Explained. Toate detaliile: [technical_full.md](technical_full.md), [lab.md](lab.md), [questions.md](questions.md).

**Ce face.** `netscan` citește scanări nmap XML offline și scanează live **doar** hotspotul echipei. Aplică exact catalogul oficial de 15 coduri, calculează scorul standard `max(0, 100 − puncte)` și explică fiecare problemă în română și engleză, cu 1–5 pași. Păstrează istoricul și arată înainte/după. Regula noastră: **codul decide, modelul formulează, codul verifică.**

## Arhitectura
```
scan --confirm (singurul pas cu admin) ─┐
fișiere nmap XML ───────────────────────┴─> parser sigur (defusedxml, max. 20 MB) -> reguli (catalogul exact) -> scor
  -> findings.csv + scores.csv · SQLite local (istoric, diferențe) · texte RO/EN · UI web doar pe 127.0.0.1
```
Python 3.11, Flask + Jinja2 (autoescape), SQLite, pytest. Module: `scan/` (rețeaua, guardrail, nmap, asistent, protecția live), `engine/` (parser, reguli, scor, CSV), `explain/` (texte, glosar, CIS/OWASP), `ui/` (pagini, istoric).

## Lab-ul
Hotspot iPhone `RSH-Ibiza2028` (`172.20.10.0/28`); laptop-scanner Windows (nmap 7.99 + Npcap); laptop-țintă Fedora cu redis, mosquitto 1.6 și nginx „Admin Login” în Docker, telnet și FTP false în Python (doar banner, fără login real) și SSH. **8 coduri diferite.** După oprirea redis și a telnet-ului, scorul crește **0 → 30**. Scanările sunt în `fixtures/lab/`.

## Siguranța scanării live
Interfața cu ruta implicită (fără adaptoare virtuale și fără VPN), numele Wi-Fi verificat, ținta doar IPv4 privat din subnetul hotspotului (refuz pentru IP public, subnet mai mare, rețeaua venue). nmap pornește cu listă de argumente, fără shell, cu `--max-rate 100` și doar cu `--confirm`. Doar acest pas cere drepturi de admin.

## Presupuneri (confirmate de mentori)
Doar porturile `open`; decizia după numele serviciului, nu după port; UPnP și SNMP doar pe UDP; HTTP_ADMIN = `http` fără SSL, cu un cuvânt-cheie în titlu; Samba învechit raportează SMB + OUTDATED o singură dată, pe 445 (altfel 139); `mosquitto version X` = MQTT.

## Limitări
- Porturile UDP `open|filtered` nu sunt raportate: nmap nu le poate deosebi.
- Telefoanele și laptopurile moderne au MAC aleatoriu, deci ies UNKNOWN_DEVICE după regula exactă; UI-ul le numește „adresă privată”.
- Dacă nmap identifică greșit un serviciu, și noi îl vedem greșit.
- O rețea /24 cu multe dispozitive poate depăși 5 minute; nu am avut un /24 pe care avem voie să-l scanăm.
- Fără cont și parolă, intenționat: aplicația ascultă doar pe 127.0.0.1 și refuză cererile de pe alte site-uri.

## Folosirea AI-ului
Problemele, severitățile și scorul vin **doar din reguli**, la fel la fiecare rulare. Fără AI online (mentorii: fără alte rețele). Textele sunt predefinite, iar asistentul răspunde din scanare. Opțional, un model local (Ollama, doar `127.0.0.1`) reformulează textul. Un **validator** respinge orice IP, port, cod, CVE sau telefon care nu e în scanare și atunci afișează textul predefinit.

## Cifre
- **Validation Set:** 24/24 de rânduri și 8/8 scoruri identice cu baremul (V7 = ERROR, fără crash); două rulări dau fișiere identice.
- **24 de fișiere-capcană** proprii și **1 608 teste** automate (`pytest -q`).
- **Viteză:** Validation Set analizat sub o secundă; un XML de 17,7 MB în circa 5 s; scanare live /28 în 3 min 25 s.
- **Explicații:** trec un test automat de limbaj simplu (fără jargon neexplicat, propoziții de max. 20 de cuvinte, pași care încep cu o acțiune, LIX mediu 40 RO / 35 EN). Testul e automat; nu au fost testate cu un om netehnic.
- **Securitate:** gitleaks fără secrete; MAC-uri mascate peste tot; SQL parametrizat; buton „șterge istoricul”.
