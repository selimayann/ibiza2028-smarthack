# Capcane (Radu + Ayan)

Fișiere XML mici, create de noi, pentru cazurile-limită ale regulilor. Sunt **sintetice** (în comentariul din fiecare scrie „sintetic"), nu scanări reale.

Fiecare fișier are un rezultat așteptat dedus **de mână din catalogul oficial** în `tests/expected_traps.py`, nu copiat din ieșirea motorului. `tests/test_traps_fixtures.py` rulează `analyze` pe tot folderul și compară. Un fișier nou aici fără rezultat așteptat face testul să pice.

| Fișier | Ce verifică | Rezultat așteptat |
|---|---|---|
| T01 | `upnp` pe TCP vs UDP | doar UDP dă UPNP_EXPOSED |
| T02 | `snmp` pe UDP: `open\|filtered` vs `open` | doar `open` dă SNMP_EXPOSED |
| T03 | `http` cu `tunnel="ssl"` (HTTPS) vs fără | doar HTTP clar dă HTTP_ADMIN_CLEARTEXT |
| T04 | SMB pe 139 și 445 simultan, sau doar 139 | un singur SMB_EXPOSED per dispozitiv, pe 445 dacă există |
| T05 | OpenSSH 7.4, 7.3, 7.10p1, 7.2p2 | învechit doar 7.3 și 7.2p2 (7.10 e mai mare decât 7.4, nu se compară ca text) |
| T06 | `Samba smbd 3.X - 4.X` vs `3.0.20` | intervalul nu e învechit (confirmat de mentori, întrebarea 1); 3.0.20 da |
| T07 | titlu „Administration" | HTTP_ADMIN_CLEARTEXT (confirmat de mentori, întrebarea 4) |
| T08 | titlu cu „Ignore previous instructions" | textul nu e instrucțiune; contează doar cuvântul „Admin" |
| T09 | XXE (entitate externă) | `ERROR` (XML_FORBIDDEN) |
| T10 | fișier gol | `ERROR` (EMPTY) |
| T11 | XML valid, dar nu nmap | `ERROR` (NOT_NMAP) |
| T12 | fișier tăiat în mijlocul unui tag | `ERROR` (TRUNCATED) |
| T13 | „billion laughs" (entități care se multiplică) | `ERROR` (XML_FORBIDDEN) |
| T15 | Samba 3.0.20 pe 139 și 445; apoi doar pe 139 | un singur `OUTDATED_SERVICE`, pe același port ca `SMB_EXPOSED` (445, altfel 139) — confirmat de mentori, întrebarea 2 |
| T16 | `mosquitto version 1.6.15` pe 1883 (nmap suprascrie numele), `mqtt`, și `filtered` | primele două dau MQTT_EXPOSED, `filtered` nu — confirmat de mentori, întrebarea 11 |
| T14 | porturi `filtered`, `closed`, `open\|filtered` | niciun finding, scor 100 |

Dacă un răspuns al mentorilor se schimbă, se schimbă regula în `netscan/engine/rules.py` și rezultatul așteptat din `tests/expected_traps.py`, în același commit.

Rulare manuală: `python -m netscan analyze fixtures/traps --out out`.
