# Catalogul și regulile de detecție

> Responsabil: **Radu**. Detaliile complete sunt în [roles/A_Radu_Motor.md](roles/A_Radu_Motor.md), secțiunea 2.2.

## Ce am găsit în fișierele din Validation Set

_De completat după ce deschizi XML-urile: unde apare titlul paginii, cum arată MAC/vendor, stările UDP, atributul `tunnel`._

## Decizii luate

| Decizie | Motiv | Confirmat de mentori? |
|---|---|---|
| | | |

## Capcane cunoscute

| Fișier | Capcană |
|---|---|
| V1 | HTTPS pe 443 nu e finding |
| V2 | TV 8008/8009 nu sunt în catalog |
| V3 | IPP 631 nu e finding |
| V4 | vsftpd 2.3.4 dă două rânduri pe portul 21 |
| V5 | `.8:8443` e HTTPS; `.9:3306` e filtrat, nu deschis |
| V6a → V6b | istoricul trebuie să arate 3 findings rezolvate |
| V7 | fișier trunchiat: `ERROR`, fără crash, continuă cu restul |
