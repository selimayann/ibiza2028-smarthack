# Întrebări pentru mentori

> Responsabil: **Oneata**. Scrie răspunsul sub fiecare întrebare și anunță echipa (mai ales pe Radu, pentru reguli).

| # | Întrebare | Răspuns | Pe cine afectează |
|---|---|---|---|
| 1 | `Samba smbd 3.X - 4.X` se consideră învechit (OUTDATED_SERVICE)? | | Radu |
| 2 | Pentru Samba învechit, OUTDATED_SERVICE apare pe același port ca SMB (445, altfel 139)? | | Radu |
| 3 | `http-proxy` / `http-alt` contează ca `http` la HTTP_ADMIN_CLEARTEXT, sau doar numele exact? | | Radu |
| 4 | Cuvintele din titlu se caută fără diferență între litere mari și mici, și ca subșir (ex. „Administration”)? | | Radu |
| 5 | Un MAC prezent, dar fără vendor înseamnă „fără vendor” la UNKNOWN_DEVICE? | | Radu |
| 6 | Fișierele de test conțin ieșirea scriptului `http-title`? | | Radu |
| 7 | În folderul de test pot fi și fișiere care nu sunt `.xml`? Coloana `file` e doar numele fișierului? | | Radu |
| 8 | În scanările noastre live, laptopul care scanează apare fără MAC și fără hostname. Laptopul-țintă apare și el cu MAC randomizat (adresă administrată local, vendor „Unknown”) și fără hostname. Cu regula exactă, amândouă ies UNKNOWN_DEVICE dacă au porturi deschise. Le raportăm așa, sau dispozitivele cu MAC randomizat / laptopul care scanează se tratează altfel? | | Radu, Ayan |
| 9 | Putem pune în repo scanările din lab (nmap XML) cu MAC-urile din ele? MAC-ul laptopului-țintă e randomizat de sistemul de operare, nu cel hardware. Dacă nu, acceptați să ținem XML-urile doar local și să punem în repo doar CSV-urile generate de tool (care conțin doar MAC-ul mascat)? Nu vrem să le edităm de mână, ca să nu pară rezultate fabricate. | | Ayan |
| 10 | Numele hotspotului: confirmăm formatul `RSH-<nume-echipă>`? | | Ayan, Oneata |
| 11 | La scanarea din lab, nmap 7.993 cu `-sV` a raportat mosquitto 1.6.15 pe 1883/tcp ca `<service name="mosquitto version 1.6.15" method="probed" conf="10"/>`, nu `mqtt`. Cauza e confirmată: scriptul `mqtt-subscribe` (categoria `version`, rulează automat la `-sV`) citește subiectul `$SYS/broker/version` și suprascrie numele serviciului. În lab am oprit `$SYS` pe broker (`sys_interval 0`) și acum apare `mqtt`. Pentru Test Set: dacă un fișier are numele de serviciu de forma `mosquitto version X`, îl raportăm ca MQTT_EXPOSED sau nu? | | Radu, Ayan |
| 12 | Un serviciu pe care nmap nu l-a confirmat, ci l-a ghicit din tabelul de porturi (`<service name="ftp" method="table" .../>`), contează pentru reguli (de exemplu FTP_CLEARTEXT pe 21), sau doar `method="probed"`? Exemplul nostru: iPhone-ul (172.20.10.1:21) din lab. | | Radu, Ayan |
