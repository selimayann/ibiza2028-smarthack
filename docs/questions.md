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
| 8 | Laptopul care scanează (apare fără MAC) trebuie raportat ca UNKNOWN_DEVICE în scanările noastre? | | Radu, Ayan |
| 9 | Scanările din lab pot fi puse în repo cu MAC-urile reale, sau trebuie altfel? | | Ayan |
| 10 | Numele hotspotului: confirmăm formatul `RSH-<nume-echipă>`? | | Ayan, Oneata |
| 11 | La scanarea noastră, nmap 7.993 cu `-sV` raportează mosquitto 1.6.15 pe 1883/tcp ca `<service name="mosquitto version 1.6.15" method="probed" conf="10"/>`, nu `name="mqtt"` (probabil scriptul `mqtt-subscribe` suprascrie numele). Pentru MQTT_EXPOSED contează doar numele exact `mqtt`, sau și un astfel de nume (care conține „mosquitto” / pe 1883)? Fișierele din Test Set pot avea această formă? | | Radu, Ayan |
