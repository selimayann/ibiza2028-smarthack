# Demo-ul de verificare: cele 2 probleme ușor de verificat (cerut de mentor)

Mentorul a cerut un test în care **chiar verificăm** că o reparație s-a făcut, pe cele mai ușoare 2 probleme.
Am ales **baza de date expusă (Redis, port 6379)** și **mesageria IoT (Mosquitto, port 1883)**: amândouă sunt
în Docker pe laptopul-țintă și se „repară” oprind containerul, iar portul închis se vede imediat.

## `verify_two_easy.xml` e un fișier de TEST, făcut de mână

Arată cum iese scanarea lab-ului când pe laptopul-țintă rulează **doar** redis și mosquitto (plus SSH-ul
sistemului). **Nu e o scanare reală** și nu se pune în `scans/`: aplicația verifică live **doar** cea mai nouă
scanare scrisă de scanerul nostru, ca să nu bată la ușa nimănui pe baza unui fișier (`own_newest_scan`).
Testul `tests/test_verify_demo.py` arată pe el exact ce se întâmplă la demo.

| Problema | Port | Puncte | Se verifică live? |
|---|---|---|---|
| Baza de date expusă (DB_EXPOSED) | 6379 | 20 | **da**: oprești redis, portul refuză |
| Mesagerie IoT expusă (MQTT_EXPOSED) | 1883 | 10 | **da**: oprești mosquitto, portul refuză |
| Dispozitiv necunoscut (MAC privat, fără nume) | – | 5 | nu (nu ține de un port) |
| SSH deschis (doar informativ) | 22 | 0 | nu contează la scor |

Scor: **65** → după cele 2 reparații confirmate: **95**.

## Pașii, pe hotspot (cu lab-ul real)

1. Laptopul-țintă pe `RSH-Ibiza2028`, doar cele 2 servicii (fără nginx și fără serviciile false):
   `LAB_BIND=<IP-ul laptopului-țintă> docker compose -f lab/docker-compose.yml up -d redis mosquitto`
2. Laptopul de demo pe hotspot, cu `NETSCAN_EXPECTED_SSID=RSH-Ibiza2028` în `.env`; pornește `python -m netscan ui`
   (fără `NETSCAN_SCANS_DIR`, ca scanarea să fie a noastră, în `scans/`).
3. În aplicație: bifează acordul → **„Scanează acum”**. La final, Acasă arată scanarea de acum (scor ~65).
4. Pe laptopul-țintă: `docker compose -f lab/docker-compose.yml stop redis` → în SafeEel, la „Bază de date
   expusă”: **„Am făcut asta, verifică”** → „Verificat”, scorul după reparații crește cu 20.
5. `docker compose -f lab/docker-compose.yml stop mosquitto` → la „Mesagerie IoT”: **„Am făcut asta, verifică”**
   → „Verificat”, încă +10.
6. Contra-proba (opțional): pornește la loc redis (`start redis`) și apasă „Verifică din nou” pe un pas încă
   nebifat: portul răspunde, deci pasul rămâne de făcut. Aplicația nu ia nimic pe cuvânt.
