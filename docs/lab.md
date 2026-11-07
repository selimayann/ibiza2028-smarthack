# Lab-ul (hotspot)

> Responsabil: **Ayan**. Pașii compleți sunt în [roles/C_Ayan_Lab_Explicatii.md](roles/C_Ayan_Lab_Explicatii.md).
> Fără parole în acest fișier.

Regula de aur: **simulăm, nu expunem.** Fără shell-uri, date sau parole reale în spatele serviciilor slabe.

## Dispozitive

| Dispozitiv | Rol | Ce rulează |
|---|---|---|
| Telefon | Hotspot `RSH-<nume-echipă>` (gateway) | — |
| Laptop-scanner (B) | nmap + tool-ul | — |
| Laptop-țintă (C, Fedora) | Ținte | redis, mosquitto 1.6, nginx (Docker) · telnet/FTP false (Python) · SSH |

## Ținte și findings vizate

| Serviciu | Port | Cum | Finding vizat |
|---|---|---|---|
| redis (fără parolă, fără persistență) | 6379/tcp | Docker | DB_EXPOSED |
| eclipse-mosquitto 1.6 (acceptă clienți anonimi, fără `$SYS`) | 1883/tcp | Docker + `lab/mosquitto/mosquitto.conf` | MQTT_EXPOSED |
| nginx, pagină `<title>Admin Login</title>` | 8080/tcp | Docker | HTTP_ADMIN_CLEARTEXT |
| telnet fals, semnătura BusyBox telnetd + `login: ` | 2323/tcp | `lab/fake_services/fake_telnet.py` | TELNET_OPEN |
| FTP fals, banner `220 (vsFTPd 2.3.4)` | 2121/tcp | `lab/fake_services/fake_ftp.py` | FTP_CLEARTEXT + OUTDATED_SERVICE |
| OpenSSH real (Fedora, versiune recentă) | 22/tcp | `sshd` | SSH_OPEN |

Bannerele false sunt verificate în teste față de semnăturile exacte din `nmap-service-probes`
(`tests/test_lab_fake_services.py`): nmap -sV le raportează ca `telnet` (BusyBox telnetd) și `ftp` (vsftpd 2.3.4).

## Pornire / oprire (pe laptopul-țintă)

Înainte de orice:
- Laptopul-țintă e conectat **doar** la hotspot. Află-ți IP-ul: `ip -br a` (pe iPhone, subnetul e de obicei `172.20.10.0/28`).
- **Oprește orice alt container** care publică porturi (`docker ps`). Altfel apare în scanare ca finding în plus și poate ocupa porturile (6379).

```bash
cd ibiza2028-smarthack
export LAB_BIND=<IP-ul laptopului-țintă din hotspot>   # porturile se publică DOAR pe acest IP

# 1. Docker: redis, mosquitto, nginx
docker compose -f lab/docker-compose.yml up -d

# 2. Servicii false (câte un terminal fiecare; Ctrl+C le oprește)
python3 lab/fake_services/fake_telnet.py --bind "$LAB_BIND"     # 2323
python3 lab/fake_services/fake_ftp.py    --bind "$LAB_BIND"     # 2121

# 3. SSH (Fedora)
sudo systemctl start sshd
```

Oprire (obligatoriu înainte să plecați):
```bash
docker compose -f lab/docker-compose.yml down
# Ctrl+C în terminalele cu telnet și FTP
sudo systemctl stop sshd
```

Fără `LAB_BIND`, totul ascultă doar pe `127.0.0.1` (sigur pe Wi-Fi-ul venue, dar invizibil pentru scanner).

### Verificare înainte de capturi (de pe laptopul-scanner)
```
sudo nmap -sV --script http-title -p 22,1883,2121,2323,6379,8080 <IP-laptop-țintă>
```
Trebuie să apară: `ssh`, `mqtt`, `ftp` cu `vsftpd 2.3.4`, `telnet`, `redis`, `http` cu titlul „Admin Login”.

### Între scanarea 2 și scanarea 3 („reparăm” două probleme)
```bash
docker compose -f lab/docker-compose.yml stop redis   # dispare DB_EXPOSED
# Ctrl+C pe fake_telnet.py                              # dispare TELNET_OPEN
```

## Findings așteptate per scanare (așteptare de test, nu rezultat)

> Doar laptopul-țintă, la IP-ul lui din hotspot. **Nu sunt rezultate**: rezultatele le produce doar tool-ul.

| Scanare | Coduri așteptate (laptop-țintă) | Scor așteptat |
|---|---|---|
| `scan_01_before.xml` | SSH_OPEN (22), MQTT_EXPOSED (1883), FTP_CLEARTEXT (2121), OUTDATED_SERVICE (2121), TELNET_OPEN (2323), DB_EXPOSED (6379), HTTP_ADMIN_CLEARTEXT (8080) | 10 (= 100 − 90) |
| `scan_02.xml` | identic cu `scan_01_before.xml` | 10 |
| `scan_03_after.xml` | SSH_OPEN, MQTT_EXPOSED, FTP_CLEARTEXT, OUTDATED_SERVICE, HTTP_ADMIN_CLEARTEXT | 50 (= 100 − 50) |

7 coduri diferite în scanarea 1 (cerința: cel puțin 5). Diferența 1 → 3: DB_EXPOSED și TELNET_OPEN rezolvate.

Posibile rânduri în plus (nu le forțăm, le notăm după capturi):
- **UNKNOWN_DEVICE** pe laptopul-scanner (apare fără MAC), vezi întrebarea 8 din `docs/questions.md`.
- **UNKNOWN_DEVICE** pe laptopul-țintă sau pe telefon, dacă au MAC randomizat (fără vendor), niciun hostname și cel puțin un port deschis. Asta poate schimba scorurile de mai sus.

## Probleme întâlnite

- Pe laptopul-țintă rulau alte containere Docker (alt proiect) publicate pe `0.0.0.0`, inclusiv pe portul 6379. Le oprim înainte de lab; altfel apar ca findings în plus și blochează portul redis.
- Docker ocolește firewall-ul Fedora (firewalld) când publică porturi. De aceea porturile se publică explicit doar pe `LAB_BIND`, nu pe toate interfețele.
- **nmap a raportat portul 1883 ca `mosquitto version 1.6.15`, nu `mqtt`** (găsit de B la prima verificare). Cauza: scriptul `mqtt-subscribe` (categoria `version`, rulează automat la `-sV`) citește subiectul `$SYS/broker/version` și înlocuiește numele serviciului (`port.version.name = ver` în `mqtt-subscribe.nse`). Reparat în configurarea lab-ului, nu în motor și nu în XML: `sys_interval 0` în `lab/mosquitto/mosquitto.conf` oprește subiectele `$SYS`. Bun și pentru pitch: un broker real n-ar trebui să-și anunțe versiunea.
- Laptopul-țintă apare cu MAC randomizat (`(Unknown)` la vendor) și fără hostname, deci motorul va raporta probabil și **UNKNOWN_DEVICE** pentru el.
- Fedora Workstation permite implicit porturile 1025–65535 și SSH în firewall, deci nu trebuie deschis nimic manual.
