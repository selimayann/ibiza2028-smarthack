# lab (Ayan)

Materialele pentru rețeaua de test. **Nu** fac parte din aplicație.

- `docker-compose.yml` — redis (6379), eclipse-mosquitto:1.6 (1883), nginx (8080)
- `nginx/index.html` — pagină cu `<title>Admin Login</title>`
- `fake_services/` — telnet fals (2323) și FTP fals cu banner `220 (vsFTPd 2.3.4)` (2121)

Regula de aur: **simulăm, nu expunem.** Fără shell-uri, date sau parole reale. Opriți totul când plecați.
Detalii: [docs/roles/C_Ayan_Lab_Explicatii.md](../docs/roles/C_Ayan_Lab_Explicatii.md).
