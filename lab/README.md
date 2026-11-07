# lab (Oneata)

Materialele pentru rețeaua de test. **Nu** fac parte din aplicație.

- `docker-compose.yml` — redis (6379), eclipse-mosquitto:1.6 (1883), nginx (8080); porturile se publică doar pe `LAB_BIND` (implicit 127.0.0.1)
- `nginx/index.html` — pagină cu `<title>Admin Login</title>`, montată doar-citire
- `fake_services/fake_telnet.py` — telnet fals pe 2323 (semnătura BusyBox telnetd), orice login eșuează
- `fake_services/fake_ftp.py` — FTP fals pe 2121, banner `220 (vsFTPd 2.3.4)`, orice comandă → `530 Login incorrect.`
- `fake_services/common.py` — server comun: nu execută și nu salvează nimic din ce primește, închide după 8 s sau 4 KB, max. 20 conexiuni

Pornire, oprire și findings așteptate: [docs/lab.md](../docs/lab.md). Teste: `pytest tests/test_lab_fake_services.py`.

Regula de aur: **simulăm, nu expunem.** Fără shell-uri, date sau parole reale. Opriți totul când plecați.
