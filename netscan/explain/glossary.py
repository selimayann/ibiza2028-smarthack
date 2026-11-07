"""Glosar RO/EN pentru termenii tehnici care apar în UI și în explicații (Oneata).

get_glossary(lang) -> [{"term": str, "definition": str}, ...], ordonat alfabetic după termen.
"""

from __future__ import annotations

# (termen RO, definiție RO, termen EN, definiție EN)
_ENTRIES: list[tuple[str, str, str, str]] = [
    ("Port", "O „ușă” numerotată a unui dispozitiv, prin care intră un anumit serviciu (de exemplu, pagina web).",
     "Port", "A numbered \"door\" on a device that a specific service uses (for example, the web page)."),
    ("Serviciu", "Un program de pe dispozitiv care răspunde la cereri din rețea, cum ar fi o pagină web sau partajarea de fișiere.",
     "Service", "A program on a device that answers requests from the network, like a web page or file sharing."),
    ("Criptare", "Amestecarea datelor astfel încât doar cine are cheia să le poată citi.",
     "Encryption", "Scrambling data so that only someone with the key can read it."),
    ("Necriptat", "Trimis la vedere: oricine ascultă în rețea poate citi.",
     "Unencrypted", "Sent in plain sight: anyone listening on the network can read it."),
    ("Firmware", "Programul din interiorul unui dispozitiv (router, cameră, imprimantă). Se actualizează din pagina de administrare.",
     "Firmware", "The software inside a device (router, camera, printer). You update it from the admin page."),
    ("Router", "Dispozitivul care face rețeaua de acasă și o leagă la internet.",
     "Router", "The device that creates your home network and connects it to the internet."),
    ("Pagină de administrare", "Pagina web a unui dispozitiv din care îi schimbi setările.",
     "Admin page", "A device's web page where you change its settings."),
    ("Firewall", "Un filtru care decide cine are voie să se conecteze la un dispozitiv.",
     "Firewall", "A filter that decides who is allowed to connect to a device."),
    ("VPN", "Un tunel criptat prin care te conectezi în siguranță la rețeaua ta de departe.",
     "VPN", "An encrypted tunnel for connecting safely to your network from far away."),
    ("SSH", "O cale criptată de a controla un dispozitiv de la distanță, din linia de comandă.",
     "SSH", "An encrypted way to control a device remotely from the command line."),
    ("HTTP / HTTPS", "Felul în care se deschid paginile web. HTTPS e criptat (lacătul din browser), HTTP nu.",
     "HTTP / HTTPS", "How web pages load. HTTPS is encrypted (the padlock in the browser), HTTP is not."),
    ("Parolă din fabrică", "Parola cu care vine dispozitivul. E aceeași pe multe dispozitive și se găsește ușor pe internet.",
     "Factory password", "The password a device ships with. It is the same on many devices and easy to find online."),
    ("Adresă MAC", "Numărul de identificare al plăcii de rețea. Noi îl arătăm doar mascat.",
     "MAC address", "The ID number of a network card. We only show it masked."),
    ("Adresă IP", "Adresa unui dispozitiv în rețea, ca un număr de casă.",
     "IP address", "A device's address on the network, like a house number."),
    ("Rețea pentru oaspeți", "O rețea Wi-Fi separată a routerului, care nu vede restul dispozitivelor tale.",
     "Guest network", "A separate Wi-Fi network on your router that can't see your other devices."),
    ("Ransomware", "Un virus care îți blochează fișierele și cere bani ca să le deblocheze.",
     "Ransomware", "A virus that locks your files and asks for money to unlock them."),
    ("Broker MQTT", "„Poștașul” dispozitivelor inteligente: primește mesajele și le împarte celor abonați.",
     "MQTT broker", "The \"mail carrier\" for smart devices: it receives messages and passes them to subscribers."),
    ("Scor standard", "Nota rețelei, de la 0 la 100: pornește de la 100 și scade cu punctele fiecărei probleme găsite.",
     "Standard score", "Your network's grade from 0 to 100: it starts at 100 and drops by each problem's points."),
    ("Severitate", "Cât de gravă e o problemă: ridicată, medie, scăzută sau doar informativă.",
     "Severity", "How serious a problem is: high, medium, low or just informational."),
    ("Server", "Un calculator sau un program care oferă ceva altor dispozitive, de exemplu fișiere sau o pagină web.",
     "Server", "A computer or program that gives something to other devices, like files or a web page."),
    ("Autentificare", "Pasul în care dovedești cine ești, de obicei cu nume și parolă.",
     "Authentication", "The step where you prove who you are, usually with a name and a password."),
    ("Telnet", "O cale veche de a controla un dispozitiv de la distanță. Trimite totul la vedere, inclusiv parola.",
     "Telnet", "An old way to control a device from far away. It sends everything in plain sight, even the password."),
    ("Remote Desktop (RDP)", "Funcția Windows prin care cineva vede și folosește ecranul calculatorului de la distanță.",
     "Remote Desktop (RDP)", "The Windows feature that lets someone see and use the computer's screen from far away."),
    ("VNC", "Un program care arată ecranul unui dispozitiv altcuiva și îl lasă să-l controleze.",
     "VNC", "A program that shows a device's screen to someone else and lets them control it."),
    ("SMB", "Felul în care calculatoarele Windows împart fișiere și imprimante în rețea.",
     "SMB", "How Windows computers share files and printers on a network."),
    ("UPnP", "O funcție prin care dispozitivele deschid singure uși în router, fără să te întrebe.",
     "UPnP", "A feature that lets devices open doors in your router by themselves, without asking you."),
    ("SNMP", "Un serviciu prin care un dispozitiv spune detalii despre el celor care întreabă.",
     "SNMP", "A service through which a device tells details about itself to whoever asks."),
    ("Community string", "Parola folosită de SNMP. Cea din fabrică, „public”, o știe toată lumea.",
     "Community string", "The password SNMP uses. The factory one, \"public\", is known to everyone."),
    ("FTP / SFTP / FTPS", "Moduri de a muta fișiere prin rețea. FTP trimite totul la vedere; SFTP și FTPS sunt criptate.",
     "FTP / SFTP / FTPS", "Ways to move files over a network. FTP sends everything in plain sight; SFTP and FTPS are encrypted."),
    ("RTSP", "Felul în care o cameră trimite imaginea video direct prin rețea.",
     "RTSP", "How a camera sends its video directly over the network."),
    ("TLS", "Criptarea care protejează o conexiune, aceeași care pune lacătul în browser.",
     "TLS", "The encryption that protects a connection, the same one behind the padlock in the browser."),
    ("Printare directă (RAW / JetDirect)", "Felul în care imprimanta primește lucrări direct din rețea, fără nicio verificare.",
     "Direct printing (RAW / JetDirect)", "How a printer takes print jobs straight from the network, with no check."),
    ("Root", "Contul de administrator pe Linux, care poate face orice pe dispozitiv.",
     "Root", "The administrator account on Linux, which can do anything on the device."),
    ("NLA (Network Level Authentication)", "O verificare Windows care cere parola înainte să se deschidă Remote Desktop.",
     "NLA (Network Level Authentication)", "A Windows check that asks for the password before Remote Desktop opens."),
]


def get_glossary(lang: str = "ro") -> list[dict]:
    en = (lang or "").lower() == "en"
    items = [{"term": e[2], "definition": e[3]} if en else {"term": e[0], "definition": e[1]} for e in _ENTRIES]
    return sorted(items, key=lambda d: d["term"].lower())
