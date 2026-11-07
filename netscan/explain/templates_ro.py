"""Explicații în română per cod (Ayan): max. 2 propoziții, 1-5 pași, nivelul unui copil de 12 ani.

Reguli pentru texte (verificate în tests/test_explain.py):
- fără numere de port, IP-uri, coduri din catalog, CVE-uri sau linkuri: textul e același pentru orice
  scanare, deci nu are voie să afirme lucruri care s-ar putea să nu fie în scanarea utilizatorului;
- `text` are cel mult 2 propoziții; `steps` are între 1 și 5 pași, primul e cel mai important
  (UI-ul îl afișează ca „Fă asta întâi”).
"""

from __future__ import annotations

TEMPLATES: dict[str, dict] = {
    "TELNET_OPEN": {
        "text": "Telnet e o ușă veche prin care cineva poate controla dispozitivul de la distanță, iar parola "
                "trece prin rețea necriptată, ca o carte poștală pe care o poate citi oricine. Cine o prinde "
                "poate prelua dispozitivul.",
        "steps": [
            "Oprește Telnet din pagina de administrare a dispozitivului (de obicei la „Servicii” sau „Acces la distanță”).",
            "Dacă ai nevoie de acces la distanță, folosește SSH în loc de Telnet.",
            "Schimbă parola dispozitivului, pentru că s-ar putea să fi fost deja văzută.",
            "Actualizează firmware-ul; dacă Telnet nu se poate opri, cere ajutor producătorului sau înlocuiește dispozitivul.",
        ],
    },
    "RDP_EXPOSED": {
        "text": "Remote Desktop îi lasă pe alții să vadă și să controleze ecranul calculatorului prin rețea. "
                "Atacatorii încearcă mii de parole pe el sau folosesc greșeli vechi din Windows ca să intre.",
        "steps": [
            "Dacă nu folosești Remote Desktop, oprește-l: Setări → Sistem → Desktop la distanță → Dezactivat.",
            "Dacă îl folosești, lasă doar utilizatorii care chiar au nevoie și pune-le parole lungi.",
            "Păstrează activată opțiunea „Network Level Authentication”.",
            "Instalează toate actualizările Windows.",
            "Nu deschide niciodată Remote Desktop spre internet din router; folosește un VPN.",
        ],
    },
    "VNC_EXPOSED": {
        "text": "VNC arată ecranul dispozitivului altcuiva din rețea și îl lasă să-l controleze. Are adesea "
                "parole scurte sau deloc, iar ce se vede pe ecran poate trece necriptat.",
        "steps": [
            "Oprește serverul VNC dacă nu-l folosești.",
            "Dacă îl folosești, pune o parolă lungă și unică.",
            "Lasă VNC să accepte conexiuni doar prin SSH sau VPN, nu direct din rețea.",
            "Actualizează programul VNC la ultima versiune.",
        ],
    },
    "DB_EXPOSED": {
        "text": "O bază de date ține informațiile unei aplicații și aici poate fi accesată direct din rețea. "
                "Multe baze de date vin fără parolă, așa că oricine din rețea le-ar putea citi, schimba sau șterge.",
        "steps": [
            "Setează baza de date să asculte doar pe calculatorul ei (adresa locală), nu pe toată rețeaua.",
            "Pornește autentificarea și pune o parolă puternică.",
            "Din firewall, lasă să se conecteze doar aplicația care chiar are nevoie de ea.",
            "Actualizează serverul bazei de date.",
        ],
    },
    "CAMERA_STREAM_EXPOSED": {
        "text": "Imaginile camerei video pot fi văzute direct din rețea, fără aplicația ei. Dacă parola lipsește "
                "sau e cea din fabrică, oricine din rețea se poate uita la ce filmează camera.",
        "steps": [
            "Schimbă parola din fabrică a camerei cu una lungă și unică.",
            "Oprește transmisia video directă (RTSP) dacă aplicația camerei nu are nevoie de ea.",
            "Actualizează firmware-ul camerei.",
            "Mută camerele într-o rețea separată, de exemplu rețeaua pentru oaspeți a routerului.",
        ],
    },
    "OUTDATED_SERVICE": {
        "text": "Un program de pe acest dispozitiv e o versiune veche, cu greșeli de securitate pe care "
                "atacatorii le cunosc deja. Pentru unele dintre ele există unelte gata făcute care intră singure.",
        "steps": [
            "Actualizează programul sau firmware-ul dispozitivului la ultima versiune.",
            "Dacă nu mai există actualizări, oprește serviciul sau înlocuiește dispozitivul.",
            "Pornește actualizările automate, dacă dispozitivul le are.",
        ],
    },
    "FTP_CLEARTEXT": {
        "text": "FTP mută fișiere prin rețea, dar trimite parola și fișierele necriptate. Oricine ascultă "
                "în aceeași rețea le poate citi.",
        "steps": [
            "Oprește FTP dacă nu-l folosești.",
            "Folosește în loc SFTP sau FTPS, care criptează parola și fișierele.",
            "Oprește autentificarea anonimă (fără cont).",
            "Schimbă parola contului FTP, pentru că s-ar putea să fi fost deja văzută.",
        ],
    },
    "HTTP_ADMIN_CLEARTEXT": {
        "text": "Pagina de administrare a dispozitivului se deschide prin HTTP, fără criptare. Când te "
                "autentifici, parola trece prin rețea la vedere și poate fi furată.",
        "steps": [
            "Pornește HTTPS din setările dispozitivului și folosește doar adresa cu https.",
            "Schimbă parola din fabrică cu una lungă și unică.",
            "Oprește administrarea de la distanță (din internet), dacă nu ai nevoie de ea.",
            "Actualizează firmware-ul dispozitivului.",
        ],
    },
    "SMB_EXPOSED": {
        "text": "Partajarea de fișiere Windows (SMB) e deschisă în rețea. Prin ea, atacatorii pot încerca "
                "să ajungă la fișiere, iar virușii de tip ransomware se pot răspândi de la un calculator la altul.",
        "steps": [
            "Dacă nu partajezi fișiere, oprește partajarea din setările de rețea.",
            "Dacă partajezi, cere parolă și dă acces doar persoanelor care au nevoie.",
            "Oprește versiunea veche SMBv1 (din „Activare sau dezactivare caracteristici Windows”).",
            "Instalează toate actualizările sistemului.",
            "Pe Windows, setează rețelele publice (cafenea, hotel) ca „Public”, ca partajarea să nu fie vizibilă acolo.",
        ],
    },
    "MQTT_EXPOSED": {
        "text": "MQTT e sistemul prin care dispozitivele inteligente își trimit mesaje, de exemplu becuri, "
                "senzori sau încuietori. Fără parolă, oricine din rețea poate citi mesajele sau poate trimite "
                "comenzi, cum ar fi să aprindă luminile.",
        "steps": [
            "Cere nume de utilizator și parolă pentru toți clienții (oprește accesul anonim).",
            "Pornește criptarea (TLS) pentru conexiuni.",
            "Lasă brokerul să accepte conexiuni doar de la dispozitivele tale, din firewall.",
            "Actualizează brokerul MQTT la ultima versiune.",
        ],
    },
    "UPNP_EXPOSED": {
        "text": "UPnP le permite dispozitivelor să deschidă singure uși în router, fără să te întrebe. "
                "Un virus de pe un dispozitiv poate folosi asta ca să deschidă rețeaua ta spre internet.",
        "steps": [
            "Oprește UPnP din pagina de administrare a routerului.",
            "Deschide manual în router doar porturile de care ai nevoie, și doar cât timp ai nevoie.",
            "Actualizează firmware-ul routerului.",
        ],
    },
    "SNMP_EXPOSED": {
        "text": "SNMP spune oricui întreabă multe detalii despre dispozitiv, cum ar fi modelul, setările "
                "și rețeaua. Adesea folosește parola din fabrică „public”, pe care o știe toată lumea.",
        "steps": [
            "Oprește SNMP dacă nu îl folosești.",
            "Dacă îl folosești, schimbă parolele („community strings”) din fabrică.",
            "Treci la SNMPv3, care are autentificare și criptare.",
            "Lasă doar calculatorul de administrare să trimită cereri SNMP.",
        ],
    },
    "PRINTER_RAW_EXPOSED": {
        "text": "Imprimanta primește lucrări de printare direct din rețea, fără nicio verificare. Oricine "
                "din rețea poate printa pe ea sau îi poate trimite comenzi ciudate.",
        "steps": [
            "Oprește printarea directă (RAW / JetDirect) din pagina de administrare a imprimantei, dacă nu o folosești.",
            "Lasă doar calculatoarele tale să printeze, din setările imprimantei.",
            "Pune o parolă pe pagina de administrare a imprimantei.",
            "Actualizează firmware-ul imprimantei.",
        ],
    },
    "UNKNOWN_DEVICE": {
        "text": "În rețea e un dispozitiv cu servicii deschise, dar fără nume și fără producător cunoscut. "
                "E bine să știi ce e fiecare dispozitiv din rețeaua ta, pentru că unul străin poate spiona sau ataca.",
        "steps": [
            "Caută dispozitivul în lista de dispozitive conectate din router.",
            "Telefoanele și laptopurile noi își ascund adresa reală, deci verifică întâi dacă nu e unul de-al tău.",
            "Dacă nu e al tău, schimbă parola Wi-Fi.",
            "Dă-i un nume în router, ca să-l recunoști data viitoare.",
            "Mută dispozitivele inteligente și pe cele necunoscute în rețeaua pentru oaspeți.",
        ],
    },
    "SSH_OPEN": {
        "text": "SSH e o cale sigură și criptată de a controla un dispozitiv de la distanță, deci nu e o "
                "problemă în sine. Contează doar să fie protejat bine, pentru că atacatorii încearcă des parole pe el.",
        "steps": [
            "Dacă nu folosești SSH, oprește-l.",
            "Folosește chei SSH în loc de parole.",
            "Nu permite autentificarea directă ca administrator (root).",
            "Ține serverul SSH actualizat.",
        ],
    },
}
