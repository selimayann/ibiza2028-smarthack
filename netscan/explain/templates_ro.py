"""Explicații în română per cod (Oneata): max. 2 propoziții, 1-5 pași, nivelul unui copil de 12 ani.

Reguli pentru texte (verificate în tests/test_explain.py):
- fără numere de port, IP-uri, coduri din catalog, CVE-uri sau linkuri: textul e același pentru orice
  scanare, deci nu are voie să afirme lucruri care s-ar putea să nu fie în scanarea utilizatorului;
- `harm` = un rând „ce poate face cineva rău intenționat” (get_harm), fără exagerări;
- `text` are cel mult 2 propoziții; `steps` are între 1 și 5 pași, primul e cel mai important
  (UI-ul îl afișează ca „Fă asta întâi”).
"""

from __future__ import annotations

TEMPLATES: dict[str, dict] = {
    "TELNET_OPEN": {
        "harm": "Cineva din rețea îți poate afla parola și poate controla dispozitivul.",
        "text": "Telnet e o ușă veche prin care cineva poate controla dispozitivul de la distanță. Parola trece prin rețea la vedere, ca o carte poștală, iar cine o prinde poate prelua dispozitivul.",
        "steps": [
            "Oprește Telnet din pagina de administrare a dispozitivului (de obicei la „Servicii” sau „Acces la distanță”).",
            "Dacă ai nevoie de acces la distanță, folosește SSH în loc de Telnet.",
            "Schimbă parola dispozitivului, pentru că s-ar putea să fi fost deja văzută.",
            "Actualizează firmware-ul; dacă Telnet nu se poate opri, cere ajutor producătorului sau înlocuiește dispozitivul.",
        ],
    },
    "RDP_EXPOSED": {
        "harm": "Cineva poate ghici parola și poate folosi calculatorul ca și cum ar sta în fața lui.",
        "text": "Remote Desktop îi lasă pe alții să vadă și să controleze ecranul calculatorului prin rețea. "
                "Atacatorii încearcă mii de parole pe el sau folosesc greșeli vechi din Windows ca să intre.",
        "steps": [
            "Dacă nu folosești Remote Desktop, oprește-l: Setări → Sistem → Desktop la distanță → Dezactivat.",
            "Dacă îl folosești, lasă doar utilizatorii care chiar au nevoie și pune-le parole lungi.",
            "Lasă pornită verificarea NLA, care cere parola înainte să se deschidă ecranul.",
            "Instalează toate actualizările Windows.",
            "Nu deschide niciodată Remote Desktop spre internet din router; folosește un VPN.",
        ],
    },
    "VNC_EXPOSED": {
        "harm": "Cineva din rețea poate vedea ce faci pe ecran și poate muta mouse-ul în locul tău.",
        "text": "VNC îi arată altcuiva din rețea ecranul acestui dispozitiv și îl lasă să-l controleze. Are adesea "
                "parole scurte sau deloc, iar ce se vede pe ecran poate trece necriptat.",
        "steps": [
            "Oprește programul VNC de pe acest dispozitiv, dacă nu-l folosești.",
            "Dacă îl folosești, pune în setările programului VNC o parolă lungă și unică.",
            "Dacă te conectezi din afara casei, folosește un VPN (un tunel criptat) în loc să lași VNC deschis.",
            "Actualizează programul VNC la ultima versiune.",
        ],
    },
    "DB_EXPOSED": {
        "harm": "Cineva din rețea poate citi, schimba sau șterge datele aplicației.",
        "text": "O bază de date ține informațiile unei aplicații și aici poate fi accesată direct din rețea. "
                "Multe baze de date vin fără parolă, așa că oricine din rețea le-ar putea citi, schimba sau șterge.",
        "steps": [
            "Caută programul care a pus baza de date pe acest dispozitiv și oprește-l, dacă nu-l mai folosești.",
            "Dacă îl folosești, cere-i celui care l-a instalat să închidă baza de date pentru restul rețelei.",
            "Pornește autentificarea (nume și parolă) din setările bazei de date și pune o parolă lungă.",
            "Actualizează programul bazei de date.",
        ],
    },
    "CAMERA_STREAM_EXPOSED": {
        "harm": "Oricine din rețea poate vedea ce filmează camera.",
        "text": "Imaginile camerei video pot fi văzute direct din rețea, fără aplicația ei. Dacă parola lipsește "
                "sau e cea din fabrică, oricine din rețea se poate uita la ce filmează camera.",
        "steps": [
            "Schimbă parola din fabrică a camerei cu una lungă și unică.",
            "Oprește transmisia video directă (RTSP) dacă aplicația camerei nu are nevoie de ea.",
            "Actualizează firmware-ul camerei.",
            "Mută camerele într-o rețea separată, de exemplu rețeaua pentru oaspeți a routerului, dacă are una.",
        ],
    },
    "OUTDATED_SERVICE": {
        "harm": "Cineva poate folosi o unealtă gata făcută ca să intre în dispozitiv.",
        "text": "Un program de pe acest dispozitiv e o versiune veche, cu greșeli pe care atacatorii le știu deja. Pentru unele există unelte gata făcute care intră singure.",
        "steps": [
            "Actualizează programul vechi sau firmware-ul dispozitivului la ultima versiune.",
            "Dacă nu mai are actualizări, oprește serviciul sau schimbă dispozitivul.",
            "Pornește actualizările automate, dacă există.",
        ],
    },
    "FTP_CLEARTEXT": {
        "harm": "Cineva din rețea poate citi parola și fișierele pe care le trimiți.",
        "text": "FTP mută fișiere prin rețea, dar trimite parola și fișierele necriptate. Oricine ascultă "
                "în aceeași rețea le poate citi.",
        "steps": [
            "Oprește FTP dacă nu-l folosești.",
            "Folosește în locul lui SFTP sau FTPS, care criptează parola și fișierele.",
            "Oprește autentificarea anonimă (fără cont).",
            "Schimbă parola contului FTP, pentru că s-ar putea să fi fost deja văzută.",
        ],
    },
    "HTTP_ADMIN_CLEARTEXT": {
        "harm": "Cineva din rețea îți poate fura parola și poate schimba setările dispozitivului.",
        "text": "Pagina de administrare a dispozitivului se deschide prin HTTP, fără criptare. Când îți scrii "
                "parola acolo, ea trece prin rețea la vedere și poate fi furată.",
        "steps": [
            "Pornește HTTPS din setările dispozitivului și folosește doar adresa cu https.",
            "Schimbă parola din fabrică cu una lungă și unică.",
            "Oprește administrarea de la distanță (din internet), dacă nu ai nevoie de ea.",
            "Actualizează firmware-ul dispozitivului.",
        ],
    },
    "SMB_EXPOSED": {
        "harm": "Cineva poate ajunge la fișierele tale sau poate răspândi un virus care cere bani.",
        "text": "Partajarea de fișiere Windows (SMB) e deschisă în rețea. Prin ea, atacatorii pot ajunge la fișiere, iar virușii care cer bani trec de la un calculator la altul.",
        "steps": [
            "Dacă nu împarți fișiere, oprește partajarea: Setări → Rețea și internet → Setări avansate de rețea → Setări avansate de partajare.",
            "Dacă împarți, cere parolă și dă acces doar celor care au nevoie.",
            "Oprește versiunea veche SMBv1 (din „Activare sau dezactivare caracteristici Windows”).",
            "Instalează toate actualizările sistemului.",
            "Pe Windows, alege „Public” pentru rețelele din cafenele sau hoteluri, ca partajarea să nu se vadă acolo.",
        ],
    },
    "MQTT_EXPOSED": {
        "harm": "Cineva din rețea poate aprinde luminile sau poate da alte comenzi aparatelor tale smart.",
        "text": "MQTT e felul în care becurile, senzorii sau încuietorile smart își trimit mesaje. Fără parolă, oricine din rețea le poate citi mesajele sau le poate da comenzi.",
        "steps": [
            "În aplicația sau pagina centralei casei inteligente, cere nume și parolă de la toate aparatele.",
            "Pornește tot acolo criptarea (TLS).",
            "Din firewall, lasă poștașul mesajelor (brokerul) să primească doar aparatele tale.",
            "Actualizează programul MQTT (brokerul) la ultima versiune.",
        ],
    },
    "UPNP_EXPOSED": {
        "harm": "Un virus de pe un dispozitiv poate deschide rețeaua ta spre internet.",
        "text": "UPnP le permite dispozitivelor să deschidă singure uși în router, fără să te întrebe. "
                "Un virus de pe un dispozitiv poate folosi asta ca să deschidă rețeaua ta spre internet.",
        "steps": [
            "Oprește UPnP din setările dispozitivului (la router: din pagina de administrare).",
            "Deschide manual în router doar porturile (ușile) de care ai nevoie, și doar cât timp ai nevoie.",
            "Actualizează firmware-ul dispozitivului.",
        ],
    },
    "SNMP_EXPOSED": {
        "harm": "Cineva poate afla modelul și setările dispozitivului, ca să știe cum să-l atace.",
        "text": "SNMP spune oricui întreabă multe detalii despre dispozitiv, cum ar fi modelul, setările "
                "și rețeaua. Adesea folosește parola din fabrică „public”, pe care o știe toată lumea.",
        "steps": [
            "Oprește SNMP din pagina de administrare a dispozitivului (de obicei la „Administrare” sau „Servicii”), dacă nu îl folosești.",
            "Dacă îl folosești, schimbă parola SNMP din fabrică („public”) cu una lungă.",
            "Alege versiunea 3 a SNMP (SNMPv3), singura care cere parolă și criptează.",
            "Actualizează firmware-ul dispozitivului.",
        ],
    },
    "PRINTER_RAW_EXPOSED": {
        "harm": "Cineva din rețea poate printa pe imprimanta ta fără voie sau o poate bloca.",
        "text": "Imprimanta primește lucrări direct din rețea, fără nicio verificare. Oricine din rețea poate printa pe ea sau îi poate da comenzi ciudate.",
        "steps": [
            "Oprește printarea directă (RAW / JetDirect) din pagina de administrare a imprimantei, dacă nu o folosești.",
            "Lasă doar calculatoarele tale să printeze, din setările imprimantei.",
            "Pune o parolă pe pagina de administrare a imprimantei.",
            "Actualizează firmware-ul imprimantei.",
        ],
    },
    "UNKNOWN_DEVICE": {
        "harm": "Un dispozitiv străin poate spiona ce se întâmplă în rețeaua ta.",
        "text": "Scanarea nu a aflat nici numele, nici producătorul unui dispozitiv din rețea care acceptă conexiuni. "
                "E bine să știi ce e fiecare dispozitiv, pentru că unul străin te poate spiona.",
        "steps": [
            "Caută dispozitivul în lista de dispozitive conectate din router.",
            "Verifică întâi dacă nu e un telefon sau un laptop de-al tău: cele noi își ascund adresa reală.",
            "Dacă nu e al tău, schimbă parola Wi-Fi.",
            "Dă-i un nume în router, ca să-l recunoști data viitoare.",
            "Mută dispozitivele inteligente și pe cele necunoscute în rețeaua pentru oaspeți, dacă routerul are una.",
        ],
    },
    "SSH_OPEN": {
        "harm": "Cineva poate încerca mii de parole, iar dacă una merge, controlează dispozitivul.",
        "text": "SSH e o cale criptată de a controla un dispozitiv de la distanță, deci nu e o problemă în sine. Trebuie doar protejat bine, pentru că atacatorii încearcă des parole pe el.",
        "steps": [
            "Dacă nu folosești SSH, oprește-l.",
            "Folosește chei SSH (un fel de cheie digitală) în loc de parole.",
            "Nu permite autentificarea directă ca administrator (root).",
            "Ține serverul SSH actualizat.",
        ],
    },
}
