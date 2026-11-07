"""Maparea fiecărui cod din catalog pe CIS Controls v8 și OWASP IoT Top 10 2018 (Oneata, D3).

Doar trimiteri, pentru afișare lângă explicație: nu schimbă findings, severități, scoruri sau
textele din get_explanation(). Nu e o „certificare”: arată de ce standard ține fiecare problemă.

Surse verificate (7 nov. 2026):
- OWASP IoT Top 10 2018, PDF-ul oficial:
  https://owasp.org/www-pdf-archive/OWASP-IoT-Top-10-2018-final.pdf
- CIS Controls v8, numerele și titlurile safeguard-urilor din specificația de evaluare publicată de CIS:
  https://controls-assessment-specification.readthedocs.io/en/latest/
  (pagina controalelor: https://www.cisecurity.org/controls/v8)

Titlurile în engleză sunt cele oficiale, cuvânt cu cuvânt; cele în română sunt traducerea noastră.

Interfața pentru UI:
    get_standards(code, lang) -> {"cis": [{"id", "title"}], "owasp_iot": [{"id", "title"}]}
Cod necunoscut → liste goale.
"""

from __future__ import annotations

CIS_NAME = {"ro": "CIS Controls v8", "en": "CIS Controls v8"}
OWASP_NAME = {"ro": "OWASP IoT Top 10 (2018)", "en": "OWASP IoT Top 10 (2018)"}

SOURCES = {
    "cis": "https://www.cisecurity.org/controls/v8",
    "owasp_iot": "https://owasp.org/www-project-internet-of-things/",
}

# Safeguard-urile CIS Controls v8 folosite: id → titlu (en = oficial, ro = traducere).
CIS = {
    "1.1": {"en": "Establish and Maintain Detailed Enterprise Asset Inventory",
            "ro": "Ține o listă detaliată și actualizată a dispozitivelor"},
    "1.2": {"en": "Address Unauthorized Assets",
            "ro": "Rezolvă dispozitivele neautorizate"},
    "2.2": {"en": "Ensure Authorized Software is Currently Supported",
            "ro": "Folosește doar programe care încă primesc actualizări"},
    "3.10": {"en": "Encrypt Sensitive Data in Transit",
             "ro": "Criptează datele sensibile când circulă prin rețea"},
    "4.2": {"en": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
            "ro": "Configurează sigur echipamentele de rețea"},
    "4.4": {"en": "Implement and Manage a Firewall on Servers",
            "ro": "Folosește un firewall pe servere"},
    "4.5": {"en": "Implement and Manage a Firewall on End-User Devices",
            "ro": "Folosește un firewall pe calculatoarele utilizatorilor"},
    "4.6": {"en": "Securely Manage Enterprise Assets and Software",
            "ro": "Administrează dispozitivele doar prin protocoale sigure"},
    "4.7": {"en": "Manage Default Accounts on Enterprise Assets and Software",
            "ro": "Gestionează conturile și parolele din fabrică"},
    "4.8": {"en": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
            "ro": "Dezinstalează sau oprește serviciile de care nu ai nevoie"},
    "5.2": {"en": "Use Unique Passwords",
            "ro": "Folosește parole unice"},
    "7.3": {"en": "Perform Automated Operating System Patch Management",
            "ro": "Actualizează automat sistemul de operare"},
    "7.4": {"en": "Perform Automated Application Patch Management",
            "ro": "Actualizează automat aplicațiile"},
    "12.2": {"en": "Establish and Maintain a Secure Network Architecture",
             "ro": "Organizează rețeaua sigur, separată pe zone"},
}

# OWASP IoT Top 10 2018: id → titlu (en = oficial, ro = traducere).
OWASP_IOT = {
    "I1": {"en": "Weak, Guessable, or Hardcoded Passwords",
           "ro": "Parole slabe, ușor de ghicit sau scrise în firmware"},
    "I2": {"en": "Insecure Network Services",
           "ro": "Servicii de rețea nesigure"},
    "I4": {"en": "Lack of Secure Update Mechanism",
           "ro": "Lipsa unui mecanism sigur de actualizare"},
    "I5": {"en": "Use of Insecure or Outdated Components",
           "ro": "Componente nesigure sau învechite"},
    "I6": {"en": "Insufficient Privacy Protection",
           "ro": "Protecție insuficientă a vieții private"},
    "I7": {"en": "Insecure Data Transfer and Storage",
           "ro": "Transfer și stocare nesigure a datelor"},
    "I8": {"en": "Lack of Device Management",
           "ro": "Lipsa gestionării dispozitivelor"},
    "I9": {"en": "Insecure Default Settings",
           "ro": "Setări implicite nesigure"},
}

# Cod → trimiteri, cea mai relevantă prima. De ce, pe scurt:
# - serviciu de care nu e nevoie, deschis în rețea → CIS 4.8 + OWASP I2 (punctul de pornire din ghid);
# - parolă/date în clar (Telnet, FTP, HTTP) → CIS 3.10 / 4.6 + OWASP I7; CIS 4.6 numește explicit Telnet și HTTP;
# - parole din fabrică / fără parolă → CIS 4.7, 5.2 + OWASP I1, I9;
# - versiuni vechi → CIS 2.2, 7.3, 7.4 + OWASP I5, I4;
# - dispozitiv necunoscut → CIS 1.1, 1.2 (inventar) + OWASP I8.
MAPPING: dict[str, dict[str, list[str]]] = {
    "TELNET_OPEN": {"cis": ["4.6", "4.8", "3.10"], "owasp_iot": ["I2", "I7"]},
    "RDP_EXPOSED": {"cis": ["4.8", "4.5", "5.2"], "owasp_iot": ["I2"]},
    "VNC_EXPOSED": {"cis": ["4.8", "5.2", "3.10"], "owasp_iot": ["I2", "I1"]},
    "DB_EXPOSED": {"cis": ["4.4", "4.7", "12.2"], "owasp_iot": ["I2", "I9"]},
    "CAMERA_STREAM_EXPOSED": {"cis": ["4.7", "4.8", "12.2"], "owasp_iot": ["I1", "I6", "I2"]},
    "OUTDATED_SERVICE": {"cis": ["2.2", "7.4", "7.3"], "owasp_iot": ["I5", "I4"]},
    "FTP_CLEARTEXT": {"cis": ["3.10", "4.8"], "owasp_iot": ["I7", "I2"]},
    "HTTP_ADMIN_CLEARTEXT": {"cis": ["4.6", "3.10", "4.7"], "owasp_iot": ["I7", "I1"]},
    "SMB_EXPOSED": {"cis": ["4.8", "4.5", "7.3"], "owasp_iot": ["I2"]},
    "MQTT_EXPOSED": {"cis": ["4.8", "3.10", "5.2"], "owasp_iot": ["I2", "I9", "I7"]},
    "UPNP_EXPOSED": {"cis": ["4.2", "4.8"], "owasp_iot": ["I9", "I2"]},
    "SNMP_EXPOSED": {"cis": ["4.7", "4.8", "3.10"], "owasp_iot": ["I9", "I1"]},
    "PRINTER_RAW_EXPOSED": {"cis": ["4.8", "12.2"], "owasp_iot": ["I2"]},
    "UNKNOWN_DEVICE": {"cis": ["1.1", "1.2"], "owasp_iot": ["I8"]},
    "SSH_OPEN": {"cis": ["4.8", "4.7", "5.2"], "owasp_iot": ["I1"]},
}


def _lang(lang: str | None) -> str:
    lang = (lang or "").lower()
    return lang if lang in ("ro", "en") else "ro"


def get_standards(code: str, lang: str = "ro") -> dict:
    """Trimiterile pentru un cod: {"cis": [{"id", "title"}], "owasp_iot": [{"id", "title"}]}."""
    lang = _lang(lang)
    entry = MAPPING.get(code, {"cis": [], "owasp_iot": []})
    return {
        "cis": [{"id": i, "title": CIS[i][lang]} for i in entry["cis"]],
        "owasp_iot": [{"id": i, "title": OWASP_IOT[i][lang]} for i in entry["owasp_iot"]],
    }
