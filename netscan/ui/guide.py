"""Ghidul „Începe depanarea”: ce scene (animații) se arată pentru fiecare dintre cele 15 coduri.

Doar date, fără logică de risc: scorul, gravitatea și ordinea vin din motor. Numărul de gesturi e mic și
finit, deci scenele sunt refolosite: găsește dispozitivul, întoarce-l și citește eticheta, deschide pagina de
administrare, apoi UN gest (oprește serviciul / actualizează / schimbă parola / pornește HTTPS / setări Windows /
rețea pentru oaspeți / caută în lista routerului) și, la final, verificarea.
"""
from __future__ import annotations

from dataclasses import dataclass

FIND, LABEL, ADMIN, TOGGLE, UPDATE, PASSWORD, HTTPS, WINDOWS, GUEST, ROUTERLIST, CONFIG, VERIFY = (
    "find", "label", "admin", "toggle", "update", "password", "https", "windows", "guest", "routerlist", "config", "verify")

ALL_SCENES = (FIND, LABEL, ADMIN, TOGGLE, UPDATE, PASSWORD, HTTPS, WINDOWS, GUEST, ROUTERLIST, CONFIG, VERIFY)

# Fiecare plan urmează pașii din netscan/explain pentru codul respectiv (aceeași ordine, aceleași condiții).
# Unde un pas depinde de situație („dacă nu-l folosești”), textul scenei o spune explicit (cheile g_<scenă>_<COD>).
PLANS: dict[str, tuple[str, ...]] = {
    "TELNET_OPEN": (FIND, LABEL, ADMIN, TOGGLE, PASSWORD, VERIFY),
    "FTP_CLEARTEXT": (FIND, LABEL, ADMIN, TOGGLE, VERIFY),
    "SNMP_EXPOSED": (FIND, LABEL, ADMIN, TOGGLE, VERIFY),
    "UPNP_EXPOSED": (FIND, LABEL, ADMIN, TOGGLE, VERIFY),
    "VNC_EXPOSED": (FIND, TOGGLE, VERIFY),                       # programul VNC rulează pe un calculator
    "SSH_OPEN": (FIND, TOGGLE, VERIFY),                          # doar informativ: oprit numai dacă nu e folosit
    "PRINTER_RAW_EXPOSED": (FIND, ADMIN, TOGGLE, PASSWORD, VERIFY),
    "DB_EXPOSED": (FIND, CONFIG, VERIFY),                        # adresa de ascultare 127.0.0.1, apoi repornire
    "MQTT_EXPOSED": (FIND, CONFIG, VERIFY),                      # fără acces anonim
    "CAMERA_STREAM_EXPOSED": (FIND, LABEL, ADMIN, PASSWORD, TOGGLE, VERIFY),
    "OUTDATED_SERVICE": (FIND, LABEL, ADMIN, UPDATE, VERIFY),
    "HTTP_ADMIN_CLEARTEXT": (FIND, LABEL, ADMIN, HTTPS, PASSWORD, VERIFY),
    "RDP_EXPOSED": (FIND, WINDOWS, VERIFY),
    "SMB_EXPOSED": (FIND, WINDOWS, VERIFY),
    "UNKNOWN_DEVICE": (FIND, ROUTERLIST, PASSWORD, GUEST, VERIFY),
}
DEFAULT_PLAN = (FIND, LABEL, ADMIN, VERIFY)

# Linia din fișierul de configurare, înainte -> după (aceeași în orice limbă: e text de configurare).
CONFIG_LINES: dict[str, tuple[str, str]] = {
    "DB_EXPOSED": ("bind 0.0.0.0", "bind 127.0.0.1"),
    "MQTT_EXPOSED": ("allow_anonymous true", "allow_anonymous false"),
}

# Câte %s primește textul fiecărei scene (și orice text special g_<scenă>_<COD>): găsește = (dispozitiv, IP),
# comutator = serviciul, Windows = calea din setări, lista routerului = IP.
TEXT_ARGS = {FIND: 2, TOGGLE: 1, WINDOWS: 1, ROUTERLIST: 1}

ICON_BY_TYPE = {"router": "router", "camera": "camera", "printer": "printer"}


@dataclass(frozen=True)
class Guide:
    code: str
    scenes: tuple[str, ...]
    config: tuple[str, str] | None = None


# Calculatoarele nu au etichetă cu parola de fabrică și nici pagină de administrare în browser:
# acolo serviciul se oprește din programul sau din setările calculatorului.
COMPUTER_TYPES = frozenset({"pc_windows", "server", "phone_laptop"})


def guide_for(code: str | None, device_type: str | None = None) -> Guide:
    code = code or ""
    scenes = PLANS.get(code, DEFAULT_PLAN)
    if device_type in COMPUTER_TYPES:
        scenes = tuple(s for s in scenes if s not in (LABEL, ADMIN))
    return Guide(code, scenes, CONFIG_LINES.get(code))


def device_icon(device_type: str | None) -> str:
    return ICON_BY_TYPE.get(device_type or "", "generic")
