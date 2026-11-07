"""Ghicirea tipului de dispozitiv (FR-03). Euristică simplă, deterministă.

Nu influențează findings sau scorul (acestea vin doar din rules.py); tipul e
folosit în UI și în explicații. Se calculează doar din date deja curățate.
"""

from __future__ import annotations

import re

from netscan.model import Port

_CAMERA_WORDS = ("camera", "hikvision", "dahua", "reolink", "axis", "ipcam")
_PRINTER_WORDS = ("printer", "canon", "epson", "brother", "xerox", "lexmark")
_ROUTER_WORDS = (
    "router", "tp-link", "tplink", "netgear", "d-link", "dlink", "mikrotik",
    "ubiquiti", "linksys", "zyxel", "gateway",
)
_TV_WORDS = ("tv", "roku", "chromecast", "bravia", "webos")
_WINDOWS_WORDS = ("microsoft", "windows")
_IOT_WORDS = ("espressif", "tuya", "shelly", "hub", "sensor", "esp32", "esp8266")

_WINDOWS_SERVICES = {"ms-wbt-server", "microsoft-ds", "netbios-ssn"}
_SERVER_SERVICES = {"mysql", "postgresql", "redis", "mongodb", "ftp", "ssh"}


def _has_word(text: str, words: tuple[str, ...]) -> bool:
    # potrivire pe cuvinte întregi (tv să nu se potrivească în "vendor")
    for w in words:
        if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", text):
            return True
    return False


def guess_device_type(
    vendor: str | None, hostname: str | None, ports: list[Port]
) -> str:
    """Întoarce unul din: router | camera | printer | tv | pc_windows | server |
    phone_laptop | iot | unknown."""
    open_ports = [p for p in ports if p.state == "open"]
    services = {(p.service or "").lower() for p in open_ports}
    text = " ".join(x for x in (vendor, hostname) if x).lower()
    titles = " ".join(p.title.lower() for p in open_ports if p.title)

    if "rtsp" in services or _has_word(text, _CAMERA_WORDS):
        return "camera"
    if "jetdirect" in services or _has_word(text, _PRINTER_WORDS):
        return "printer"
    if _has_word(text, _ROUTER_WORDS) or _has_word(titles, ("router",)):
        return "router"
    if "upnp" in services:
        return "router"
    if _has_word(text, _TV_WORDS):
        return "tv"
    if services & _WINDOWS_SERVICES or _has_word(text, _WINDOWS_WORDS):
        return "pc_windows"
    if "mqtt" in services or _has_word(text, _IOT_WORDS):
        return "iot"
    if services & _SERVER_SERVICES:
        return "server"
    if not open_ports and (vendor or hostname):
        return "phone_laptop"
    return "unknown"
