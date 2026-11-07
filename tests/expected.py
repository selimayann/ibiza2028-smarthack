"""Răspunsurile oficiale ale Validation Set-ului, din brief (24 de rânduri).

Aceste valori vin din brief. Verifică numele exacte ale fișierelor când primești
Validation Set-ul și ajustează aici dacă e nevoie.
"""

from __future__ import annotations

# (file, ip, port ca text — gol la UNKNOWN_DEVICE —, cod, severitate)
EXPECTED_ROWS: set[tuple[str, str, str, str, str]] = {
    ("V1_home_basic.xml", "192.168.1.1", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V2_smart_home.xml", "192.168.1.1", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V2_smart_home.xml", "192.168.1.1", "1900", "UPNP_EXPOSED", "medium"),
    ("V2_smart_home.xml", "192.168.1.40", "554", "CAMERA_STREAM_EXPOSED", "high"),
    ("V2_smart_home.xml", "192.168.1.40", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V2_smart_home.xml", "192.168.1.41", "1883", "MQTT_EXPOSED", "medium"),
    ("V3_small_office.xml", "192.168.1.10", "9100", "PRINTER_RAW_EXPOSED", "low"),
    ("V3_small_office.xml", "192.168.1.20", "445", "SMB_EXPOSED", "medium"),
    ("V3_small_office.xml", "192.168.1.20", "22", "SSH_OPEN", "info"),
    ("V3_small_office.xml", "192.168.1.30", "3389", "RDP_EXPOSED", "high"),
    ("V3_small_office.xml", "192.168.1.40", "22", "SSH_OPEN", "info"),
    ("V3_small_office.xml", "192.168.1.40", "3306", "DB_EXPOSED", "high"),
    ("V4_legacy.xml", "192.168.1.1", "23", "TELNET_OPEN", "high"),
    ("V4_legacy.xml", "192.168.1.1", "161", "SNMP_EXPOSED", "medium"),
    ("V4_legacy.xml", "192.168.1.1", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V4_legacy.xml", "192.168.1.60", "21", "FTP_CLEARTEXT", "medium"),
    ("V4_legacy.xml", "192.168.1.60", "21", "OUTDATED_SERVICE", "high"),
    ("V4_legacy.xml", "192.168.1.99", "", "UNKNOWN_DEVICE", "low"),
    ("V5_nonstandard_ports.xml", "192.168.1.5", "2323", "TELNET_OPEN", "high"),
    ("V5_nonstandard_ports.xml", "192.168.1.6", "8081", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V5_nonstandard_ports.xml", "192.168.1.7", "6380", "DB_EXPOSED", "high"),
    ("V6a_before.xml", "192.168.1.1", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("V6a_before.xml", "192.168.1.1", "1900", "UPNP_EXPOSED", "medium"),
    ("V6a_before.xml", "192.168.1.30", "23", "TELNET_OPEN", "high"),
}

EXPECTED_SCORES: dict[str, str] = {
    "V1_home_basic.xml": "90",
    "V2_smart_home.xml": "40",
    "V3_small_office.xml": "45",
    "V4_legacy.xml": "25",
    "V5_nonstandard_ports.xml": "50",
    "V6a_before.xml": "60",
    "V6b_after.xml": "100",
    "V7_broken.xml": "ERROR",
}

assert len(EXPECTED_ROWS) == 24, "brief-ul cere exact 24 de rânduri"
