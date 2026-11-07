"""Rezultatele AȘTEPTATE pentru fixtures/traps/, deduse de mână din catalogul oficial.

NU sunt copiate din ieșirea motorului: dacă un test pică, fie motorul, fie această listă
are o greșeală, și trebuie decis care. Cazurile marcate DE CONFIRMAT sunt decizii proprii
(vezi docs/questions.md) și se schimbă dacă mentorii răspund altfel.

Format rând: (fișier, ip, port, cod, severitate)
"""

P = "192.168.1."

FINDINGS = [
    # T01: upnp contează doar pe UDP; pe TCP nu e finding
    ("T01_upnp_tcp_vs_udp.xml", P + "11", "1900", "UPNP_EXPOSED", "medium"),
    # T02: snmp open|filtered nu e finding; snmp open pe UDP da
    ("T02_snmp_open_filtered.xml", P + "11", "161", "SNMP_EXPOSED", "medium"),
    # T03: http cu tunnel="ssl" (HTTPS) nu e HTTP_ADMIN_CLEARTEXT
    ("T03_http_vs_https.xml", P + "10", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T04: SMB o singură dată pe dispozitiv: 445 dacă există, altfel 139
    ("T04_smb_139_445.xml", P + "10", "445", "SMB_EXPOSED", "medium"),
    ("T04_smb_139_445.xml", P + "11", "139", "SMB_EXPOSED", "medium"),
    # T05: OpenSSH < 7.4 e învechit (7.10 > 7.4: comparație numerică, nu pe text)
    ("T05_openssh_versions.xml", P + "10", "22", "SSH_OPEN", "info"),
    ("T05_openssh_versions.xml", P + "11", "22", "OUTDATED_SERVICE", "high"),
    ("T05_openssh_versions.xml", P + "11", "22", "SSH_OPEN", "info"),
    ("T05_openssh_versions.xml", P + "12", "22", "SSH_OPEN", "info"),
    ("T05_openssh_versions.xml", P + "13", "22", "OUTDATED_SERVICE", "high"),
    ("T05_openssh_versions.xml", P + "13", "22", "SSH_OPEN", "info"),
    # T06: Samba 3.X - 4.X e ambiguu -> doar SMB_EXPOSED (confirmat de mentori, întrebarea 1);
    #      Samba 3.0.20 e clar învechit
    ("T06_samba_versions.xml", P + "10", "445", "SMB_EXPOSED", "medium"),
    ("T06_samba_versions.xml", P + "11", "445", "OUTDATED_SERVICE", "high"),
    ("T06_samba_versions.xml", P + "11", "445", "SMB_EXPOSED", "medium"),
    # T07: „Administration” conține „admin” (DE CONFIRMAT, întrebarea 4: subșir)
    ("T07_title_administration.xml", P + "10", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T08: textul din titlu nu e instrucțiune; doar cuvântul „Admin” contează
    ("T08_title_prompt_injection.xml", P + "11", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T15: mentori (întrebarea 2): OUTDATED_SERVICE o singură dată pentru Samba, pe același port ca
    #      SMB_EXPOSED (445, altfel 139). .10 are 139 și 445 -> doar 445; .11 are doar 139 -> 139
    ("T15_samba_outdated_139_445.xml", P + "10", "445", "OUTDATED_SERVICE", "high"),
    ("T15_samba_outdated_139_445.xml", P + "10", "445", "SMB_EXPOSED", "medium"),
    ("T15_samba_outdated_139_445.xml", P + "11", "139", "OUTDATED_SERVICE", "high"),
    ("T15_samba_outdated_139_445.xml", P + "11", "139", "SMB_EXPOSED", "medium"),
    # T16: mentori (întrebarea 11): și „mosquitto version X" pe 1883 e MQTT_EXPOSED; filtered nu
    ("T16_mosquitto_service_name.xml", P + "10", "1883", "MQTT_EXPOSED", "medium"),
    ("T16_mosquitto_service_name.xml", P + "11", "1883", "MQTT_EXPOSED", "medium"),
    # --- Oneata (pre-flight Test Set) ---
    # T17: decide numele serviciului, nu portul: ssh pe 2222, telnet pe 2323, mysql pe 3307
    ("T17_catalog_on_unusual_ports.xml", P + "10", "2222", "SSH_OPEN", "info"),
    ("T17_catalog_on_unusual_ports.xml", P + "10", "2323", "TELNET_OPEN", "high"),
    ("T17_catalog_on_unusual_ports.xml", P + "10", "3307", "DB_EXPOSED", "high"),
    # T18: hostname fără MAC nu e UNKNOWN_DEVICE (are nume); martorul fără MAC și fără nume este
    ("T18_hostname_without_mac.xml", P + "10", "22", "SSH_OPEN", "info"),
    ("T18_hostname_without_mac.xml", P + "11", "", "UNKNOWN_DEVICE", "low"),
    ("T18_hostname_without_mac.xml", P + "11", "22", "SSH_OPEN", "info"),
    # T19: vendor fără hostname nu e UNKNOWN_DEVICE; martorul cu MAC fără vendor este (mentori, întrebarea 5)
    ("T19_vendor_without_hostname.xml", P + "10", "23", "TELNET_OPEN", "high"),
    ("T19_vendor_without_hostname.xml", P + "11", "", "UNKNOWN_DEVICE", "low"),
    ("T19_vendor_without_hostname.xml", P + "11", "21", "FTP_CLEARTEXT", "medium"),
    # T20: pragurile din catalog: IIS <= 7.5, Apache httpd <= 2.2.x, OpenSSH < 7.4 sunt învechite;
    #      IIS 8.0, Apache 2.4.0 și OpenSSH 7.4 nu. `http` fără titlu de admin nu e în catalog.
    ("T20_version_boundaries.xml", P + "10", "80", "OUTDATED_SERVICE", "high"),
    ("T20_version_boundaries.xml", P + "12", "80", "OUTDATED_SERVICE", "high"),
    ("T20_version_boundaries.xml", P + "14", "22", "OUTDATED_SERVICE", "high"),
    ("T20_version_boundaries.xml", P + "14", "22", "SSH_OPEN", "info"),
    ("T20_version_boundaries.xml", P + "15", "22", "SSH_OPEN", "info"),
    # T21: „Pagină de LOGIN” și „Setări Router” conțin cuvinte-cheie (subșir, fără diferență de litere,
    #      mentori întrebarea 4); „Pagina principală” nu
    ("T21_title_case_diacritics.xml", P + "10", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("T21_title_case_diacritics.xml", P + "11", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T22: hosturi fără niciun port deschis: niciun rând, nici UNKNOWN_DEVICE
    # T23: același serviciu pe mai multe porturi: câte un rând per (ip, port, cod)
    ("T23_same_service_many_ports.xml", P + "10", "23", "TELNET_OPEN", "high"),
    ("T23_same_service_many_ports.xml", P + "10", "2323", "TELNET_OPEN", "high"),
    ("T23_same_service_many_ports.xml", P + "11", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("T23_same_service_many_ports.xml", P + "11", "8080", "HTTP_ADMIN_CLEARTEXT", "medium"),
    ("T23_same_service_many_ports.xml", P + "12", "21", "FTP_CLEARTEXT", "medium"),
    ("T23_same_service_many_ports.xml", P + "12", "2121", "FTP_CLEARTEXT", "medium"),
    # T24: fișier nmap valid fără niciun host: niciun rând, scor 100
]

SCORES = {
    "T01_upnp_tcp_vs_udp.xml": "90",
    "T02_snmp_open_filtered.xml": "90",
    "T03_http_vs_https.xml": "90",
    "T04_smb_139_445.xml": "80",
    "T05_openssh_versions.xml": "60",
    "T06_samba_versions.xml": "60",
    "T07_title_administration.xml": "90",
    "T15_samba_outdated_139_445.xml": "40",
    "T16_mosquitto_service_name.xml": "80",
    "T08_title_prompt_injection.xml": "90",
    "T09_xxe.xml": "ERROR",
    "T10_empty.xml": "ERROR",
    "T11_not_nmap.xml": "ERROR",
    "T12_truncated.xml": "ERROR",
    "T13_billion_laughs.xml": "ERROR",
    "T14_closed_and_filtered.xml": "100",
    "T17_catalog_on_unusual_ports.xml": "60",       # 100 - 0 - 20 - 20
    "T18_hostname_without_mac.xml": "95",           # 100 - 5 (UNKNOWN_DEVICE la martor)
    "T19_vendor_without_hostname.xml": "65",        # 100 - 20 - 5 - 10
    "T20_version_boundaries.xml": "40",             # 100 - 3 x 20
    "T21_title_case_diacritics.xml": "80",          # 100 - 2 x 10
    "T22_host_without_open_ports.xml": "100",
    "T23_same_service_many_ports.xml": "20",        # 100 - 2 x 20 - 2 x 10 - 2 x 10
    "T24_valid_without_hosts.xml": "100",
}

ERROR_CODES = {
    "T09_xxe.xml": "XML_FORBIDDEN",
    "T10_empty.xml": "EMPTY",
    "T11_not_nmap.xml": "NOT_NMAP",
    "T12_truncated.xml": "TRUNCATED",
    "T13_billion_laughs.xml": "XML_FORBIDDEN",
}
