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
    # T06: Samba 3.X - 4.X e ambiguu -> doar SMB_EXPOSED (DE CONFIRMAT, întrebarea 1);
    #      Samba 3.0.20 e clar învechit
    ("T06_samba_versions.xml", P + "10", "445", "SMB_EXPOSED", "medium"),
    ("T06_samba_versions.xml", P + "11", "445", "OUTDATED_SERVICE", "high"),
    ("T06_samba_versions.xml", P + "11", "445", "SMB_EXPOSED", "medium"),
    # T07: „Administration” conține „admin” (DE CONFIRMAT, întrebarea 4: subșir)
    ("T07_title_administration.xml", P + "10", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T08: textul din titlu nu e instrucțiune; doar cuvântul „Admin” contează
    ("T08_title_prompt_injection.xml", P + "11", "80", "HTTP_ADMIN_CLEARTEXT", "medium"),
    # T15: OUTDATED_SERVICE pe FIECARE port cu Samba veche; SMB_EXPOSED o singură dată (pe 445)
    #      (DE CONFIRMAT, întrebarea 2). .11: 139 veche (3.0.20), 445 nouă (4.15.13)
    ("T15_samba_outdated_139_445.xml", P + "10", "139", "OUTDATED_SERVICE", "high"),
    ("T15_samba_outdated_139_445.xml", P + "10", "445", "OUTDATED_SERVICE", "high"),
    ("T15_samba_outdated_139_445.xml", P + "10", "445", "SMB_EXPOSED", "medium"),
    ("T15_samba_outdated_139_445.xml", P + "11", "139", "OUTDATED_SERVICE", "high"),
    ("T15_samba_outdated_139_445.xml", P + "11", "445", "SMB_EXPOSED", "medium"),
]

SCORES = {
    "T01_upnp_tcp_vs_udp.xml": "90",
    "T02_snmp_open_filtered.xml": "90",
    "T03_http_vs_https.xml": "90",
    "T04_smb_139_445.xml": "80",
    "T05_openssh_versions.xml": "60",
    "T06_samba_versions.xml": "60",
    "T07_title_administration.xml": "90",
    "T15_samba_outdated_139_445.xml": "20",
    "T08_title_prompt_injection.xml": "90",
    "T09_xxe.xml": "ERROR",
    "T10_empty.xml": "ERROR",
    "T11_not_nmap.xml": "ERROR",
    "T12_truncated.xml": "ERROR",
    "T13_billion_laughs.xml": "ERROR",
    "T14_closed_and_filtered.xml": "100",
}

ERROR_CODES = {
    "T09_xxe.xml": "XML_FORBIDDEN",
    "T10_empty.xml": "EMPTY",
    "T11_not_nmap.xml": "NOT_NMAP",
    "T12_truncated.xml": "TRUNCATED",
    "T13_billion_laughs.xml": "XML_FORBIDDEN",
}
