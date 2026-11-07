# Contractul de date (v1)

> Sursa unică de adevăr pentru forma datelor. Se schimbă doar după ce anunțați echipa, iar `docs/contract.md`, `netscan/model.py` și `fixtures/sample.json` se modifică **în același commit**.

## Structura

```
Scan
  file: str                  # numele fișierului (basename), ex. "V2_smart_home.xml"
  started_at: int | null     # atributul "start" din <nmaprun> (epoch); ordonează istoricul
  status: "ok" | "error"
  error_code: null | "EMPTY" | "TRUNCATED" | "INVALID_XML" | "XML_FORBIDDEN" | "NOT_NMAP" | "TOO_LARGE"
  score: int | null          # null dacă status = "error"
  hosts: [Host]
  findings: [Finding]

Host
  ip: str
  device_id: str             # sha256(salt + MAC real)[:12] dacă există MAC, altfel "ip:" + ip
  mac_masked: str | null     # "AA:BB:CC:XX:XX:XX"; MAC-ul real NU apare nicăieri în model
  vendor: str | null
  hostname: str | null
  device_type: str | null    # router | camera | printer | tv | pc_windows | server | phone_laptop | iot | unknown
  ports: [Port]

Port
  port: int
  proto: "tcp" | "udp"
  state: str                 # exact ca în nmap: "open", "filtered", "open|filtered", ...
  service: str | null        # atributul name din <service>
  product: str | null
  version: str | null
  extrainfo: str | null
  tunnel: str | null         # "ssl" dacă nmap l-a pus
  title: str | null          # titlul paginii web; TEXT NESIGUR (scris de oricine)

Finding
  file: str
  ip: str
  device_id: str
  port: int | null           # null doar la UNKNOWN_DEVICE
  code: str                  # unul din cele 15 coduri
  severity: "high" | "medium" | "low" | "info"
  points: int
  evidence: str              # ex. "21/tcp ftp vsftpd 2.3.4"
```

**Trei decizii fixate (A + D):**
1. **Identitatea dispozitivului:** `device_id`. Salt-ul vine din variabila de mediu `NETSCAN_SALT`.
2. **Identitatea unui finding** (pentru istoric): `(device_id, port, code)`.
3. **Ordinea:**
   - findings: `(file, ip numeric, port cu null primul, code)`;
   - dispozitive în UI („cel mai periculos”): suma punctelor ↓, apoi severitatea maximă ↓ (`high > medium > low > info`), apoi IP numeric ↑.

**Ieșirea standard (FR-15):**
```
findings.csv   file,ip,port,finding_code,severity        (port gol la UNKNOWN_DEVICE; severity cu litere mici)
scores.csv     file,network_score                        (ERROR pentru fișiere ilizibile)
```

**Catalogul (cod · severitate · puncte):**

| Cod | Sev. | Pct. | Cod | Sev. | Pct. |
|---|---|---|---|---|---|
| TELNET_OPEN | high | 20 | HTTP_ADMIN_CLEARTEXT | medium | 10 |
| RDP_EXPOSED | high | 20 | SMB_EXPOSED | medium | 10 |
| VNC_EXPOSED | high | 20 | MQTT_EXPOSED | medium | 10 |
| DB_EXPOSED | high | 20 | UPNP_EXPOSED | medium | 10 |
| CAMERA_STREAM_EXPOSED | high | 20 | SNMP_EXPOSED | medium | 10 |
| OUTDATED_SERVICE | high | 20 | PRINTER_RAW_EXPOSED | low | 5 |
| FTP_CLEARTEXT | medium | 10 | UNKNOWN_DEVICE | low | 5 |
| | | | SSH_OPEN | info | 0 |

## Exemplu: `fixtures/sample.json` (exemplu ilustrativ, bazat pe V2; se completează în prima oră)

```json
{
  "file": "V2_smart_home.xml", "started_at": 1762500000, "status": "ok", "error_code": null, "score": 40,
  "hosts": [
    {"ip": "192.168.1.1", "device_id": "d1a2b3c4d5e6", "mac_masked": "AA:BB:CC:XX:XX:XX", "vendor": "ExempluVendor",
     "hostname": null, "device_type": "router",
     "ports": [
       {"port": 80, "proto": "tcp", "state": "open", "service": "http", "product": null, "version": null,
        "extrainfo": null, "tunnel": null, "title": "Router Login"},
       {"port": 1900, "proto": "udp", "state": "open", "service": "upnp", "product": null, "version": null,
        "extrainfo": null, "tunnel": null, "title": null}]},
    {"ip": "192.168.1.40", "device_id": "e1f2a3b4c5d6", "mac_masked": "DD:EE:FF:XX:XX:XX", "vendor": "ExempluCam",
     "hostname": null, "device_type": "camera",
     "ports": [
       {"port": 554, "proto": "tcp", "state": "open", "service": "rtsp", "product": null, "version": null,
        "extrainfo": null, "tunnel": null, "title": null},
       {"port": 80, "proto": "tcp", "state": "open", "service": "http", "product": null, "version": null,
        "extrainfo": null, "tunnel": null, "title": "Camera Admin"}]},
    {"ip": "192.168.1.41", "device_id": "f1a2b3c4d5e7", "mac_masked": "11:22:33:XX:XX:XX", "vendor": "ExempluHub",
     "hostname": "smart-hub", "device_type": "iot",
     "ports": [
       {"port": 1883, "proto": "tcp", "state": "open", "service": "mqtt", "product": null, "version": null,
        "extrainfo": null, "tunnel": null, "title": null}]}
  ],
  "findings": [
    {"file": "V2_smart_home.xml", "ip": "192.168.1.1", "device_id": "d1a2b3c4d5e6", "port": 80,
     "code": "HTTP_ADMIN_CLEARTEXT", "severity": "medium", "points": 10, "evidence": "80/tcp http, titlu: Router Login"},
    {"file": "V2_smart_home.xml", "ip": "192.168.1.1", "device_id": "d1a2b3c4d5e6", "port": 1900,
     "code": "UPNP_EXPOSED", "severity": "medium", "points": 10, "evidence": "1900/udp upnp"},
    {"file": "V2_smart_home.xml", "ip": "192.168.1.40", "device_id": "e1f2a3b4c5d6", "port": 80,
     "code": "HTTP_ADMIN_CLEARTEXT", "severity": "medium", "points": 10, "evidence": "80/tcp http, titlu: Camera Admin"},
    {"file": "V2_smart_home.xml", "ip": "192.168.1.40", "device_id": "e1f2a3b4c5d6", "port": 554,
     "code": "CAMERA_STREAM_EXPOSED", "severity": "high", "points": 20, "evidence": "554/tcp rtsp"},
    {"file": "V2_smart_home.xml", "ip": "192.168.1.41", "device_id": "f1a2b3c4d5e7", "port": 1883,
     "code": "MQTT_EXPOSED", "severity": "medium", "points": 10, "evidence": "1883/tcp mqtt"}
  ]
}
```

Vendorii, MAC-urile și titlurile de mai sus sunt inventate pentru test. Nu sunt rezultate și nu ajung niciodată în CSV-urile de predare.

## Istoricul versiunilor

| Versiune | Ce s-a schimbat | Cine |
|---|---|---|
| v1 | Versiunea inițială | toată echipa |
