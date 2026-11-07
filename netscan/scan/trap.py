"""Ușa-capcană (B): un Telnet fals pe laptopul nostru, ca să aflăm când cineva din rețea încearcă să intre.

Idee de la honeypot-uri ca OpenCanary: nimeni legitim nu are de ce să se conecteze acolo, deci orice
încercare e o alertă. Fără agenți pe alte dispozitive și fără log-uri citite de pe ele.

Reguli (aceleași ca serviciile false din lab: „simulăm, nu expunem”):
- ascultă DOAR pe IP-ul laptopului din hotspot (niciodată 0.0.0.0) și pornește doar dacă rețeaua e OK
  (SSID-ul echipei, o singură rețea); fără --confirm e doar dry-run;
- nu execută nimic, nu are login real: trimite un prompt, citește ce primește și îl ARUNCĂ, închide în câteva secunde;
- păstrează doar IP-ul, ora și portul (local, data/trap_attempts.jsonl), niciodată parola sau ce a scris omul;
  încercările mai vechi de 7 zile se șterg automat, iar „Șterge istoricul” le șterge pe toate;
- ignoră IP-urile din lista de excepții (scannerul nostru, NETSCAN_TRAP_IGNORE) și dă cel mult o alertă
  pe minut pentru același IP; cel mult MAX_CONNECTIONS conexiuni simultane.
- e doar defensivă: nu răspunde înapoi spre IP-ul care a încercat și nu sugerează niciun „contraatac”.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from netscan.scan import local_data, network

DEFAULT_PORT = 2323
READ_TIMEOUT = 5.0
MAX_READ = 256
MAX_CONNECTIONS = 20
ALERT_EVERY_S = 60
BANNER = b"\r\nBusyBox v1.24.1 (built-in shell (ash))\r\n\r\nlogin: "

TEXTS = {
    "ro": {
        "attempt": ("Cineva din rețea ({ip}) a încercat să intre pe ușa-capcană (port {port}). Dacă nu știi cine e, "
                    "verifică dispozitivul și schimbă parolele dispozitivelor tale. Nu am păstrat nimic din ce a scris."),
        "listening": "Ușa-capcană ascultă pe {ip}:{port} (doar în hotspot). Oprește cu Ctrl+C.",
        "dry_run": "Dry-run. Aș deschide ușa-capcană pe {ip}:{port} (doar în hotspot). Adaugă --confirm ca s-o pornești.",
        "firewall": ("Pe Windows, permite portul doar pe rețeaua Private (terminal de Administrator):\n"
                     "  New-NetFirewallRule -DisplayName netscan-trap -Direction Inbound -Protocol TCP "
                     "-LocalPort {port} -Profile Private -Action Allow\n"
                     "  (ștergere după demo: Remove-NetFirewallRule -DisplayName netscan-trap)"),
        "refused": "Nu deschid ușa-capcană: {why}",
        "bad_port": "Portul trebuie să fie între 1024 și 65535 (fără drepturi de administrator).",
        "stopped": "Ușa-capcană oprită.",
    },
    "en": {
        "attempt": ("Someone on the network ({ip}) tried to get in through the trap door (port {port}). If you don't "
                    "know who it is, check that device and change your devices' passwords. Nothing they typed was kept."),
        "listening": "The trap door is listening on {ip}:{port} (hotspot only). Stop with Ctrl+C.",
        "dry_run": "Dry-run. I would open the trap door on {ip}:{port} (hotspot only). Add --confirm to start it.",
        "firewall": ("On Windows, allow the port on the Private network only (Administrator terminal):\n"
                     "  New-NetFirewallRule -DisplayName netscan-trap -Direction Inbound -Protocol TCP "
                     "-LocalPort {port} -Profile Private -Action Allow\n"
                     "  (remove after the demo: Remove-NetFirewallRule -DisplayName netscan-trap)"),
        "refused": "Not opening the trap door: {why}",
        "bad_port": "The port must be between 1024 and 65535 (no administrator rights).",
        "stopped": "Trap door stopped.",
    },
}


@dataclass(frozen=True)
class TrapPlan:
    ok: bool
    ip: Optional[str] = None
    message_ro: str = ""
    message_en: str = ""


def plan_trap(detect: Callable[[], network.NetworkInfo] = network.detect_network) -> TrapPlan:
    """IP-ul pe care are voie să asculte: doar IP-ul laptopului din hotspot, când rețeaua e OK."""
    info = detect()
    if not info.scan_allowed or not info.ip:
        ro, en = network.MESSAGES.get(info.status, ("Rețeaua nu e potrivită.", "The network isn't suitable."))
        return TrapPlan(False, None, ro, en)
    ip = ipaddress.IPv4Address(info.ip)
    if not ip.is_private or ip.is_loopback or ip.is_unspecified:
        return TrapPlan(False, None, "IP-ul nu e o adresă privată din hotspot.", "The IP isn't a private hotspot address.")
    return TrapPlan(True, str(ip))


def ignore_list(own_ip: Optional[str], env: Optional[dict] = None) -> set[str]:
    env = os.environ if env is None else env
    ips = {own_ip} if own_ip else set()
    for part in (env.get("NETSCAN_TRAP_IGNORE") or "").split(","):
        part = part.strip()
        try:
            ips.add(str(ipaddress.IPv4Address(part)))
        except ValueError:
            continue
    return ips


class TrapServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, bind_ip: str, port: int, ignore: Iterable[str], on_attempt: Callable[[dict], None],
                 now: Callable[[], float] = time.time):
        if bind_ip in ("0.0.0.0", "", "::"):
            raise ValueError("ușa-capcană nu ascultă pe toate interfețele")
        self.ignore = set(ignore)
        self.on_attempt = on_attempt
        self.now = now
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()
        super().__init__((bind_ip, port), _Handler)

    def record(self, ip: str, port: int) -> None:
        if ip in self.ignore:
            return
        with self._lock:
            t = self.now()
            if t - self._last_alert.get(ip, -1e18) < ALERT_EVERY_S:
                return
            self._last_alert[ip] = t
        self.on_attempt({"ts": t, "ip": ip, "port": port})


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: TrapServer = self.server  # type: ignore[assignment]
        if not server.slots.acquire(blocking=False):
            return                                     # prea multe conexiuni: închidem imediat
        try:
            ip = self.client_address[0]
            server.record(ip, server.server_address[1])
            sock: socket.socket = self.request
            sock.settimeout(READ_TIMEOUT)
            try:
                sock.sendall(BANNER)
                sock.recv(MAX_READ)                    # citim și ARUNCĂM: nu păstrăm nimic din ce s-a scris
                sock.sendall(b"\r\nLogin incorrect\r\n")
            except OSError:
                pass
        finally:
            server.slots.release()


def save_attempt(event: dict, db_path=None) -> None:
    """Doar IP, oră, port. Purjarea automată a celor vechi se face la fiecare scriere."""
    clean = {"ts": float(event["ts"]), "ip": str(ipaddress.IPv4Address(event["ip"])), "port": int(event["port"])}
    path = local_data.trap_path(db_path)
    local_data.append_events(path, [clean])
    local_data.purge_old(path)


def run_trap(confirm: bool, port: int = DEFAULT_PORT, lang: str = "ro", out: Callable[[str], None] = print,
             detect: Callable = network.detect_network, env: Optional[dict] = None, db_path=None,
             serve: bool = True) -> int:
    t = TEXTS[lang if lang in TEXTS else "ro"]
    if not 1024 <= port <= 65535:
        out(t["bad_port"])
        return 2
    plan = plan_trap(detect)
    if not plan.ok:
        out(t["refused"].format(why=plan.message_en if lang == "en" else plan.message_ro))
        return 2
    if not confirm:
        out(t["dry_run"].format(ip=plan.ip, port=port))
        out(t["firewall"].format(port=port))
        return 0

    local_data.purge_old(local_data.trap_path(db_path))

    def on_attempt(ev: dict) -> None:
        save_attempt(ev, db_path)
        out(time.strftime("[%H:%M] ", time.localtime(ev["ts"])) + t["attempt"].format(ip=ev["ip"], port=ev["port"]))

    server = TrapServer(plan.ip, port, ignore_list(plan.ip, env), on_attempt)
    out(t["listening"].format(ip=plan.ip, port=port))
    if not serve:
        server.server_close()
        return 0
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out(t["stopped"])
    finally:
        server.server_close()
    return 0
