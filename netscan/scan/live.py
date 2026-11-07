"""Protecția live (B): ce se întâmplă ACUM în hotspot, fără să aștepți o scanare completă.

Rulează în procesul aplicației, ca utilizator normal, doar după ce utilizatorul o pornește din Dashboard și doar
cât timp laptopul e în hotspotul echipei: la fiecare ~10 s refacem aceleași verificări ca la scanare (SSID, o
singură rețea, guardrail). Când rețeaua nu mai e cea bună, totul intră în pauză (nici capcana nu mai ascultă) și
pornește singur înapoi când revii pe hotspot.

Straturile:
1. Prezența (la ~20 s): o datagramă goală spre fiecare adresă din hotspot + tabela ARP a sistemului (vezi
   neighbors.py) -> cine e conectat acum, cine a venit, cine a plecat.
2. Porturile riscante (la ~60 s): câte o conexiune TCP spre porturile riscante ale dispozitivelor prezente
   (Telnet, FTP, baze de date, camere, desktop la distanță…) și spre porturile văzute deschise la ultima scanare.
   Doar conectare și închidere: nu trimitem și nu citim date. Cel mult MAX_ATTEMPTS_PER_S încercări pe secundă
   (regula e ≤100 pachete/s).
3. Ușa-capcană: Telnet fals pe IP-ul laptopului din hotspot; orice încercare = alertă pe loc (doar IP, oră, port).
4. Scanarea completă (nmap, cu drepturi de administrator): pornită din buton, cu fereastra de permisiune a
   sistemului și progres live (elevate.py, scan_job.py). Când se termină, o aducem în istoric de aici, ca
   utilizator normal (NFR-04).

Ce NU face: nu identifică programe sau versiuni și nu calculează probleme sau scor (le dă doar motorul, din
scanarea completă), nu păstrează MAC-uri complete, nu citește traficul nimănui, nu repară nimic singur.
"""
from __future__ import annotations

import errno
import inspect
import ipaddress
import json
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from netscan.scan import elevate, guardrail, local_data, neighbors, network, scan_job, trap

TICK_S = 1.0
GATE_EVERY_S = 10
SWEEP_EVERY_S = 20
READ_AFTER_S = 9            # Windows reverifică o intrare ARP veche în ~8 s (5 s așteptare + 3 încercări)
GONE_AFTER_MISSES = 2
PULSE_EVERY_S = 60
PROBE_TIMEOUT_S = 2.5       # pe Windows, „port închis” vine abia după ~2 s
PROBE_WORKERS = 8
MAX_ATTEMPTS_PER_S = 10    # + ≤25 datagrame/s la prezență: mult sub 100 de pachete/s, chiar pe un /24
MAX_SWEEP_ADDRESSES = 256   # hotspotul e un /28; o rețea mai mare de /24 nu e a noastră
MAX_PORTS_PER_DEVICE = 40
MAX_EVENTS = 60
SETTINGS_FILE = "live.json"
LAUNCH_TIMEOUT_S = 120      # după acordul utilizatorului, procesul de admin trebuie să scrie progresul

# Porturile verificate pe fiecare dispozitiv prezent: serviciile din catalog, pe porturile lor obișnuite.
# Eticheta e doar „ce rulează de obicei acolo”; ce rulează de fapt spune scanarea completă.
RISKY_TCP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 139: "SMB", 445: "SMB", 554: "RTSP", 1883: "MQTT",
    2323: "Telnet", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP",
    8080: "HTTP", 8081: "HTTP", 27017: "MongoDB",
}

OFF, ACTIVE, PAUSED = "off", "active", "paused"
TOO_LARGE = "TOO_LARGE"
PERSISTED_KINDS = ("NEW_DEVICE", "DEVICE_GONE", "PORT_OPENED", "PORT_CLOSED")   # ajung și în Jurnal

TEXTS = {
    "ro": {
        "NEW_DEVICE": "Dispozitiv nou în rețea: {ip} ({who}).",
        "DEVICE_BACK": "{ip} s-a reconectat la rețea.",
        "DEVICE_GONE": "{ip} a plecat din rețea.",
        "PORT_OPENED": "Port deschis pe {ip}: {port}{label}.",
        "PORT_OPENED_VS_SCAN": "Port deschis pe {ip}: {port}{label}, nou față de ultima scanare.",
        "PORT_CLOSED": "Portul {port}{label} de pe {ip} s-a închis.",
        "PORT_CLOSED_VS_SCAN": "Portul {port}{label} de pe {ip} e închis acum (în ultima scanare era deschis).",
        "TRAP": "Cineva de pe {ip} a încercat să intre pe portul {port} (ușa-capcană).",
        "PAUSED": "Protecția live e în pauză: {why}",
        "RESUMED": "Ești pe hotspot: protecția live merge.",
        "SCAN_DONE": "Scanarea completă s-a terminat ({file}). A fost adusă în istoric.",
        "who_vendor": "{vendor}",
        "who_private": "MAC privat: telefon sau laptop",
        "who_unknown": "producător necunoscut",
        "too_large": "rețeaua e mai mare decât un hotspot (/24), așa că nu o verific automat.",
    },
    "en": {
        "NEW_DEVICE": "New device on the network: {ip} ({who}).",
        "DEVICE_BACK": "{ip} reconnected to the network.",
        "DEVICE_GONE": "{ip} left the network.",
        "PORT_OPENED": "Open port on {ip}: {port}{label}.",
        "PORT_OPENED_VS_SCAN": "Open port on {ip}: {port}{label}, new since the last scan.",
        "PORT_CLOSED": "Port {port}{label} on {ip} closed.",
        "PORT_CLOSED_VS_SCAN": "Port {port}{label} on {ip} is closed now (it was open in the last scan).",
        "TRAP": "Someone at {ip} tried to get in on port {port} (trap door).",
        "PAUSED": "Live protection is paused: {why}",
        "RESUMED": "You are on the hotspot: live protection is running.",
        "SCAN_DONE": "The full scan finished ({file}). It was added to the history.",
        "who_vendor": "{vendor}",
        "who_private": "private MAC: phone or laptop",
        "who_unknown": "unknown maker",
        "too_large": "the network is larger than a hotspot (/24), so I don't check it automatically.",
    },
}
TONES = {"NEW_DEVICE": "urgent", "TRAP": "urgent", "PORT_OPENED": "urgent", "PORT_CLOSED": "good",
         "DEVICE_BACK": "info", "DEVICE_GONE": "info", "PAUSED": "info", "RESUMED": "good", "SCAN_DONE": "good"}
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._/-]")


@dataclass
class LiveEvent:
    ts: float
    kind: str
    ip: Optional[str]
    port: Optional[int]
    text_ro: str
    text_en: str
    tone: str


@dataclass
class LiveDevice:
    ip: str
    mac_masked: Optional[str]
    vendor: Optional[str]
    private_mac: bool
    first_seen: float
    last_seen: float
    online: bool = True
    misses: int = 0
    new: bool = False                                    # a apărut după ce am pornit protecția
    open_ports: dict[int, float] = field(default_factory=dict)   # port -> de când e deschis
    pulsed: bool = False


@dataclass(frozen=True)
class KnownScan:
    """Ce știm din ultima scanare completă (motorul): tipul dispozitivului și porturile TCP deschise."""
    file: str
    types: dict[str, Optional[str]]
    ports: dict[str, dict[int, str]]                     # ip -> {port: serviciul văzut de nmap}


def tcp_state(ip: str, port: int, timeout: float = PROBE_TIMEOUT_S) -> str:
    """O conexiune TCP, închisă imediat: "open", "closed" (refuz) sau "unknown" (fără răspuns)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        return "closed" if exc.errno == errno.ECONNREFUSED else "unknown"


class _Pacer:
    """Cel mult `per_s` încercări pe secundă, pe toate firele."""

    def __init__(self, per_s: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.gap = 1.0 / per_s
        self.clock, self.sleep = clock, sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            t = self.clock()
            start = max(t, self._next)
            self._next = start + self.gap
        if start > t:
            self.sleep(start - t)


def _label(port: int, service: Optional[str] = None) -> str:
    """Eticheta afișată lângă port: serviciul din scanare (curățat) sau cel obișnuit pe acel port."""
    name = _SAFE_LABEL.sub("", (service or "").strip())[:20] or RISKY_TCP.get(port, "")
    return name


class LiveMonitor:
    def __init__(self, scans_dir: Path = scan_job.SCANS_DIR, db_path=None,
                 detect: Callable[[], network.NetworkInfo] = network.detect_network,
                 read_table: Callable = neighbors.read_neighbors, poke: Callable = neighbors.poke,
                 probe: Callable[[str, int], str] = tcp_state, launcher: Callable = elevate.launch,
                 trap_server: Optional[Callable] = trap.TrapServer, analyze: Optional[Callable] = None,
                 clock: Callable[[], float] = time.time, env: Optional[dict] = None, persist: bool = True,
                 pacer: Optional[_Pacer] = None):
        import os
        self.scans_dir = Path(scans_dir)
        self.db_path = db_path
        self.detect, self.read_table, self.poke, self.probe = detect, read_table, poke, probe
        self.launcher, self.trap_server, self.clock = launcher, trap_server, clock
        self.env = os.environ if env is None else env
        self.persist = persist
        self._analyze = analyze
        self._pacer = pacer or _Pacer(MAX_ATTEMPTS_PER_S)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._reset_state()
        self._launch: dict = {}                       # starea ferestrei de permisiune pentru scanarea completă
        self._imported: set[str] = set()
        self._known_cache: dict = {}

    # ---------- pornire / oprire ----------

    def _reset_state(self) -> None:
        self.status = OFF
        self.reason: Optional[str] = None
        self.reason_text = ("", "")
        self.info: Optional[network.NetworkInfo] = None
        self.targets: set[str] = set()
        self.devices: dict[str, LiveDevice] = {}
        self.events: list[LiveEvent] = []
        self.baseline_done = False
        self.last_gate = self.last_sweep = self.last_pulse = 0.0
        self.next_gate = self.next_sweep = self.next_pulse = 0.0
        self.poked_at: Optional[float] = None
        self.pulse_running = False
        self.pulse_now: set[str] = set()
        self.gen = 0
        self._trap = None
        self._trap_ip: Optional[str] = None
        self._trap_stop = threading.Event()
        self.trap_state = ("off", None)               # (stare, cod)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._reset_state()
            self.status = PAUSED                       # până la prima verificare a rețelei
            self.reason = "STARTING"
            self._thread = threading.Thread(target=self._loop, name="netscan-live", daemon=True)
            self._thread.start()
        self._save_setting(True)

    def stop(self, remember: bool = True) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=5)
        with self._lock:
            self._stop_trap()
            self.gen += 1
            self.status = OFF
            self._thread = None
        if self.full_scan_status().get("job") == "auto":
            self.stop_full_scan()                      # oprirea protecției oprește și rescanarea automată
        if remember:
            self._save_setting(False)

    def autostart(self) -> bool:
        """La pornirea aplicației: reia protecția dacă utilizatorul a lăsat-o pornită."""
        if self._load_setting():
            self.start()
            return True
        return False

    def _settings_path(self) -> Path:
        return local_data.data_dir(self.db_path) / SETTINGS_FILE

    def _save_setting(self, on: bool) -> None:
        if not self.persist:
            return
        try:
            path = self._settings_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"on": bool(on)}), encoding="utf-8")
        except OSError:
            pass

    def _load_setting(self) -> bool:
        try:
            return json.loads(self._settings_path().read_text(encoding="utf-8")).get("on") is True
        except (OSError, ValueError, AttributeError):
            return False

    # ---------- bucla ----------

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = self.clock()
            try:
                if now >= self.next_gate:
                    self._check_gate(now)
                if self.status == ACTIVE:
                    self._sweep_step(now)
                    self._maybe_pulse(now)
            except Exception:                          # protecția nu are voie să moară în tăcere
                with self._lock:
                    self.next_gate = now               # reverificăm rețeaua la tura următoare
            self._stop.wait(TICK_S)

    def tick(self, now: Optional[float] = None) -> None:
        """Un pas al buclei, sincron (pentru teste)."""
        now = self.clock() if now is None else now
        if now >= self.next_gate:
            self._check_gate(now)
        if self.status == ACTIVE:
            self._sweep_step(now)
            self._maybe_pulse(now, wait=True)

    # ---------- 0. rețeaua: doar hotspotul echipei ----------

    def _check_gate(self, now: float) -> None:
        info = self.detect()
        self.next_gate = now + GATE_EVERY_S
        self.last_gate = now
        code, ro, en, targets = self._allowed_targets(info)
        with self._lock:
            changed = self.info is None or (self.info.ip, self.info.cidr) != (info.ip, info.cidr)
            was, was_reason = self.status, self.reason
            self.info = info
            if code != guardrail.OK:
                if was != PAUSED or self.reason != code:
                    self.gen += 1
                    self._stop_trap()
                    for d in self.devices.values():
                        d.online = False
                    if was == ACTIVE:
                        self._event(now, "PAUSED", None, None, why=(ro, en))
                self.status, self.reason, self.reason_text, self.targets = PAUSED, code, (ro, en), set()
                self.poked_at = None
                return
            if changed and self.devices:
                self.gen += 1
                self.devices, self.baseline_done, self.pulse_now = {}, False, set()
            self.targets = targets
            self.status, self.reason, self.reason_text = ACTIVE, None, ("", "")
            if was == PAUSED and was_reason not in (None, "STARTING"):
                self._event(now, "RESUMED", None, None)
        self._ensure_trap(info)

    def _allowed_targets(self, info: network.NetworkInfo) -> tuple[str, str, str, set[str]]:
        if not info.scan_allowed or not info.ip or not info.cidr:
            ro, en = network.MESSAGES.get(info.status, ("Rețeaua nu e potrivită.", "The network isn't suitable."))
            return info.status or "NETWORK", ro, en, set()
        net = ipaddress.IPv4Network(info.cidr, strict=False)
        if net.num_addresses > MAX_SWEEP_ADDRESSES:
            return TOO_LARGE, TEXTS["ro"]["too_large"], TEXTS["en"]["too_large"], set()
        allowlist = guardrail.build_allowlist(info.cidr, self.env.get("NETSCAN_ALLOWLIST"))
        targets = {str(h) for h in net.hosts()
                   if str(h) != info.ip and guardrail.check_target(f"{h}/32", allowlist).ok}
        if not targets:
            d = guardrail.check_target(info.cidr, allowlist)
            return d.reason_code or "NETWORK", d.msg_ro, d.msg_en, set()
        return guardrail.OK, "", "", targets

    def allowed(self, ip: str, gen: Optional[int] = None) -> bool:
        with self._lock:
            return self.status == ACTIVE and ip in self.targets and (gen is None or gen == self.gen)

    # ---------- 1. prezența ----------

    def _sweep_step(self, now: float) -> None:
        if self.poked_at is None:
            if now < self.next_sweep:
                return
            with self._lock:
                targets, info, self.poked_at = sorted(self.targets), self.info, now
            self.poke(targets, info.ip)
            return
        if now < self.poked_at + READ_AFTER_S:
            return
        with self._lock:
            info, gen = self.info, self.gen
            self.poked_at = None
            self.next_sweep = now + max(SWEEP_EVERY_S - READ_AFTER_S, 1)
        table = self.read_table(info)
        if table is None:
            return
        with self._lock:
            if gen != self.gen or self.status != ACTIVE:
                return
            self._apply_presence({ip: n for ip, n in table.items() if ip in self.targets}, now)
            self.last_sweep = now

    def _apply_presence(self, seen: dict, now: float) -> None:
        for ip, n in seen.items():
            d = self.devices.get(ip)
            if d is not None and d.mac_masked and n.mac_masked != d.mac_masked:
                d = None                               # alt dispozitiv pe același IP
            if d is None:
                is_new = self.baseline_done
                self.devices[ip] = LiveDevice(ip=ip, mac_masked=n.mac_masked, vendor=n.vendor,
                                              private_mac=n.private_mac, first_seen=now, last_seen=now,
                                              new=is_new)
                if is_new:
                    who = (("who_vendor", n.vendor) if n.vendor else ("who_private", None) if n.private_mac
                           else ("who_unknown", None))
                    self._event(now, "NEW_DEVICE", ip, None,
                                who=tuple(TEXTS[lang][who[0]].format(vendor=who[1]) for lang in ("ro", "en")))
                    self.pulse_now.add(ip)             # porturile dispozitivului nou, cât mai repede
                continue
            if not d.online:
                self._event(now, "DEVICE_BACK", ip, None)
            d.online, d.misses, d.last_seen = True, 0, now
        for ip, d in self.devices.items():
            if ip in seen or not d.online:
                continue
            d.misses += 1
            if d.misses >= GONE_AFTER_MISSES:
                d.online = False
                d.open_ports.clear()
                d.pulsed = False
                self._event(now, "DEVICE_GONE", ip, None)
        if not self.baseline_done:
            self.baseline_done = True
            self.next_pulse = now                      # prima verificare a porturilor imediat

    # ---------- 2. porturile riscante ----------

    def ports_for(self, ip: str) -> dict[int, str]:
        known = self.known_scan()
        ports = {p: _label(p) for p in RISKY_TCP}
        if known is not None:
            for p, service in known.ports.get(ip, {}).items():
                ports[p] = _label(p, service)
        return dict(sorted(ports.items())[:MAX_PORTS_PER_DEVICE])

    def _maybe_pulse(self, now: float, wait: bool = False) -> None:
        with self._lock:
            if self.pulse_running or not self.baseline_done:
                return
            if now < self.next_pulse and not self.pulse_now:
                return
            full = now >= self.next_pulse
            ips = [ip for ip, d in self.devices.items() if d.online and (full or ip in self.pulse_now)]
            self.pulse_now = set()
            if full:
                self.next_pulse = now + PULSE_EVERY_S
            if not ips:
                return
            self.pulse_running = True
            gen = self.gen
        work = threading.Thread(target=self._pulse, args=(ips, gen), name="netscan-live-pulse", daemon=True)
        work.start()
        if wait:
            work.join()

    def _pulse(self, ips: list[str], gen: int) -> None:
        try:
            jobs = [(ip, port) for ip in ips for port in self.ports_for(ip)]

            def one(ip: str, port: int) -> Optional[str]:
                if self._stop.is_set() or not self.allowed(ip, gen):
                    return None
                self._pacer.wait()
                if not self.allowed(ip, gen):          # rețeaua s-a schimbat între timp: nu mai atingem nimic
                    return None
                return self.probe(ip, port)

            with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
                results = list(zip(jobs, ex.map(lambda j: one(*j), jobs)))
            self._apply_ports(results, gen, self.clock())
        finally:
            with self._lock:
                self.pulse_running = False

    def _apply_ports(self, results: list, gen: int, now: float) -> None:
        known = self.known_scan()
        with self._lock:
            if gen != self.gen or self.status != ACTIVE:
                return
            by_ip: dict[str, dict[int, str]] = {}
            for (ip, port), state in results:
                if state is not None:
                    by_ip.setdefault(ip, {})[port] = state
            for ip, states in by_ip.items():
                d = self.devices.get(ip)
                if d is None or not d.online:
                    continue
                in_scan = known.ports.get(ip) if known is not None and ip in known.types else None
                labels = self.ports_for(ip)
                for port, state in sorted(states.items()):
                    label = labels.get(port, "")
                    was_open = port in d.open_ports
                    if state == "open" and not was_open:
                        d.open_ports[port] = now
                        if not d.pulsed:
                            # prima verificare: comparăm cu ultima scanare (dacă dispozitivul e în ea)
                            if in_scan is None or port not in in_scan:
                                kind = "PORT_OPENED_VS_SCAN" if in_scan is not None else "PORT_OPENED"
                                self._event(now, kind, ip, port, label=label)
                        else:
                            self._event(now, "PORT_OPENED", ip, port, label=label)
                    elif state == "closed":
                        if was_open:
                            del d.open_ports[port]
                            self._event(now, "PORT_CLOSED", ip, port, label=label)
                        elif not d.pulsed and in_scan is not None and port in in_scan:
                            self._event(now, "PORT_CLOSED_VS_SCAN", ip, port, label=label)
                d.pulsed = True
            self.last_pulse = now

    # ---------- 3. ușa-capcană ----------

    def _ensure_trap(self, info: network.NetworkInfo) -> None:
        if self.trap_server is None:
            return
        with self._lock:
            if self.status != ACTIVE or (self._trap is not None and self._trap_ip == info.ip):
                return
            self._stop_trap()
            try:
                server = self.trap_server(info.ip, trap.DEFAULT_PORT, trap.ignore_list(info.ip, self.env),
                                          self._on_trap)
            except OSError as exc:
                busy = exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1), 10048)
                self.trap_state = ("error", "BUSY" if busy else "FAILED")
                return
            except ValueError:
                self.trap_state = ("error", "FAILED")
                return
            stop = threading.Event()
            self._trap, self._trap_ip, self._trap_stop = server, info.ip, stop
            self.trap_state = ("listening", None)
            threading.Thread(target=self._serve_trap, args=(server, stop), name="netscan-live-trap",
                             daemon=True).start()

    @staticmethod
    def _serve_trap(server, stop: threading.Event) -> None:
        # handle_request() cu timeout, nu serve_forever(): oprirea nu se poate bloca (shutdown() așteaptă la
        # nesfârșit dacă e chemat înainte ca serve_forever să fi pornit).
        server.timeout = 0.5
        while not stop.is_set():
            try:
                server.handle_request()
            except OSError:
                if stop.is_set():
                    break
                time.sleep(0.5)
        try:
            server.server_close()
        except OSError:
            pass

    def _stop_trap(self) -> None:
        server, self._trap, self._trap_ip = self._trap, None, None
        if server is not None:
            self._trap_stop.set()                      # firul capcanei închide socket-ul în ≤0,5 s
        self.trap_state = ("off", None)

    def _on_trap(self, ev: dict) -> None:
        if self.persist:
            try:
                trap.save_attempt(ev, self.db_path)
            except (OSError, ValueError, KeyError):
                pass
        with self._lock:
            self._event(float(ev["ts"]), "TRAP", str(ev["ip"]), int(ev["port"]))

    # ---------- evenimente ----------

    def _event(self, ts: float, kind: str, ip: Optional[str], port: Optional[int], label: str = "",
               why: tuple[str, str] = ("", ""), who: tuple[str, str] = ("", "")) -> None:
        base = {"PORT_OPENED_VS_SCAN": "PORT_OPENED", "PORT_CLOSED_VS_SCAN": "PORT_CLOSED"}.get(kind, kind)
        texts = []
        for i, lang in enumerate(("ro", "en")):
            texts.append(TEXTS[lang][kind].format(ip=ip, port=port, label=f" ({label})" if label else "",
                                                  why=why[i], who=who[i], file=label))
        ev = LiveEvent(ts=ts, kind=base, ip=ip, port=port, text_ro=texts[0], text_en=texts[1],
                       tone=TONES.get(base, "info"))
        self.events.insert(0, ev)
        del self.events[MAX_EVENTS:]
        if self.persist and base in PERSISTED_KINDS:
            try:
                local_data.append_events(local_data.alerts_path(self.db_path),
                                         [{"ts": ts, "kind": base, "ip": ip, "port": port, "proto": "tcp" if port else None,
                                           "text_ro": ev.text_ro, "text_en": ev.text_en, "source": "live"}])
            except OSError:
                pass

    # ---------- ultima scanare completă ----------

    def known_scan(self) -> Optional[KnownScan]:
        """Cea mai nouă scanare VALIDĂ din scans/, analizată de motor (cu cache după fișier și dată).
        Un fișier stricat sau incomplet e sărit (se ia următorul)."""
        try:
            files = sorted(((p.stat().st_mtime, p) for p in self.scans_dir.glob("*.xml")), reverse=True)
        except OSError:
            return None
        cache = self._known_cache
        for mtime, path in files[:5]:
            key = (path.name, mtime)
            if key not in cache:
                cache[key] = self._read_known(path)
            if cache[key] is not None:
                return cache[key]
        return None

    def _read_known(self, path: Path) -> Optional[KnownScan]:
        analyze = self._analyze
        if analyze is None:
            from netscan.engine.parser import analyze_file as analyze
        try:
            scan = analyze(str(path))
        except Exception:
            return None
        if scan is None or scan.status != "ok":
            return None
        types = {h.ip: h.device_type for h in scan.hosts}
        ports = {h.ip: {p.port: (p.service or "") for p in h.ports if p.proto == "tcp" and p.state == "open"}
                 for h in scan.hosts}
        return KnownScan(file=scan.file, types=types, ports=ports)

    # ---------- 4. scanarea completă (pasul de admin) ----------

    def request_full_scan(self, job: str = "scan") -> str:
        """Pornește scanarea completă: OK, NOT_ON_HOTSPOT, BUSY sau BAD_JOB. Fereastra de permisiune o deschide
        sistemul; aici doar verificăm dinainte că are sens (procesul de admin verifică din nou tot)."""
        if job not in elevate.JOBS:
            return "BAD_JOB"
        code, *_ = self._allowed_targets(self.detect())
        if code != guardrail.OK:
            return "NOT_ON_HOTSPOT"
        with self._lock:
            st = self.full_scan_status()
            if st["state"] in ("waiting_permission", "running", "waiting_next"):
                return "BUSY"
            self._launch = {"state": "waiting_permission", "job": job, "since": self.clock()}
        self.scans_dir.mkdir(parents=True, exist_ok=True)     # creat de utilizator, nu de procesul de admin
        try:
            (self.scans_dir / scan_job.STOP_FILE).unlink()
        except OSError:
            pass
        threading.Thread(target=self._do_launch, args=(job,), name="netscan-elevate", daemon=True).start()
        return "OK"

    def _do_launch(self, job: str) -> None:
        since = self._launch.get("since") or 0.0

        def started() -> bool:
            """Procesul de admin a scris progresul pentru această pornire (= permisiune dată)."""
            prog = scan_job.read_progress(self.scans_dir)
            return prog is not None and (prog.get("started") or 0) >= since - 2

        # elevate.launch primește `started` (pe Linux așteaptă răspunsul la fereastra pkexec);
        # launcherele de test, cu un singur parametru, sunt chemate ca înainte
        try:
            takes_started = "started" in inspect.signature(self.launcher).parameters
        except (TypeError, ValueError):
            takes_started = False
        result = self.launcher(job, started=started) if takes_started else self.launcher(job)
        with self._lock:
            if not result.ok:
                state = {elevate.DENIED: "denied", elevate.AUTH_FAILED: "auth_failed"}.get(result.code, "launch_failed")
                self._launch = {"state": state, "job": job, "since": self.clock()}
            else:
                self._launch["launched"] = True

    def stop_full_scan(self) -> None:
        """Oprește scanarea completă / rescanarea automată (fișierul de oprire, scris de utilizator)."""
        st = self.full_scan_status()
        if st["state"] in ("running", "waiting_next"):
            try:
                self.scans_dir.mkdir(parents=True, exist_ok=True)
                (self.scans_dir / scan_job.STOP_FILE).write_text("stop")
            except OSError:
                pass

    def full_scan_status(self) -> dict:
        """Starea scanării complete: din fereastra de permisiune (în memorie) și din progresul scris de procesul
        de admin (citit ca date nesigure). Când o scanare s-a terminat, o aduce în istoric (o singură dată)."""
        with self._lock:
            launch = dict(self._launch)
        prog = scan_job.read_progress(self.scans_dir)
        since = launch.get("since") or 0.0
        if prog is not None and (prog.get("started") or 0) >= since - 2:
            st = dict(prog)
            if st["state"] in ("running", "waiting_next") and st.get("pid") and not scan_job._pid_alive(st["pid"]):
                st["state"] = "failed" if st["state"] == "running" else "stopped"
            if st["state"] == "done" and st.get("file"):
                self._import(st["file"])
            return st
        if launch:
            state = launch["state"]
            if state == "waiting_permission" and launch.get("launched") and self.clock() - since > LAUNCH_TIMEOUT_S:
                state = "launch_failed"                # pornit, dar nu a scris niciun progres
            return {"state": state, "job": launch.get("job"), "percent": 0.0, "discovered": [],
                    "phase": None, "eta_s": None, "file": None, "msg_ro": "", "msg_en": "", "next_at": None}
        if prog is not None:
            st = dict(prog)
            if st["state"] in ("running", "waiting_next") and st.get("pid") and not scan_job._pid_alive(st["pid"]):
                st["state"] = "failed" if st["state"] == "running" else "stopped"
            return st
        return {"state": "idle", "job": None, "percent": 0.0, "discovered": [], "phase": None, "eta_s": None,
                "file": None, "msg_ro": "", "msg_en": "", "next_at": None}

    def _import(self, file: str) -> None:
        """Pasul neprivilegiat (NFR-04): scanarea terminată intră în istoric, iar alertele față de scanarea
        anterioară ajung în Jurnal. Rulează ca utilizator normal, în aplicație."""
        with self._lock:
            if file in self._imported:
                return
            self._imported.add(file)
        path = self.scans_dir / file
        if not path.is_file():
            return
        try:
            from netscan.scan.watch import build_alerts
            from netscan.ui import storage
            analyze = self._analyze
            if analyze is None:
                from netscan.engine.parser import analyze_file as analyze
            scan = analyze(str(path))
            if scan.status != "ok":
                return
            new = storage.find_scan(scan.file, scan.started_at, self.db_path) is None
            if new:
                storage.save_scan(scan, self.db_path)
                older = sorted((p for p in self.scans_dir.glob("*.xml") if p != path
                                and p.stat().st_mtime < path.stat().st_mtime),
                               key=lambda p: p.stat().st_mtime)
                if older:
                    prev = analyze(str(older[-1]))
                    if prev.status == "ok":
                        alerts = build_alerts(prev, scan, ts=self.clock())
                        if self.persist:
                            local_data.append_events(local_data.alerts_path(self.db_path),
                                                     (asdict(a) for a in alerts))
            with self._lock:
                self._event(self.clock(), "SCAN_DONE", None, None, label=file)
        except Exception:
            return

    # ---------- ce vede aplicația ----------

    def snapshot(self) -> dict:
        known = self.known_scan()
        with self._lock:
            info = self.info
            devices = []
            for d in sorted(self.devices.values(), key=lambda x: ipaddress.IPv4Address(x.ip)):
                labels = self.ports_for(d.ip)
                devices.append({
                    "ip": d.ip, "mac_masked": d.mac_masked, "vendor": d.vendor, "private_mac": d.private_mac,
                    "online": d.online, "new": d.new, "first_seen": d.first_seen, "last_seen": d.last_seen,
                    "in_scan": known is not None and d.ip in known.types,
                    "device_type": known.types.get(d.ip) if known is not None else None,
                    "open_ports": [{"port": p, "label": labels.get(p, "")} for p in sorted(d.open_ports)],
                    "pulsed": d.pulsed,
                })
            return {
                "on": self.running, "status": self.status if self.running else OFF, "reason": self.reason,
                "reason_ro": self.reason_text[0], "reason_en": self.reason_text[1],
                "ssid": info.ssid if info is not None and self.status == ACTIVE else None,
                "cidr": info.cidr if info is not None and self.status == ACTIVE else None,
                "own_ip": info.ip if info is not None and self.status == ACTIVE else None,
                "devices": devices, "online": sum(1 for d in devices if d["online"]),
                "events": [asdict(e) for e in self.events[:30]],
                "trap_state": self.trap_state[0], "trap_code": self.trap_state[1], "trap_port": trap.DEFAULT_PORT,
                "last_sweep": self.last_sweep or None, "last_pulse": self.last_pulse or None,
                "pulse_running": self.pulse_running, "baseline_done": self.baseline_done,
                "known_file": known.file if known is not None else None,
            }
