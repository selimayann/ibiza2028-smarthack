"""FR-13 / D1: jurnalul de securitate. Alertele se derivă din diff() între scanări consecutive.

Tipul Alert e intern în netscan/ui/ (propunerea P1 din docs/direction.md, varianta minimă):
nu intră în contract și nu adaugă nimic în motor. Severitatea vine din motor, nu se calculează aici.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from netscan.model import SEVERITY_ORDER, Host, Scan
from netscan.ui import storage
from netscan.ui.view import ip_key

NEW_DEVICE = "NEW_DEVICE"
DEVICE_GONE = "DEVICE_GONE"
PORT_OPENED = "PORT_OPENED"
PORT_CLOSED = "PORT_CLOSED"
FINDING_NEW = "FINDING_NEW"
FINDING_RESOLVED = "FINDING_RESOLVED"

# În aceeași scanare: problemele noi primele, apoi restul (docs/direction.md, P1).
KIND_ORDER = [FINDING_NEW, NEW_DEVICE, PORT_OPENED, FINDING_RESOLVED, PORT_CLOSED, DEVICE_GONE]
# Cum se prezintă: o schimbare care cere atenție, una bună sau doar o informație.
TONE = {FINDING_NEW: "bad", NEW_DEVICE: "bad", PORT_OPENED: "bad",
        FINDING_RESOLVED: "good", PORT_CLOSED: "good", DEVICE_GONE: "info"}


@dataclass
class Alert:
    kind: str
    scan_id: int | None
    started_at: int | None
    file: str
    device_id: str
    ip: str
    device_type: str | None
    port: int | None = None
    proto: str | None = None
    code: str | None = None
    severity: str | None = None

    @property
    def tone(self) -> str:
        return TONE[self.kind]


def alerts_between(old: Scan, new: Scan, scan_id: int | None = None) -> list[Alert]:
    """Alertele pentru trecerea old -> new, în ordinea din jurnal."""
    d = storage.diff(old, new)
    hosts: dict[str, Host] = {h.device_id: h for h in old.hosts} | {h.device_id: h for h in new.hosts}
    mapping = storage.match_devices(old, new)
    old_hosts: dict[str, Host] = {h.device_id: h for h in old.hosts}

    def mk(kind: str, device_id: str, type_from: Host | None = None, **kw) -> Alert:
        h = hosts.get(device_id)
        # O problemă rezolvată (sau un port închis) se spune pe dispozitivul așa cum era când exista problema:
        # tipul estimat din scanarea nouă poate fi altul dacă dispozitivul și-a pierdut porturile.
        shown = type_from or h
        return Alert(kind=kind, scan_id=scan_id, started_at=new.started_at, file=new.file, device_id=device_id,
                     ip=kw.pop("ip", None) or (h.ip if h else ""), device_type=shown.device_type if shown else None,
                     **kw)

    new_ids = {h.device_id for h in d.new_devices}
    gone_ids = {h.device_id for h in d.removed_devices}
    out: list[Alert] = []
    out += [mk(NEW_DEVICE, h.device_id) for h in d.new_devices]
    out += [mk(DEVICE_GONE, h.device_id) for h in d.removed_devices]
    # Porturile unui dispozitiv nou sau dispărut sunt deja spuse de alerta pentru dispozitiv.
    out += [mk(PORT_OPENED, dev, port=p, proto=pr) for dev, p, pr in d.opened_ports if dev not in new_ids]
    out += [mk(PORT_CLOSED, dev, type_from=old_hosts.get(dev), port=p, proto=pr) for dev, p, pr in d.closed_ports
            if dev not in gone_ids and dev not in new_ids]
    out += [mk(FINDING_NEW, f.device_id, ip=f.ip, port=f.port, code=f.code, severity=f.severity)
            for f in d.new_findings]
    out += [mk(FINDING_RESOLVED, mapping.get(f.device_id, f.device_id), type_from=old_hosts.get(f.device_id),
               ip=f.ip, port=f.port, code=f.code, severity=f.severity) for f in d.resolved_findings]
    # în fiecare tip, problemele cele mai grave primele (ca în Jurnal să nu rămână ascunse sub „Arată încă”)
    sev_rank = lambda a: -SEVERITY_ORDER.get(a.severity, -1)  # noqa: E731  (high=3 ... info=0; fără severitate la final)
    out.sort(key=lambda a: (KIND_ORDER.index(a.kind), sev_rank(a), ip_key(a.ip), a.port if a.port is not None else -1,
                            a.code or ""))
    return out


def journal(path: str | Path | None = None) -> list[Alert]:
    """Tot jurnalul din istoric: pentru fiecare scanare citibilă, schimbările față de cea citibilă dinainte.
    Cele mai noi întâi; în aceeași scanare, ordinea din KIND_ORDER."""
    ok = [s for s in storage.list_scans(path) if s.status == "ok"]
    out: list[Alert] = []
    for prev, cur in zip(ok, ok[1:]):
        a, b = storage.get_scan(prev.id, path), storage.get_scan(cur.id, path)
        if a is not None and b is not None:
            out += alerts_between(a, b, scan_id=cur.id)
    order = {s.id: i for i, s in enumerate(ok)}
    out.sort(key=lambda a: -order.get(a.scan_id, -1))  # sortare stabilă: păstrează ordinea din scanare
    return out


FOLDABLE = {PORT_OPENED, PORT_CLOSED}
EXPLAINS_PORT = {FINDING_NEW, FINDING_RESOLVED}


def fold_port_alerts(alerts: list[Alert]) -> tuple[list[Alert], list[Alert]]:
    """Jurnalul pe înțeles: un port deschis/închis care e chiar portul unei probleme noi/rezolvate din ACEEAȘI
    scanare spune același lucru de două ori. Le pliem: (alertele afișate, porturile pliate dedesubt).
    Potrivire după (ip, port) sau (dispozitiv, port); ordinea alertelor rămâne aceeași."""
    keys = set()
    for a in alerts:
        if a.kind in EXPLAINS_PORT and a.port is not None:
            keys.add(("ip", a.ip, a.port))
            keys.add(("dev", a.device_id, a.port))
    shown, folded = [], []
    for a in alerts:
        if a.kind in FOLDABLE and a.port is not None and (("ip", a.ip, a.port) in keys
                                                          or ("dev", a.device_id, a.port) in keys):
            folded.append(a)
        else:
            shown.append(a)
    return shown, folded
