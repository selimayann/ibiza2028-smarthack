"""Ordonarea pentru afișare, după contract (docs/contract.md, decizia 3).

UI-ul NU calculează severități, puncte sau scoruri: le ia din motor și doar le ordonează.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace

from netscan.model import SEVERITY_ORDER, Finding, Host, Scan
from netscan.scan.device_info import DeviceInfo, describe

# Praguri propuse pentru eticheta scorului (de confirmat cu echipa).
BAND_GOOD_MIN = 80
BAND_FAIR_MIN = 50


def ip_key(ip: str) -> tuple:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (99, 0, ip)


def score_band(score: int | None) -> str | None:
    if score is None:
        return None
    if score >= BAND_GOOD_MIN:
        return "good"
    if score >= BAND_FAIR_MIN:
        return "fair"
    return "poor"


def finding_rank_key(f: Finding) -> tuple:
    """Cea mai gravă problemă: puncte ↓, severitate ↓, port ↑ (fără port la final)."""
    return (-f.points, -SEVERITY_ORDER.get(f.severity, -1), f.port is None, f.port or 0, f.code)


@dataclass
class DeviceView:
    host: Host
    findings: list[Finding] = field(default_factory=list)  # cea mai gravă prima
    info: DeviceInfo | None = None  # FR-03: producător (nmap/IEEE), MAC privat, tip; doar pentru afișare

    @property
    def total_points(self) -> int:
        return sum(f.points for f in self.findings)

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, -1)).severity

    @property
    def worst(self) -> Finding | None:
        return self.findings[0] if self.findings else None


def rank_devices(scan: Scan) -> list[DeviceView]:
    """Dispozitive: suma punctelor ↓, severitatea maximă ↓, IP numeric ↑."""
    views: dict[str, DeviceView] = {}
    for h in scan.hosts:
        info = describe(h)  # FR-03, doar afișare: findings și scorul rămân cele din motor
        views[h.device_id] = DeviceView(
            host=replace(h, vendor=info.vendor, device_type=info.device_type), info=info
        )
    for f in scan.findings:
        if f.device_id not in views:  # defensiv: finding fără host în listă
            views[f.device_id] = DeviceView(host=Host(ip=f.ip, device_id=f.device_id))
        views[f.device_id].findings.append(f)
    for v in views.values():
        v.findings.sort(key=finding_rank_key)
    return sorted(
        views.values(),
        key=lambda v: (-v.total_points, -SEVERITY_ORDER.get(v.max_severity or "", -1), ip_key(v.host.ip)),
    )


def most_dangerous(scan: Scan) -> DeviceView | None:
    ranked = rank_devices(scan)
    if not ranked or not ranked[0].findings:
        return None
    return ranked[0]


# ---------- propoziția-rezumat din capul paginii ----------

@dataclass
class Summary:
    """Datele pentru fraza de sus: câte probleme sunt și cu ce să începi. Doar numără și alege; severitățile,
    punctele și ordinea vin din motor și din contract."""
    kind: str                            # "error" | "clean" | "info" | "fixed" | "problems"
    serious: int = 0                     # probleme cu severitatea „high”
    minor: int = 0                       # restul problemelor care costă puncte (medium, low)
    device: DeviceView | None = None     # primul dispozitiv, după ordinea din contract
    finding: Finding | None = None       # cea mai gravă problemă a lui (primul ei pas se ia din explicații)
    error_code: str | None = None


def summary_of(scan: Scan, worst: DeviceView | None, all_fixed: bool = False) -> Summary:
    """Cazurile: scanare cu eroare, nicio problemă, doar informări (0 puncte, ex. SSH_OPEN), tot ce s-a găsit
    e deja rezolvat (`all_fixed`), probleme. `scan` și `worst` sunt aceleași ca la cardul „Cel mai periculos
    dispozitiv” de dedesubt (fără problemele verificate), ca fraza și cardul să spună același lucru."""
    if scan.status != "ok":
        return Summary("error", error_code=scan.error_code)
    costly = [f for f in scan.findings if f.points > 0]
    if not costly:
        if all_fixed:
            return Summary("fixed")
        if scan.findings:   # doar informări fără puncte (ex. SSH_OPEN): le numim, dar nu sunt probleme
            return Summary("info", finding=scan.findings[0])
        return Summary("clean")
    serious = sum(1 for f in costly if f.severity == "high")
    return Summary("problems", serious=serious, minor=len(costly) - serious,
                   device=worst, finding=worst.worst if worst else None)


# ---------- dovada „înainte / după” (după ce ai reparat și ai verificat din nou) ----------

@dataclass
class Proof:
    """Ce s-a schimbat între două scanări, pentru cardul „Dovada”. Scorurile vin din motor (nu se recalculează aici);
    aici doar se numără și se grupează rezultatele lui diff()."""
    before: Scan
    after: Scan
    score_before: int
    score_after: int
    resolved: list[Finding] = field(default_factory=list)     # „ușile închise”
    remaining: list[Finding] = field(default_factory=list)    # încă deschise
    new: list[Finding] = field(default_factory=list)          # apărute între scanări

    @property
    def closed(self) -> int:
        return len(self.resolved)

    @property
    def direction(self) -> str:
        return ("up" if self.score_after > self.score_before
                else "down" if self.score_after < self.score_before else "same")


def proof_of(before: Scan, after: Scan, d) -> Proof | None:
    """`d` e storage.diff(before, after). Fără dovadă dacă una dintre scanări nu are scor (e ilizibilă)."""
    if d.score_before is None or d.score_after is None:
        return None
    key = lambda f: finding_rank_key(f)  # noqa: E731  (cea mai gravă întâi, ca peste tot în UI)
    return Proof(before, after, d.score_before, d.score_after, sorted(d.resolved_findings, key=key),
                 sorted(d.persistent_findings, key=key), sorted(d.new_findings, key=key))


# ---------- trendul scorului (FR-10), pentru graficul din istoric ----------

@dataclass
class TrendPoint:
    scan_id: int
    file: str
    started_at: int | None
    score: int
    x: float
    y: float


@dataclass
class Trend:
    points: list[TrendPoint]
    width: int
    height: int
    plot_left: int
    plot_right: int
    plot_top: int
    plot_bottom: int

    def y_for(self, score: int) -> float:
        return self.plot_bottom - (self.plot_bottom - self.plot_top) * score / 100

    @property
    def path(self) -> str:
        return " ".join(f"{'M' if i == 0 else 'L'}{p.x:.1f},{p.y:.1f}" for i, p in enumerate(self.points))

    @property
    def first(self) -> TrendPoint:
        return self.points[0]

    @property
    def last(self) -> TrendPoint:
        return self.points[-1]

    @property
    def direction(self) -> str:
        a, b = self.first.score, self.last.score
        return "up" if b > a else "down" if b < a else "same"


def score_trend(items, width: int = 800, height: int = 260) -> Trend | None:
    """Scorul în timp, din istoricul salvat (în ordinea istoricului). Doar scanările cu scor;
    fișierele cu eroare nu au scor și nu apar pe grafic. Nevoie de cel puțin 2 puncte."""
    scored = [s for s in items if s.status == "ok" and s.score is not None]
    if len(scored) < 2:
        return None
    left, right, top, bottom = 64, width - 60, 18, height - 36
    step = (right - left) / (len(scored) - 1)
    trend = Trend(points=[], width=width, height=height,
                  plot_left=left, plot_right=right, plot_top=top, plot_bottom=bottom)
    for i, s in enumerate(scored):
        trend.points.append(TrendPoint(scan_id=s.id, file=s.file, started_at=s.started_at, score=s.score,
                                       x=left + step * i, y=trend.y_for(s.score)))
    return trend



# ---------- D5: o singură acțiune pe rând ----------

def action_plan(scan: Scan) -> list[Finding]:
    """Toate problemele, în ordinea riscului: dispozitivele după contract, apoi problemele fiecăruia."""
    return [f for d in rank_devices(scan) for f in d.findings]


@dataclass
class ActionStep:
    finding: Finding
    device: Host
    number: int          # 1..total
    total: int
    done_count: int


# ---------- D5: pași verificați pe date reale (nu doar bifați) ----------

def _networks(scan: Scan) -> set:
    nets = set()
    for h in scan.hosts:
        try:
            nets.add(ipaddress.ip_network(f"{h.ip}/24", strict=False))
        except ValueError:
            continue
    return nets


def same_network(a: Scan, b: Scan) -> bool:
    """Două scanări sunt ale aceleiași rețele dacă au dispozitive în același /24 (doar pentru afișare)."""
    return bool(_networks(a) & _networks(b))


def verified_by_newer(scan: Scan, others) -> dict[tuple, str]:
    """Pașii confirmați de o scanare mai nouă a ACELEIAȘI rețele: cheie -> fișierul scanării.
    Pentru fiecare problemă se ia doar cea mai nouă scanare a rețelei în care apare dispozitivul (același
    device_id). Pasul e verificat doar dacă acea scanare a văzut și portul problemei (portul e în lista
    dispozitivului) și problema nu mai e acolo. Dispozitiv lipsă sau port neverificat = nu știm: rămâne de făcut."""
    if scan.started_at is None:
        return {}
    newer = sorted((o for o in others if o.status == "ok" and o.started_at is not None
                    and o.started_at > scan.started_at and same_network(scan, o)),
                   key=lambda o: o.started_at, reverse=True)
    out: dict[tuple, str] = {}
    for f in scan.findings:
        for o in newer:
            host = next((h for h in o.hosts if h.device_id == f.device_id), None)
            if host is None:
                continue
            covered = f.port is None or any(p.port == f.port for p in host.ports)
            if covered and f.key() not in {g.key() for g in o.findings}:
                out[f.key()] = o.file
            break
    return out


@dataclass
class StepInfo:
    finding: Finding
    device: Host
    number: int
    status: str            # "todo" | "declared" (bifat, neconfirmat) | "verified" | "accepted" (risc acceptat)
    verified_by: str | None = None   # "live" sau numele scanării mai noi


@dataclass
class StepsView:
    steps: list[StepInfo]
    index: int             # pasul afișat (0-based)
    score_now: int         # scorul calculat de motor fără problemele verificate
    verified_count: int
    declared_count: int

    @property
    def current(self) -> StepInfo:
        return self.steps[self.index]

    @property
    def total(self) -> int:
        return len(self.steps)

    @property
    def fixed_keys(self) -> set[tuple]:
        """Problemele confirmate ca rezolvate (live sau de o scanare mai nouă)."""
        return {s.finding.key() for s in self.steps if s.status == "verified"}

    @property
    def all_resolved(self) -> bool:
        return all(s.status != "todo" for s in self.steps)

    @property
    def accepted_count(self) -> int:
        return sum(1 for s in self.steps if s.status == "accepted")


def steps_view(scan: Scan, declared: set, verified_live: set, by_scan: dict[tuple, str],
               requested: int | None = None, accepted: set = frozenset()) -> StepsView | None:
    """Toți pașii în ordinea riscului, cu starea fiecăruia. Pasul afișat: cel cerut (1-based, din
    butoanele Înapoi/Înainte) sau primul încă de făcut. Scorul nou e al motorului, pe problemele rămase."""
    from netscan.engine.scoring import compute_score

    plan = action_plan(scan)
    if not plan:
        return None
    hosts = {h.device_id: h for h in scan.hosts}
    steps = []
    for i, f in enumerate(plan, 1):
        k = f.key()
        if k in verified_live:
            st, by = "verified", "live"
        elif k in by_scan:
            st, by = "verified", by_scan[k]
        elif k in accepted:
            st, by = "accepted", None          # risc acceptat: nu e reparat, scorul rămâne
        else:
            st, by = ("declared" if k in declared else "todo"), None
        steps.append(StepInfo(f, hosts.get(f.device_id, Host(ip=f.ip, device_id=f.device_id)), i, st, by))
    if requested is not None and 1 <= requested <= len(steps):
        index = requested - 1
    else:
        index = next((i for i, s in enumerate(steps) if s.status == "todo"), 0)
    fixed = {s.finding.key() for s in steps if s.status == "verified"}
    return StepsView(steps, index, compute_score(f for f in scan.findings if f.key() not in fixed),
                     sum(1 for s in steps if s.status == "verified"), sum(1 for s in steps if s.status == "declared"))


def remaining_scan(scan: Scan, fixed_keys) -> Scan:
    """Aceeași scanare, fără problemele confirmate ca rezolvate (doar pentru ordonarea afișării)."""
    fixed = set(fixed_keys or ())
    if not fixed:
        return scan
    return replace(scan, findings=[f for f in scan.findings if f.key() not in fixed])


def order_devices(scan: Scan, fixed_keys=frozenset()) -> list[DeviceView]:
    """Lista dispozitivelor, completă, în ordinea riscului RĂMAS: problemele confirmate ca rezolvate trec la
    final (și pe fiecare rând, și în listă). Fără nimic rezolvat e exact rank_devices(scan) (contractul).
    Primul rând cu o problemă nerezolvată e mereu același dispozitiv ca în cardul „Cel mai periculos”."""
    fixed = set(fixed_keys or ())
    full = {d.host.device_id: d for d in rank_devices(scan)}
    if not fixed:
        return list(full.values())
    order = [d.host.device_id for d in rank_devices(remaining_scan(scan, fixed))]
    order += [k for k in full if k not in order]
    out = []
    for k in order:
        d = full.get(k)
        if d is None:
            continue
        d.findings.sort(key=lambda f: f.key() in fixed)      # stabil: ordinea riscului se păstrează
        out.append(d)
    return out


def worst_device(scan: Scan, fixed_keys=frozenset()) -> DeviceView | None:
    """Cel mai periculos dispozitiv cu probleme NErezolvate (doar ele, cea mai gravă prima)."""
    return most_dangerous(remaining_scan(scan, fixed_keys))


def verdict_view(scan: Scan | None, fixed_keys=frozenset(), accepted_keys=frozenset(), lang: str = "ro") -> dict:
    """Verdictul pentru pagina Acasă, numai din datele motorului: banda vine din scan.score (scorul standard),
    numărătorile din severitățile motorului (Finding.severity), cel mai periculos din punctele motorului."""
    from netscan.ui import i18n
    from netscan.ui.explain_stub import get_explanation

    if scan is None or scan.status != "ok":
        return {"band": None, "score": None, "clean": False, "n_high": 0, "n_medium": 0, "n_low": 0, "n_info": 0,
                "n_findings": 0, "n_devices": 0, "n_devices_with_problems": 0, "n_fixed": 0, "n_accepted": 0,
                "worst": None, "worst_name": None, "worst_ip": None, "first_step": None, "first_code": None,
                "tie_name": None, "tie_ip": None, "counts_text": ""}
    keys = {f.key() for f in scan.findings}
    fixed = set(fixed_keys or ()) & keys
    accepted = set(accepted_keys or ()) & keys
    counts = {sev: sum(1 for f in scan.findings if f.severity == sev) for sev in ("high", "medium", "low", "info")}
    ranked = rank_devices(remaining_scan(scan, fixed))
    worst = ranked[0] if ranked and ranked[0].findings else None
    tie = None
    if worst is not None and len(ranked) > 1 and ranked[1].findings and \
            (ranked[1].total_points, ranked[1].max_severity) == (worst.total_points, worst.max_severity):
        tie = ranked[1]
    first = get_explanation(worst.worst.code, lang) if worst is not None else None
    return {
        "band": score_band(scan.score), "score": scan.score, "clean": not scan.findings,
        **{f"n_{k}": v for k, v in counts.items()},
        "n_findings": len(scan.findings), "n_devices": len(scan.hosts),
        "n_devices_with_problems": len({f.device_id for f in scan.findings}),
        "n_fixed": len(fixed), "n_accepted": len(accepted),
        "worst": worst,
        "worst_name": i18n.device_type_label(lang, worst.host.device_type) if worst is not None else None,
        "worst_ip": worst.host.ip if worst is not None else None,
        "first_step": (first or {}).get("steps", [None])[0] if first else None,
        "first_code": worst.worst.code if worst is not None else None,
        "tie_name": i18n.device_type_label(lang, tie.host.device_type) if tie is not None else None,
        "tie_ip": tie.host.ip if tie is not None else None,
        # propoziția cu numerele, doar categoriile care nu sunt zero (plural corect în RO)
        "counts_text": i18n.verdict_counts_text(lang, counts["high"], counts["medium"], counts["low"], counts["info"]),
    }


# ---------- afișarea dovezii (evidence) din motor, pe înțeles în limba paginii ----------

_UNKNOWN_EVIDENCE = re.compile(r"^fără producător și fără nume, (\d+) port\(uri\) deschise$")
_TITLE_RO = ", titlu: "


def evidence_text(f: Finding, lang: str = "ro") -> str:
    """Textul dovezii, doar pentru afișare (findings.csv și istoricul rămân exact cum le dă motorul).
    EN nu arată românește („titlu:”, „fără producător…”), iar RO are pluralul corect."""
    from netscan.ui import i18n

    text = f.evidence or ""
    m = _UNKNOWN_EVIDENCE.match(text)
    if m:
        n = int(m.group(1))
        if lang == "en":
            return f"no maker and no name, {n} open port" + ("" if n == 1 else "s")
        if n == 1:
            ports = "1 port deschis"
        else:
            ports = f"{n} {'de ' if i18n.ro_needs_de(n) else ''}porturi deschise"
        return f"fără producător și fără nume, {ports}"
    if lang == "en" and _TITLE_RO in text:
        head, title = text.split(_TITLE_RO, 1)        # doar primul: titlul paginii e text nesigur, rămâne neatins
        return f"{head}, title: {title}"
    return text


# ---------- „rezultatul în format standard”: aceleași rânduri ca findings.csv / scores.csv ----------

def csv_view(scan: Scan | None) -> dict:
    """Rândurile din findings.csv pentru scanarea afișată (aceeași ordine ca exportul) și rândul din scores.csv.
    Valorile sunt exact ale motorului (codul și severitatea în engleză, ca în CSV)."""
    if scan is None:
        return {"header": [], "findings": [], "score": None}
    from netscan.engine.rules import finding_sort_key

    rows = [] if scan.status != "ok" else [
        {"file": f.file, "ip": f.ip, "port": "" if f.port is None else f.port, "finding_code": f.code,
         "severity": f.severity}
        for f in sorted(scan.findings, key=finding_sort_key)]
    score = "ERROR" if scan.status != "ok" or scan.score is None else scan.score
    return {"header": ["file", "ip", "port", "finding_code", "severity"], "findings": rows,
            "score": {"file": scan.file, "network_score": score}}


# ---------- dovada înainte / după (pagina de comparație din istoric) ----------

def proof_view(old: Scan, new: Scan, d) -> dict:
    """Ce dovedește comparația dintre două scanări, fără să ghicească:
    - fixed: problemele dispărute de pe dispozitive văzute și în scanarea nouă (likely_same=True dacă
      dispozitivul a fost recunoscut doar după IP, adică MAC-ul s-a schimbat);
    - not_seen: problemele dispărute pentru că dispozitivul NU a mai fost văzut (nu înseamnă reparat);
    - still / new: problemele rămase și cele noi. Scorurile sunt ale motorului."""
    from netscan.ui.storage import match_devices

    removed = {h.device_id for h in d.removed_devices}
    mapping = match_devices(old, new)
    by_ip = {h.device_id for h in d.matched_by_ip}
    fixed, not_seen = [], []
    for f in d.resolved_findings:
        if f.device_id in removed or f.device_id not in mapping:
            not_seen.append(f)
        else:
            fixed.append({"finding": f, "likely_same": mapping[f.device_id] in by_ip})
    return {
        "fixed": fixed, "not_seen": not_seen, "still": list(d.persistent_findings), "new": list(d.new_findings),
        "n_fixed": len(fixed), "n_not_seen": len(not_seen), "n_still": len(d.persistent_findings),
        "n_new": len(d.new_findings),
        "score_before": d.score_before, "score_after": d.score_after,
        "direction": (None if d.score_before is None or d.score_after is None else
                      "up" if d.score_after > d.score_before else "down" if d.score_after < d.score_before
                      else "same"),
        "file_before": old.file, "file_after": new.file,
        "started_before": old.started_at, "started_after": new.started_at,
    }


def current_action(scan: Scan, done: set) -> ActionStep | None:
    """Primul pas încă nebifat. None dacă nu există probleme sau dacă toate sunt bifate."""
    hosts = {h.device_id: h for h in scan.hosts}
    plan = action_plan(scan)
    done_count = sum(1 for f in plan if f.key() in done)
    for i, f in enumerate(plan, 1):
        if f.key() not in done:
            return ActionStep(finding=f, device=hosts.get(f.device_id, Host(ip=f.ip, device_id=f.device_id)),
                              number=i, total=len(plan), done_count=done_count)
    return None
