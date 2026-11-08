"""FR-02 (Oneata): check_target() refuză tot ce e în afara allowlist-ului și orice IP public. Fără DNS.

Reguli (docs/roles/B_Oneata_Siguranta_Scanare_AI.md, 2.2):
- ținta se parsează doar cu `ipaddress`; orice altceva (hostname, text, injecții) e refuzat;
- niciodată rezolvare DNS;
- IPv6 e refuzat în această fază;
- refuz pentru adrese nespecificate, loopback, link-local, multicast, rezervate sau ne-private
  (`100.64.0.0/10`, rețeaua operatorului mobil, nu e privată, deci e refuzată);
- ținta trebuie să fie `subnet_of()` una din rețelele din allowlist; intrările din allowlist
  trec prin aceleași verificări, iar cele invalide sunt ignorate (fail-safe).

Funcția e pură: nu atinge rețeaua și nu citește variabile de mediu. Allowlist-ul se construiește
cu `build_allowlist()`: subnetul interfeței active, pe care `NETSCAN_ALLOWLIST` îl poate doar ÎNGUSTA
(ex. un singur dispozitiv), niciodată lărgi.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Optional, Union

IPv4Net = ipaddress.IPv4Network
AllowEntry = Union[str, IPv4Net]

# Codurile de motiv. "OK" e singurul care permite scanarea.
OK = "OK"
EMPTY = "EMPTY"
NOT_AN_IP = "NOT_AN_IP"
IPV6_NOT_SUPPORTED = "IPV6_NOT_SUPPORTED"
UNSPECIFIED = "UNSPECIFIED"
LOOPBACK = "LOOPBACK"
LINK_LOCAL = "LINK_LOCAL"
MULTICAST = "MULTICAST"
RESERVED = "RESERVED"
NOT_PRIVATE = "NOT_PRIVATE"
NO_ALLOWLIST = "NO_ALLOWLIST"
TOO_LARGE = "TOO_LARGE"
OUTSIDE_ALLOWLIST = "OUTSIDE_ALLOWLIST"

# O țintă validă e scurtă și conține doar cifre ASCII, puncte și cel mult un "/".
_MAX_TARGET_LEN = 32
_IPV4_CHARS = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?")
_IPV6_CHARS = re.compile(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?")


@dataclass(frozen=True)
class Decision:
    ok: bool
    reason_code: str
    msg_ro: str
    msg_en: str
    network: Optional[str] = None   # ținta normalizată (ex. "172.20.10.5/32"), doar dacă s-a putut parsa

    def __bool__(self) -> bool:
        return self.ok


def _fmt(nets: Iterable[IPv4Net]) -> str:
    return ", ".join(str(n) for n in nets)


def _refuse(code: str, ro: str, en: str, network: Optional[IPv4Net] = None) -> Decision:
    return Decision(
        ok=False,
        reason_code=code,
        msg_ro=f"Nu scanez această adresă: {ro}",
        msg_en=f"I won't scan this address: {en}",
        network=str(network) if network is not None else None,
    )


def _parse(target: object) -> Union[IPv4Net, Decision]:
    """Transformă textul într-o rețea IPv4 sau întoarce refuzul. Nu face niciodată DNS."""
    if not isinstance(target, str):
        return _refuse(NOT_AN_IP, "nu este o adresă IP.", "it is not an IP address.")
    t = target.strip()
    if not t:
        return _refuse(EMPTY, "nu ai dat nicio adresă.", "no address was given.")
    if len(t) > _MAX_TARGET_LEN + 16:
        return _refuse(NOT_AN_IP, "nu este o adresă IP.", "it is not an IP address.")

    if ":" in t:
        if _IPV6_CHARS.fullmatch(t):
            try:
                ipaddress.IPv6Network(t, strict=False)
                return _refuse(IPV6_NOT_SUPPORTED, "adresele IPv6 nu sunt acceptate încă.",
                               "IPv6 addresses are not supported yet.")
            except ValueError:
                pass
        return _refuse(NOT_AN_IP, "nu este o adresă IP.", "it is not an IP address.")

    if len(t) > _MAX_TARGET_LEN or not _IPV4_CHARS.fullmatch(t):
        return _refuse(NOT_AN_IP, "nu este o adresă IP (numele de dispozitive nu sunt acceptate).",
                       "it is not an IP address (device names are not accepted).")
    try:
        return ipaddress.IPv4Network(t, strict=False)
    except ValueError:
        return _refuse(NOT_AN_IP, "nu este o adresă IP validă.", "it is not a valid IP address.")


def _check_kind(net: IPv4Net) -> Optional[Decision]:
    """Refuză tipurile de adrese care nu pot fi niciodată rețeaua echipei."""
    if net.is_unspecified or net.network_address.is_unspecified:
        return _refuse(UNSPECIFIED, "este o adresă nespecificată (0.0.0.0).",
                       "it is an unspecified address (0.0.0.0).", net)
    if net.is_loopback:
        return _refuse(LOOPBACK, "este chiar acest calculator (loopback).",
                       "it is this computer itself (loopback).", net)
    if net.is_link_local:
        return _refuse(LINK_LOCAL, "este o adresă link-local (169.254.x.x).",
                       "it is a link-local address (169.254.x.x).", net)
    if net.is_multicast:
        return _refuse(MULTICAST, "este o adresă multicast.", "it is a multicast address.", net)
    if net.is_reserved:
        return _refuse(RESERVED, "este o adresă rezervată.", "it is a reserved address.", net)
    if not net.is_private:
        return _refuse(NOT_PRIVATE, "este o adresă publică, din afara rețelei tale.",
                       "it is a public address, outside your network.", net)
    return None


def normalize_allowlist(allowlist: Iterable[AllowEntry]) -> list[IPv4Net]:
    """Păstrează doar intrările care trec aceleași verificări ca ținta. Restul se ignoră."""
    nets: list[IPv4Net] = []
    for entry in allowlist or []:
        net = entry if isinstance(entry, IPv4Net) else _parse(entry)
        if isinstance(net, Decision) or _check_kind(net) is not None:
            continue
        if net not in nets:
            nets.append(net)
    return nets


def check_target(target: str, allowlist: Iterable[AllowEntry]) -> Decision:
    """Decide dacă `target` (IP sau subnet IPv4) poate fi scanat. Nu atinge rețeaua."""
    net = _parse(target)
    if isinstance(net, Decision):
        return net

    refused = _check_kind(net)
    if refused is not None:
        return refused

    allowed = normalize_allowlist(allowlist)
    if not allowed:
        return _refuse(NO_ALLOWLIST, "nu știu care e rețeaua ta, așa că nu scanez nimic.",
                       "I don't know which network is yours, so I won't scan anything.", net)

    for a in allowed:
        if net.subnet_of(a):
            return Decision(
                ok=True,
                reason_code=OK,
                msg_ro=f"Adresa {net} face parte din rețeaua ta ({a}).",
                msg_en=f"Address {net} is part of your network ({a}).",
                network=str(net),
            )

    if any(a.subnet_of(net) for a in allowed):
        return _refuse(TOO_LARGE, f"intervalul {net} e mai mare decât rețeaua ta ({_fmt(allowed)}).",
                       f"the range {net} is larger than your network ({_fmt(allowed)}).", net)

    return _refuse(OUTSIDE_ALLOWLIST, f"nu face parte din rețeaua ta ({_fmt(allowed)}).",
                   f"it is not part of your network ({_fmt(allowed)}).", net)


def parse_allowlist_env(value: Optional[str]) -> list[str]:
    """`NETSCAN_ALLOWLIST="172.20.10.0/28, 10.0.0.0/29"` -> ["172.20.10.0/28", "10.0.0.0/29"]."""
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def build_allowlist(iface_cidr: Optional[str], env_value: Optional[str] = None) -> list[IPv4Net]:
    """Allowlist-ul = subnetul interfeței active. `NETSCAN_ALLOWLIST` poate doar să-l ÎNGUSTEZE: se păstrează
    numai intrările din interiorul subnetului (`subnet_of`), iar dacă rămâne vreuna, ele înlocuiesc subnetul.
    O intrare din afară (alt subnet privat, rețeaua sălii, internetul) e ignorată: variabila nu poate lărgi
    niciodată ce scanăm. Fără interfață nu e nimic permis."""
    base = normalize_allowlist([iface_cidr] if iface_cidr else [])
    if not base:
        return []
    iface = base[0]
    narrowed = [n for n in normalize_allowlist(parse_allowlist_env(env_value)) if n.subnet_of(iface)]
    return narrowed or base
