"""Demonstrația validatorului anti-halucinații (B), pentru juriu: `python -m netscan demo-ai-check <scan.xml>`.

Fără rețea și fără model AI: textele „generate” sunt SIMULATE, scrise de noi ca exemplu, fiecare cu o greșeală
tipică (un port care nu e în scanare, un CVE inventat, un IP din altă rețea și un număr de telefon). Validatorul
real (`ai_check.check_llm_text`) le respinge, iar aplicația afișează în locul lor textul verificat. La final, un
text corect, construit din faptele scanării, trece validarea. Ieșirea încape pe un ecran de proiector (≤ 25 rânduri).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from netscan.model import Scan
from netscan.scan import ai_check, assistant

ABSENT_PORT_CANDIDATES = (3389, 5900, 445, 23, 8443)
OTHER_NETWORK_IPS = ("192.168.0.50", "10.99.0.7")
FAKE_CVE = "CVE-2024-99999"
FAKE_PHONE = "0721 234 567"


@dataclass(frozen=True)
class Example:
    text: str
    expected: tuple[str, ...]          # problemele pe care TREBUIE să le găsească validatorul (gol = trebuie să treacă)


def _facts(scan: Scan):
    ips = {h.ip for h in scan.hosts} | {f.ip for f in scan.findings}
    ports = {p.port for h in scan.hosts for p in h.ports} | {f.port for f in scan.findings if f.port is not None}
    ranked = assistant.ranked_devices(scan)
    if ranked:
        ip, findings = ranked[0]
        worst = findings[0]
    else:
        ip, worst = (scan.hosts[0].ip if scan.hosts else None), None
    return ips, ports, ip, worst


def build_examples(scan: Scan, lang: str = "ro") -> list[Example]:
    """3 texte greșite + 1 corect, toate construite din scanarea dată."""
    ips, ports, ip, worst = _facts(scan)
    if ip is None:
        raise ValueError("scanarea nu are niciun dispozitiv")
    absent = next(p for p in ABSENT_PORT_CANDIDATES if p not in ports)
    foreign = next(i for i in OTHER_NETWORK_IPS if i not in ips)
    real_port = worst.port if worst is not None and worst.port is not None else None
    port_txt = (f", portul {real_port}" if lang == "ro" else f", port {real_port}") if real_port else ""
    ro = lang == "ro"
    comma = "," if port_txt else ""
    examples = [
        Example((f"Închide portul {absent} (Desktop la distanță) pe {ip}." if ro
                 else f"Close port {absent} (Remote Desktop) on {ip}."), (f"PORT:{absent}",)),
        Example((f"Serviciul de pe {ip}{port_txt}{comma} are vulnerabilitatea {FAKE_CVE}." if ro
                 else f"The service on {ip}{port_txt}{comma} has vulnerability {FAKE_CVE}."), (f"CVE:{FAKE_CVE}",)),
        Example((f"Verifică și camera de la {foreign} sau sună la {FAKE_PHONE}." if ro
                 else f"Also check the camera at {foreign} or call {FAKE_PHONE}."), (f"IP:{foreign}", "PHONE")),
    ]
    if worst is not None:
        good = (f"{worst.code} pe {ip}{port_txt}: urmează pașii de reparare din aplicație." if ro
                else f"{worst.code} on {ip}{port_txt}: follow the repair steps in the app.")
    else:
        good = (f"Dispozitivul {ip} nu are probleme din catalog." if ro else f"Device {ip} has no catalog problems.")
    examples.append(Example(good, ()))
    return examples


def render(scan: Scan, lang: str = "ro") -> list[str]:
    ro = lang == "ro"
    lines = [
        "Demo: validatorul anti-halucinații · Hallucination check demo",
        "SIMULARE: textele de mai jos sunt scrise de noi ca exemplu, nu de un model AI.",
        "SIMULATION: the texts below are examples we wrote, not answers from an AI model.",
        (f"Scanare: {scan.file} · {len(scan.hosts)} dispozitive · {len(scan.findings)} probleme · scor {scan.score}" if ro
         else f"Scan: {scan.file} · {len(scan.hosts)} devices · {len(scan.findings)} problems · score {scan.score}"),
        "",
    ]
    for n, ex in enumerate(build_examples(scan, lang), 1):
        check = ai_check.check_llm_text(ex.text, scan)
        lines.append(f"{n}. „{ex.text}”" if ro else f'{n}. "{ex.text}"')
        if check.ok:
            lines.append("   [ACCEPTAT] tot ce menționează există în scanare")
            lines.append("   [ACCEPTED] everything it mentions exists in the scan")
        else:
            lines.append("   [RESPINS] " + "; ".join(ai_check.explain_problem(p, "ro") for p in check.problems)
                         + " → folosim textul verificat")
            lines.append("   [REJECTED] " + "; ".join(ai_check.explain_problem(p, "en") for p in check.problems)
                         + " → we use the verified text")
    verified, _ = assistant.fallback_answer("Ce fac întâi?" if ro else "What should I do first?", scan, lang)
    lines += ["", "Textul verificat (din scanare) · Verified text (from the scan):", "  " + verified.splitlines()[0]]
    return lines


def run_demo(path: str, lang: str = "ro", out=print) -> int:
    from netscan.engine.parser import analyze_file
    scan = analyze_file(path)
    if scan.status != "ok":
        out(("Fișierul nu a putut fi citit: " if lang == "ro" else "The file could not be read: ") + str(scan.error_code))
        return 2
    if not scan.hosts:
        out("Scanarea nu are dispozitive." if lang == "ro" else "The scan has no devices.")
        return 2
    for line in render(scan, lang):
        out(line)
    return 0
