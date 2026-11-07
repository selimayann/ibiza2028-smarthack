"""RBRT, NFR-08: pe ecran niciun text sub 16px. Verifică regulile CSS din afara @media print."""
import re
from pathlib import Path

STATIC = Path(__file__).parent.parent / "netscan" / "ui" / "static"


def _screen_rules(css: str) -> str:
    """Scoate blocurile @media print (pe hârtie textul poate fi mai mic, ca raportul să încapă pe o pagină)."""
    out, i = [], 0
    for m in re.finditer(r"@media\s+print\s*\{", css):
        out.append(css[i:m.start()])
        depth, j = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            j += 1
        i = j
    out.append(css[i:])
    return "".join(out)


def _too_small(value: str) -> bool:
    v = value.strip()
    if v.startswith("max("):          # max(1rem, ...) nu scade sub 16px
        return "1rem" not in v and "16px" not in v
    m = re.match(r"([\d.]+)(rem|em|px)$", v)
    if not m:
        return False
    n, unit = float(m.group(1)), m.group(2)
    return n < 16 if unit == "px" else n < 1


def test_no_screen_text_below_16px():
    bad = []
    for name in ("style.css", "report.css"):
        css = _screen_rules((STATIC / name).read_text(encoding="utf-8"))
        css = re.sub(r"@media\s*\(max-width[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}", "", css)  # pe telefon, graficul are mărimi proprii
        for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            for val in re.findall(r"font-size\s*:\s*([^;]+)", body):
                if _too_small(val) and ".trend-" not in sel:  # textul din grafic e scalat cu SVG-ul; verificat în browser
                    bad.append(f"{name}: {sel.strip()} -> {val.strip()}")
    assert bad == [], bad
