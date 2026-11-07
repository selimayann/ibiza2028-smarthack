import math
"""Generează schițele mascotei (țiparul SafeEel în 5 stări): pagina de previzualizare + câte un .svg."""
from pathlib import Path

HERE = Path(__file__).parent
BODY = (HERE / "body.txt").read_text().strip()

VIEWBOX = "45 15 190 215"
AMBER = "#F5A400"
GOOD = "#16663a"
INK = "#343A40"

ARCS = (
    '<g class="waves">'
    '<path d="M168.7 46.9 A42 42 0 0 1 201.1 79.3" fill="none" stroke="currentColor" stroke-width="8" stroke-linecap="round"/>'
    '<path d="M173.3 25.4 A64 64 0 0 1 222.6 74.7" fill="none" stroke="currentColor" stroke-width="8" stroke-linecap="round"/>'
    '</g>'
)


def _ray(cx, cy, deg, r0, r1):
    a = math.radians(deg)
    return (f"M{cx + r0 * math.cos(a):.1f} {cy + r0 * math.sin(a):.1f} "
            f"L{cx + r1 * math.cos(a):.1f} {cy + r1 * math.sin(a):.1f}")


def eye_open(px=169.0, py=84.5, r_white=8.5, r_pupil=4.2, cls="eye"):
    return (
        f'<g class="{cls}"><circle cx="167" cy="84" r="{r_white}" fill="var(--eye, #fff)"/>'
        f'<circle cx="{px}" cy="{py}" r="{r_pupil}" fill="var(--pupil, #14174d)"/>'
        f'<circle cx="{px + 1.5}" cy="{py - 1.5}" r="1.3" fill="var(--eye, #fff)"/></g>'
    )


def stroke(d, w=2.8, color="var(--eye, #fff)"):
    return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{w}" stroke-linecap="round" stroke-linejoin="round"/>'


STATES = {
    "asteapta": {
        "name": "Așteaptă",
        "when": "Chat-ul e deschis, Volt așteaptă o întrebare.",
        "label": "Întreabă-mă orice despre rețeaua ta.",
        "parts": ARCS + eye_open() + stroke("M163 97 Q169 101.5 175 96.5"),
    },
    "gandeste": {
        "name": "Se gândește",
        "when": "Modelul AI local scrie răspunsul: Volt se încolăcește și se învârte ca un șarpe până e gata.",
        "label": "Mă gândesc…",
        "coil": True,
        "parts": "",
    },
    "verificat": {
        "name": "Verificat",
        "when": "Răspunsul AI a trecut verificarea codului: Volt se îndoaie în formă de bifă.",
        "label": "Verificat de cod: totul vine din scanare.",
        "check": True,
        "parts": "",
    },
    "prins": {
        "name": "Te-am prins!",
        "when": "Verificarea a respins o informație inventată de AI: Volt e surprins, iar aplicația afișează textul predefinit.",
        "label": "Am oprit o informație inventată. Îți arăt răspunsul sigur.",
        "parts": (
            '<g class="sparks">'
            + "".join(stroke(_ray(160, 88, deg, 31, 47), w=6.5, color=AMBER) for deg in (-80, -45, -10))
            + "</g>"
            + eye_open(px=167, py=84, r_white=10, r_pupil=3.6)
            + stroke("M157.5 71.5 L174 75.5", w=3.4)
            + stroke("M163.5 99 L175 97", w=3)
            + f'<path d="M205 168 L226 175.5 L226 192 Q226 208.5 205 217 Q184 208.5 184 192 L184 175.5 Z" fill="{AMBER}"/>'
            + f'<rect x="196.5" y="190" width="17" height="14" rx="2.5" fill="{INK}"/>'
            + stroke("M199.5 190 V185 A5.5 5.5 0 0 1 210.5 185 V190", w=3.2, color=INK)
        ),
    },
    "fara-ai": {
        "name": "Fără AI",
        "when": "AI-ul local e oprit: răspunde cu textele predefinite (fără undele de semnal: niciun model nu e pornit).",
        "label": "Răspuns din textele predefinite.",
        "parts": (
            eye_open()
            + stroke("M164 97.5 Q169 99.5 174 97.5")
            + f'<path d="M186 185 Q195.5 179.5 205 186 Q214.5 179.5 224 185 V208 Q214.5 202.5 205 209 Q195.5 202.5 186 208 Z" '
              f'fill="#fff" stroke="{INK}" stroke-width="3" stroke-linejoin="round"/>'
            + stroke("M205 186 V209", w=3, color=INK)
            + stroke("M191 190 Q196 188 200 190 M191 196 Q196 194 200 196 M210 190 Q214 188 219 190 M210 196 Q214 194 219 196", w=1.8, color=INK)
        ),
    },
}


import math

CX, CY, R = 140.0, 122.0, 50.0


def _pt(deg):
    a = math.radians(deg)
    return CX + R * math.cos(a), CY + R * math.sin(a)


def coil():
    # Un singur contur care se îngroașă lin de la coadă (-10°) la cap (270°), în sensul acelor de ceasornic.
    start, end, w0, w1 = -25.0, 270.0, 4.0, 40.0
    steps = 56
    outer, inner = [], []
    for i in range(steps + 1):
        f = i / steps
        deg = start + (end - start) * f
        half = (w0 + (w1 - w0) * f ** 0.55) / 2
        rad = math.radians(deg)
        outer.append((CX + (R + half) * math.cos(rad), CY + (R + half) * math.sin(rad)))
        inner.append((CX + (R - half) * math.cos(rad), CY + (R - half) * math.sin(rad)))
    pts = outer + inner[::-1]
    d = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in pts) + " Z"
    tx, ty = _pt(start)
    out = [f'<path d="{d}" fill="currentColor"/>', f'<circle cx="{tx:.1f}" cy="{ty:.1f}" r="{w0 / 2:.1f}" fill="currentColor"/>']
    hx, hy = _pt(270)
    out.append(f'<circle cx="{hx:.1f}" cy="{hy:.1f}" r="21" fill="currentColor"/>')
    # fața privește în direcția mișcării (spre dreapta, sus pe cerc)
    out.append(eye_open().replace('cx="167" cy="84"', f'cx="{hx + 7:.1f}" cy="{hy - 4:.1f}"')
               .replace('cx="169.0" cy="84.5"', f'cx="{hx + 9:.1f}" cy="{hy - 3.5:.1f}"')
               .replace('cx="170.5" cy="83.0"', f'cx="{hx + 10.5:.1f}" cy="{hy - 5:.1f}"'))
    out.append(stroke(f"M{hx + 3:.1f} {hy + 9:.1f} Q{hx + 9:.1f} {hy + 13.5:.1f} {hx + 15:.1f} {hy + 8.5:.1f}"))
    return "".join(out)


def _sparkle(x, y, r, color):
    # stea cu 4 colțuri
    k = r * 0.28
    return (f'<path d="M{x} {y - r} Q{x + k} {y - k} {x + r} {y} Q{x + k} {y + k} {x} {y + r} '
            f'Q{x - k} {y + k} {x - r} {y} Q{x - k} {y - k} {x} {y - r} Z" fill="{color}"/>')


def check_body():
    # Bifa: coada sus-stânga → vârful de jos (colț rotunjit) → capul sus-dreapta. Corpul se îngroașă spre cap.
    p0, v, p2 = (70, 112), (112, 168), (172, 92)

    def lerp(p, q, f):
        return p[0] + (q[0] - p[0]) * f, p[1] + (q[1] - p[1]) * f

    a, b = lerp(v, p0, 0.5), lerp(v, p2, 0.36)  # colțul rotunjit începe cu ~30 de unități înainte de vârf
    pts = [lerp(p0, a, i / 24) for i in range(24)]
    for i in range(32):  # colțul de jos: Bézier pătratică A → B cu punctul de control în vârf
        f = i / 31
        pts.append(lerp(lerp(a, v, f), lerp(v, b, f), f))
    pts += [lerp(b, p2, i / 36) for i in range(1, 37)]
    # grosimea crește după lungimea parcursă (nu după numărul punctului), ca să fie lină
    acc = [0.0]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        acc.append(acc[-1] + math.hypot(x1 - x0, y1 - y0))
    total = acc[-1]
    n = len(pts) - 1
    outer, inner = [], []
    for i, (x, y) in enumerate(pts):
        j0, j1 = max(i - 2, 0), min(i + 2, n)
        dx, dy = pts[j1][0] - pts[j0][0], pts[j1][1] - pts[j0][1]
        L = math.hypot(dx, dy) or 1
        nx, ny = -dy / L, dx / L
        half = (3 + 35 * (acc[i] / total) ** 0.6) / 2
        outer.append((x + nx * half, y + ny * half)); inner.append((x - nx * half, y - ny * half))
    d = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in outer + inner[::-1]) + " Z"
    hx, hy = p2
    out = [f'<path d="{d}" fill="currentColor"/>',
           f'<circle cx="{p0[0]}" cy="{p0[1]}" r="1.5" fill="currentColor"/>',
           f'<circle cx="{hx}" cy="{hy}" r="21" fill="currentColor"/>',
           # ochi deschis, vesel, privește în sus-dreapta (direcția bifei)
           f'<g transform="translate({hx - 160} {hy - 88})">' + ARCS + eye_open() + stroke("M161 95.5 Q168.5 104 176 94.5", w=3) + '</g>',
           '<g class="twinkle">', _sparkle(212, 132, 7, GOOD), _sparkle(58, 80, 6, GOOD), _sparkle(96, 196, 4.5, GOOD), "</g>"]
    return "".join(out)


def svg(key, extra_class=""):
    s = STATES[key]
    if s.get("check"):
        return f'<svg class="volt {extra_class}" viewBox="{VIEWBOX}" aria-hidden="true"><g class="pop">{check_body()}</g></svg>'
    if s.get("coil"):
        return f'<svg class="volt {extra_class}" viewBox="{VIEWBOX}" aria-hidden="true"><g class="spin">{coil()}</g></svg>'
    return (
        f'<svg class="volt {extra_class}" viewBox="{VIEWBOX}" aria-hidden="true">'
        f'<g class="swim"><path d="{BODY}" fill="currentColor" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>'
        f'<circle cx="160" cy="88" r="21" fill="currentColor"/>{s["parts"]}</g></svg>'
    )


def standalone(key):
    body = svg(key).replace(' class="volt "', "").replace(' aria-hidden="true"', "")
    return body.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" color="#3333FF" ', 1)


cards = []
for key, s in STATES.items():
    cards.append(f"""
  <article class="card">
    <div class="big">{svg(key, "s-" + key)}</div>
    <h2>{s["name"]}</h2>
    <p class="when">{s["when"]}</p>
    <div class="sizes" aria-label="Mărimi">
      <span class="sz"><span style="width:32px;height:32px">{svg(key, "s-" + key)}</span>32px</span>
      <span class="sz"><span style="width:48px;height:48px">{svg(key, "s-" + key)}</span>48px</span>
      <span class="sz"><span class="avatar">{svg(key, "s-" + key)}</span>avatar chat</span>
    </div>
    <div class="chat"><span class="avatar small">{svg(key, "s-" + key)}</span><p>{s["label"]}</p></div>
  </article>""")

page = f"""<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Volt · schițe mascotă SafeEel</title>
<style>
:root {{ --brand:#3333FF; --bg:#F0F8FF; --ink:#343A40; --muted:#5B6570; --line:#D7E0EB; }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 system-ui, sans-serif; }}
header {{ padding:28px 16px 8px; max-width:1200px; margin:auto }}
h1 {{ margin:0 0 4px; font-size:28px }} header p {{ margin:0; color:var(--muted) }}
main {{ max-width:1200px; margin:auto; padding:16px; display:grid; gap:16px; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)) }}
.card {{ background:#fff; border:1px solid var(--line); border-radius:16px; padding:18px; display:flex; flex-direction:column; gap:8px }}
.big {{ display:grid; place-items:center; height:200px; color:var(--brand) }}
.big svg {{ width:180px; height:200px }}
h2 {{ margin:6px 0 0; font-size:20px }} .when {{ margin:0; color:var(--muted); min-height:72px }}
.sizes {{ display:flex; gap:14px; align-items:flex-end; color:var(--muted); font-size:13px; border-top:1px solid var(--line); padding-top:10px }}
.sz {{ display:flex; flex-direction:column; align-items:center; gap:4px }}
.sz > span {{ display:block; color:var(--brand) }}
.sz > span.avatar, .chat .avatar {{ color:#fff }} .sz svg {{ width:100%; height:100% }}
svg.volt {{ overflow:visible }}
.avatar {{ overflow:hidden; width:48px; height:48px; border-radius:50%; background:var(--brand); color:#fff; display:grid !important; place-items:center;
  --eye:var(--brand); --pupil:#fff }}
.avatar svg {{ width:34px !important; height:34px !important }}
.avatar.small {{ width:40px; height:40px; flex:none }} .avatar.small svg {{ width:28px !important; height:28px !important }}
.chat {{ display:flex; gap:10px; align-items:center; background:#EEF0FF; border-radius:12px; padding:10px; margin-top:6px }}
.chat p {{ margin:0 }}
@media (prefers-reduced-motion: no-preference) {{
  .s-asteapta .waves path {{ animation:rise 1.6s ease-out infinite }}
  .s-asteapta .waves path:nth-child(2) {{ animation-delay:.2s }}
  .s-asteapta .eye {{ transform-box:fill-box; transform-origin:center; animation:blink 4s infinite }}
  .s-gandeste .spin {{ transform-box:view-box; transform-origin:140px 120px; animation:spin 1.8s linear infinite }}
  .s-prins .sparks path {{ transform-box:view-box; transform-origin:160px 88px; animation:burst 1.3s ease-out infinite }}
  .s-prins .sparks path:nth-child(2) {{ animation-delay:.08s }} .s-prins .sparks path:nth-child(3) {{ animation-delay:.16s }}
  .s-verificat .pop {{ transform-box:view-box; transform-origin:130px 125px; animation:pop .5s ease-out }}
  .s-verificat .twinkle {{ animation:pulse 1.6s infinite }}
}}
@keyframes blink {{ 0%,92%,100% {{ transform:scaleY(1) }} 95% {{ transform:scaleY(.1) }} }}
@keyframes spin {{ to {{ transform:rotate(360deg) }} }}
@keyframes pop {{ 0% {{ transform:scale(.6) }} 70% {{ transform:scale(1.08) }} 100% {{ transform:scale(1) }} }}
@keyframes pulse {{ 0%,100% {{ opacity:.35 }} 50% {{ opacity:1 }} }}
@keyframes rise {{ 0% {{ transform:translateY(0); opacity:1 }} 55% {{ transform:translateY(-12px); opacity:0 }} 56% {{ transform:translateY(0); opacity:0 }} 80%,100% {{ transform:translateY(0); opacity:1 }} }}
@keyframes burst {{ 0% {{ transform:scale(.75); opacity:0 }} 25% {{ transform:scale(1); opacity:1 }} 60% {{ transform:scale(1.04); opacity:1 }} 100% {{ transform:scale(1.18); opacity:0 }} }}
@keyframes zap {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:.2 }} }}
footer {{ max-width:1200px; margin:auto; padding:0 16px 32px; color:var(--muted) }}
</style></head><body>
<header><h1>Volt, țiparul SafeEel</h1>
<p>Schițe pentru mascota asistentului: aceeași formă ca logo-ul, câte o stare pentru fiecare pas. Culorile vin din brand (#3333FF pe #F0F8FF).</p></header>
<main>{''.join(cards)}
</main>
<footer>Animațiile (clipit, bule, scântei) se opresc dacă sistemul cere „reducerea mișcării”. Starea e scrisă mereu și în text, nu doar desenată.</footer>
</body></html>"""

(HERE / "index.html").write_text(page)
for key in STATES:
    (HERE / f"volt-{key}.svg").write_text(standalone(key))
print("ok")
