# Volt, mascota asistentului (SafeEel)

Țiparul din logo-ul SafeEel, cu față și 5 stări pentru asistentul AI. Desenat de noi (Oneata), pornind de la `#i-eel`
(`netscan/ui/templates/_eel_symbol.html`): aceeași formă, același albastru `#3333FF`. Fără imagini externe.

| Fișier | Starea | Când apare în asistent |
|---|---|---|
| `volt-asteapta.svg` | zâmbește; undele de semnal urcă și dispar | chat deschis, încă nicio întrebare |
| `volt-gandeste.svg` | încolăcit, se învârte ca un șarpe | se așteaptă răspunsul |
| `volt-verificat.svg` | corpul face o bifă ✓ | `Answer.source == "llm"` (a trecut validatorul) |
| `volt-prins.svg` | surprins, linii de alertă, scut cu lacăt | `Answer.source == "fallback"` și `Answer.problems` nu e gol |
| `volt-fara-ai.svg` | fără unde, cu o carte | `Answer.source == "fallback"`, fără `problems` |

- `index.html`: previzualizarea tuturor stărilor (32px, 48px, avatar pe cerc albastru), cu animațiile CSS. `preview.png`: captură.
- Culori: corpul e `currentColor`; ochiul și gura `var(--eye)`, pupila `var(--pupil)`. Pe avatar albastru: `color:#fff; --eye:var(--brand); --pupil:#fff`.
- Animațiile sunt doar CSS, numai cu `prefers-reduced-motion: no-preference`. Mascota e decor (`aria-hidden`); starea se scrie mereu și în text.
- `build.py` (+ `body.txt`, conturul țiparului din logo) regenerează `index.html` și SVG-urile: `python3 build.py`.
