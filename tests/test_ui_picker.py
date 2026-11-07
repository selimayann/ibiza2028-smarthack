"""Alegerea scanării: cu JavaScript se aplică direct, deci butonul „Arată” apare doar fără JS."""

from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "netscan" / "ui" / "static"


def test_show_button_hidden_only_when_js_runs():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    # clasa „js” se pune doar după verificarea că actualizările parțiale merg (altfel butonul rămâne)
    guard = js.index("if (!window.fetch || !window.DOMParser) return;")
    assert js.index('document.documentElement.classList.add("js")') > guard
    assert '.js .picker-row button[type="submit"] { display: none; }' in css
    # fără clasa „js” (fără JavaScript), butonul nu e ascuns de nicio altă regulă
    assert ".picker-row button" not in css.replace('.js .picker-row button[type="submit"]', "")
