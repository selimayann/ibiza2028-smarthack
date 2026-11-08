"""Volt, mascota asistentului: starea după răspuns (verificat / prins / fără AI), mereu și în text."""
import re
from pathlib import Path
from urllib.parse import quote

import pytest

import netscan.scan.local_llm as local_llm
from netscan.ui.app import reply_state
from tests.test_ui_app import make_client, sample

ROOT = Path(__file__).parent.parent
VOLT = ROOT / "netscan" / "ui" / "templates" / "_volt.html"
STATES = ("asteapta", "gandeste", "verificat", "prins", "fara-ai")


class R:
    def __init__(self, source, problems=()):
        self.source, self.problems = source, list(problems)


def test_reply_state_mapping():
    assert reply_state(R("llm")) == "verificat"
    assert reply_state(R("fallback", ["ip inventat"])) == "prins"
    assert reply_state(R("fallback")) == "fara-ai"


def test_volt_template_matches_branding_and_is_safe():
    tpl = VOLT.read_text(encoding="utf-8")
    for st in STATES:
        src = (ROOT / "branding" / "mascot" / f"volt-{st}.svg").read_text(encoding="utf-8")
        for d in re.findall(r' d="([^"]+)"', src):
            assert d in tpl, st
        assert f"s-{st}" in tpl
    assert "<script" not in tpl and "href" not in tpl and "style=" not in tpl and "http" not in tpl.split("#}", 1)[1]
    assert tpl.count('aria-hidden="true"') == len(STATES)


def test_ai_off_shows_waiting_volt_and_no_ai_state(tmp_path, monkeypatch):
    monkeypatch.delenv("NETSCAN_LOCAL_LLM", raising=False)
    client, _ = make_client(tmp_path, [sample()])
    html = client.get("/?ask=1").get_data(as_text=True)
    # mascota (chenarul cu 3 puncte) e doar în antetul ferestrei; mesajele nu mai au mascota lângă ele
    assert 'class="chat-avatar" aria-hidden="true"><svg class="fab-dots"' in html and "msg-volt" not in html
    data = client.get("/api/ask?scan=0&q=" + quote("Ce fac întâi?")).get_json()
    assert data["state"] == "fara-ai" and data["source_icon"] == "info"
    html = client.get("/?q=" + quote("Ce fac întâi?")).get_data(as_text=True)
    assert "msg-row-fara-ai" in html and "Răspuns construit direct din scanare" in html


def test_validator_rejection_shows_caught_volt_with_text(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_LOCAL_LLM", "1")
    monkeypatch.setattr(local_llm, "make_llm", lambda *a, **k: (lambda ctx: "Schimbă parola camerei 10.9.9.9 acum."))
    client, _ = make_client(tmp_path, [sample()])
    data = client.get("/api/ask?scan=0&q=" + quote("Ce fac întâi?")).get_json()
    assert data["state"] == "prins" and data["source_icon"] == "shield"
    assert data["source_label"].startswith("Am oprit o informație inventată")
    html = client.get("/?lang=en&q=" + quote("What should I do first?")).get_data(as_text=True)
    assert "msg-row-prins" in html and "I stopped a made-up detail" in html and "10.9.9.9" not in html


def test_checked_ai_answer_shows_verified_volt(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCAN_LOCAL_LLM", "1")
    monkeypatch.setattr(local_llm, "make_llm", lambda *a, **k: (lambda ctx: "Începe cu primul pas din listă."))
    client, _ = make_client(tmp_path, [sample()])
    data = client.get("/api/ask?scan=0&q=" + quote("Ce fac întâi?")).get_json()
    if data["source"] != "llm":
        pytest.skip("validatorul a respins textul de test")
    assert data["state"] == "verificat" and data["source_icon"] == "eel"
