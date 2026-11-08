"""Ayan: D8, modelul AI local (Ollama pe 127.0.0.1). Fără Ollama real: cererile sunt simulate."""
import io
import json
import socket
from pathlib import Path

import pytest

from netscan.cli import main as cli_main
from netscan.engine.parser import analyze_file
from netscan.scan import assistant, local_llm

V2 = analyze_file(str(Path(__file__).parent.parent / "fixtures" / "validation" / "V2_smart_home.xml"))
ON = {"NETSCAN_LOCAL_LLM": "1"}


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.requests, self.response, self.error = [], response, error

    def open(self, req, timeout=None):
        self.requests.append((req, timeout))
        if self.error:
            raise self.error
        return FakeResp(json.dumps({"response": self.response}).encode())


def llm_with(opener, env=ON):
    return local_llm.make_llm(env=env, opener_factory=lambda: opener)


# --- pornire și adrese -----------------------------------------------------------------------------

def test_disabled_by_default():
    assert local_llm.make_llm(env={}) is None
    assert local_llm.make_llm(env={"NETSCAN_LOCAL_LLM": "0"}) is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://127.0.0.1:8080/", "http://[::1]:11434"])
def test_local_urls_accepted(url):
    assert local_llm.check_local_url(url)


@pytest.mark.parametrize("url", [
    "http://localhost:11434",            # nume: ar cere DNS / fișierul hosts
    "http://192.168.1.5:11434",          # alt calculator din rețea
    "http://172.20.10.1:11434",          # chiar și gateway-ul hotspotului
    "https://api.openai.com",            # AI online (interzis de mentori)
    "http://127.0.0.1.evil.com:11434",
    "http://user:pass@127.0.0.1:11434",
    "http://127.0.0.1:11434/api?x=1",
    "ftp://127.0.0.1",
    "",
])
def test_non_local_urls_refused(url):
    with pytest.raises(local_llm.NotLocalError):
        local_llm.check_local_url(url)


def test_make_llm_refuses_remote_url():
    with pytest.raises(local_llm.NotLocalError):
        local_llm.make_llm(env={**ON, "NETSCAN_LOCAL_LLM_URL": "https://api.example.com"})


def test_default_opener_ignores_system_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    opener = local_llm._no_proxy_opener()
    assert not any(getattr(h, "proxies", None) for h in opener.handlers)


# --- cererea și promptul ---------------------------------------------------------------------------

def test_request_goes_only_to_localhost_with_answer_text_only():
    op = FakeOpener("Text simplu.")
    llm = llm_with(op)
    out = llm({"lang": "ro", "answer_from_scan": "Fă asta întâi: X", "question_untrusted": "SECRET-Q",
               "findings": [{"ip": "192.168.1.40"}]})
    assert out == "Text simplu."
    req, timeout = op.requests[0]
    assert req.full_url == "http://127.0.0.1:11434/api/generate" and timeout == 60.0
    body = json.loads(req.data)
    assert body["model"] == "qwen2.5:7b" and body["stream"] is False and body["keep_alive"] == "30m"
    assert "Fă asta întâi: X" in body["prompt"]
    assert "SECRET-Q" not in body["prompt"] and "192.168.1.40" not in body["prompt"]


def test_model_and_timeout_from_env():
    op = FakeOpener("ok")
    llm_with(op, {**ON, "NETSCAN_LOCAL_MODEL": "qwen3:4b", "NETSCAN_LOCAL_LLM_TIMEOUT": "5"})({"lang": "en"})
    req, timeout = op.requests[0]
    assert json.loads(req.data)["model"] == "qwen3:4b" and timeout == 5.0


def test_prompt_language_and_length():
    assert "English" in local_llm.build_prompt({"lang": "en", "answer_from_scan": "x"})
    assert len(local_llm.build_prompt({"lang": "ro", "answer_from_scan": "y" * 10_000})) < 2000


# --- cu asistentul: verificat și cu fallback -------------------------------------------------------

def test_good_local_answer_is_used():
    good = "Camera de la 192.168.1.40 are parola din fabrică. Schimb-o și închide portul 554."
    r = assistant.answer("Ce fac întâi?", V2, llm=llm_with(FakeOpener(good)))
    assert r.source == "llm" and r.text == good


@pytest.mark.parametrize("bad", ["Închide portul 23 pe 192.168.1.40.", "Sună la 0721 234 567.",
                                 "E vulnerabilă la CVE-2021-36260."])
def test_hallucinated_local_answer_is_rejected(bad):
    r = assistant.answer("Ce fac întâi?", V2, llm=llm_with(FakeOpener(bad)))
    assert r.source == "fallback" and r.problems
    assert r.text == assistant.fallback_answer("Ce fac întâi?", V2)[0]


def test_ollama_not_running_falls_back():
    r = assistant.answer("Care e scorul?", V2, llm=llm_with(FakeOpener(error=ConnectionRefusedError())))
    assert r.source == "fallback" and r.problems == ["LLM_ERROR"]


def test_empty_model_answer_falls_back():
    r = assistant.answer("Care e scorul?", V2, llm=llm_with(FakeOpener("   ")))
    assert r.source == "fallback"


# --- CLI ---------------------------------------------------------------------------------------------

V2_PATH = str(Path(__file__).parent.parent / "fixtures" / "validation" / "V2_smart_home.xml")


def test_cli_verify_text_demo(capsys):
    assert cli_main(["ask", V2_PATH, "x", "--verify-text", "Închide portul 23 pe 192.168.1.99."]) == 1
    out = capsys.readouterr().out
    assert "RESPINS" in out and "PORT:23" in out and "IP:192.168.1.99" in out
    assert cli_main(["ask", V2_PATH, "x", "--verify-text", "Camera 192.168.1.40, portul 554."]) == 0


def test_cli_local_ai_without_ollama_falls_back(capsys, monkeypatch):
    def refuse(self, *a, **k):
        raise ConnectionRefusedError("Ollama nu rulează")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    assert cli_main(["ask", V2_PATH, "Care e scorul?", "--local-ai"]) == 0
    out = capsys.readouterr().out
    assert "40 din 100" in out and "răspuns predefinit" in out
