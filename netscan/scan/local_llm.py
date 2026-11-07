"""D8 (Ayan): model AI rulat local (Qwen cu Ollama), doar ca să reformuleze răspunsurile asistentului.

Mentorii: AI online NU (întrebarea 13), model local DA (întrebarea 14).
- **Doar pe laptop:** cererile merg exclusiv spre 127.0.0.1 / ::1 (Ollama). Orice altă adresă e refuzată,
  iar proxy-urile sistemului sunt ignorate, ca nicio cerere să nu iasă din calculator.
- **Oprit implicit:** pornește doar cu `NETSCAN_LOCAL_LLM=1` (sau `ask --local-ai`).
- **Modelul primește doar răspunsul construit de cod** (`answer_from_scan`) și limba; nu primește întrebarea
  utilizatorului și nici datele brute din scanare. Textul lui trece apoi prin validator (`ai_check`), iar
  dacă e respins sau modelul nu răspunde, se afișează răspunsul predefinit (vezi `assistant.answer`).

Variabile (opționale): NETSCAN_LOCAL_MODEL (implicit qwen2.5:7b), NETSCAN_LOCAL_LLM_URL (implicit
http://127.0.0.1:11434), NETSCAN_LOCAL_LLM_TIMEOUT (secunde, implicit 30), NETSCAN_LOCAL_KEEP_ALIVE (cât rămâne
modelul încărcat, implicit 30m). Prima cerere încarcă modelul în placa video și poate depăși timeout-ul:
înainte de demo rulează o dată `ollama run qwen2.5:7b "salut"`.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlparse

DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_TIMEOUT = 30.0
DEFAULT_KEEP_ALIVE = "30m"   # modelul rămâne încărcat în placa video între întrebări (demo)
MAX_ANSWER_CHARS = 1200
LOCAL_HOSTS = frozenset({"127.0.0.1", "::1"})

LANG_NAMES = {"ro": "română", "en": "English"}


class NotLocalError(ValueError):
    """Adresa modelului nu e pe acest calculator."""


def is_enabled(env: Optional[dict] = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("NETSCAN_LOCAL_LLM") or "").strip() == "1"


def check_local_url(url: str) -> str:
    """Acceptă doar http://127.0.0.1:<port> sau http://[::1]:<port>. Fără nume (fără DNS), fără https extern."""
    parsed = urlparse(url or "")
    if parsed.scheme != "http" or parsed.hostname not in LOCAL_HOSTS:
        raise NotLocalError("modelul AI trebuie să ruleze pe acest calculator (127.0.0.1)")
    if parsed.username or parsed.password or (parsed.path not in ("", "/")) or parsed.query or parsed.fragment:
        raise NotLocalError("adresa modelului trebuie să fie doar http://127.0.0.1:<port>")
    return url.rstrip("/")


def build_prompt(context: dict) -> str:
    """Promptul: doar textul deja construit de cod, cu instrucțiunea de a-l reformula simplu."""
    lang = context.get("lang") if context.get("lang") in LANG_NAMES else "ro"
    text = str(context.get("answer_from_scan") or "")[:MAX_ANSWER_CHARS]
    knowledge = context.get("knowledge") or []
    background = ""
    if knowledge:
        parts = [f"[{k.get('id')}] {str(k.get('text') or '')[:700]}" for k in knowledge[:2]]
        background = ("\n\nFRAGMENTE DIN BAZA DE CUNOȘTINȚE (doar ca sprijin; nu adăuga din ele IP-uri, porturi "
                      "sau coduri):\n" + "\n".join(parts))
    return (
        f"Rescrie textul de mai jos în {LANG_NAMES[lang]}, simplu, pentru un om fără cunoștințe tehnice "
        "(nivelul unui copil de 12 ani), în cel mult 4 propoziții scurte. Păstrează exact IP-urile, porturile și "
        "codurile care apar în text. Nu adăuga alte IP-uri, porturi, coduri, versiuni, CVE-uri, numere de telefon, "
        "link-uri sau sfaturi noi; poți folosi fragmentele din baza de cunoștințe doar ca să explici mai clar. "
        "Răspunde doar cu textul rescris.\n\n"
        f"TEXT:\n{text}{background}"
    )


def _no_proxy_opener():
    # ProxyHandler({}) = fără proxy: cererea spre 127.0.0.1 nu poate fi redirecționată în afara laptopului.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def make_llm(env: Optional[dict] = None, opener_factory: Callable = _no_proxy_opener,
             force: bool = False) -> Optional[Callable[[dict], Optional[str]]]:
    """Funcția `llm(context)` pentru `assistant.answer()`, sau None dacă modelul local e oprit."""
    env = os.environ if env is None else env
    if not (force or is_enabled(env)):
        return None
    base = check_local_url(env.get("NETSCAN_LOCAL_LLM_URL") or DEFAULT_URL)
    model = (env.get("NETSCAN_LOCAL_MODEL") or DEFAULT_MODEL).strip()
    try:
        timeout = float(env.get("NETSCAN_LOCAL_LLM_TIMEOUT") or DEFAULT_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    keep_alive = (env.get("NETSCAN_LOCAL_KEEP_ALIVE") or DEFAULT_KEEP_ALIVE).strip()
    opener = opener_factory()

    def llm(context: dict) -> Optional[str]:
        body = json.dumps({
            "model": model,
            "prompt": build_prompt(context),
            "stream": False,
            "keep_alive": keep_alive,
            "options": {"temperature": 0.2, "num_predict": 220},
        }).encode("utf-8")
        req = urllib.request.Request(f"{base}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1_000_000).decode("utf-8"))
        text = data.get("response") if isinstance(data, dict) else None
        return text.strip() if isinstance(text, str) and text.strip() else None

    return llm
