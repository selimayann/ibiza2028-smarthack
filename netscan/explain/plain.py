"""Testul automat de limbaj simplu pentru explicații (folosit de tests/test_plain_language.py și
scripts/plain_language_report.py). NU e un test cu oameni: măsoară doar reguli verificabile.

Reguli:
a) jargon: un termen tehnic din JARGON apare doar dacă e în glosar sau e explicat în aceeași frază;
b) propoziții de cel mult MAX_SENTENCE_WORDS cuvinte;
c) fiecare pas începe cu un verb de acțiune din ACTION_VERBS;
d) LIX = cuvinte/propoziții + 100 × cuvinte lungi/cuvinte (cuvânt lung = peste 6 litere).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from netscan.explain import get_explanation, get_glossary, get_harm

MAX_SENTENCE_WORDS = 20
# Praguri LIX (Björnsson): ~40 = text de dificultate medie. Româna iese mai mare din cauza cuvintelor lungi
# (în studii comparative, textele medicale RO au ~61, cele EN ~42), deci pragul RO e ceva mai sus.
# Nu ridicăm pragul ca să treacă un text greu: textul se rescrie.
LIX_MAX = {"ro": 45, "en": 40}
LONG_WORD = 6   # litere; un cuvânt e „lung” dacă are mai mult de atât

# Termeni tehnici, ca rădăcini (se potrivesc la începutul cuvântului, fără diferență de litere și diacritice).
# O singură constantă, ușor de editat: rădăcină -> eticheta afișată în raport.
JARGON: dict[str, dict[str, str]] = {
    "ro": {
        "port": "port", "protocol": "protocol", "tcp": "TCP", "udp": "UDP", "firmware": "firmware",
        "cript": "criptare", "necript": "criptare", "autentific": "autentificare", "exploit": "exploit",
        "ip": "IP", "server": "server", "router": "router", "smb": "SMB", "rdp": "RDP", "remote desktop": "RDP",
        "vnc": "VNC", "mqtt": "MQTT", "broker": "broker", "upnp": "UPnP", "snmp": "SNMP", "ssh": "SSH",
        "telnet": "Telnet", "ftp": "FTP", "sftp": "FTP", "ftps": "FTP", "http": "HTTP", "https": "HTTP",
        "banner": "banner", "vulnerabil": "vulnerabilitate", "tls": "TLS", "rtsp": "RTSP", "vpn": "VPN",
        "firewall": "firewall", "ransomware": "ransomware", "root": "root", "jetdirect": "JetDirect",
        "raw": "RAW", "community string": "community strings", "network level authentication": "NLA",
        "serviciu": "serviciu", "servicii": "serviciu", "broker": "broker",
    },
    "en": {
        "port": "port", "protocol": "protocol", "tcp": "TCP", "udp": "UDP", "firmware": "firmware",
        "encrypt": "encryption", "unencrypt": "encryption", "authenticat": "authentication", "exploit": "exploit",
        "ip": "IP", "server": "server", "router": "router", "smb": "SMB", "rdp": "RDP", "remote desktop": "RDP",
        "vnc": "VNC", "mqtt": "MQTT", "broker": "broker", "upnp": "UPnP", "snmp": "SNMP", "ssh": "SSH",
        "telnet": "Telnet", "ftp": "FTP", "sftp": "FTP", "ftps": "FTP", "http": "HTTP", "https": "HTTP",
        "banner": "banner", "vulnerab": "vulnerability", "tls": "TLS", "rtsp": "RTSP", "vpn": "VPN",
        "firewall": "firewall", "ransomware": "ransomware", "root": "root", "jetdirect": "JetDirect",
        "raw": "RAW", "community string": "community strings", "network level authentication": "NLA",
        "service": "service",
    },
}

# Verbe de acțiune concrete cu care trebuie să înceapă un pas (forme de imperativ / conjuncții de condiție
# urmate de verb sunt tratate separat în step_starts_with_action).
ACTION_VERBS: dict[str, tuple[str, ...]] = {
    "ro": ("deschide", "intră", "oprește", "dezactivează", "schimbă", "setează", "alege", "apasă",
           "actualizează", "scoate", "verifică", "notează", "sună", "cere", "pune", "pornește", "folosește",
           "lasă", "mută", "caută", "dă", "instalează", "treci", "păstrează", "ține", "nu"),
    "en": ("open", "go", "turn", "disable", "change", "set", "choose", "press", "update", "unplug", "check",
           "write", "call", "ask", "put", "start", "use", "let", "keep", "move", "look", "give", "install",
           "switch", "require", "allow", "never", "don't", "make", "enable", "find", "rename", "stop", "remove"),
}

# „X e/este/înseamnă …”, „X (…)”, „X, adică …” = termen explicat în aceeași frază
_EXPLAINED = {
    "ro": r"\s*(?:\(|,?\s*(?:e|este|sunt|înseamnă|adică)\b)",
    "en": r"\s*(?:\(|,?\s*(?:is|are|means|which is)\b)",
}


def _fold(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")


_SENT = re.compile(r"(?<=[.!?])\s+")
_WORD = re.compile(r"[^\W_]+(?:[-’'][^\W_]+)*")   # litere din orice alfabet, inclusiv ș, ț


def sentences(text: str) -> list[str]:
    return [s for s in _SENT.split(text.strip()) if s]


def words(text: str) -> list[str]:
    return _WORD.findall(text)


def lix(texts: list[str]) -> float:
    sents = [s for t in texts for s in sentences(t)]
    ws = [w for t in texts for w in words(t)]
    if not ws or not sents:
        return 0.0
    long_ = sum(1 for w in ws if len(re.sub(r"[-’']", "", w)) > LONG_WORD)
    return len(ws) / len(sents) + 100 * long_ / len(ws)


def _glossary_terms(lang: str) -> list[str]:
    out = []
    for g in get_glossary(lang):
        for part in re.split(r"\s*/\s*", g["term"]):
            out.append(_fold(part))
    return out


def _in_glossary(stem: str, lang: str) -> bool:
    return any(re.search(r"\b" + re.escape(stem), t) for t in _glossary_terms(lang))


def jargon_in(sentence: str, lang: str) -> list[str]:
    """Termenii tehnici din frază care nu sunt nici în glosar, nici explicați chiar în ea."""
    folded = _fold(sentence)
    found = []
    for stem, label in JARGON[lang].items():
        m = re.search(r"\b" + re.escape(stem) + r"\w*", folded)
        if not m:
            continue
        if _in_glossary(stem, lang) or _in_glossary(_fold(label), lang):
            continue
        if re.match(_EXPLAINED[lang], folded[m.end():]):
            continue
        if label not in found:
            found.append(label)
    return found


# Un pas poate începe cu o condiție scurtă („Dacă îl folosești, …”, „Pe Windows, …”): verbul vine după virgulă.
_LEAD = re.compile(r"^(?:dacă|if|pe|on|din|from|la|at|în|in)\b[^,]{0,60},\s*", re.I)


def first_verb(step: str) -> str:
    w = words(_LEAD.sub("", step.strip()))
    if not w:
        return ""
    return w[0].lower().split("-")[0]      # „oprește-l” -> „oprește”, „don't” rămâne „don't”


def step_starts_with_action(step: str, lang: str) -> bool:
    return first_verb(step) in ACTION_VERBS[lang]


@dataclass
class Report:
    code: str
    lang: str
    lix: float
    max_words: int
    long_sentences: list[str] = field(default_factory=list)
    jargon: list[str] = field(default_factory=list)
    bad_steps: list[str] = field(default_factory=list)


def measure(code: str, lang: str) -> Report:
    e = get_explanation(code, lang)
    texts = [e["text"], *e["steps"], get_harm(code, lang)]
    sents = [s for t in texts for s in sentences(t)]
    jargon: list[str] = []
    for s in sents:
        for j in jargon_in(s, lang):
            if j not in jargon:
                jargon.append(j)
    return Report(
        code=code, lang=lang, lix=lix(texts),
        max_words=max(len(words(s)) for s in sents),
        long_sentences=[s for s in sents if len(words(s)) > MAX_SENTENCE_WORDS],
        jargon=jargon,
        bad_steps=[s for s in e["steps"] if not step_starts_with_action(s, lang)],
    )
