"""Teste pentru maparea pe CIS Controls v8 și OWASP IoT Top 10 2018 (Oneata, D3)."""

from __future__ import annotations

import pytest

from netscan.explain import get_explanation
from netscan.explain.standards import CIS, MAPPING, OWASP_IOT, get_standards
from netscan.scan.ai_check import CATALOG

# Titlurile oficiale, copiate din surse (vezi docstring-ul din standards.py). Dacă cineva
# schimbă un titlu sau adaugă un id inventat, testul pică.
OFFICIAL_OWASP_2018 = {
    "I1": "Weak, Guessable, or Hardcoded Passwords",
    "I2": "Insecure Network Services",
    "I3": "Insecure Ecosystem Interfaces",
    "I4": "Lack of Secure Update Mechanism",
    "I5": "Use of Insecure or Outdated Components",
    "I6": "Insufficient Privacy Protection",
    "I7": "Insecure Data Transfer and Storage",
    "I8": "Lack of Device Management",
    "I9": "Insecure Default Settings",
    "I10": "Lack of Physical Hardening",
}
OFFICIAL_CIS_V8 = {
    "1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "1.2": "Address Unauthorized Assets",
    "2.2": "Ensure Authorized Software is Currently Supported",
    "3.10": "Encrypt Sensitive Data in Transit",
    "4.2": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
    "4.4": "Implement and Manage a Firewall on Servers",
    "4.5": "Implement and Manage a Firewall on End-User Devices",
    "4.6": "Securely Manage Enterprise Assets and Software",
    "4.7": "Manage Default Accounts on Enterprise Assets and Software",
    "4.8": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
    "5.2": "Use Unique Passwords",
    "7.3": "Perform Automated Operating System Patch Management",
    "7.4": "Perform Automated Application Patch Management",
    "12.2": "Establish and Maintain a Secure Network Architecture",
}

CASES = [(code, lang) for code in sorted(CATALOG) for lang in ("ro", "en")]


def test_mapping_covers_exactly_the_catalog():
    assert set(MAPPING) == set(CATALOG)


def test_english_titles_are_the_official_ones():
    for i, t in OWASP_IOT.items():
        assert OFFICIAL_OWASP_2018[i] == t["en"], i
    for i, t in CIS.items():
        assert OFFICIAL_CIS_V8[i] == t["en"], i


def test_every_title_has_ro_and_en():
    for table in (CIS, OWASP_IOT):
        for i, t in table.items():
            assert set(t) == {"ro", "en"} and t["ro"].strip() and t["en"].strip(), i


@pytest.mark.parametrize("code,lang", CASES)
def test_shape_and_references_exist(code, lang):
    s = get_standards(code, lang)
    assert set(s) == {"cis", "owasp_iot"}
    assert 1 <= len(s["cis"]) <= 3
    assert 1 <= len(s["owasp_iot"]) <= 3
    for item in s["cis"]:
        assert item["id"] in OFFICIAL_CIS_V8 and item["title"] == CIS[item["id"]][lang]
    for item in s["owasp_iot"]:
        assert item["id"] in OFFICIAL_OWASP_2018 and item["title"] == OWASP_IOT[item["id"]][lang]
    assert len({i["id"] for i in s["cis"]}) == len(s["cis"])
    assert len({i["id"] for i in s["owasp_iot"]}) == len(s["owasp_iot"])


def test_starting_points_from_the_guide():
    # Ghidul (secțiunea 11): majoritatea → OWASP I2 + CIS 4.8; OUTDATED → I5; text în clar → I7;
    # UPNP → I9; UNKNOWN_DEVICE → inventarul.
    with_48_and_i2 = [c for c, m in MAPPING.items() if "4.8" in m["cis"] and "I2" in m["owasp_iot"]]
    assert len(with_48_and_i2) > len(MAPPING) / 2
    assert MAPPING["OUTDATED_SERVICE"]["owasp_iot"][0] == "I5"
    for code in ("TELNET_OPEN", "FTP_CLEARTEXT", "HTTP_ADMIN_CLEARTEXT"):
        assert "I7" in MAPPING[code]["owasp_iot"], code
    assert MAPPING["UPNP_EXPOSED"]["owasp_iot"][0] == "I9"
    assert MAPPING["UNKNOWN_DEVICE"]["cis"][0] == "1.1"


def test_unknown_code_and_lang():
    assert get_standards("NOT_A_CODE") == {"cis": [], "owasp_iot": []}
    assert get_standards("TELNET_OPEN", "de") == get_standards("TELNET_OPEN", "ro")
    assert get_standards("TELNET_OPEN", "EN") == get_standards("TELNET_OPEN", "en")


def test_explanations_unchanged_by_standards():
    assert set(get_explanation("TELNET_OPEN", "ro")) == {"text", "steps"}


def test_returns_fresh_lists():
    get_standards("SSH_OPEN")["cis"].append({"id": "x", "title": "x"})
    assert len(get_standards("SSH_OPEN")["cis"]) == len(MAPPING["SSH_OPEN"]["cis"])
