"""Oneata: check_target() refuză IP public, 100.64.0.0/10, subnet prea mare, hostname, rețeaua venue.

Toate testele sunt pe text: nu ating rețeaua și nu fac DNS.
"""
import socket

import pytest

from netscan.scan import guardrail as g
from netscan.scan.guardrail import build_allowlist, check_target, normalize_allowlist, parse_allowlist_env

ALLOW = ["172.20.10.0/28"]


# --- tabelul din docs/roles/B_Oneata_Siguranta_Scanare_AI.md -----------------------------------

@pytest.mark.parametrize("target", ["172.20.10.5", "172.20.10.0/28"])
def test_accepted(target):
    d = check_target(target, ALLOW)
    assert d.ok and d.reason_code == g.OK


@pytest.mark.parametrize(
    "target, code",
    [
        ("8.8.8.8", g.NOT_PRIVATE),
        ("1.1.1.0/24", g.NOT_PRIVATE),
        ("100.64.1.1", g.NOT_PRIVATE),          # rețeaua operatorului mobil (CGNAT)
        ("172.20.0.0/16", g.TOO_LARGE),         # mai mare decât allowlist-ul
        ("192.168.1.0/24", g.OUTSIDE_ALLOWLIST),  # privată, dar nu a noastră (ex. venue)
        ("127.0.0.1", g.LOOPBACK),
        ("router.local", g.NOT_AN_IP),
        ("172.20.10.5; rm -rf /", g.NOT_AN_IP),
    ],
)
def test_refused_table(target, code):
    d = check_target(target, ALLOW)
    assert not d.ok
    assert d.reason_code == code


# --- cazuri în plus ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "target, code",
    [
        ("", g.EMPTY),
        ("   ", g.EMPTY),
        ("0.0.0.0", g.UNSPECIFIED),
        ("0.0.0.0/0", g.UNSPECIFIED),
        ("169.254.1.1", g.LINK_LOCAL),
        ("224.0.0.1", g.MULTICAST),
        ("255.255.255.255", g.RESERVED),
        ("240.0.0.1", g.RESERVED),
        ("100.64.0.0/10", g.NOT_PRIVATE),
        ("100.127.255.254", g.NOT_PRIVATE),
        ("172.20.10.16", g.OUTSIDE_ALLOWLIST),  # imediat după /28
        ("172.20.10.0/27", g.TOO_LARGE),
        ("10.0.0.1", g.OUTSIDE_ALLOWLIST),
        ("::1", g.IPV6_NOT_SUPPORTED),
        ("fe80::1", g.IPV6_NOT_SUPPORTED),
        ("::ffff:172.20.10.5", g.IPV6_NOT_SUPPORTED),
        ("localhost", g.NOT_AN_IP),
        ("google.com", g.NOT_AN_IP),
        ("172.20.10.5 && whoami", g.NOT_AN_IP),
        ("172.20.10.5\n8.8.8.8", g.NOT_AN_IP),
        ("172.20.10.5,8.8.8.8", g.NOT_AN_IP),
        ("172.20.10.1-15", g.NOT_AN_IP),         # sintaxa de interval nmap nu e acceptată
        ("172.20.10.*", g.NOT_AN_IP),
        ("-iL /etc/passwd", g.NOT_AN_IP),         # argument nmap deghizat
        ("--script=evil", g.NOT_AN_IP),
        ("172.020.010.005", g.NOT_AN_IP),        # zerouri în față (octal ambiguu)
        ("0xac.20.10.5", g.NOT_AN_IP),
        ("2886994437", g.NOT_AN_IP),             # IP ca număr întreg
        ("172.20.10.256", g.NOT_AN_IP),
        ("172.20.10.5/33", g.NOT_AN_IP),
        ("１７２.２０.１０.５", g.NOT_AN_IP),         # cifre Unicode
        ("172.20.10.5" + " " * 100, g.OK),       # spațiile de la capete se ignoră
        ("x" * 10_000, g.NOT_AN_IP),
    ],
)
def test_refused_extra(target, code):
    d = check_target(target, ALLOW)
    assert d.reason_code == code
    assert d.ok == (code == g.OK)


@pytest.mark.parametrize("target", [None, 123, b"172.20.10.5", ["172.20.10.5"]])
def test_non_string_refused(target):
    d = check_target(target, ALLOW)
    assert not d.ok and d.reason_code == g.NOT_AN_IP


def test_host_with_prefix_is_normalized():
    d = check_target("172.20.10.5/28", ALLOW)
    assert d.ok and d.network == "172.20.10.0/28"


def test_single_ip_network_is_32():
    assert check_target("172.20.10.5", ALLOW).network == "172.20.10.5/32"


# --- allowlist-ul ------------------------------------------------------------------------------

def test_empty_allowlist_refuses_everything():
    d = check_target("172.20.10.5", [])
    assert not d.ok and d.reason_code == g.NO_ALLOWLIST


@pytest.mark.parametrize(
    "bad_entry",
    ["0.0.0.0/0", "8.8.8.0/24", "100.64.0.0/10", "127.0.0.0/8", "router.local", "", "::/0", "1.0.0.0/1"],
)
def test_bad_allowlist_entries_are_ignored(bad_entry):
    """O intrare greșită în NETSCAN_ALLOWLIST nu poate deschide internetul."""
    assert normalize_allowlist([bad_entry]) == []
    d = check_target("8.8.8.8", [bad_entry])
    assert not d.ok


def test_extra_allowlist_entry_works():
    allow = ["172.20.10.0/28", "10.42.0.0/29"]
    assert check_target("10.42.0.3", allow).ok
    assert not check_target("10.42.0.9", allow).ok


def test_parse_allowlist_env():
    assert parse_allowlist_env(None) == []
    assert parse_allowlist_env("") == []
    assert parse_allowlist_env(" 172.20.10.0/28 , ,10.0.0.0/29 ") == ["172.20.10.0/28", "10.0.0.0/29"]


def test_build_allowlist_from_interface_and_env():
    nets = build_allowlist("172.20.10.3/28", "10.42.0.0/29, 8.8.8.0/24, junk")
    assert [str(n) for n in nets] == ["172.20.10.0/28", "10.42.0.0/29"]


def test_build_allowlist_without_interface():
    assert build_allowlist(None, None) == []


# --- mesaje -------------------------------------------------------------------------------------

def test_messages_are_bilingual_and_name_the_network():
    d = check_target("192.168.1.0/24", ALLOW)
    assert d.msg_ro == "Nu scanez această adresă: nu face parte din rețeaua ta (172.20.10.0/28)."
    assert d.msg_en == "I won't scan this address: it is not part of your network (172.20.10.0/28)."


def test_refusal_message_does_not_echo_untrusted_input():
    evil = "<script>alert(1)</script>"
    d = check_target(evil, ALLOW)
    assert not d.ok
    assert evil not in d.msg_ro and evil not in d.msg_en
    assert d.network is None


# --- fără rețea ---------------------------------------------------------------------------------

def test_no_dns_or_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("guardrail-ul nu are voie să folosească rețeaua")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, boom)
    monkeypatch.setattr(socket.socket, "connect", boom)

    for t in ["router.local", "google.com", "8.8.8.8", "172.20.10.5", "localhost"]:
        check_target(t, ALLOW)
