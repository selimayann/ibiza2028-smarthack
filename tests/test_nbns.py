"""Numele calculatorului prin NetBIOS: o singură întrebare, doar în rețeaua locală; răspunsul e text nesigur."""
import struct

from netscan.scan import nbns


def _reply(tid, names):
    body = struct.pack(">HHHHHH", tid, 0x8400, 0, 1, 0, 0) + bytes([32]) + b"C" * 32 + b"\x00" + struct.pack(">HHIH", 0x21, 1, 0, 0)
    body += bytes([len(names)])
    for n, suffix, flags in names:
        body += n.encode("latin-1").ljust(15)[:15] + bytes([suffix]) + struct.pack(">H", flags)
    return body + b"\x00" * 6


def test_reads_the_computer_name_not_the_workgroup():
    data = _reply(7, [("WORKGROUP", 0x00, 0x8400), ("LAPTOP-ALEX", 0x00, 0x0400), ("LAPTOP-ALEX", 0x20, 0x0400)])
    assert nbns.parse_reply(data, 7) == "LAPTOP-ALEX"


def test_hostile_names_are_cleaned_and_wrong_replies_ignored():
    assert nbns.parse_reply(_reply(7, [("<script>x", 0x00, 0)]), 7) == "scriptx"
    assert nbns.parse_reply(_reply(8, [("LAPTOP", 0x00, 0)]), 7) is None        # alt id: nu e răspunsul nostru
    assert nbns.parse_reply(b"\x00\x07garbage", 7) is None


def test_only_local_addresses_are_asked():
    never = lambda: (_ for _ in ()).throw(AssertionError("nu trebuia trimis nimic"))
    assert nbns.query_name("8.8.8.8", make_socket=never) is None
    assert nbns.query_name("nu-e-ip", make_socket=never) is None
