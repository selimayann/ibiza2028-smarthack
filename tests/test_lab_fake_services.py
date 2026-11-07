"""Teste pentru serviciile false din lab (Ayan). Rulează doar pe 127.0.0.1, fără rețea."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab" / "fake_services"))

import common  # noqa: E402
import fake_ftp  # noqa: E402
import fake_telnet  # noqa: E402

# Semnăturile exacte din nmap-service-probes (probe-ul NULL), copiate din baza nmap.
NMAP_BUSYBOX_TELNETD = re.compile(
    rb"^\xff\xfd\x01\xff\xfd\x1f\xff\xfd!\xff\xfb\x01\xff\xfb\x03login: ", re.S
)
NMAP_VSFTPD = re.compile(rb"^220 \(vsFTPd ([-.\w]+)\)\r\n$", re.S)


async def _session(handler, send: list[bytes], read_timeout: float = 1.0) -> bytes:
    server = await common.start(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        out = b""
        try:
            out += await asyncio.wait_for(reader.read(1024), read_timeout)
            for msg in send:
                writer.write(msg)
                await writer.drain()
                await asyncio.sleep(0.05)
            while True:
                chunk = await asyncio.wait_for(reader.read(1024), read_timeout)
                if not chunk:
                    break
                out += chunk
        except asyncio.TimeoutError:
            pass
        writer.close()
    return out


def run(coro):
    return asyncio.run(coro)


def test_telnet_banner_matches_nmap_busybox():
    assert NMAP_BUSYBOX_TELNETD.match(fake_telnet.BANNER)


def test_ftp_banner_matches_nmap_vsftpd_234():
    m = NMAP_VSFTPD.match(fake_ftp.BANNER)
    assert m and m.group(1) == b"2.3.4"


def test_telnet_banner_on_connect_without_client_input():
    # nmap trimite nimic pe probe-ul NULL: bannerul trebuie să vină singur.
    out = run(_session(fake_telnet.handle, [], read_timeout=0.5))
    assert out == fake_telnet.BANNER


def test_ftp_banner_on_connect_without_client_input():
    out = run(_session(fake_ftp.handle, [], read_timeout=0.5))
    assert out == fake_ftp.BANNER


def test_telnet_login_always_fails_and_closes():
    out = run(_session(fake_telnet.handle, [b"root\r\n", b"root\r\n"]))
    assert out.endswith(fake_telnet.LOGIN_FAILED)
    assert b"#" not in out.replace(fake_telnet.BANNER, b"")  # niciun prompt de shell


@pytest.mark.parametrize("cmd", [b"USER anonymous\r\n", b"PASS x\r\n", b"LIST\r\n", b"SITE EXEC id\r\n"])
def test_ftp_every_command_rejected(cmd):
    out = run(_session(fake_ftp.handle, [cmd, b"QUIT\r\n"]))
    assert out == fake_ftp.BANNER + fake_ftp.LOGIN_INCORRECT + fake_ftp.GOODBYE


def test_ftp_vsftpd_backdoor_smiley_does_nothing():
    # Backdoor-ul real din vsftpd 2.3.4 se declanșa cu „:)” în user. Aici nu se întâmplă nimic.
    out = run(_session(fake_ftp.handle, [b"USER x:)\r\n", b"PASS x\r\n", b"QUIT\r\n"]))
    assert out == fake_ftp.BANNER + fake_ftp.LOGIN_INCORRECT * 2 + fake_ftp.GOODBYE


def test_connection_closed_after_too_much_data():
    big = b"A" * (common.MAX_BYTES + 100)
    out = run(_session(fake_ftp.handle, [big]))
    assert out == fake_ftp.BANNER  # închis fără răspuns


def test_session_timeout(monkeypatch):
    monkeypatch.setattr(common, "SESSION_TIMEOUT", 0.3)
    # clientul nu trimite nimic; serverul trebuie să închidă singur înainte de 2 s
    out = run(_session(fake_telnet.handle, [], read_timeout=2.0))
    assert out == fake_telnet.BANNER
