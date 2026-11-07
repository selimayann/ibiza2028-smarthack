"""Telnet fals (BusyBox telnetd) pentru lab → TELNET_OPEN.

Trimite negocierea telnet + promptul `login: ` exact ca BusyBox telnetd, ca nmap -sV
să-l recunoască (semnătura „BusyBox telnetd” din nmap-service-probes).
Orice login eșuează. Nu există shell, nu se execută nimic, nu se salvează nimic.

Pornire:  python lab/fake_services/fake_telnet.py --bind <IP-din-hotspot>   (port implicit 2323)
"""

from __future__ import annotations

import asyncio

from common import MAX_BYTES, main, read_lines

DEFAULT_PORT = 2323

# IAC DO ECHO, IAC DO NAWS, IAC DO LFLOW, IAC WILL ECHO, IAC WILL SGA
NEGOTIATION = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03"
BANNER = NEGOTIATION + b"login: "
PASSWORD_PROMPT = b"Password: "
LOGIN_FAILED = b"\r\nLogin incorrect\r\n"


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(BANNER)
    await writer.drain()
    budget = [MAX_BYTES]
    lines = 0
    async for _ in read_lines(reader, budget):
        lines += 1
        if lines == 1:  # „utilizatorul” (ignorat)
            writer.write(PASSWORD_PROMPT)
        else:  # „parola” (ignorată) → eșec și închidem
            writer.write(LOGIN_FAILED)
            await writer.drain()
            return
        await writer.drain()


if __name__ == "__main__":
    main("Telnet", handle, DEFAULT_PORT)
