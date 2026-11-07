"""FTP fals (vsFTPd 2.3.4) pentru lab → FTP_CLEARTEXT + OUTDATED_SERVICE.

Trimite exact bannerul `220 (vsFTPd 2.3.4)`, pe care nmap -sV îl recunoaște ca vsftpd 2.3.4.
La orice comandă răspunde `530 Login incorrect.` (la QUIT: `221 Goodbye.` și închide).
Nu există fișiere, nu se execută nimic, nu se salvează nimic.

Pornire:  python lab/fake_services/fake_ftp.py --bind <IP-din-hotspot>   (port implicit 2121)
"""

from __future__ import annotations

import asyncio

from common import MAX_BYTES, READ_CHUNK, main

DEFAULT_PORT = 2121

BANNER = b"220 (vsFTPd 2.3.4)\r\n"
LOGIN_INCORRECT = b"530 Login incorrect.\r\n"
GOODBYE = b"221 Goodbye.\r\n"


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(BANNER)
    await writer.drain()
    budget = MAX_BYTES
    buf = b""
    while True:
        chunk = await reader.read(READ_CHUNK)
        if not chunk:
            return
        budget -= len(chunk)
        if budget < 0:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            # Ne uităm doar dacă e QUIT, ca să închidem politicos. Restul e aruncat.
            if line.strip().upper() == b"QUIT":
                writer.write(GOODBYE)
                await writer.drain()
                return
            writer.write(LOGIN_INCORRECT)
            await writer.drain()
        buf = buf[-READ_CHUNK:]


if __name__ == "__main__":
    main("FTP", handle, DEFAULT_PORT)
