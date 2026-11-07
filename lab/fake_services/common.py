"""Server TCP comun pentru serviciile false din lab.

Regula de aur: simulăm, nu expunem.
- Nu executăm și nu interpretăm nimic din ce trimite clientul (doar numărăm rândurile).
- Nu salvăm și nu logăm ce trimite clientul.
- Fiecare conexiune se închide după SESSION_TIMEOUT secunde sau după MAX_BYTES primiți.
- Maxim MAX_CONNECTIONS conexiuni simultane; restul se închid imediat.
- Implicit ascultăm doar pe 127.0.0.1. Pe hotspot pornești explicit cu --bind <IP-ul tău din hotspot>.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Awaitable, Callable

SESSION_TIMEOUT = 8.0  # secunde; nmap -sV așteaptă bannerul ~6 s pe probe-ul NULL
MAX_BYTES = 4096  # după atât închidem, oricum nu folosim datele
MAX_CONNECTIONS = 20
READ_CHUNK = 512

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def read_lines(reader: asyncio.StreamReader, budget: list[int]):
    """Generează câte un eveniment pentru fiecare rând primit (fără conținut).

    Conținutul e aruncat imediat: generatorul dă doar `None` la fiecare rând,
    ca să nu existe nicio cale prin care datele clientului să ajungă mai departe.
    """
    pending = 0
    while True:
        chunk = await reader.read(READ_CHUNK)
        if not chunk:
            return
        budget[0] -= len(chunk)
        if budget[0] < 0:
            return
        pending += chunk.count(b"\n")
        del chunk
        while pending:
            pending -= 1
            yield None


def _wrap(handler: Handler, sem: asyncio.Semaphore) -> Handler:
    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if sem.locked():
            writer.close()
            return
        async with sem:
            try:
                await asyncio.wait_for(handler(reader, writer), SESSION_TIMEOUT)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

    return on_connect


async def start(handler: Handler, host: str, port: int) -> asyncio.base_events.Server:
    sem = asyncio.Semaphore(MAX_CONNECTIONS)
    return await asyncio.start_server(_wrap(handler, sem), host, port, reuse_address=True)


def main(name: str, handler: Handler, default_port: int) -> None:
    parser = argparse.ArgumentParser(description=f"{name} fals pentru lab (simulăm, nu expunem)")
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="IP-ul pe care ascultă. Implicit 127.0.0.1. În lab: IP-ul laptopului-țintă din hotspot.",
    )
    parser.add_argument("--port", type=int, default=default_port)
    args = parser.parse_args()
    if args.port < 1024:
        parser.error("folosește un port peste 1024 (rulăm ca utilizator normal, fără admin)")

    async def run() -> None:
        server = await start(handler, args.bind, args.port)
        print(f"{name} fals ascultă pe {args.bind}:{args.port}. Ctrl+C ca să-l oprești.", flush=True)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print(f"\n{name} fals oprit.")
