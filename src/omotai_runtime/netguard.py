"""Forward proxy the browser is forced through. It sees every hop, including redirects.

page.route() is not consulted for redirect targets: the browser follows them on its own. So a
request to an allowed origin that answers 302 to a foreign origin would escape a route-only guard.
Here every hop is a fresh proxied request, judged by the same policy, and refused with 403.

Scope: plain HTTP is judged by method and URL; HTTPS (CONNECT) only by host and port, because the
tunnel is opaque (methods on HTTPS stay covered by page.route). One request per connection.
"""

import asyncio
from collections.abc import Callable
from urllib.parse import urlsplit

from omotai_runtime.policy import Decision

Decide = Callable[[str, str], Decision]  # (method, url) -> Decision; CONNECT arrives as GET
Report = Callable[[str, str, Decision], None]


class Proxy:
    def __init__(self, decide: Decide, report: Report):
        self.decide, self.report = decide, report
        self._server: asyncio.Server | None = None
        self.port = 0
        self._addrs: dict[tuple[str, int], str] = {}  # (host, port) -> address that worked

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _connect(self, host: str, port: int):
        """Open the upstream connection without paying for the wrong address family.

        `localhost` resolves to ::1 first. Where nothing listens on IPv6 (a container published on
        IPv4 only) the refused connect takes about 2 s on Windows, and every proxied request paid
        it: a page of 40 resources kept Chromium's 6 sockets busy for ~20 s. Race the families
        (Happy Eyeballs) and remember the address that worked. Policy is decided on the host name
        in the URL, never on the address, so this changes nothing about what is allowed.
        """
        key = (host, port)
        if cached := self._addrs.get(key):
            try:
                return await asyncio.open_connection(cached, port)
            except OSError:
                del self._addrs[key]  # stale: resolve again
        reader, writer = await asyncio.open_connection(host, port, happy_eyeballs_delay=0.25)
        self._addrs[key] = writer.get_extra_info("peername")[0]
        return reader, writer

    async def _refuse(self, writer, method: str, url: str, d: Decision) -> None:
        self.report(method, url, d)
        writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line, *headers = head.decode("latin-1").split("\r\n")[:-2]
            method, target, version = line.split(" ", 2)
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
                url, upstream_head = f"https://{target}", None
            else:
                parts = urlsplit(target)
                host, port = parts.hostname or "", str(parts.port or 80)
                path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                url = target
                kept = [
                    h
                    for h in headers
                    if h.split(":")[0].lower() not in ("proxy-connection", "connection")
                ]
                upstream_head = "\r\n".join(
                    [f"{method} {path} {version}", *kept, "Connection: close", "", ""]
                )
            d = self.decide("GET" if method == "CONNECT" else method, url)
            if not d.allowed:
                return await self._refuse(writer, method, url, d)
            up_reader, up_writer = await self._connect(host, int(port))
            if upstream_head is None:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                up_writer.write(upstream_head.encode("latin-1"))
            pipes = [
                asyncio.create_task(_pipe(reader, up_writer)),
                asyncio.create_task(_pipe(up_reader, writer)),
            ]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
            for t in pipes:
                t.cancel()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, OSError):
            pass
        finally:
            writer.close()


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()
    except OSError:
        pass
    finally:
        dst.close()
