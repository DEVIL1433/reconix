"""Automated tests for Reconix permission-matrix (role-matrix) scanning:
admin-area access for non-admins, API data without authentication,
restricted pages without authentication, plus the matrix section in
the PDF report.

Each test spins a small purpose-built stub server on an ephemeral
port. Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import matrix  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings  # noqa: E402
from wscan.engine import Ctx  # noqa: E402
from wscan.report3 import to_pdf  # noqa: E402


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="text/html", extra=None):
    data = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    for k, v in (extra or {}).items():
        h.send_header(k, v)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _ctx(base, opts=None):
    F = Findings()
    return Ctx(Client(), F, None, base, opts or {}, lambda m: None), F


_ADMIN_BODY = ("Admin panel. User management. All users, roles and "
               "permissions, audit log and site settings. " * 3)
_ACCOUNT_BODY = ("Your account dashboard. Logout. Orders: order 51 shipped, "
                 "order 52 delivered. Payment method on file: card ending "
                 "4242. Address: 12 Palm Street, Springfield.")
_API_BODY = ('{"user": "alice", "email": "alice@example.com", "orders": '
             '["order 51 shipped", "order 52 delivered", "order 53 '
             'processing"], "payment": "card ending 4242", "address": '
             '"12 Palm Street, Springfield", "member_since": "2021"}')


class _MatrixHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        is_admin = "session=admin" in cookie
        is_user = "session=user" in cookie
        if self.path == "/manage/users":
            if is_admin or is_user:
                return _send(self, 200, _ADMIN_BODY)
            return _send(self, 403, "forbidden")
        if self.path == "/manage/secret":
            if is_admin:
                return _send(self, 200, _ADMIN_BODY)
            return _send(self, 403, "forbidden")
        if self.path == "/api/me":
            return _send(self, 200, _API_BODY, ctype="application/json")
        if self.path == "/api/private":
            if is_user:
                return _send(self, 200, _API_BODY, ctype="application/json")
            return _send(self, 401, "please sign in")
        if self.path == "/account":
            return _send(self, 200, _ACCOUNT_BODY)
        if self.path == "/public":
            return _send(self, 200, "Welcome to our public page. News and "
                                    "updates for everyone, no login needed.")
        return _send(self, 404, "not found")


class TestMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_MatrixHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _titles(self, ctx, F, url):
        primary = ctx.client.fetch(url)
        matrix.build(ctx, [(url, primary)])
        return [f["title"] for f in F.items]

    def test_admin_area_non_admin_path(self):
        # /manage is an admin area even though it is not /admin.
        ctx, F = _ctx(self.base, {"cookie_admin": "session=admin"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/manage/users")
        self.assertIn("Admin Page Accessible to Non-Admin Session", titles)

    def test_admin_area_enforced(self):
        ctx, F = _ctx(self.base, {"cookie_admin": "session=admin"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/manage/secret")
        self.assertNotIn("Admin Page Accessible to Non-Admin Session",
                         titles)

    def test_api_data_without_auth(self):
        ctx, F = _ctx(self.base, {"cookie": "session=user"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/api/me")
        self.assertIn("API Data Accessible Without Authentication", titles)

    def test_api_data_enforced(self):
        ctx, F = _ctx(self.base, {"cookie": "session=user"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/api/private")
        self.assertNotIn("API Data Accessible Without Authentication",
                         titles)

    def test_restricted_page_anon(self):
        ctx, F = _ctx(self.base, {"cookie": "session=user"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/account")
        self.assertIn("Restricted Page Accessible Without Authentication",
                      titles)

    def test_public_page_no_finding(self):
        ctx, F = _ctx(self.base, {"cookie": "session=user",
                                   "cookie_admin": "session=admin"})
        ctx.client = Client(cookie="session=user")
        titles = self._titles(ctx, F, self.base + "/public")
        for t in ("Admin Page Accessible to Non-Admin Session",
                  "API Data Accessible Without Authentication",
                  "Restricted Page Accessible Without Authentication",
                  "User Data Accessible to Another User (BOLA)"):
            self.assertNotIn(t, titles)


class TestMatrixPdf(unittest.TestCase):
    def _result(self, mx):
        return {"target": "http://example.test", "findings": [],
                "counts": {}, "permission_matrix": mx}

    def test_pdf_includes_matrix(self):
        mx = [{"url": "http://example.test/manage/users",
               "results": {"anonymous": {"status": 403, "length": 9},
                           "primary": {"status": 200, "length": 270},
                           "admin": {"status": 200, "length": 270}}}]
        text = to_pdf(self._result(mx)).decode("latin-1", errors="replace")
        self.assertIn("Permission matrix", text)
        self.assertIn("/manage/users", text)

    def test_pdf_omits_empty_matrix(self):
        text = to_pdf(self._result([])).decode("latin-1", errors="replace")
        self.assertNotIn("Permission matrix", text)


if __name__ == "__main__":
    unittest.main()
