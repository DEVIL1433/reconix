"""Automated tests for the 3.12 VAPT Automation Pack:
auto-proof (SQLi data extraction), attack chaining, business-logic
workflow attacks, permission-matrix BOLA, WAF-adaptive client.

Each test spins a small purpose-built stub server on an ephemeral
port. Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sqlite3
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import bizlogic, chains, har as har_mod, matrix, proof  # noqa: E402
from wscan.client import Client                                     # noqa: E402
from wscan.core import Findings                                     # noqa: E402
from wscan.engine import Ctx                                        # noqa: E402


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


# ------------------------------------------------------------- auto-proof

class _SqliHandler(BaseHTTPRequestHandler):
    db = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        code = (q.get("code") or [""])[0]
        sql = f"SELECT label FROM items WHERE code='{code}'"
        try:
            rows = self.db.execute(sql).fetchall()
        except Exception as e:
            rows = []
            return _send(self, 200, f"error near: {e}")
        if rows:
            return _send(self, 200, "FOUND: " + ", ".join(r[0] for r in rows))
        return _send(self, 200, "no results for that code")


class TestProofSqli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _SqliHandler.db = sqlite3.connect(":memory:",
                                          check_same_thread=False)
        _SqliHandler.db.execute(
            "CREATE TABLE items (code TEXT, label TEXT)")
        _SqliHandler.db.execute(
            "INSERT INTO items VALUES ('abc', 'widget')")
        cls.srv, cls.base = _serve(_SqliHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_extracts_first_table_name(self):
        ctx, F = _ctx(self.base)
        url = self.base + "/item?code=abc"
        f = F.add("High", "SQL Injection (boolean-based blind)", url,
                  "boolean differential", param="code",
                  proof="similarity base/TRUE=1.00 | DBMS fingerprinted: "
                        "SQLite",
                  resp=None, cwe="CWE-89")
        data = proof.prove_sqli(ctx, f)
        self.assertEqual(data, "items")
        proven = proof.prove(ctx)
        self.assertEqual(proven, 1)
        self.assertTrue(f["proof_verified"])
        self.assertEqual(f["proof_data"], "items")


# ------------------------------------------------------------- chains

class TestChains(unittest.TestCase):
    def test_xss_plus_httponly_chains(self):
        ctx, F = _ctx("http://t.local")
        F.add("High", "Cross-Site Scripting (reflected)",
              "http://t.local/x?q=1", "d", proof="p", param="q", resp=None)
        F.add("Low", "Cookie Missing HttpOnly", "http://t.local/", "d",
              proof="p", resp=None)
        made = chains.correlate(ctx)
        self.assertTrue(any("Attack Chain: XSS" in f["title"]
                            for f in made))
        self.assertTrue(all(f.get("is_chain") for f in made))

    def test_cors_plus_idor_chains_critical(self):
        ctx, F = _ctx("http://t.local")
        F.add("High", "Cross-Origin Resource Sharing (CORS) "
              "Misconfiguration", "http://t.local/api", "d",
              proof="ACAO reflects https://evil.example; ACAC=true",
              resp=None)
        F.add("High", "Possible IDOR / Broken Access Control",
              "http://t.local/api/orders?id=5", "d", proof="p",
              param="id", resp=None)
        made = chains.correlate(ctx)
        self.assertTrue(any(f["severity"] == "Critical"
                            and "Attack Chain" in f["title"] for f in made))

    def test_single_finding_no_chain(self):
        ctx, F = _ctx("http://t.local")
        F.add("High", "Cross-Site Scripting (reflected)",
              "http://t.local/x?q=1", "d", proof="p", param="q", resp=None)
        self.assertEqual(chains.correlate(ctx), [])


# ------------------------------------------------------------- bizlogic

class _FlowHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _params(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        return dict(urllib.parse.parse_qsl(raw))

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        self._params()
        cookie = self.headers.get("Cookie") or ""
        if path == "/step/cart":
            return _send(self, 200, "cart ok",
                         extra={"Set-Cookie": "flow=1; Path=/"})
        if path == "/step/pay":
            if "flow=1" in cookie or "flow=2" in cookie:
                return _send(self, 200, "payment ok",
                             extra={"Set-Cookie": "flow=2; Path=/"})
            return _send(self, 403, "invalid order state")
        if path == "/step/confirm":
            # vulnerable on purpose: no state check at all
            return _send(self, 200, "ORDER CONFIRMED")
        if path == "/redeem":
            # vulnerable on purpose: coupon works every time
            return _send(self, 200, "coupon applied 10 percent off")
        return _send(self, 404, "not here")


def _har(steps):
    entries = []
    for method, url, params, status, body in steps:
        entries.append({
            "request": {"method": method, "url": url,
                        "postData": {
                            "mimeType":
                                "application/x-www-form-urlencoded",
                            "params": [{"name": k, "value": v}
                                       for k, v in params.items()]}},
            "response": {"status": status,
                         "content": {"text": body}}})
    return json.dumps({"log": {"entries": entries}})


class TestBizlogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_FlowHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_skip_replay_tamper(self):
        har_text = _har([
            ("POST", self.base + "/step/cart", {"item": "book"},
             200, "cart ok"),
            ("POST", self.base + "/redeem", {"coupon": "DIWALI10"},
             200, "coupon applied 10 percent off"),
            ("POST", self.base + "/step/pay", {"amount": "500"},
             200, "payment ok"),
            ("POST", self.base + "/step/confirm", {"addr": "home"},
             200, "ORDER CONFIRMED"),
        ])
        steps = har_mod.parse_har_steps(har_text)
        self.assertEqual(len(steps), 4)
        ctx, F = _ctx(self.base)
        # prime the session the way the recorded user had: cart first
        ctx.client.fetch(self.base + "/step/cart", method="POST",
                         data={"item": "book"})
        made = bizlogic.run(ctx, steps)
        titles = [f["title"] for f in F.items]
        self.assertIn("Business Logic: Workflow Step Can Be Skipped",
                      titles)
        self.assertIn("Business Logic: One-Time Step Is Replayable",
                      titles)
        self.assertIn("Business Logic: Price/Quantity Tampering "
                      "Accepted", titles)
        self.assertGreaterEqual(made, 3)


# ------------------------------------------------------------- matrix BOLA

_ACCOUNT = ("Your account dashboard. Logout. Orders: order 51 shipped, "
            "order 52 delivered, order 53 processing. Payment method on "
            "file: card ending 4242. Address: 12 Palm Street.")


class _AccountHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        if "user=" in cookie:
            # vulnerable on purpose: same private page for every user
            return _send(self, 200, _ACCOUNT)
        return _send(self, 401, "please sign in")


class TestMatrixBola(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_AccountHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_second_user_reads_owner_data(self):
        url = self.base + "/account?id=7"
        ctx, F = _ctx(self.base, {"cookie": "user=alice"})
        ctx.client = Client(cookie="user=alice")
        ctx.client_b = Client(cookie="user=bob")
        primary = ctx.client.fetch(url)
        matrix.build(ctx, [(url, primary)])
        titles = [f["title"] for f in F.items]
        self.assertIn("User Data Accessible to Another User (BOLA)",
                      titles)


# ------------------------------------------------------------- WAF client

class _WafHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if "john%2520doe" in self.path:
            return _send(self, 200, "hello john doe profile page")
        if "john%20doe" in self.path or "%27" in self.path:
            return _send(self, 403,
                         "Request blocked by web application firewall "
                         "(incident id 42)")
        return _send(self, 200, "other page")


class TestWafAdaptiveClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_WafHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_benign_blocked_request_evades(self):
        c = Client()
        c.adaptive = True
        r = c.fetch(self.base + "/page?name=john%20doe")
        self.assertEqual(r.status, 200)
        self.assertIn("hello", r.body)
        self.assertTrue(c.waf_mode)

    def test_attack_probe_returned_as_answered(self):
        c = Client()
        c.adaptive = True
        r = c.fetch(self.base + "/page?name=x%27%20OR%201%3D1")
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
