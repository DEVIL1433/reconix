"""Automated tests for the 3.31 checks: third-party Subresource
Integrity (passive) and XPath injection (error-based + boolean
differential, with control guards).

Each test spins a small purpose-built stub server on an ephemeral
port. Run:  python3 -m unittest discover -s tests -v
"""
import os
import re
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import checks, passive  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings  # noqa: E402
from wscan.engine import Ctx  # noqa: E402


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="text/html"):
    data = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _ctx(base, opts=None):
    F = Findings()
    return Ctx(Client(), F, None, base, opts or {}, lambda m: None), F


# ------------------------------------------------------- SRI (passive)

_SRI_PAGE = """<html><head>
<script src="https://cdn.example.com/lib.js"></script>
<script src="https://cdn.example.com/good.js"
 integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
 crossorigin="anonymous"></script>
<script src="https://cdn.example.com/nocors.js"
 integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>
<script src="https://cdn.example.com/bad.js" integrity="md5-abc"></script>
<link rel="stylesheet" href="https://fonts.example.com/style.css">
<script src="/static/app.js"></script>
</head><body>ok</body></html>"""

_SRI_CLEAN_PAGE = """<html><head>
<script src="https://cdn.example.com/good.js"
 integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
 crossorigin="anonymous"></script>
<script src="/static/app.js"></script>
</head><body>ok</body></html>"""


def _sri_handler(page):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            _send(self, 200, page)

        def log_message(self, *a):
            pass

    return H


class TestSRI(unittest.TestCase):
    def test_missing_invalid_and_nocors_flagged(self):
        _srv, base = _serve(_sri_handler(_SRI_PAGE))
        ctx, F = _ctx(base)
        r = ctx.client.fetch(base + "/")
        passive.third_party_integrity_scan(ctx, [(base + "/", r)])
        titles = sorted(f["title"] for f in F.items)
        self.assertIn("Third-Party Script Without Subresource Integrity",
                      titles)
        self.assertIn("Third-Party Stylesheet Without Subresource Integrity",
                      titles)
        self.assertIn("Invalid Subresource Integrity Value", titles)
        self.assertIn("Subresource Integrity Ignored: Missing crossorigin",
                      titles)
        # the good SRI script and the same-origin script must not flag
        self.assertEqual(len(F.items), 4)
        self.assertTrue(all(f["cwe"] == "CWE-829" for f in F.items))
        # same asset on a second page must not double-report
        passive.third_party_integrity_scan(ctx, [(base + "/other", r)])
        self.assertEqual(len(F.items), 4)

    def test_clean_page_no_finding(self):
        _srv, base = _serve(_sri_handler(_SRI_CLEAN_PAGE))
        ctx, F = _ctx(base)
        r = ctx.client.fetch(base + "/")
        passive.third_party_integrity_scan(ctx, [(base + "/", r)])
        self.assertEqual(len(F.items), 0)


# ------------------------------------------------------- XPath injection

class _XpathHandler(BaseHTTPRequestHandler):
    """Simulates an app interpolating a param into an XPath query:
    //user[name='VALUE']. A lone quote breaks the query (parser
    error); ' or '1'='1 returns every user; ' or '1'='2' none."""

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = q.get("name", ["alice"])[0]
        if "' or '1'='1" in val:
            body = "<users><user>alice</user><user>bob</user><user>carol</user></users>"
        elif "' or '1'='2" in val:
            body = "<users></users>"
        elif "'" in val or '"' in val:
            body = "Warning: xpath: Invalid expression in query"
        elif val == "alice":
            body = "<users><user>alice</user></users>"
        else:
            body = "<users></users>"
        _send(self, 200, body, "application/xml")

    def log_message(self, *a):
        pass


class _XpathCleanHandler(BaseHTTPRequestHandler):
    """Ignores the param (or merely echoes it) — nothing must fire."""

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = q.get("name", ["alice"])[0]
        _send(self, 200, f"<html><body>search results for {val}</body></html>")

    def log_message(self, *a):
        pass


class _XpathNoisyHandler(BaseHTTPRequestHandler):
    """Prints an xpath error even for benign input — the control
    guard must suppress the error-based finding."""

    def do_GET(self):
        _send(self, 200, "Warning: xpath: Invalid expression in query")

    def log_message(self, *a):
        pass


class TestXPath(unittest.TestCase):
    def test_error_based(self):
        _srv, base = _serve(_XpathHandler)
        ctx, F = _ctx(base)
        checks.xpath_url(ctx, base + "/search?name=alice")
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"], "XPath Injection (error-based)")
        self.assertEqual(F.items[0]["cwe"], "CWE-643")
        self.assertEqual(F.items[0]["severity"], "High")

    def test_boolean_differential_without_error(self):
        # A backend that suppresses parser errors but still evaluates
        # the query: error probes return no error text, so the
        # boolean pair must carry the finding.
        class H(_XpathHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(self.path).query)
                val = q.get("name", ["alice"])[0]
                if "' or '1'='1" in val:
                    body = ("<users><user>alice</user><user>bob</user>"
                            "<user>carol</user></users>")
                elif "' or '1'='2" in val:
                    body = "<users></users>"
                elif val == "alice":
                    body = "<users><user>alice</user></users>"
                else:
                    body = "<users></users>"
                _send(self, 200, body, "application/xml")

        _srv, base = _serve(H)
        ctx, F = _ctx(base)
        checks.xpath_url(ctx, base + "/search?name=alice")
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"],
                         "XPath Injection (boolean-based blind)")
        self.assertEqual(F.items[0]["confidence"],
                         "Needs manual confirmation")

    def test_clean_app_no_finding(self):
        _srv, base = _serve(_XpathCleanHandler)
        ctx, F = _ctx(base)
        checks.xpath_url(ctx, base + "/search?name=alice")
        self.assertEqual(len(F.items), 0)

    def test_error_in_baseline_suppressed(self):
        _srv, base = _serve(_XpathNoisyHandler)
        ctx, F = _ctx(base)
        checks.xpath_url(ctx, base + "/search?name=alice")
        self.assertEqual(len(F.items), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
