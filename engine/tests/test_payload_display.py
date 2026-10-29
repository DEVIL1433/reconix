"""Automated tests for the Reconix payload display: every injection
finding records the exact payload used, and the payload shows up in
the PDF report and the CSV export.

Each live test spins a small purpose-built stub server on an ephemeral
port. Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import checks  # noqa: E402
from wscan.browser import _probe_payload  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings, with_param  # noqa: E402
from wscan.engine import Ctx  # noqa: E402
from wscan.report3 import to_csv, to_pdf  # noqa: E402


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


class _PayloadHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = (q.get("q") or [""])[0]
        if self.path.startswith("/search"):
            # reflects the input unescaped, like a vulnerable search box
            return _send(self, 200,
                         f"<html><body>results for {val}</body></html>")
        if self.path.startswith("/item"):
            if "'" in val:
                return _send(self, 200, "You have an error in your SQL "
                                        "syntax; check the manual")
            return _send(self, 200, "ok item")
        return _send(self, 404, "not found")


class TestPayloadField(unittest.TestCase):
    def test_findings_store_payload(self):
        F = Findings()
        f = F.add("High", "T", "http://x/", "d", payload="P1")
        self.assertEqual(f["payload"], "P1")
        f2 = F.add("Low", "T2", "http://x/2", "d")
        self.assertEqual(f2["payload"], "")

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_PayloadHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_xss_url_records_payload(self):
        ctx, F = _ctx(self.base)
        checks.xss_url(ctx, self.base + "/search?q=test")
        hits = [f for f in F.items
                if f["title"] == "Cross-Site Scripting (reflected)"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["param"], "q")
        self.assertEqual(hits[0]["payload"], checks.XSS_PAYLOADS[0])

    def test_sqli_error_records_payload(self):
        ctx, F = _ctx(self.base)
        checks.sqli_url(ctx, self.base + "/item?q=test")
        hits = [f for f in F.items
                if f["title"] == "SQL Injection (error-based)"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["param"], "q")
        self.assertEqual(hits[0]["payload"], "test'")

    def test_browser_probe_payload_helper(self):
        pl = 'wscan"><svg onload=alert(1)>'
        url = with_param("http://x/search?q=test", "q", pl)
        self.assertEqual(_probe_payload(url, "q"), pl)
        frag = "http://x/page#<svg onload=alert(1)>"
        self.assertEqual(_probe_payload(frag, "(fragment)"),
                         "#<svg onload=alert(1)>")


class TestPayloadReports(unittest.TestCase):
    def _finding(self):
        return {"severity": "High", "title": "Cross-Site Scripting",
                "confidence": "Confirmed",
                "cwe": "CWE-79", "url": "http://x/search", "param": "q",
                "detail": "d", "proof": "p", "remediation": "fix",
                "payload": "PAYLOAD-123"}

    def test_pdf_includes_payload(self):
        result = {"target": "http://x", "findings": [self._finding()],
                  "counts": {"High": 1}}
        text = to_pdf(result).decode("latin-1", errors="replace")
        self.assertIn("Payload: PAYLOAD-123", text)

    def test_csv_includes_payload(self):
        out = to_csv([self._finding()])
        lines = out.strip().splitlines()
        self.assertTrue(lines[0].endswith("payload"))
        self.assertIn("PAYLOAD-123", lines[1])


if __name__ == "__main__":
    unittest.main()
