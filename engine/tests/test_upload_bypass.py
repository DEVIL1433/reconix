"""Automated tests for Reconix file-upload execution checks: the plain .php
and double-extension paths plus the .php5 / .phtml / uppercase-.PHP,
content-type and magic-byte bypass variants. Each test spins a small stub
upload server on an ephemeral port. The stub "executes" an uploaded file
only when its extension is in the test's executable set, returning the
computed marker WS51317; otherwise it serves the raw content.
Run:  python3 -m unittest discover -s tests -v
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
from wscan import checks  # noqa: E402
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


def _handler_for(executable, policy="all"):
    """policy: "all" stores every upload; "image_ct" stores only parts
    declared as image/*; "gif_magic" stores only parts starting with GIF89a.
    """
    class H(BaseHTTPRequestHandler):
        store = {}

        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            m = re.search(rb'filename="([^"]+)"\r\nContent-Type: ([^\r\n]+)\r\n\r\n(.*)\r\n--',
                          raw, re.S)
            if m:
                name = m.group(1).decode()
                ctype = m.group(2).decode()
                content = m.group(3)
                if policy == "image_ct" and not ctype.startswith("image/"):
                    pass
                elif policy == "gif_magic" and not content.startswith(b"GIF89a"):
                    pass
                else:
                    H.store[name] = content
            _send(self, 200, "ok")

        def do_GET(self):
            name = urllib.parse.urlsplit(self.path).path.rsplit("/", 1)[-1]
            if name not in H.store:
                _send(self, 404, "not found")
                return
            content = H.store[name]
            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            if ext in executable or (name.endswith(".php.txt")
                                    and "php.txt" in executable):
                _send(self, 200, "WS51317", "text/plain")
            else:
                _send(self, 200, content.decode("latin-1"), "text/plain")

    return H


def _run(executable, policy="all"):
    srv, base = _serve(_handler_for(executable, policy))
    try:
        F = Findings()
        ctx = Ctx(Client(), F, None, base, {}, lambda m: None)
        form = {"inputs": [{"name": "f", "type": "file"}], "action": "/upload"}
        checks.upload_check(ctx, base + "/", form)
        return F.items
    finally:
        srv.shutdown()
        srv.server_close()


def _titles(items, severity=None):
    return [f["title"] for f in items
            if severity is None or f["severity"] == severity]


class UploadBypassTests(unittest.TestCase):
    def test_plain_php_still_caught(self):
        items = _run({"php"})
        crit = _titles(items, "Critical")
        self.assertEqual(crit, ["File Upload — Remote Code Execution"])

    def test_php5_variant(self):
        items = _run({"php5"})
        crit = _titles(items, "Critical")
        self.assertEqual(crit, ["File Upload — Remote Code Execution (.php5)"])

    def test_phtml_variant(self):
        items = _run({"phtml"})
        crit = _titles(items, "Critical")
        self.assertEqual(crit, ["File Upload — Remote Code Execution (.phtml)"])

    def test_uppercase_variant(self):
        items = _run({"PHP"})
        crit = _titles(items, "Critical")
        self.assertEqual(
            crit, ["File Upload — Remote Code Execution (uppercase extension)"])

    def test_double_ext_skips_variants(self):
        # Double-extension RCE already proves the hole; variant uploads
        # must not add noise findings after it.
        items = _run({"php.txt", "php5"})
        crit = _titles(items, "Critical")
        self.assertEqual(
            crit, ["File Upload — Remote Code Execution (double ext)"])

    def test_content_type_bypass(self):
        # Server checks the declared MIME type, not the extension: only the
        # .php part declared as image/jpeg is stored and executed.
        items = _run({"php"}, policy="image_ct")
        crit = _titles(items, "Critical")
        self.assertEqual(
            crit, ["File Upload — Remote Code Execution (content-type bypass)"])

    def test_magic_byte_bypass(self):
        # Server checks the file signature: only the GIF89a-headed .php part
        # is stored and executed.
        items = _run({"php"}, policy="gif_magic")
        crit = _titles(items, "Critical")
        self.assertEqual(
            crit, ["File Upload — Remote Code Execution (magic-byte bypass)"])

    def test_nothing_executes_no_critical(self):
        # Files stored web-accessible but never executed: only the Medium
        # storage finding, no RCE claim.
        items = _run(set())
        self.assertEqual(_titles(items, "Critical"), [])
        self.assertIn("File Upload — unrestricted file stored web-accessible",
                      _titles(items, "Medium"))


if __name__ == "__main__":
    unittest.main()
