"""Automated tests for the 3.21 fifth-wave checks: JavaScript prototype
pollution (server-side merge + browser DOM proof) and insecure
deserialization (marker reflection + deserializer error text).

Each test spins a small purpose-built stub server on an ephemeral
port. Run:  python3 -m unittest discover -s tests -v
"""
import base64
import json
import os
import pickle
import re
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import checks5  # noqa: E402
from wscan.browser import available as browser_available  # noqa: E402
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


# ------------------------------------------------------------- deserialization

class _DeserPhpHandler(BaseHTTPRequestHandler):
    """Simulates a PHP app that unserializes a param and echoes the
    resulting object's marker property back in the response."""

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = q.get("data", [""])[0]
        m = re.search(r's:12:"reconixmark";s:\d+:"([^"]+)"', val)
        if val.startswith("O:") and m:
            _send(self, 200, '{"reconixmark": "%s"}' % m.group(1),
                  "application/json")
        else:
            _send(self, 200, "<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


class _DeserJavaHandler(BaseHTTPRequestHandler):
    """Simulates a Java app that feeds a param to ObjectInputStream
    and answers with the stream error."""

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = q.get("data", [""])[0]
        try:
            raw = base64.b64decode(val)
        except Exception:
            raw = b""
        if raw.startswith(b"\xac\xed"):
            _send(self, 200, "java.io.StreamCorruptedException: "
                             "invalid stream header")
        else:
            _send(self, 200, "<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


class _DeserPickleHandler(BaseHTTPRequestHandler):
    """Simulates a Python app that unpickles a param and echoes the
    resulting dict's marker. Only unpickles payloads the test itself
    generated (benign dicts)."""

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        val = q.get("data", [""])[0]
        try:
            obj = pickle.loads(base64.b64decode(val))
        except Exception:
            obj = None
        if isinstance(obj, dict) and "reconixmark" in obj:
            _send(self, 200, '{"reconixmark": "%s"}' % obj["reconixmark"],
                  "application/json")
        else:
            _send(self, 200, "<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


class _DeserCleanHandler(BaseHTTPRequestHandler):
    """Ignores params entirely — nothing must be reported."""

    def do_GET(self):
        _send(self, 200, "<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


class _DeserNoisyControlHandler(BaseHTTPRequestHandler):
    """Shows a deserializer error even for benign input — the control
    guard must suppress the finding."""

    def do_GET(self):
        _send(self, 200, "java.io.StreamCorruptedException: "
                         "invalid stream header")

    def log_message(self, *a):
        pass


class TestDeser(unittest.TestCase):
    def test_php_marker_reflection(self):
        _srv, base = _serve(_DeserPhpHandler)
        ctx, F = _ctx(base)
        checks5.deser_url(ctx, base + "/view?data=hello")
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"], "Insecure Deserialization")
        self.assertEqual(F.items[0]["cwe"], "CWE-502")
        self.assertEqual(F.items[0]["severity"], "Critical")

    def test_java_error_text(self):
        _srv, base = _serve(_DeserJavaHandler)
        ctx, F = _ctx(base)
        checks5.deser_url(ctx, base + "/view?data=hello")
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"], "Insecure Deserialization")
        self.assertIn("StreamCorruptedException", F.items[0]["proof"])

    def test_pickle_marker_reflection(self):
        _srv, base = _serve(_DeserPickleHandler)
        ctx, F = _ctx(base)
        checks5.deser_url(ctx, base + "/view?data=hello")
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["cwe"], "CWE-502")

    def test_clean_app_no_finding(self):
        _srv, base = _serve(_DeserCleanHandler)
        ctx, F = _ctx(base)
        checks5.deser_url(ctx, base + "/view?data=hello")
        self.assertEqual(len(F.items), 0)

    def test_error_in_control_suppressed(self):
        _srv, base = _serve(_DeserNoisyControlHandler)
        ctx, F = _ctx(base)
        checks5.deser_url(ctx, base + "/view?data=hello")
        self.assertEqual(len(F.items), 0)


# ------------------------------------------------------- prototype pollution

class _PpJsonHandler(BaseHTTPRequestHandler):
    """Simulates a Node-style API: POSTed JSON is deep-merged into a
    shared object, and GET serializes a fresh object — so a polluted
    prototype shows up in fresh serializations, exactly like the real
    vulnerability's observable behavior."""
    prototype = {}

    def do_GET(self):
        merged = dict(self.prototype)
        merged["normal"] = 1
        _send(self, 200, json.dumps(merged), "application/json")

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        try:
            obj = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            obj = {}
        proto = obj.get("__proto__")
        if isinstance(proto, dict):
            self.prototype.update(proto)
        _send(self, 200, json.dumps({"ok": True}), "application/json")

    def log_message(self, *a):
        pass


class _PpQueryHandler(BaseHTTPRequestHandler):
    """Simulates a qs-style query parser + vulnerable merge: a
    __proto__ query parameter pollutes the shared prototype, and GET
    serializes a fresh object carrying the polluted key."""
    prototype = {}

    def do_GET(self):
        q = urllib.parse.urlsplit(self.path).query
        m = re.search(r"__proto__\[reconixpp\]=([^&]+)", q)
        if m:
            self.prototype["reconixpp"] = urllib.parse.unquote(m.group(1))
        merged = dict(self.prototype)
        merged["normal"] = 1
        _send(self, 200, json.dumps(merged), "application/json")

    def log_message(self, *a):
        pass


_PP_PAGE = """<html><head><script>
function merge(dst, src) {
  for (const k in src) {
    if (src[k] && typeof src[k] === 'object') {
      if (!dst[k]) dst[k] = {};
      merge(dst[k], src[k]);
    } else dst[k] = src[k];
  }
}
function parseKey(key, val) {
  const parts = key.replace(/\\]/g, '').split('[');
  let o = {}, cur = o;
  parts.forEach((p, i) => {
    if (i === parts.length - 1) cur[p] = val;
    else { cur[p] = {}; cur = cur[p]; }
  });
  return o;
}
const out = {};
for (const [k, v] of new URLSearchParams(location.search))
  merge(out, parseKey(k, v));
</script></head><body>ok</body></html>"""


class _PpBrowserHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _send(self, 200, _PP_PAGE)

    def log_message(self, *a):
        pass


class _PpCleanPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _send(self, 200, "<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


class TestProtoPollution(unittest.TestCase):
    def setUp(self):
        _PpJsonHandler.prototype = {}
        _PpQueryHandler.prototype = {}

    def test_server_side_json_merge(self):
        _srv, base = _serve(_PpJsonHandler)
        ctx, F = _ctx(base)
        checks5.protopollution_check(ctx, [(base + "/api/data", None)])
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"],
                         "JavaScript Prototype Pollution")
        self.assertEqual(F.items[0]["severity"], "Critical")
        self.assertEqual(F.items[0]["cwe"], "CWE-1321")

    def test_server_side_query_merge(self):
        _srv, base = _serve(_PpQueryHandler)
        ctx, F = _ctx(base)
        checks5.protopollution_check(ctx, [(base + "/api/data", None)])
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["severity"], "Critical")

    @unittest.skipUnless(browser_available(),
                         "Playwright/Chromium not installed")
    def test_browser_dom_proof(self):
        _srv, base = _serve(_PpBrowserHandler)
        ctx, F = _ctx(base)
        checks5.protopollution_check(ctx, [(base + "/page", None)])
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"],
                         "JavaScript Prototype Pollution")
        self.assertEqual(F.items[0]["severity"], "High")

    @unittest.skipUnless(browser_available(),
                         "Playwright/Chromium not installed")
    def test_browser_clean_page_no_finding(self):
        _srv, base = _serve(_PpCleanPageHandler)
        ctx, F = _ctx(base)
        checks5.protopollution_check(ctx, [(base + "/page", None)])
        self.assertEqual(len(F.items), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
