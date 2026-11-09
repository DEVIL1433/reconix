"""Tests for the 4.3 weekly-improvement checks: mass assignment (BOPLA) in
wscan/api_scan.py and IBM/OpenStack cloud-metadata SSRF probes in
wscan/checks.py.

No live external scans: both checks run against localhost stub servers,
exactly like the existing tests. Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import threading
import types
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import api_scan as api_mod  # noqa: E402
from wscan import checks as checks_mod  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings  # noqa: E402
from wscan.engine import Ctx  # noqa: E402


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="application/json"):
    data = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _ctx(base, oob=None):
    F = Findings()
    return Ctx(Client(), F, oob, base, {}, lambda m: None), F


# =============================================================== mass assignment

class _MassAssignHandler(BaseHTTPRequestHandler):
    """Three write endpoints sharing one store each:
    /api/users        vulnerable: stores every JSON field it receives.
    /api/strict-users strict: stores only the declared name/email fields.
    /api/echo-users   echo-only: returns the body verbatim, stores nothing.
    GET on each returns the stored list ([] for the echo endpoint).
    Bodies with only declared fields get a fixed {"ok": true} reply so the
    SQLi/NoSQL probes in fuzz_endpoints see identical responses."""
    store = {}
    allowed = {"name", "email"}

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/api/users", "/api/strict-users", "/api/echo-users"):
            key = path.rsplit("/", 1)[-1]
            _send(self, 200, json.dumps(self.store.get(key, [])))
        else:
            _send(self, 404, json.dumps({"error": "not found"}))

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        body = self._read_json()
        if path == "/api/users":
            key = "users"
            if set(body) <= self.allowed:
                _send(self, 201, json.dumps({"ok": True}))
            else:
                self.store.setdefault(key, []).append(dict(body))
                _send(self, 201, json.dumps(dict(body)))
        elif path == "/api/strict-users":
            key = "strict-users"
            stored = {k: v for k, v in body.items() if k in self.allowed}
            if set(body) <= self.allowed:
                _send(self, 201, json.dumps({"ok": True}))
            else:
                self.store.setdefault(key, []).append(stored)
                _send(self, 201, json.dumps(stored))
        elif path == "/api/echo-users":
            _send(self, 201, json.dumps(dict(body)))
        else:
            _send(self, 404, json.dumps({"error": "not found"}))

    def log_message(self, *a):
        pass


def _api_ep(base, path, fields):
    return {"method": "POST", "url": base + path, "params": [],
            "param_schemas": {}, "json_fields": fields,
            "field_schemas": {f: {"type": "string"} for f in fields}}


class TestMassAssignment(unittest.TestCase):
    def setUp(self):
        _MassAssignHandler.store = {}
        self.srv, self.base = _serve(_MassAssignHandler)

    def tearDown(self):
        self.srv.shutdown()

    def _run(self, path, fields):
        ctx, F = _ctx(self.base)
        api_mod.fuzz_endpoints(ctx, [_api_ep(self.base, path, fields)])
        return F

    def test_vulnerable_endpoint_reports_mass_assignment(self):
        F = self._run("/api/users", ["name", "email"])
        mass = [f for f in F.items
                if f["title"] == "Mass Assignment (stored undeclared field)"]
        self.assertEqual(len(mass), 1)
        f = mass[0]
        self.assertEqual(f["severity"], "High")
        self.assertEqual(f["param"], "role")
        self.assertEqual(f["cwe"], "CWE-915")
        self.assertIn("rxcanary-4d2a-admin", f["proof"])

    def test_strict_endpoint_no_finding(self):
        F = self._run("/api/strict-users", ["name", "email"])
        self.assertEqual(
            [f for f in F.items if "Mass Assignment" in f["title"]], [])

    def test_echo_only_endpoint_no_finding(self):
        # The write response echoes the canary, but the GET read-back never
        # shows it: echo is not storage, so no finding. This is the guard
        # that keeps the check proof-based.
        F = self._run("/api/echo-users", ["name", "email"])
        self.assertEqual(
            [f for f in F.items if "Mass Assignment" in f["title"]], [])

    def test_declared_fields_are_not_tried(self):
        # Every candidate field is in the schema, so the loop skips them
        # all even though the endpoint stores everything it receives.
        F = self._run("/api/users",
                      ["name", "email", "role", "is_admin", "price"])
        self.assertEqual(
            [f for f in F.items if "Mass Assignment" in f["title"]], [])

    def test_json_field_value_helper(self):
        self.assertEqual(api_mod._json_field_value('{"role": "x"}', "role"),
                         "x")
        self.assertEqual(
            api_mod._json_field_value('[{"role": "y"}]', "role"), "y")
        self.assertIs(api_mod._json_field_value('{"a": 1}', "role"),
                      api_mod._MISSING)
        self.assertIs(api_mod._json_field_value('not json', "role"),
                      api_mod._MISSING)
        self.assertIs(api_mod._json_field_value('[]', "role"),
                      api_mod._MISSING)


# =============================================================== cloud metadata SSRF

_AWS_BODY = ("ami-id\nami-0abc123\ninstance-id\ni-0abc123\n"
             "security-credentials\n")
_IBM_BODY = json.dumps({
    "id": "0787-1111-2222-3333",
    "crn": "crn:v1:bluemix:public:is:us-south:a/abc::instance:0787-1111",
    "name": "vm-1", "status": "running",
    "network_interfaces": [{"id": "nic-1", "primary_ipv4_address": "10.0.0.4"}],
})
_OS_BODY = json.dumps({
    "uuid": "74e3dc71-1acc-4a38-82dc-a268cf5f8f41",
    "availability_zone": "nova", "hostname": "vm-1.novalocal",
    "public_keys": {"k": "ssh-rsa AAAA"},
})


class _FetchHandler(BaseHTTPRequestHandler):
    """/fetch simulates a vulnerable app that fetches the URL in its
    `url` param and returns what it got; /safe never fetches."""
    aws_only = False

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(parts.query)
        target = (q.get("url") or [""])[0]
        if parts.path == "/fetch" and not self.aws_only:
            if "169.254.169.254/latest/meta-data/" in target:
                _send(self, 200, _AWS_BODY, "text/plain")
                return
            if "169.254.169.254/metadata/v1/instance" in target:
                _send(self, 200, _IBM_BODY)
                return
            if "169.254.169.254/openstack/latest/meta_data.json" in target:
                _send(self, 200, _OS_BODY)
                return
        if parts.path == "/fetch" and self.aws_only:
            if "169.254.169.254/latest/meta-data/" in target:
                _send(self, 200, _AWS_BODY, "text/plain")
                return
        _send(self, 200, "<html><body>generic page</body></html>",
              "text/html")

    def log_message(self, *a):
        pass


def _ssrf_ctx(base):
    fake_oob = types.SimpleNamespace(
        new_token=lambda: "ssrftest-token",
        url=lambda tok: "http://127.0.0.1:9/oob/" + tok)
    return _ctx(base, oob=fake_oob)


class TestCloudMetadataSsrf(unittest.TestCase):
    def setUp(self):
        _FetchHandler.aws_only = False
        self.srv, self.base = _serve(_FetchHandler)

    def tearDown(self):
        self.srv.shutdown()

    def _run(self, path):
        ctx, F = _ssrf_ctx(self.base)
        checks_mod.ssrf_url(ctx, self.base + path)
        return F

    def test_all_three_providers(self):
        F = self._run("/fetch?url=http://example.com")
        meta = [f for f in F.items
                if f["title"] == "Server-Side Request Forgery (cloud metadata)"]
        self.assertEqual(len(meta), 3)
        providers = sorted(f["detail"].split("fetch the ")[1].split(" metadata")[0]
                           for f in meta)
        self.assertEqual(providers, ["AWS EC2", "IBM Cloud", "OpenStack"])
        payloads = sorted(f["payload"] for f in meta)
        self.assertEqual(payloads, sorted(
            url for _, url, _ in checks_mod.CLOUD_METADATA_PROBES))
        self.assertTrue(all(f["severity"] == "Critical" for f in meta))
        self.assertTrue(all(f["cwe"] == "CWE-918" for f in meta))

    def test_safe_server_no_finding(self):
        F = self._run("/safe?url=http://example.com")
        self.assertEqual(
            [f for f in F.items if "cloud metadata" in f["title"]], [])

    def test_aws_only_server_reports_only_aws(self):
        _FetchHandler.aws_only = True
        F = self._run("/fetch?url=http://example.com")
        meta = [f for f in F.items
                if f["title"] == "Server-Side Request Forgery (cloud metadata)"]
        self.assertEqual(len(meta), 1)
        self.assertIn("AWS EC2", meta[0]["detail"])
