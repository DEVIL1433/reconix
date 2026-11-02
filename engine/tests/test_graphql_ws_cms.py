"""Tests for wscan.graphql, wscan.websocket, wscan.cms.

Every test runs against a local stub server on an ephemeral port —
never the network. Run: python3 -m unittest discover -s tests -v
"""
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import cms as cms_mod          # noqa: E402
from wscan import graphql as gql_mod      # noqa: E402
from wscan import websocket as ws_mod     # noqa: E402
from wscan.client import Client           # noqa: E402
from wscan.core import Findings           # noqa: E402
from wscan.engine import Ctx              # noqa: E402


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="text/html", extra=None):
    data = body.encode() if isinstance(body, str) else body
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    for k, v in (extra or {}).items():
        h.send_header(k, v)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _ctx(base, opts=None, cookie_b=None, anon=False):
    F = Findings()
    ctx = Ctx(Client(), F, None, base, opts or {}, lambda m: None)
    if cookie_b:
        ctx.client_b = Client(cookie=cookie_b)
    if anon:
        ctx.client_anon = Client()
    return ctx, F


def _titles(F):
    return [f["title"] for f in F.items]


# ================================================================ GraphQL

_INTROSPECTION = {
    "data": {"__schema": {"queryType": {"name": "Query"},
                          "mutationType": None,
                          "types": [
                              {"name": "Query", "kind": "OBJECT",
                               "fields": [
                                   {"name": "me",
                                    "type": {"name": "User", "kind": "OBJECT",
                                             "ofType": None}},
                                   {"name": "users",
                                    "type": {"name": None, "kind": "LIST",
                                             "ofType": {"name": "User",
                                                        "kind": "OBJECT",
                                                        "ofType": None}}},
                                   {"name": "user",
                                    "type": {"name": "User", "kind": "OBJECT",
                                             "ofType": None}},
                                   {"name": "adminPanel",
                                    "type": {"name": "Admin", "kind": "OBJECT",
                                             "ofType": None}}]},
                              {"name": "User", "kind": "OBJECT",
                               "fields": [
                                   {"name": "id",
                                    "type": {"name": "String", "kind": "SCALAR",
                                             "ofType": None}},
                                   {"name": "email",
                                    "type": {"name": "String", "kind": "SCALAR",
                                             "ofType": None}},
                                   {"name": "friends",
                                    "type": {"name": None, "kind": "LIST",
                                             "ofType": {"name": "User",
                                                        "kind": "OBJECT",
                                                        "ofType": None}}}]},
                              {"name": "Admin", "kind": "OBJECT",
                               "fields": [
                                   {"name": "secret",
                                    "type": {"name": "String", "kind": "SCALAR",
                                             "ofType": None}}]},
                          ]}}}


def _nested_friends(depth):
    node = {"id": 42}
    for _ in range(depth):
        node = {"friends": node}
    return [node]


class _GqlHandler(BaseHTTPRequestHandler):
    MODE = "vuln"  # or "hardened"

    def log_message(self, *a):
        pass

    def _session(self):
        cookie = self.headers.get("Cookie") or ""
        for pair in cookie.split(";"):
            if pair.strip().startswith("session="):
                return pair.strip().split("=", 1)[1]
        return None

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return _send(self, 400, "bad json")
        vuln = self.MODE == "vuln"
        if isinstance(payload, list):  # batch
            if not vuln:
                return _send(self, 200, json.dumps(
                    {"errors": [{"message": "batching disabled"}]}),
                    "application/json")
            return _send(self, 200, json.dumps(
                [{"data": {"__typename": "Query"}} for _ in payload]),
                "application/json")
        q = payload.get("query") or ""
        if "__schema" in q:
            if not vuln:
                return _send(self, 200, json.dumps(
                    {"errors": [{"message": "introspection disabled"}]}),
                    "application/json")
            return _send(self, 200, json.dumps(_INTROSPECTION),
                         "application/json")
        if "__typ" in q and "__typename" not in q:
            if not vuln:
                return _send(self, 200, json.dumps(
                    {"errors": [{"message": "field not found"}]}),
                    "application/json")
            return _send(self, 200, json.dumps(
                {"errors": [{"message": "Cannot query field '__typ' on "
                             "type 'Query'. Did you mean '__typename'?"}]}),
                "application/json")
        if q.count("friends") >= 6:
            if not vuln:
                return _send(self, 200, json.dumps(
                    {"errors": [{"message": "max depth exceeded"}]}),
                    "application/json")
            node = {"id": 42}
            for _ in range(8):
                node = {"friends": node}
            root = "me" if q.strip().startswith("{ me") else "users"
            data = {"me": node} if root == "me" else {"users": [node]}
            return _send(self, 200, json.dumps({"data": data}),
                         "application/json")
        if "adminPanel" in q:
            if vuln or self._session() == "admin":
                return _send(self, 200, json.dumps(
                    {"data": {"adminPanel": {"secret": "topsecret"}}}),
                    "application/json")
            return _send(self, 200, json.dumps(
                {"data": {"adminPanel": None},
                 "errors": [{"message": "denied"}]}), "application/json")
        if "users" in q:
            if vuln or self._session() == "admin":
                return _send(self, 200, json.dumps(
                    {"data": {"users": [{"id": 1,
                                         "email": "victim@example.com"}]}}),
                    "application/json")
            return _send(self, 200, json.dumps(
                {"data": {"users": None},
                 "errors": [{"message": "denied"}]}), "application/json")
        if "user(" in q:
            if vuln or self._session() in ("admin",):
                return _send(self, 200, json.dumps(
                    {"data": {"user": {"id": 1,
                                       "email": "victim@example.com"}}}),
                    "application/json")
            if self._session() == "user2" and "id: 2" in q:
                return _send(self, 200, json.dumps(
                    {"data": {"user": {"id": 2,
                                       "email": "user2@example.com"}}}),
                    "application/json")
            return _send(self, 200, json.dumps(
                {"data": {"user": None},
                 "errors": [{"message": "denied"}]}), "application/json")
        if "__typename" in q:
            # Must precede the "me" branch: "__typename" contains "me".
            return _send(self, 200, json.dumps(
                {"data": {"__typename": "Query"}}), "application/json")
        if "me" in q:
            if self._session():
                return _send(self, 200, json.dumps(
                    {"data": {"me": {"id": 9,
                                     "email": "me@example.com"}}}),
                    "application/json")
            if vuln:
                return _send(self, 200, json.dumps(
                    {"data": {"me": {"id": 1,
                                     "email": "victim@example.com"}}}),
                    "application/json")
            return _send(self, 200, json.dumps(
                {"data": {"me": None},
                 "errors": [{"message": "denied"}]}), "application/json")
        return _send(self, 200, json.dumps(
            {"errors": [{"message": "unknown field"}]}), "application/json")


class _GqlVulnHandler(_GqlHandler):
    MODE = "vuln"


class _GqlHardHandler(_GqlHandler):
    MODE = "hardened"


class TestGraphql(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv_v, cls.base_v = _serve(_GqlVulnHandler)
        cls.srv_h, cls.base_h = _serve(_GqlHardHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv_v.shutdown()
        cls.srv_h.shutdown()

    def test_discovery_finds_live_endpoint(self):
        ctx, _F = _ctx(self.base_v)
        eps = gql_mod.discover_graphql(ctx, self.base_v)
        self.assertIn(self.base_v + "/graphql", eps)

    def test_vuln_full_scan_proves_all_four(self):
        ctx, F = _ctx(self.base_v, cookie_b="session=user2", anon=True)
        out = gql_mod.graphql_scan(
            ctx, self.base_v,
            cross_user_queries=[{"query": "{ user(id: 1) { id email } }",
                                 "label": "user"}])
        self.assertIn(self.base_v + "/graphql", out["endpoints"])
        t = _titles(F)
        self.assertIn("GraphQL Introspection Enabled", t)
        self.assertIn("GraphQL Broken Access Control (unauthenticated)", t)
        self.assertIn("GraphQL Broken Access Control (cross-user)", t)
        self.assertIn("GraphQL Query Batching Enabled", t)
        self.assertIn("GraphQL Query Depth / Complexity Unbounded", t)
        # every finding carries its exact query as payload evidence
        for f in F.items:
            self.assertTrue(f["payload"] or f["proof"])

    def test_depth_proof_states_resolved_depth(self):
        ctx, F = _ctx(self.base_v)
        gql_mod.depth_check(ctx, [self.base_v + "/graphql"])
        self.assertEqual(len(F.items), 1)
        self.assertIn("8", F.items[0]["proof"])

    def test_batching_proof_counts_results(self):
        ctx, F = _ctx(self.base_v)
        gql_mod.batching_check(ctx, [self.base_v + "/graphql"])
        self.assertEqual(len(F.items), 1)
        self.assertIn("10", F.items[0]["proof"])

    def test_hardened_server_yields_no_findings(self):
        ctx, F = _ctx(self.base_h, cookie_b="session=user2", anon=True)
        gql_mod.graphql_scan(
            ctx, self.base_h,
            cross_user_queries=[{"query": "{ user(id: 1) { id email } }",
                                 "label": "user"}])
        self.assertEqual(F.items, [])

    def test_dead_endpoint_is_never_a_finding(self):
        ctx, F = _ctx("http://127.0.0.1:1")
        gql_mod.graphql_scan(ctx, "http://127.0.0.1:1")
        self.assertEqual(F.items, [])


# ============================================================== WebSocket

def _ws_frame_send(conn, text):
    import os as _os
    data = text.encode()
    mask = _os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    head = bytes([0x81, 0x80 | len(data)]) + mask + masked
    conn.sendall(head)


def _ws_frame_recv(conn):
    conn.settimeout(3)
    head = conn.recv(2)
    if len(head) < 2:
        return None
    masked = bool(head[1] & 0x80)
    ln = head[1] & 0x7F
    if ln == 126:
        ln = int.from_bytes(conn.recv(2), "big")
    elif ln == 127:
        ln = int.from_bytes(conn.recv(8), "big")
    mask = conn.recv(4) if masked else None
    data = b""
    while len(data) < ln:
        chunk = conn.recv(ln - len(data))
        if not chunk:
            break
        data += chunk
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return data.decode("utf-8", errors="replace")


def _ws_accept(key):
    return base64.b64encode(hashlib.sha1(
        (key + ws_mod.WS_GUID).encode()).digest()).decode()


def _make_ws_server():
    srv_sock = socket.socket()
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(50)
    port = srv_sock.getsockname()[1]
    control = f"http://127.0.0.1:{port}"

    def _handle(conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.decode("iso-8859-1", errors="replace")
            path = head.split(" ", 2)[1] if " " in head else "/"
            origin = ""
            key = ""
            for line in head.split("\r\n"):
                if line.lower().startswith("origin:"):
                    origin = line.split(":", 1)[1].strip()
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            if path == "/ws-origin" and origin != control:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: "
                             b"0\r\n\r\n")
                return
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {_ws_accept(key)}\r\n\r\n"
                          ).encode())
            if path == "/ws-private":
                _ws_send_text(conn, json.dumps(
                    {"user": "alice", "email": "alice@example.com"}))
            elif path == "/ws-public":
                _ws_send_text(conn, json.dumps({"welcome": "public"}))
            while True:
                msg = _ws_frame_recv(conn)
                if msg is None:
                    return
                if path == "/ws-inject":
                    if "' OR '" in msg:
                        _ws_send_text(conn, json.dumps(
                            {"error": "SQL syntax error near 'OR'",
                             "echo": msg}))
                    else:
                        _ws_send_text(conn, json.dumps({"ok": "received"}))
                elif path == "/ws-echo":
                    _ws_send_text(conn, json.dumps({"echo": msg}))
                else:
                    _ws_send_text(conn, json.dumps({"ok": "received"}))
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _loop():
        while True:
            try:
                conn, _ = srv_sock.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,),
                             daemon=True).start()

    threading.Thread(target=_loop, daemon=True).start()
    return srv_sock, f"ws://127.0.0.1:{port}"


def _ws_send_text(conn, text):
    data = text.encode()
    if len(data) < 126:
        conn.sendall(bytes([0x81, len(data)]) + data)
    else:
        conn.sendall(bytes([0x81, 126]) + len(data).to_bytes(2, "big")
                     + data)


class TestWebsocket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sock, cls.base = _make_ws_server()

    @classmethod
    def tearDownClass(cls):
        cls.sock.close()

    def test_client_roundtrip_and_ping(self):
        conn = ws_mod.ws_connect(self.base + "/ws-public")
        self.assertIsNotNone(conn)
        msg = conn.recv_text(timeout=3)
        self.assertIn("welcome", msg)
        conn.send_text("hello")
        self.assertIn("received", conn.recv_text(timeout=3))
        conn.close()

    def test_missing_auth_proven_by_protected_data(self):
        ctx, F = _ctx("http://127.0.0.1")
        ws_mod.missing_auth_check(ctx, [self.base + "/ws-private"])
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"],
                         "WebSocket Missing Authentication")
        self.assertIn("alice@example.com", F.items[0]["proof"])

    def test_public_welcome_is_not_a_finding(self):
        ctx, F = _ctx("http://127.0.0.1")
        ws_mod.missing_auth_check(ctx, [self.base + "/ws-public"])
        self.assertEqual(F.items, [])

    def test_origin_control_comparison(self):
        ctx, F = _ctx(self.base.replace("ws://", "http://"))
        # foreign origin accepted on the open endpoint -> finding
        ws_mod.origin_check(ctx, [self.base + "/ws-private"],
                            base=self.base.replace("ws://", "http://"))
        self.assertEqual(len(F.items), 1)
        self.assertIn("Cross-Site Hijacking", F.items[0]["title"])
        # origin-enforcing endpoint rejects foreign -> no finding
        ctx2, F2 = _ctx(self.base.replace("ws://", "http://"))
        ws_mod.origin_check(ctx2, [self.base + "/ws-origin"],
                            base=self.base.replace("ws://", "http://"))
        self.assertEqual(F2.items, [])

    def test_injection_differential_not_pure_echo(self):
        ctx, F = _ctx("http://127.0.0.1")
        ws_mod.injection_check(ctx, [self.base + "/ws-inject"])
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["title"], "WebSocket Message Injection")
        ctx2, F2 = _ctx("http://127.0.0.1")
        ws_mod.injection_check(ctx2, [self.base + "/ws-echo"])
        self.assertEqual(F2.items, [])

    def test_dead_endpoint_is_never_a_finding(self):
        ctx, F = _ctx("http://127.0.0.1")
        ws_mod.websocket_scan(ctx, "http://127.0.0.1:1",
                              ws_urls=["ws://127.0.0.1:1/ws"])
        self.assertEqual(F.items, [])

    def test_discovery_from_page_bodies(self):
        from wscan.client import Resp
        page = (self.base.replace("ws://", "http://") + "/",
                Resp(200, {}, [], f'connect to {self.base}/ws-private',
                     "", 0.0, ""))
        urls = ws_mod.discover_websocket_urls(
            self.base.replace("ws://", "http://"), pages=[page])
        self.assertIn(self.base + "/ws-private", urls)


# ==================================================================== CMS

_WP_HOME = """<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<script src="/wp-includes/js/jquery.js?ver=6.4.2"></script>
<script src="/wp-content/plugins/contact-form-7/js/scripts.js"></script>
<link href="/wp-content/themes/twentytwentyfour/style.css" />
</head><body>hello</body></html>"""


class _WPHandler(BaseHTTPRequestHandler):
    MODE = "vuln"  # "vuln" | "hardened" | "author"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = _WP_HOME if self.MODE != "hardened" else \
                "<html><body>hello</body></html>"
            return _send(self, 200, body)
        if self.path == "/readme.html":
            if self.MODE == "vuln":
                return _send(self, 200, "WordPress<br/>Version 6.4.2")
            return _send(self, 404, "not found")
        if self.path == "/license.txt":
            if self.MODE == "vuln":
                return _send(self, 200, "WordPress License GPLv2")
            return _send(self, 404, "not found")
        if self.path == "/wp-config.php":
            if self.MODE == "vuln":
                return _send(self, 200, "define('DB_PASSWORD', 's3cret');",
                             "text/plain")
            return _send(self, 403, "")
        if self.path == "/xmlrpc.php":
            if self.MODE == "vuln":
                return _send(self, 200,
                             "XML-RPC server accepts POST requests.")
            return _send(self, 404, "not found")
        if self.path == "/wp-json/wp/v2/users":
            if self.MODE == "vuln":
                return _send(self, 200, json.dumps(
                    [{"id": 1, "slug": "admin", "name": "Admin"}]),
                    "application/json")
            return _send(self, 403, "forbidden")
        if self.path == "/wp-json/":
            return _send(self, 404, "not found")
        if self.path == "/?author=1":
            if self.MODE in ("vuln", "author"):
                return _send(self, 302, "",
                             extra={"Location": "/author/admin/"})
            return _send(self, 200, "home")
        if self.path == "/wp-login.php":
            return _send(self, 200, "<html><body><form action="
                         "'/wp-login.php' method='post'>login</form>"
                         "</body></html>")
        if self.path == "/wp-content/plugins/akismet/readme.txt":
            if self.MODE == "vuln":
                return _send(self, 200, "=== Akismet ===\nStable tag: 5.3")
            return _send(self, 404, "not found")
        if self.path == "/wp-content/themes/twentytwentyfour/style.css":
            if self.MODE == "vuln":
                return _send(self, 200, "/*\nTheme Name: Twenty "
                             "Twenty-Four\n*/")
            return _send(self, 404, "not found")
        if self.path.startswith("/wp-content/"):
            return _send(self, 404, "not found")
        return _send(self, 404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(
            self.rfile.read(n).decode(errors="replace"))
        log = (form.get("log") or [""])[0]
        if self.path == "/wp-login.php":
            if log == "admin":
                return _send(self, 200, "ERROR: The password you entered "
                             "for the username admin is incorrect.")
            return _send(self, 200, "ERROR: Invalid username.")
        return _send(self, 404, "not found")


class _WPVuln(_WPHandler):
    MODE = "vuln"


class _WPHard(_WPHandler):
    MODE = "hardened"


class _WPAuthor(_WPHandler):
    MODE = "author"


class TestCms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv_v, cls.base_v = _serve(_WPVuln)
        cls.srv_h, cls.base_h = _serve(_WPHard)
        cls.srv_a, cls.base_a = _serve(_WPAuthor)

    @classmethod
    def tearDownClass(cls):
        cls.srv_v.shutdown()
        cls.srv_h.shutdown()
        cls.srv_a.shutdown()

    def test_detect_and_version_advisory_not_a_finding(self):
        ctx, F = _ctx(self.base_v)
        out = cms_mod.cms_scan(ctx, self.base_v)
        self.assertEqual(out["cms"], "wordpress")
        self.assertEqual(out["version"]["version"], "6.4.2")
        self.assertTrue(any(a["kind"] == "advisory" and
                            "6.4.2" in a["title"]
                            for a in out["advisories"]))
        t = _titles(F)
        self.assertFalse(any("Version Disclosed" in x for x in t))
        self.assertFalse(any("Enumerated" in x for x in t))

    def test_enumeration_from_html_and_common_paths(self):
        ctx, F = _ctx(self.base_v)
        out = cms_mod.cms_scan(ctx, self.base_v)
        self.assertIn("contact-form-7", out["plugins"])
        self.assertIn("akismet", out["plugins"])
        self.assertIn("twentytwentyfour", out["themes"])

    def test_proven_weak_spots_are_findings(self):
        ctx, F = _ctx(self.base_v)
        cms_mod.cms_scan(ctx, self.base_v)
        t = _titles(F)
        self.assertIn("CMS Configuration File Exposed", t)
        self.assertIn("CMS Information File Exposed", t)
        self.assertIn("WordPress XML-RPC Enabled", t)
        self.assertIn("WordPress User Enumeration (REST API)", t)
        self.assertIn("Login Username Enumeration (error differential)", t)

    def test_author_redirect_enumeration(self):
        ctx, F = _ctx(self.base_a)
        users = cms_mod.user_enumeration_check(ctx, self.base_a, "wordpress")
        self.assertEqual(users, ["admin"])
        self.assertIn("WordPress User Enumeration (author redirect)",
                      _titles(F))

    def test_hardened_site_no_findings_no_advisories(self):
        ctx, F = _ctx(self.base_h)
        out = cms_mod.cms_scan(ctx, self.base_h)
        self.assertIsNone(out["version"])
        self.assertEqual(out["advisories"], [])
        self.assertEqual(F.items, [])

    def test_pure_detection_helpers(self):
        cms, conf, _s = cms_mod.detect_cms_from_text(_WP_HOME)
        self.assertEqual((cms, conf), ("wordpress", "high"))
        plugins, themes = cms_mod.extract_wp_assets(_WP_HOME)
        self.assertIn("contact-form-7", plugins)
        self.assertIn("twentytwentyfour", themes)
        self.assertEqual(cms_mod.detect_cms_from_text("<html></html>")[0],
                         "")


if __name__ == "__main__":
    unittest.main()
