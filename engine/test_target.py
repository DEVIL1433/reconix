#!/usr/bin/env python3
"""Deliberately vulnerable test target v2 for Reconix — localhost ONLY.

Simulates one of everything: SQLi, reflected/stored/DOM XSS, command
injection, SSTI, LFI, SSRF, XXE, open redirect, CRLF, CORS reflection,
weak-secret JWT, GraphQL introspection, unrestricted upload (+PHP exec),
host-header reflection, missing security headers, exposed .env.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB_LOCK = threading.Lock()


def db_query(sql):
    """All handler queries go through one lock: a single sqlite connection
    is not safe for unsynchronized use across server threads."""
    with DB_LOCK:
        return DB.execute(sql).fetchall()
DB.execute("CREATE TABLE products (id INTEGER, name TEXT)")
DB.executemany("INSERT INTO products VALUES (?, ?)",
               [(1, "Widget"), (2, "Gadget"), (3, "Doohickey")])
BASE = os.path.dirname(os.path.abspath(__file__))
COMMENTS = []
LAST_COMMENT = [""]
PUBLIC_PEM = ("-----BEGIN PUBLIC KEY-----\n"
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7RECONIX7391fake\n"
              "-----END PUBLIC KEY-----\n")


def _jwt():
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay = b64(json.dumps({"sub": "42", "user": "devil", "role": "user"}).encode())
    sig = b64(hmac.new(b"secret", f"{head}.{pay}".encode(),
                       hashlib.sha256).digest())
    return f"{head}.{pay}.{sig}"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None, raw_cookies=True):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if raw_cookies:
            self.send_header("Set-Cookie", "sessionid=test123; Path=/")
            self.send_header("Set-Cookie", f"token={_jwt()}; Path=/")
        origin = self.headers.get("Origin")
        if origin:  # permissive CORS app-wide: reflect any origin + credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    # ---------------------------------------------------------- GET
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        path = parsed.path
        host = self.headers.get("Host", "localhost")

        if path == "/":
            self._send(200, f"""<html><body><h1>VulnShop 2</h1>
                <a href="/search">Search</a> <a href="/product?id=1">Product</a> <a href="/blind?id=1">Blind product</a> <a href="/blindtime?id=1">Blind time</a> <a href="/blindbool?id=1">Blind bool</a> <a href="/greet">Greet</a> <a href="/spa">SPA</a> <a href="/jwt-rsa">RSA session</a>
                <a href="/redirect?next=/home">Home</a>
                <a href="/file?page=welcome.txt">Welcome</a>
                <a href="/comment">Comments</a>
                <a href="/fetch?url=http://127.0.0.1:8899/">Fetcher</a>
                <a href="/ping?host=127.0.0.1">Ping</a>
                <a href="/render?name=guest">Render</a>
                <a href="/upload">Upload</a>
                <a href="/api/data">API</a>
                <a href="/api/users">API users</a>
                <a href="/include?file=welcome.txt">Include</a>
                <a href="/admin/panel">Admin panel</a>
                <a href="/vault">Vault</a> <a href="/console">Console</a> <a href="/internal">Internal</a>
                <a href="/crlf?h=hello">CRLF test</a>
                <script src="/static/app.js"></script>
                <p>Reset your password: <a href="http://{host}/reset">here</a></p>
                <form action="/search" method="get"><input name="q">
                <input type="submit" value="Search"></form>
                <form action="/login" method="post"><input name="user">
                <input name="pass" type="password"><input type="submit"></form>
                <div id="x"></div>
                <script>
                  var q = location.hash.slice(1);
                  document.getElementById('x').innerHTML = q;
                </script>
                </body></html>""")
        elif path == "/search":
            q = qs.get("q", "")
            try:
                rows = "".join(f"<li>{r[0]}</li>"
                               for r in db_query(
                                   f"SELECT name FROM products WHERE name "
                                   f"LIKE '%{q}%'"))
            except Exception as e:
                rows = f"<p>Database error: {e} (sqlite3.OperationalError)</p>"
            self._send(200, f"<html><body><p>Results for: {q}</p><ul>{rows}</ul></body></html>")
        elif path == "/product":
            pid = qs.get("id", "1")
            try:
                _rows = db_query(f"SELECT name FROM products WHERE id = {pid}")
                row = _rows[0] if _rows else None
                self._send(200, f"<html><body><h1>{row[0] if row else 'not found'}</h1></body></html>")
            except Exception as e:
                self._send(200, f"<html><body>Error: sqlite3.OperationalError: {e}</body></html>")
        elif path == "/blind":
            # blind-only SQLi: errors are hidden behind the same page, so
            # ONLY boolean/time/UNION techniques can prove injection
            pid = qs.get("id", "1")
            try:
                _rows = db_query(f"SELECT name FROM products WHERE id = {pid}")
                row = _rows[0] if _rows else None
                name = row[0] if row else "not found"
            except Exception:
                name = "not found"
            self._send(200, f"<html><body><h1>{name}</h1>"
                            f"<p>Blind product viewer</p></body></html>")
        elif path == "/blindbool":
            # boolean-only SQLi: 2-column query, only column 2 rendered —
            # UNION markers land in column 1 and never appear; errors are
            # hidden; TRUE/FALSE still changes the rendered name
            pid = qs.get("id", "1")
            try:
                _rows = db_query(
                    f"SELECT id, name FROM products WHERE id = {pid}")
                row = _rows[0] if _rows else None
                name = row[1] if row else "not found"
            except Exception:
                name = "not found"
            self._send(200, f"<html><body><h1>{name}</h1>"
                            f"<p>Boolean product viewer</p></body></html>")
        elif path == "/blindtime":
            # blind TIME-only SQLi: the query runs for its side effect and
            # the result is never rendered — no error, boolean or UNION
            # signal exists; only a delay can prove injection
            pid = qs.get("id", "1")
            try:
                db_query(f"SELECT name FROM products WHERE id = {pid}")
            except Exception:
                pass
            self._send(200, "<html><body><h1>Request processed</h1>"
                            "<p>Thank you.</p></body></html>")
        elif path == "/redirect":
            self._send(302, "", extra={"Location": qs.get("next", "/")})
        elif path == "/file":
            page = qs.get("page", "welcome.txt")
            try:
                with open(os.path.join(BASE, "files", page), "rb") as fh:
                    content = fh.read().decode(errors="replace")
                self._send(200, f"<html><body><pre>{content}</pre></body></html>")
            except Exception as e:
                self._send(404, f"<html><body>nope: {e}</body></html>")
        elif path == "/greet":
            q = LAST_COMMENT[0]
            try:
                rows = "".join(f"<li>{r[0]}</li>"
                               for r in db_query(
                                   f"SELECT name FROM products WHERE name "
                                   f"LIKE '%{q}%'"))
            except Exception as e:
                rows = (f"<p>Database error: {e} "
                        f"(sqlite3.OperationalError)</p>")
            self._send(200, f"<html><body><h2>Greeting wall</h2>"
                            f"<ul>{rows}</ul></body></html>")
        elif path == "/spa":
            self._send(200, """<html><body><h2>SPA</h2><div id="app"></div>
                <script>fetch('/api/spa-' + 'data?id=1').then(r=>r.text())
                .then(t=>{document.getElementById('app').innerHTML=t})</script>
                </body></html>""")
        elif path == "/api/spa-data":
            pid = qs.get("id", "1")
            try:
                _rows = db_query(f"SELECT name FROM products WHERE id = {pid}")
                name = _rows[0][0] if _rows else "not found"
                self._send(200, f"<p>SPA item: {name}</p>")
            except Exception as e:
                self._send(200, f"<p>Database error: {e} "
                                f"(sqlite3.OperationalError)</p>")
        elif path == "/public.pem":
            self._send(200, PUBLIC_PEM, ctype="text/plain")
        elif path == "/jwt-rsa":
            import base64 as _b64
            def _dec(seg):
                return json.loads(_b64.urlsafe_b64decode(
                    seg + "=" * (-len(seg) % 4)))
            ck = self.headers.get("Cookie", "")
            m = re.search(r"rsatoken=([^;\s]+)", ck)
            if not m:
                hdr = _b64.urlsafe_b64encode(json.dumps(
                    {"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
                pay = _b64.urlsafe_b64encode(json.dumps(
                    {"sub": "user-12", "role": "user"}).encode()).rstrip(b"=").decode()
                tok = f"{hdr}.{pay}.fakersasig7391"
                self._send(200, "<html><body>guest page — "
                                "RS256 session token issued</body></html>",
                           extra={"Set-Cookie": f"rsatoken={tok}; Path=/"})
            else:
                try:
                    h = _dec(m.group(1).split(".")[0])
                    p = _dec(m.group(1).split(".")[1])
                except Exception:
                    h, p = {}, {}
                if h.get("alg") == "HS256":
                    import hashlib as _hl, hmac as _hm
                    signing = m.group(1).rsplit(".", 1)[0].encode()
                    want = _b64.urlsafe_b64encode(_hm.new(
                        PUBLIC_PEM.encode(), signing,
                        _hl.sha256).digest()).rstrip(b"=").decode()
                    if _hm.compare_digest(want, m.group(1).split(".")[2]):
                        self._send(200, f"<html><body>admin panel: "
                                        f"welcome {p.get('sub')}</body></html>")
                    else:
                        self._send(200, "<html><body>invalid token</body></html>")
                elif p.get("sub") == "user-12":
                    self._send(200, "<html><body>user panel: welcome "
                                    "user-12</body></html>")
                else:
                    self._send(200, "<html><body>invalid token</body></html>")
        elif path == "/openapi.json":
            self._send(200, json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "Items API", "version": "1.0"},
                "paths": {"/api/items": {
                    "get": {"parameters": [{
                        "name": "id", "in": "query",
                        "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "ok"}}},
                    "post": {"requestBody": {"content": {
                        "application/json": {"schema": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "string"}}}}}},
                        "responses": {"200": {"description": "ok"}}}}}}),
                ctype="application/json")
        elif path == "/api/items":
            self._send(200, json.dumps([{"id": 1, "name": "Widget"}]),
                       ctype="application/json")
        elif path == "/ws":
            key = self.headers.get("Sec-WebSocket-Key", "")
            if self.headers.get("Upgrade", "").lower() == "websocket" and key:
                import hashlib as _hl, base64 as _b64
                acc = _b64.b64encode(_hl.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                    .encode()).digest()).decode()
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", acc)
                self.end_headers()
            else:
                self._send(400, "expected websocket upgrade")
        elif path == "/admin":
            # hidden directory: no page anywhere links into this tree;
            # only recursive discovery can find what's inside
            self._send(200, "<html><body><h1>Admin area</h1>"
                            "<p>Restricted.</p></body></html>")
        elif path == "/admin/users":
            uid = qs.get("id", "")
            out = ""
            if uid:
                try:
                    rows = "".join(
                        f"<li>{r[0]}</li>" for r in db_query(
                            f"SELECT name FROM products WHERE id = {uid}"))
                    out = f"<ul>{rows}</ul>"
                except Exception as e:
                    out = (f"<p>Database error: {e} "
                           f"(sqlite3.OperationalError)</p>")
            self._send(200, f"""<html><body><h2>Admin user lookup</h2>
                <form action="/admin/users" method="get">
                <input name="id"><input type="submit" value="Find"></form>
                {out}</body></html>""")
        elif path == "/admin/config":
            self._send(200, "<html><body><h2>Admin config</h2>"
                            "<p>All settings nominal.</p></body></html>")
        elif path == "/comment":
            items = "".join(f"<div class='c'>{c}</div>" for c in COMMENTS)
            self._send(200, f"""<html><body><h2>Comments</h2>{items}
                <form action="/comment" method="post">
                <input name="text"><input type="submit" value="Post"></form>
                </body></html>""")
        elif path == "/fetch":
            url = qs.get("url", "")
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    body = r.read().decode(errors="replace")
                self._send(200, f"<html><body><h3>Fetched {url}</h3><pre>{body[:500]}</pre></body></html>")
            except Exception as e:
                self._send(200, f"<html><body>fetch failed: {e}</body></html>")
        elif path == "/ping":
            host_in = qs.get("host", "")
            _flag = "-n" if sys.platform.startswith("win") else "-c"
            out = subprocess.run(f"ping {_flag} 1 {host_in}", shell=True,
                                 capture_output=True, text=True, timeout=15).stdout
            self._send(200, f"<html><body><pre>{out}</pre></body></html>")
        elif path == "/render":
            name = qs.get("name", "guest")
            def ev(m):
                try:
                    return str(eval(m.group(1), {"__builtins__": {}}))
                except Exception:
                    return m.group(0)
            rendered = re.sub(r"\{\{(.+?)\}\}", ev, name)
            self._send(200, f"<html><body><h1>Hello {rendered}</h1></body></html>")
        elif path == "/upload":
            self._send(200, """<html><body><h2>Upload</h2>
                <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file"><input type="submit"></form>
                </body></html>""")
        elif path.startswith("/uploads/"):
            fname = os.path.basename(path)
            fpath = os.path.join(BASE, "files", "uploads", fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as fh:
                    content = fh.read().decode(errors="replace")
                if fname.endswith(".php") and "7331*7" in content:
                    content = "WS51317"  # simulated PHP execution
                self._send(200, content, ctype="text/plain")
            else:
                self._send(404, "no file")
        elif path == "/api/data":
            self._send(200, json.dumps({"users": ["devil", "admin"]}),
                       ctype="application/json")
        elif path == "/api/users":
            self._send(200, json.dumps({"users": [
                {"id": 1, "name": "devil", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                 "email": "devil@example.com"},
                {"id": 2, "name": "admin", "password_hash": "21232f297a57a5a743894a0e4a801fc3",
                 "email": "admin@example.com"}]}), ctype="application/json")
        elif path == "/include":
            f = qs.get("file", "")
            if f.startswith(("http://", "https://")):
                try:
                    with urllib.request.urlopen(f, timeout=5) as r:
                        content = r.read().decode(errors="replace")
                except Exception as e:
                    content = f"include failed: {e}"
            else:
                try:
                    with open(os.path.join(BASE, "files", f), "rb") as fh:
                        content = fh.read().decode(errors="replace")
                except Exception as e:
                    content = f"nope: {e}"
            self._send(200, f"<html><body><div id='inc'>{content}</div></body></html>")
        elif path == "/static/app.js":
            self._send(200, "var API_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
                            "console.log('app');\n//# sourceMappingURL=app.js.map\n",
                       ctype="application/javascript")
        elif path == "/static/app.js.map":
            self._send(200, json.dumps({"version": 3, "sources": ["app.ts"],
                                        "mappings": "AAAA"}),
                       ctype="application/json")
        elif path == "/vault":
            # 403 bypass fixture: edge ACL trusts X-Forwarded-For —
            # a normal visit is 403, claiming to be loopback gets in
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                self._send(200, "<html><body><h1>Vault — Finance "
                                "Exports</h1><p>CONFIDENTIAL — internal "
                                "use only. Q3 payroll export, vendor "
                                "payments, bank mandates.</p>" +
                                "x" * 120 + "</body></html>")
            else:
                self._send(403, "<html><body><h1>403 Forbidden</h1>"
                                "<p>Vault access is restricted to "
                                "internal IPs.</p></body></html>")
        elif path == "/console":
            # 403 bypass fixture: ACL matches the exact path only —
            # the trailing-slash spelling slips past it
            self._send(403, "<html><body><h1>403 Forbidden</h1>"
                            "<p>Console is restricted.</p></body></html>")
        elif path == "/console/":
            self._send(200, "<html><body><h1>Ops Console</h1>"
                            "<p>Restricted area — node status, job "
                            "queues, deploy controls.</p>" +
                            "x" * 120 + "</body></html>")
        elif path == "/internal":
            # negative control: a genuine hard 403 — no bypass exists
            self._send(403, "<html><body><h1>403 Forbidden</h1>"
                            "<p>Internal only.</p></body></html>")
        elif path == "/admin/panel":
            # VULN: restricted page served to absolutely anyone
            self._send(200, "<html><body><h1>Admin Dashboard</h1>"
                            "User management · system settings · "
                            "<a href='/logout'>Logout</a>" + "x" * 200 +
                            "</body></html>")
        elif path == "/openapi.json":
            self._send(200, json.dumps({
                "openapi": "3.0.0",
                "paths": {
                    "/api/users": {"get": {"parameters": [
                        {"name": "id", "in": "query"}]}},
                    "/api/login": {"post": {"requestBody": {"content": {
                        "application/json": {"schema": {"properties": {
                            "username": {}, "password": {}}}}}}}}}}),
                ctype="application/json")
        elif path == "/crlf":
            val = urllib.parse.unquote(qs.get("h", ""))
            raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                   f"X-Echo: {val}\r\nContent-Length: 2\r\n\r\nok")
            self.wfile.write(raw.encode("utf-8", errors="replace"))
        elif path == "/.env":
            self._send(200, "DB_PASSWORD=supersecret\nAPI_KEY=abcd1234\n",
                       ctype="text/plain")
        else:
            self._send(404, "<html><body>404</body></html>")

    # ---------------------------------------------------------- POST
    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        path = parsed.path

        if path == "/login":
            data = dict(urllib.parse.parse_qsl(raw.decode(errors="replace")))
            user = data.get("user", "")
            pw = data.get("pass", "")
            if user == "admin" and pw == "admin":
                self._send(200, "<html><body>Welcome admin — Dashboard | "
                                "<a href='/logout'>Logout</a></body></html>")
                return
            payload_check = "'" in user
            if payload_check:
                self._send(200, "<html><body>Login error — You have an error in "
                                f"your SQL syntax near '{user}'</body></html>")
            else:
                self._send(200, f"<html><body>Welcome {user}</body></html>")
        elif path == "/comment":
            data = dict(urllib.parse.parse_qsl(raw.decode(errors="replace")))
            COMMENTS.append(data.get("text", ""))
            LAST_COMMENT[0] = data.get("text", "")
            self._send(200, "<html><body>posted</body></html>")
        elif path == "/xml":
            body = raw.decode(errors="replace")
            m = re.search(r'<!ENTITY\s+xxe\s+SYSTEM\s+"([^"]+)"', body)
            out = body
            if m:
                uri = m.group(1)
                try:
                    if uri.startswith("file://"):
                        with open(uri[7:]) as fh:
                            content = fh.read()
                    else:  # external (blind/OOB style): fetch it
                        with urllib.request.urlopen(uri, timeout=5) as r:
                            content = r.read().decode(errors="replace")
                    out = body.replace("&xxe;", content)
                except Exception as e:
                    out = f"entity error: {e}"
            self._send(200, f"<html><body>{out}</body></html>",
                       ctype="application/xml")
        elif path == "/api/items":
            try:
                obj = json.loads(raw.decode(errors="replace") or "{}")
            except Exception:
                obj = {}
            if not isinstance(obj.get("id"), int):
                self._send(400, json.dumps(
                    {"error": "id must be integer"}),
                    ctype="application/json")
            else:
                try:
                    rows = db_query(
                        f"SELECT name FROM products WHERE name = "
                        f"'{obj.get('name', '')}'")
                    self._send(200, json.dumps(
                        {"rows": [r[0] for r in rows]}),
                        ctype="application/json")
                except Exception as e:
                    self._send(200, json.dumps(
                        {"error": f"Database error: {e} "
                                  f"(sqlite3.OperationalError)"}),
                        ctype="application/json")
        elif path == "/graphql":
            try:
                gql = json.loads(raw.decode(errors="replace") or "{}")
            except Exception:
                gql = {}
            if isinstance(gql, list):
                self._send(200, json.dumps(
                    [{"data": {"__typename": "Query"}} for _ in gql]),
                    ctype="application/json")
            else:
                q = (gql or {}).get("query", "")
                n_alias = q.count(": __typename")
                if "__schema" in q:
                    self._send(200, json.dumps({"data": {"__schema": {
                        "types": [{"name": "Query"}, {"name": "User"},
                                  {"name": "Order"}]}}}),
                        ctype="application/json")
                elif n_alias >= 10:
                    self._send(200, json.dumps({"data": {
                        f"a{i}": "Query" for i in range(n_alias)}}),
                        ctype="application/json")
                elif "__typ" in q and "__typename" not in q:
                    self._send(200, json.dumps({"errors": [{
                        "message": "Cannot query field '__typ' on type "
                                   "'Query'. Did you mean "
                                   "'__typename'?"}]}),
                        ctype="application/json")
                else:
                    self._send(200, json.dumps(
                        {"data": {"__typename": "Query"}}),
                        ctype="application/json")
        elif path == "/upload":
            ctype = self.headers.get("Content-Type", "")
            boundary = ctype.split("boundary=")[-1].encode()
            saved = "none"
            for part in raw.split(b"--" + boundary):
                if b'filename="' in part:
                    fname = re.search(rb'filename="([^"]+)"', part).group(1).decode()
                    content = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
                    dest = os.path.join(BASE, "files", "uploads")
                    os.makedirs(dest, exist_ok=True)
                    with open(os.path.join(dest, os.path.basename(fname)), "wb") as fh:
                        fh.write(content)
                    saved = fname
            self._send(200, f"<html><body>uploaded {saved}</body></html>")
        else:
            # generic XML sink: any other POST may be an XML endpoint
            if raw.lstrip().startswith(b"<?xml"):
                self.rfile = None
                self.path = "/xml"
                length2 = length
                # replay into the XML handler logic
                body = raw.decode(errors="replace")
                m = re.search(r'<!ENTITY\s+xxe\s+SYSTEM\s+"([^"]+)"', body)
                out = body
                if m:
                    uri = m.group(1)
                    try:
                        if uri.startswith("file://"):
                            with open(uri[7:]) as fh:
                                content = fh.read()
                        else:
                            with urllib.request.urlopen(uri, timeout=5) as r:
                                content = r.read().decode(errors="replace")
                        out = body.replace("&xxe;", content)
                    except Exception as e:
                        out = f"entity error: {e}"
                self._send(200, f"<html><body>{out}</body></html>",
                           ctype="application/xml")
            else:
                self._send(404, "<html><body>404</body></html>")


if __name__ == "__main__":
    os.makedirs(os.path.join(BASE, "files", "uploads"), exist_ok=True)
    with open(os.path.join(BASE, "files", "welcome.txt"), "w") as fh:
        fh.write("Welcome to VulnShop!")
    print("Vulnerable target v2 on http://127.0.0.1:8899")
    ThreadingHTTPServer(("127.0.0.1", 8899), H).serve_forever()
