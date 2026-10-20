"""Local mock application with KNOWN access-control rules.

Used by tests/test_access403.py as the integration fixture for the
Reconix 403 Access-Control Assessment Engine, and runnable standalone
for manual experiments:

    python3 tests/mock_acl_app.py 8890     # http://127.0.0.1:8890

Access-control rules of this application (the ground truth the engine
is judged against):

  /canary        Harmless test resource (body carries the marker
                 CANARY-TEST-RESOURCE-7391).
                 anonymous -> 403 · session=rolea -> 200 ·
                 session=roleb -> 403.            [correctly enforced]
  /canary/       PLANTED FLAW: the trailing-slash spelling serves the
                 canary to EVERYONE, including anonymous.
  /xff-canary    Same policy as /canary, but PLANTED FLAW: any request
                 with header  X-Forwarded-For: 127.0.0.1  is served
                 the canary (the app wrongly trusts a client-supplied
                 forwarding header).
  /head-canary   PLANTED FLAW: GET -> 403 for everyone, but HEAD ->
                 200 with the canary's Content-Length (method
                 inconsistency; HEAD alone must never be "verified").
  /f5            F5 BIG-IP ASM-style block page for everyone, with a
                 support ID (1234567890123456789) and Server: BigIP.
  /authvault     401 + WWW-Authenticate for anonymous;
                 session=letmein (or rolea) -> 200 member page.
  /public        200 public page for everyone (control resource).
  /neverprotected  The canary served to EVERYONE (no ACL at all) —
                 technique results must cap at SUSPECTED, never a
                 "bypass"; the front-door policy violation is separate.
  /hostcanary    Enforced canary, but X-Forwarded-Host:
                 internal.local serves it to anyone (PLANTED FLAW).
  /cachecanary   Enforced canary, but /cachecanary/reconix-cache.css
                 serves it to anyone with cache headers (PLANTED
                 cache-deception FLAW).
  /flaky         403; /flaky/ serves the canary only on odd-numbered
                 requests (unstable — candidate at best, never
                 verified).
  /weakauth      Prefix-based session check: any session value
                 starting with "role" passes, so truncated and stale
                 mutations of role A's token authenticate too
                 (PLANTED FLAW).
  /vault         Legacy fixture: 403 unless X-Forwarded-For is
                 127.0.0.1, then a "confidential" page.
  /console       403;  /console/ -> 200 ops console (spelling flaw).
  /internal      Hard 403 for everyone, every spelling.
  /fake          403; unknown paths behave like a catch-all site.
  /member        200 member page only with session=letmein.
  /edgeonly      403 here; the separate OriginHandler serves real
                 content for it (edge-only ACL).
  anything else  trailing slash -> generic WELCOME page (catch-all);
                 otherwise a soft-404 page served with status 200.
"""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "CANARY-TEST-RESOURCE-7391"
_FLAKY_COUNT = [0]
_FLAKY_LOCK = threading.Lock()
CANARY = ("<html><body><h1>Harmless Test Resource</h1><p>" + MARKER +
          "</p><p>Owner-planted canary. No real data.</p>" + "c" * 120 +
          "</body></html>")
VAULT = ("<html><body><h1>Vault — Finance Exports</h1><p>CONFIDENTIAL — "
         "internal use only. Q3 payroll export.</p>" + "x" * 120 +
         "</body></html>")
CONSOLE = ("<html><body><h1>Ops Console</h1><p>Restricted area — node "
           "status, job queues.</p>" + "x" * 120 + "</body></html>")
MEMBER = ("<html><body><h1>Member Area</h1><p>Your statements and "
          "documents.</p>" + "x" * 120 + "</body></html>")
WELCOME = ("<html><body><h1>Welcome</h1><p>Generic landing page for "
           "every path.</p>" + "y" * 120 + "</body></html>")
SOFT404 = ("<html><body><h1>Not here</h1><p>Sorry, that page does not "
           "exist on this site.</p>" + "z" * 120 + "</body></html>")
F403 = "<html><body><h1>403 Forbidden</h1><p>Restricted.</p></body></html>"
F5_PAGE = ("<html><head><title>Request Rejected</title></head><body>"
           "<h1>The requested URL was rejected. Please consult with "
           "your administrator.</h1><p>Your support ID is: "
           "1234567890123456789</p></body></html>")
F5_SUPPORT_ID = "1234567890123456789"


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


def _cookie(h):
    return h.headers.get("Cookie") or ""


def _cval(cookie, name="session"):
    """Exact cookie-pair value — enforcement in this mock compares
    values exactly, so truncated/stale mutations do NOT authenticate
    (except on /weakauth, whose prefix check is the planted flaw)."""
    for part in (cookie or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return ""


class MockAclHandler(BaseHTTPRequestHandler):
    """The mock application (see module docstring for its rules)."""
    def log_message(self, *a):
        pass

    def _route(self):
        path = self.path.split("?")[0]
        cookie = _cookie(self)
        sval = _cval(cookie)
        rolea = sval == "rolea"
        member = sval in ("letmein", "rolea")
        if path == "/f5":
            return _send(self, 403, F5_PAGE,
                         extra={"Server": "BigIP"})
        if path == "/canary":
            if rolea:
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/canary/":
            return _send(self, 200, CANARY)          # planted flaw
        if path == "/xff-canary":
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                return _send(self, 200, CANARY)      # planted flaw
            if rolea:
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/head-canary":
            if self.command == "HEAD":
                return _send(self, 200, CANARY)      # planted flaw
            return _send(self, 403, F403)
        if path == "/authvault":
            if member:
                return _send(self, 200, MEMBER)
            return _send(self, 401, "authentication required",
                         extra={"WWW-Authenticate":
                                'Basic realm="mock-acl"'})
        if path == "/public":
            return _send(self, 200, "<html><body><h1>Public page</h1>"
                                    "<p>Everyone may read this.</p>"
                                    "</body></html>")
        if path == "/neverprotected":
            return _send(self, 200, CANARY)   # no ACL at all (planted)
        if path == "/hostcanary":
            if self.headers.get("X-Forwarded-Host") == "internal.local":
                return _send(self, 200, CANARY)      # planted flaw
            if rolea:
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/cachecanary":
            if rolea:
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/cachecanary/reconix-cache.css":
            # planted flaw: private content under a static-looking
            # suffix, served to anyone and marked cacheable
            return _send(self, 200, CANARY,
                         extra={"X-Cache": "HIT", "Age": "42",
                                "Cache-Control": "public"})
        if path == "/flaky":
            return _send(self, 403, F403)
        if path == "/flaky/":
            # planted flaw (unstable): trailing slash serves the
            # canary only on odd-numbered requests — must never be
            # reported VERIFIED, only ever a candidate
            with _FLAKY_LOCK:
                _FLAKY_COUNT[0] += 1
                n = _FLAKY_COUNT[0]
            if n % 2 == 1:
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/weakauth":
            # planted flaw: prefix-based session validation — any
            # value starting with "role" authenticates, so truncated
            # and stale mutations of role A's token also pass
            val = ""
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("session="):
                    val = part[len("session="):]
            if val.startswith("role"):
                return _send(self, 200, CANARY)
            return _send(self, 403, F403)
        if path == "/vault":
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                return _send(self, 200, VAULT)
            return _send(self, 403, F403)
        if path == "/console":
            return _send(self, 403, F403)
        if path == "/console/":
            return _send(self, 200, CONSOLE)
        if path == "/internal":
            return _send(self, 403, F403)
        if path == "/fake":
            return _send(self, 403, F403)
        if path == "/member":
            if sval == "letmein":
                return _send(self, 200, MEMBER)
            return _send(self, 403, F403)
        if path == "/edgeonly":
            return _send(self, 403, F403)
        if path == "/":
            return _send(self, 200, WELCOME)
        if path.endswith("/"):
            return _send(self, 200, WELCOME)         # catch-all site
        return _send(self, 200, SOFT404)             # soft-404

    do_GET = _route
    do_POST = _route
    do_HEAD = _route
    do_PUT = _route
    do_PATCH = _route
    do_DELETE = _route
    do_OPTIONS = _route


class Custom403Handler(BaseHTTPRequestHandler):
    """Every path answers the identical custom 403 page."""
    def log_message(self, *a):
        pass

    def _route(self):
        return _send(self, 403,
                     "<html><body><h1>Oops</h1><p>Something went "
                     "wrong (error 403).</p></body></html>")

    do_GET = _route
    do_POST = _route
    do_HEAD = _route


class OriginHandler(BaseHTTPRequestHandler):
    """The 'origin' behind the edge: serves /edgeonly content."""
    def log_message(self, *a):
        pass

    def _route(self):
        if self.path.split("?")[0] == "/edgeonly":
            return _send(self, 200, VAULT)
        return _send(self, 200, SOFT404)

    do_GET = _route
    do_POST = _route
    do_HEAD = _route


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8890
    srv = ThreadingHTTPServer(("127.0.0.1", port), MockAclHandler)
    print(f"mock ACL app on http://127.0.0.1:{port} "
          f"(marker: {MARKER}) — Ctrl+C to stop")
    srv.serve_forever()
