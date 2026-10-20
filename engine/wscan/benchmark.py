"""Reconix benchmark: measure precision & recall instead of guessing.

Recall  — a full scan of the deliberately vulnerable test target must find
          every planted vulnerability class.
Precision — a scan of the BAIT server (soft-404s everything, dynamic
          tokens, ignored parameters, fake backup files) must NOT produce
          findings in the FP-prone classes.

Run:  python3 webscan.py --benchmark
"""
import os
import re
import socket
import urllib.parse
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPECTED = [
    "SQL Injection (error-based)",
    "SQL Injection (boolean-based blind)",
    "SQL Injection (time-based blind)",
    "SQL Injection (UNION-based)",
    "Cross-Site Scripting (reflected)",
    "Cross-Site Scripting (stored)",
    "OS Command Injection",
    "Server-Side Template Injection",
    "Local File Inclusion",
    "Open Redirect",
    "CRLF Injection",
    "XML External Entity",
    "Possible CSRF",
    "File Upload",
    "Sensitive File Exposed: /.env",
    "GraphQL Introspection Enabled",
    "JSON Web Token: Weak HMAC Secret",
    "Default Credentials Accepted",
    "DOM XSS (potential",
    "Server-Side Request Forgery",
    # Depth Pack (3.6) classes
    "GraphQL Query Batching", "GraphQL Field Suggestions",
    "JWT Algorithm Confusion", "Second-Order SQL Injection",
    "SQL Injection (JSON API field)", "WebSocket Cross-Site Hijacking",
    # 403 Bypass Pack (3.10)
    "403 Forbidden Bypass",
]

FP_CLASSES = ["Sensitive File Exposed", "Discovered Content",
              "SQL Injection", "Cross-Site Scripting (reflected)",
              "Directory Listing", "403 Forbidden Bypass"]

SOFT404 = ("<html><head><title>404 Not Found</title></head><body>"
           "<h1>Oops! Page not found</h1><p>The page you requested does "
           "not exist on this server.</p><nav>Home | Products | About | "
           "Contact</nav></body></html>")


class BaitHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # simulated WAF: obvious attack strings get a flat 403 wall
        low = urllib.parse.unquote(self.path).lower()
        if any(n in low for n in ("union", "<script", "or 1=1",
                                  "' or '", "or '1'='1")):
            return self._send(
                "<html><body><h1>403 Blocked by WAF</h1></body></html>",
                code=403)
        path = self.path.split("?")[0]
        if path == "/":
            self._send("<html><body><h1>Bait Co</h1>"
                       "<a href='/search?q=test'>Search</a> "
                       "<a href='/db.sql'>db</a> "
                       "<a href='/backup.zip'>backup</a> "
                       "<a href='/admin'>Admin</a></body></html>")
        elif path == "/search":
            # parameter fully ignored; page carries fresh token + timestamp
            self._send(f"<html><body><h1>Search results</h1>"
                       f"<input type='hidden' name='csrf' "
                       f"value='{uuid.uuid4().hex}'>"
                       f"<p>Generated at {time.strftime('%Y-%m-%dT%H:%M:%S')}"
                       f"</p><p>0 results.</p></body></html>")
        else:
            self._send(SOFT404)

    do_POST = do_GET


class _Buf:
    """Minimal buffered socket reader for the desync chain."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def read_until(self, marker):
        while marker not in self.buf:
            chunk = self.conn.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        head, _, rest = self.buf.partition(marker)
        self.buf = rest
        return head + marker

    def read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.conn.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_line(self):
        return self.read_until(b"\r\n")[:-2]


def _chain_back(conn):
    """Backend that honours Transfer-Encoding: chunked first."""
    conn.settimeout(10)
    b = _Buf(conn)
    try:
        while True:
            head = b.read_until(b"\r\n\r\n").decode(errors="replace")
            low = head.lower()
            if "transfer-encoding: chunked" in low:
                while True:
                    size = int(b.read_line().strip() or b"0", 16)
                    if size == 0:
                        b.read_line()
                        break
                    b.read_exact(size)
                    b.read_line()
            else:
                m = re.search(r"content-length:\s*(\d+)", low)
                if m:
                    b.read_exact(int(m.group(1)))
            body = b"BACK-OK"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
                         b"Connection: keep-alive\r\n\r\n" + body)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _chain_front(client, back_port):
    """Store-and-forward proxy that reads bodies by Content-Length
    ONLY — paired with the TE-aware backend this is a genuine
    CL.TE / TE.CL desync topology."""
    client.settimeout(10)
    try:
        back = socket.create_connection(("127.0.0.1", back_port),
                                        timeout=10)
    except Exception:
        client.close()
        return
    cb, bb = _Buf(client), _Buf(back)
    try:
        while True:
            head = cb.read_until(b"\r\n\r\n")
            low = head.decode(errors="replace").lower()
            m = re.search(r"content-length:\s*(\d+)", low)
            body = cb.read_exact(int(m.group(1))) if m else b""
            back.sendall(head + body)
            rhead = bb.read_until(b"\r\n\r\n")
            rm = re.search(rb"content-length:\s*(\d+)",
                           rhead.lower())
            rbody = bb.read_exact(int(rm.group(1))) if rm else b""
            client.sendall(rhead + rbody)
    except Exception:
        pass
    finally:
        for s in (client, back):
            try:
                s.close()
            except Exception:
                pass


def _serve(port, handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(50)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=handler, args=(conn,),
                             daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv


def _start_chain():
    back_port, front_port = 8896, 8897
    _serve(back_port, _chain_back)
    _serve(front_port, lambda c: _chain_front(c, back_port))
    time.sleep(0.4)
    return back_port, front_port


def run_benchmark():
    from .engine import run_scan
    print("== Reconix accuracy benchmark ==")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # never score against a stranger: refuse if 8899 is already taken
    try:
        with socket.create_connection(("127.0.0.1", 8899), timeout=0.4):
            print("ERROR: port 8899 is already in use — the benchmark "
                  "would score against an unknown server. Free the port "
                  "and re-run.")
            return {"recall": 0.0, "precision": 0.0, "missed": EXPECTED,
                    "false_positives": [], "target_findings": 0}
    except OSError:
        pass
    target_proc = subprocess.Popen(
        [sys.executable, os.path.join(here, "test_target.py")], cwd=here,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    bait = ThreadingHTTPServer(("127.0.0.1", 0), BaitHandler)
    bait_port = bait.server_address[1]
    threading.Thread(target=bait.serve_forever, daemon=True).start()
    time.sleep(1.5)
    try:
        print("\n[1/3] Recall: full scan of the vulnerable test target...")
        res = run_scan("http://127.0.0.1:8899",
                       {"profile": "full", "auth_test": True,
                        "max_pages": 60, "threads": 6})
        titles = [f["title"] for f in res["findings"]]
        found, missed = [], []
        for exp in EXPECTED:
            (found if any(exp in t for t in titles) else missed).append(exp)
        for exp in found:
            print(f"  FOUND   {exp}")
        for exp in missed:
            print(f"  MISSED  {exp}")
        recall = len(found) / len(EXPECTED) if EXPECTED else 1.0

        print("\n[2/3] Precision: scanning the bait server "
              "(soft-404s, dynamic tokens, fake files)...")
        res2 = run_scan(f"http://127.0.0.1:{bait_port}",
                        {"profile": "full", "max_pages": 30, "threads": 6})
        fps = [f for f in res2["findings"]
               if any(c in f["title"] for c in FP_CLASSES)]
        for f in fps:
            print(f"  FALSE POSITIVE  {f['title']} -> {f['url']}")
        if not fps:
            print("  No false positives in the bait classes.")
        precision = 1.0 if not fps else max(
            0.0, 1.0 - 0.25 * len(fps))

        print("\n[3/3] Request smuggling: scanning a two-tier chain "
              "(CL front / TE back)...")
        back_port, front_port = _start_chain()
        try:
            res3 = run_scan(f"http://127.0.0.1:{front_port}",
                            {"profile": "full", "max_pages": 10,
                             "threads": 4})
            smuggle_ok = any("Request Smuggling" in f["title"]
                             for f in res3["findings"])
        except Exception as e:
            print(f"  chain scan error: {e}")
            smuggle_ok = False
        print("  FOUND   Request Smuggling" if smuggle_ok
              else "  MISSED  Request Smuggling")
        rec_ok = any("/admin/" in f["url"] and "SQL Injection" in
                     f["title"] for f in res["findings"])
        print("  FOUND   Recursive Discovery + Vuln Scan"
              if rec_ok else "  MISSED  Recursive Discovery + Scan")
        total = len(EXPECTED) + 2
        got = len(found) + (1 if smuggle_ok else 0) + (1 if rec_ok else 0)
        recall = got / total
        if not smuggle_ok:
            missed = missed + ["Request Smuggling"]
        if not rec_ok:
            missed = missed + ["Recursive Discovery + Scan"]
        print(f"\n== SCORE  recall {recall:.0%} "
              f"({got}/{total}) · precision "
              f"{'100%' if not fps else f'{precision:.0%}'} "
              f"({len(fps)} FP) · overall "
              f"{(recall + precision) / 2:.0%} ==")
        return {"recall": recall, "precision": precision,
                "missed": missed, "false_positives": fps,
                "target_findings": len(titles)}
    finally:
        try:
            target_proc.terminate()
        except Exception:
            pass
        try:
            bait.shutdown()
        except Exception:
            pass
