"""Out-of-band (OOB) callback listener — the AcuMonitor equivalent.

Blind vulnerabilities (SSRF, blind XXE, blind XSS) make the *target server*
call back to this listener. A recorded hit, keyed by an unguessable token,
is proof the payload executed server-side.
"""
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class OOBServer:
    def __init__(self, host="127.0.0.1", port=8891):
        self.host, self.port = host, port
        self.hits = {}          # token -> [hit dicts]
        self.lock = threading.Lock()
        self._server = None

    def start(self):
        hits, lock = self.hits, self.lock

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _record(self):
                token = self.path.strip("/").split("/")[0]
                with lock:
                    hits.setdefault(token, []).append({
                        "path": self.path,
                        "method": self.command,
                        "headers": dict(self.headers),
                        "time": time.strftime("%H:%M:%S"),
                    })
                self.send_response(200)
                self.end_headers()
                # Body carries the token marker: if a target INCLUDES this
                # content (RFI) or echoes it, that's in-band proof too.
                self.wfile.write(f"OOBMARK-{token}".encode())

            do_GET = do_POST = do_PUT = do_HEAD = _record

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        except OSError:
            self._server = ThreadingHTTPServer((self.host, 0), Handler)
            self.port = self._server.server_address[1]
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        return self

    def new_token(self):
        return uuid.uuid4().hex[:12]

    def url(self, token):
        return f"http://{self.host}:{self.port}/{token}"

    def get_hits(self, token):
        with self.lock:
            return list(self.hits.get(token, []))

    def wait_for(self, token, seconds=6):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.get_hits(token):
                return self.get_hits(token)
            time.sleep(0.25)
        return self.get_hits(token)

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()  # actually release the port
