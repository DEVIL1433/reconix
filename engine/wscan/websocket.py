"""WebSocket testing (Reconix proof-only pack) — stdlib WS client.

Extends — never duplicates — checks3.websocket_check, which only
fires a raw HTTP Upgrade handshake and reports the 101 status. This
module completes a REAL WebSocket conversation (socket + handshake +
frames, no new dependencies) and proves each claim:

  * missing authentication: an unauthenticated socket RECEIVES
    protected data / functionality (sensitive keys, not a welcome
    banner and not an echo of our own message)
  * origin validation: a foreign Origin is accepted ONLY when the
    control connection with the correct Origin is also accepted —
    the comparison is the proof
  * message injection: a crafted message produces an ERROR or a
    STRUCTURAL differential versus a benign baseline message — a
    pure echo is never a finding

Timeouts everywhere; a dead/unreachable endpoint, a refused handshake,
or a timeout is never a finding. Stdlib only (socket + ssl + hashlib).

Integration entry point: websocket_scan(ctx, base, pages=None, ...).
"""
import base64
import hashlib
import os
import re
import socket
import ssl
import urllib.parse

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_TIMEOUT = 5.0
FOREIGN_ORIGIN = "https://reconix-cswsh.invalid"

COMMON_PATHS = ("/ws", "/websocket", "/socket", "/live", "/realtime",
                "/feed", "/notifications", "/chat", "/stream")

SENSITIVE_KEYS = ("user", "email", "account", "balance", "token",
                  "secret", "password", "admin", "profile", "private",
                  "ssn", "card")

ERROR_WORDS = ("sql", "syntax", "exception", "traceback", "error",
               "failed", "uncaught", "query failed")

BENIGN_MESSAGE = "reconix-benign-7391"
INJECTION_PAYLOADS = (
    "' OR '1'='1 reconix7391",
    "<script>reconix7391</script>",
    '{"msg": "reconix7391", "$ne": ""}',
)


# ------------------------------------------------------------------ client

class WSConnection:
    """One established WebSocket connection (RFC 6455 client side)."""

    def __init__(self, sock, url, buf=b""):
        self.sock, self.url = sock, url
        # Bytes already read past the handshake headers (a single TCP
        # recv can carry headers + the first frame) must not be lost.
        self._buf = buf
        self.closed = False

    def _read_exact(self, n, timeout):
        self.sock.settimeout(timeout)
        while len(self._buf) < n:
            try:
                chunk = self.sock.recv(4096)
            except (socket.timeout, TimeoutError):
                return None
            except OSError:
                return None
            if not chunk:
                return None
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_text(self, timeout=DEFAULT_TIMEOUT):
        """Next text message, or None on timeout/close/error. Pings
        are answered with pongs automatically; pongs are skipped."""
        fragments = []
        while True:
            head = self._read_exact(2, timeout)
            if head is None:
                return None
            b1, b2 = head[0], head[1]
            opcode = b1 & 0x0F
            length = b2 & 0x7F
            masked = bool(b2 & 0x80)
            if length == 126:
                ext = self._read_exact(2, timeout)
                if ext is None:
                    return None
                length = int.from_bytes(ext, "big")
            elif length == 127:
                ext = self._read_exact(8, timeout)
                if ext is None:
                    return None
                length = int.from_bytes(ext, "big")
            mask = self._read_exact(4, timeout) if masked else None
            if masked and mask is None:
                return None
            payload = self._read_exact(length, timeout)
            if payload is None:
                return None
            if mask:
                payload = bytes(b ^ mask[i % 4]
                                for i, b in enumerate(payload))
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong -> ignore
                continue
            if opcode == 0x8:  # close
                self.closed = True
                return None
            if opcode in (0x0, 0x1):  # continuation / text
                fragments.append(payload)
                if b1 & 0x80:  # FIN
                    try:
                        return b"".join(fragments).decode(
                            "utf-8", errors="replace")
                    except Exception:
                        return None
                continue
            return None  # binary / unknown opcodes are not text evidence

    def _send_frame(self, opcode, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        try:
            self.sock.sendall(head + mask_key + masked)
            return True
        except OSError:
            return False

    def send_text(self, text):
        return self._send_frame(0x1, text)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def ws_handshake(url, origin=None, extra_headers=None,
                 timeout=DEFAULT_TIMEOUT):
    """Raw handshake only. Returns (status, headers_dict, sock, rest),
    where rest is any bytes read past the header terminator (the first
    frame may arrive in the same TCP segment). The caller owns the
    socket on 101; on any other outcome the socket is closed and None
    is returned. Never raises for network errors."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "wss" else 80)
        sock = socket.create_connection((host, port), timeout=timeout)
        if parts.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"GET {path} HTTP/1.1", f"Host: {parts.netloc}",
                 "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        if origin:
            lines.append(f"Origin: {origin}")
        for k, v in (extra_headers or {}).items():
            lines.append(f"{k}: {v}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, TimeoutError, OSError):
            pass
        head, _, rest = data.partition(b"\r\n\r\n")
        head = head.decode("iso-8859-1", errors="replace")
        m = re.search(r"HTTP/\S+\s+(\d+)", head)
        status = int(m.group(1)) if m else None
        headers = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if status != 101:
            try:
                sock.close()
            except Exception:
                pass
            return status, headers, None, b""
        expect = base64.b64encode(hashlib.sha1(
            (key + WS_GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != expect:
            try:
                sock.close()
            except Exception:
                pass
            return status, headers, None, b""
        return status, headers, sock, rest
    except Exception:
        return None, {}, None, b""


def ws_connect(url, origin=None, extra_headers=None,
               timeout=DEFAULT_TIMEOUT):
    """Full connection: handshake + WSConnection, or None."""
    _status, _headers, sock, rest = ws_handshake(url, origin,
                                                 extra_headers, timeout)
    if sock is None:
        return None
    return WSConnection(sock, url, buf=rest)


def _collect(conn, probes, wait=1.2, timeout=DEFAULT_TIMEOUT):
    """Unsolicited messages, then one response per probe message."""
    msgs = []
    first = conn.recv_text(timeout=wait)
    if first is not None:
        msgs.append(first)
    for probe in probes:
        if not conn.send_text(probe):
            break
        resp = conn.recv_text(timeout=timeout)
        if resp is not None:
            msgs.append(resp)
    return msgs


def _sensitive_hit(text):
    """(key, snippet) if a JSON-ish message carries a sensitive key
    with a non-empty value, else None. Plain-text welcomes don't hit."""
    try:
        import json as _json
        obj = _json.loads(text)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    for k, v in obj.items():
        if k.lower() in SENSITIVE_KEYS and v not in (None, "", [], {}):
            return (k, text[:300])
    return None


# -------------------------------------------------------------- discovery

def discover_websocket_urls(base, pages=None, extra_urls=None):
    """Candidates: common paths on the target + ws(s):// URLs found in
    crawled bodies + ctx.extra['ws_urls'] + caller-supplied URLs."""
    parts = urllib.parse.urlsplit(base)
    scheme = "wss" if parts.scheme == "https" else "ws"
    root = f"{scheme}://{parts.netloc}"
    out, seen = [], set()

    def _add(u):
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    for p in COMMON_PATHS:
        _add(root + p)
    for _u, r in (pages or []):
        for m in re.finditer(r"wss?://[^\s\"'<>]+", r.body or ""):
            _add(m.group(0))
    for u in (extra_urls or []):
        _add(u)
    return out


# ------------------------------------------------------------------ checks

def missing_auth_check(ctx, ws_urls, probe_messages=None):
    """PROOF: connect with NO credentials (raw socket carries no
    cookies unless explicitly given) and receive a message carrying
    protected data. Welcome banners, public data, and echoes of our
    own probes are never findings."""
    probes = probe_messages if probe_messages is not None else (
        '{"type": "subscribe", "channel": "private"}',
        '{"action": "get_profile"}')
    found = []
    for url in ws_urls:
        if ctx.stop.is_set():
            break
        conn = ws_connect(url, timeout=DEFAULT_TIMEOUT)
        if conn is None:
            continue  # refused / dead / not a WS endpoint: not a finding
        try:
            msgs = _collect(conn, list(probes))
        finally:
            conn.close()
        for msg in msgs:
            if msg in probes:
                continue  # pure echo of our own message
            hit = _sensitive_hit(msg)
            if hit:
                f = ctx.findings.add(
                    "High", "WebSocket Missing Authentication", url,
                    "An unauthenticated WebSocket connection received "
                    "protected data: no credentials were sent, yet the "
                    "server pushed or answered with user/account data.",
                    proof=f"unauthenticated message: {msg[:300]}",
                    payload="; ".join(probes), resp=None, cwe="CWE-306")
                if f:
                    found.append(url)
                break
    return found


def origin_check(ctx, ws_urls, base=None):
    """PROOF by control comparison: the connection with the CORRECT
    origin must succeed first; only then does acceptance of a FOREIGN
    origin count. If the control fails, the endpoint is skipped — its
    origin policy cannot be judged."""
    base = base or ctx.base
    parts = urllib.parse.urlsplit(base)
    control_origin = f"{parts.scheme}://{parts.netloc}"
    found = []
    for url in ws_urls:
        if ctx.stop.is_set():
            break
        control = ws_connect(url, origin=control_origin,
                             timeout=DEFAULT_TIMEOUT)
        if control is None:
            continue  # control failed: cannot judge origin policy
        control.close()
        foreign = ws_connect(url, origin=FOREIGN_ORIGIN,
                             timeout=DEFAULT_TIMEOUT)
        if foreign is not None:
            foreign.close()
            f = ctx.findings.add(
                "High", "WebSocket Cross-Site Hijacking (CSWSH)", url,
                "The WebSocket endpoint accepts a handshake from a "
                "foreign Origin. Any website a logged-in victim visits "
                "can open a socket as the victim and read/send data.",
                proof=f"control Origin {control_origin}: HTTP 101; "
                      f"foreign Origin {FOREIGN_ORIGIN}: HTTP 101",
                resp=None, cwe="CWE-1385")
            if f:
                found.append(url)
    return found


def _json_keyset(text):
    try:
        import json as _json
        obj = _json.loads(text)
        return set(obj.keys()) if isinstance(obj, dict) else None
    except Exception:
        return None


def injection_check(ctx, ws_urls, payloads=None):
    """PROOF by differential: each crafted message is judged against
    the response to a benign baseline on the SAME connection. A
    finding needs an error indicator OR a different response structure
    (key set / type) — a pure echo with the same shape is not one."""
    payloads = payloads if payloads is not None else list(INJECTION_PAYLOADS)
    found = []
    for url in ws_urls:
        if ctx.stop.is_set():
            break
        conn = ws_connect(url, timeout=DEFAULT_TIMEOUT)
        if conn is None:
            continue
        try:
            conn.recv_text(timeout=1.0)  # drain any welcome message
            if not conn.send_text(BENIGN_MESSAGE):
                continue
            baseline = conn.recv_text(timeout=DEFAULT_TIMEOUT)
            base_keys = _json_keyset(baseline) if baseline else None
            for payload in payloads:
                if not conn.send_text(payload):
                    break
                resp = conn.recv_text(timeout=DEFAULT_TIMEOUT)
                if resp is None:
                    continue
                low = resp.lower()
                has_error = any(w in low for w in ERROR_WORDS)
                resp_keys = _json_keyset(resp)
                structural = base_keys is not None and resp_keys is not None \
                    and resp_keys != base_keys
                marker = "reconix7391" in resp
                if (has_error and marker) or (structural and marker) \
                        or (has_error and resp_keys != base_keys
                            and base_keys is not None):
                    f = ctx.findings.add(
                        "High", "WebSocket Message Injection", url,
                        "A crafted WebSocket message produced an error "
                        "or a structurally different server response "
                        "than the benign baseline — the message content "
                        "changed server-side behaviour.",
                        proof=f"baseline: {str(baseline)[:200]} | "
                              f"crafted: {payload[:120]} | response: "
                              f"{resp[:300]}",
                        param="message", payload=payload, resp=None,
                        cwe="CWE-74")
                    if f:
                        found.append(url)
                    break
        finally:
            conn.close()
    return found


# ------------------------------------------------------------- entry point

def websocket_scan(ctx, base, pages=None, ws_urls=None, probe_messages=None):
    """Discover endpoints, then run every WebSocket check. Returns a
    summary dict; findings go through ctx.findings as usual."""
    extra = list(ctx.extra.get("ws_urls") or []) if hasattr(ctx, "extra") \
        else []
    urls = discover_websocket_urls(base, pages, extra + list(ws_urls or []))
    before = len(ctx.findings.items)
    missing_auth_check(ctx, urls, probe_messages=probe_messages)
    origin_check(ctx, urls, base=base)
    injection_check(ctx, urls)
    return {"endpoints": urls,
            "findings_added": len(ctx.findings.items) - before}
