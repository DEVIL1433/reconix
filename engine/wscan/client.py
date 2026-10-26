"""HTTP client for wscan — stdlib only, captures raw request/response + timing."""
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar

from .calibrate import waf_blocked

USER_AGENT = "Reconix/3.21 (authorized security testing)"
TIMEOUT = 12

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_ATTACKY = ("'", '"', "<", ">", ";", "--", "/*", "..", "union select",
            " or 1=", " and 1=", "sleep(", "alert(", "onload", "onerror")


def _benign_query(url):
    """True when the URL's query values carry no attack-looking content
    (plain navigation parameters, ids, slugs, search words)."""
    q = urllib.parse.urlsplit(url).query
    if not q:
        return True
    for _k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
        lv = urllib.parse.unquote_plus(v).lower()
        if any(tok in lv for tok in _ATTACKY):
            return False
    return True


def ensure_url_scheme(url, probe=True, timeout=6):
    """Return `url` carrying a scheme. A bare host is probed on https
    first: defaulting to http made scans of https-only sites crawl an
    empty redirect shell (1 page, 0 params — seen live 2026-10-16).
    Any HTTP answer on https, even 403/404, means https is alive;
    connection/SSL/timeout failures fall back to http. URLs that
    already carry a scheme pass through untouched."""
    url = (url or "").strip()
    if not url or "://" in url:
        return url
    if not probe:
        return "http://" + url
    cand = "https://" + url
    try:
        req = urllib.request.Request(
            cand, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(1024)
        return cand
    except urllib.error.HTTPError:
        return cand          # the server answered on https — it is alive
    except Exception:
        return "http://" + url


def redirect_location(url, timeout=8):
    """Location header of the first response, without following the
    redirect; None when the answer is not a redirect."""
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.headers.get("Location") if e.headers else None
    except Exception:
        return None


class Resp:
    __slots__ = ("status", "headers", "raw_headers", "body", "url",
                 "elapsed", "request_text")

    def __init__(self, status, headers, raw_headers, body, url, elapsed, request_text):
        self.status = status
        self.headers = headers            # dict, lower-case keys
        self.raw_headers = raw_headers    # list[(k, v)]
        self.body = body
        self.url = url
        self.elapsed = elapsed
        self.request_text = request_text

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)


def _decode(raw, headers):
    charset = "utf-8"
    if headers:
        m = re.search(r"charset=([\w-]+)", headers.get("content-type", ""))
        if m:
            charset = m.group(1)
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


class Client:
    def __init__(self, extra_headers=None, cookie=None, proxy=None, delay=0,
                 timeout=None):
        self.jar = CookieJar()
        self.delay = delay
        self.timeout = timeout or TIMEOUT
        # WAF-adaptive mode (engine enables): once a WAF block is seen,
        # pace requests like a human and retry blocked GET probes with
        # evasion encodings so checks judge the real response, not the
        # block page.
        self.adaptive = False
        self.waf_mode = False
        self.waf_hits = 0
        handlers = [
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=_ctx),
            _NoRedirect(),
        ]
        if proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)
        self.headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if extra_headers:
            self.headers.update(extra_headers)
        if cookie:
            self.headers["Cookie"] = cookie

    # -- low level ------------------------------------------------------
    def _send(self, url, method, body_bytes, headers):
        delay = self.delay
        if self.waf_mode:
            delay = max(delay, 0.35)  # human pace once a WAF engages
        if delay:
            time.sleep(delay)
        parts = urllib.parse.urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        req_text = "\r\n".join(lines)
        if body_bytes:
            req_text += "\r\n\r\n" + body_bytes.decode("utf-8", errors="replace")[:2000]
        req = urllib.request.Request(url, data=body_bytes, method=method, headers=headers)
        start = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read(3_000_000)
                elapsed = time.perf_counter() - start
                hdrs = [(k, v) for k, v in r.headers.items()]
                low = {k.lower(): v for k, v in hdrs}
                return Resp(r.status, low, hdrs, _decode(raw, low), url, elapsed, req_text)
        except urllib.error.HTTPError as e:
            elapsed = time.perf_counter() - start
            raw = e.read(3_000_000) if e.fp else b""
            hdrs = [(k, v) for k, v in (e.headers.items() if e.headers else [])]
            low = {k.lower(): v for k, v in hdrs}
            return Resp(e.code, low, hdrs, _decode(raw, low), url, elapsed, req_text)
        except Exception:
            return Resp(None, {}, [], "", url, time.perf_counter() - start, req_text)

    # -- public API -----------------------------------------------------
    def fetch(self, url, method="GET", data=None, headers=None, raw_body=None,
              content_type=None):
        hdrs = dict(self.headers)
        if headers:
            hdrs.update(headers)
        body = raw_body
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if content_type:
            hdrs["Content-Type"] = content_type
        resp = self._send(url, method, body, hdrs)
        if self.adaptive and method == "GET" and data is None \
                and raw_body is None and waf_blocked(resp):
            self.waf_mode = True
            self.waf_hits += 1
            # Transparent evasion is applied ONLY to benign-looking
            # requests (crawl/discovery traffic), so the real page can
            # still be reached through the WAF. Attack probes are
            # returned exactly as answered — the checks run their own
            # evasion variants and the engine re-tries blocked checks
            # in its quiet-retry phase; substituting here would change
            # what the checks are measuring.
            if _benign_query(url):
                variant = self._evasion_variant(url, hdrs)
                if variant is not None:
                    return variant
        return resp

    def _evasion_variant(self, url, hdrs):
        """A WAF ate the probe: retry the same GET with evasion
        encodings (double-encoding, SQL comment spacing). Returns the
        first response that is not a WAF block, else None."""
        parts = urllib.parse.urlsplit(url)
        if not parts.query:
            return None
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)

        def build(fn):
            q = urllib.parse.urlencode([(k, fn(v)) for k, v in pairs],
                                       quote_via=urllib.parse.quote)
            return urllib.parse.urlunsplit(parts._replace(query=q))

        variants = [
            lambda v: urllib.parse.quote(
                urllib.parse.unquote(v), safe=""),                    # double-enc
            lambda v: urllib.parse.unquote(v).replace(" ", "/**/"),  # comment
        ]
        for fn in variants:
            try:
                r = self._send(build(fn), "GET", None, hdrs)
            except Exception:
                continue
            if r.status is not None and not waf_blocked(r):
                return r
        return None

    def fetch_multipart(self, url, fields, files):
        """files: {field_name: (filename, content_bytes, content_type)}"""
        boundary = "----wscan" + uuid.uuid4().hex
        out = []
        for name, value in (fields or {}).items():
            out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                       f"name=\"{name}\"\r\n\r\n{value}\r\n".encode())
        for name, (fname, content, ctype) in (files or {}).items():
            out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                       f"name=\"{name}\"; filename=\"{fname}\"\r\n"
                       f"Content-Type: {ctype}\r\n\r\n".encode())
            out.append(content if isinstance(content, bytes) else content.encode())
            out.append(b"\r\n")
        out.append(f"--{boundary}--\r\n".encode())
        body = b"".join(out)
        hdrs = dict(self.headers)
        hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        return self._send(url, "POST", body, hdrs)

    def cookies(self):
        return [(c.name, c.value) for c in self.jar]
