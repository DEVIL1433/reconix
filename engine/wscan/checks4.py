"""Fourth-wave checks (Reconix 3.10): 403 Forbidden bypass.

When a page answers 403, the access control and the content often live
in different layers (edge proxy vs origin, path normalization, trusted
proxy headers). This check runs the standard evasion battery — path
mutations, URL-override / trusted-IP headers, method change — and only
reports when the protected content actually comes back: 2xx, a body
genuinely different from the 403 page, not the site's soft-404 page,
not a login wall, and a control path fetched with the same technique
must NOT produce the same content (catch-all guard)."""
import re
import urllib.parse

from .calibrate import similarity

MAX_URLS = 12          # forbidden pages to work on per scan
MAX_ATTEMPTS = 300     # total bypass requests per scan

_SENSITIVE = re.compile(
    r"(admin|manage|console|config|backup|\.git|internal|private|"
    r"wp-admin|phpmyadmin|actuator|dashboard|control|vault|secret|"
    r"finance|export)", re.I)
_BODY_MARKERS = ("confidential", "internal use", "internal only",
                 "do not distribute", "restricted area")

_IP_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization",
               "True-Client-IP", "CF-Connecting-IP", "X-Client-IP")


def _path_variants(path):
    """(label, mutated path) — server/parser normalization mismatches."""
    out = []

    def add(label, p):
        if p and p != path and all(p != x[1] for x in out):
            out.append((label, p))

    seg = path.rstrip("/").rsplit("/", 1)[-1]
    add("trailing slash", path + "/")
    add("dot-segment prefix", "/." + path)
    add("trailing dot-segment", path.rstrip("/") + "/.")
    add("semicolon suffix", path + ";")
    add("Tomcat ..; suffix", path.rstrip("/") + "..;/")
    add("double slash", "/" + path)
    if seg:
        add("uppercase last segment",
            path[:len(path) - len(seg)] + seg.upper())
        c = seg[0]
        enc = "%%%02X" % ord(c)
        add("URL-encoded first character",
            path[:len(path) - len(seg)] + enc + seg[1:])
        add("double-encoded first character",
            path[:len(path) - len(seg)] + "%25" + enc[1:] + seg[1:])
    add("backslash separator", "\\" + path.lstrip("/"))
    add(".json extension", path + ".json")
    add("trailing space (%20)", path + "%20")
    add("trailing tab (%09)", path + "%09")
    add("null byte (%00)", path + "%00")
    return out


def _is_login_wall(body):
    low = (body or "").lower()
    return ('type="password"' in low or "type='password'" in low) and \
        any(w in low for w in ("login", "log in", "sign in", "username"))


def _content_proof(ctx, base403, r):
    """True when r looks like the real protected content, not a block
    page, soft-404, login wall, or empty stub."""
    if r is None or r.status not in (200, 201, 206):
        return False
    body = r.body or ""
    if len(body.strip()) < 30:
        return False
    if base403 is not None and similarity(body, base403.body or "") > 0.85:
        return False
    if ctx.calibrator is not None and ctx.calibrator.is_soft404(r):
        return False
    if _is_login_wall(body):
        return False
    return True


def bypass403_check(ctx, pages):
    F, client = ctx.findings, ctx.client
    candidates, seen = [], set()
    for url, resp in pages:
        if resp is not None and resp.status == 403 and url not in seen:
            seen.add(url)
            candidates.append(url)
    candidates = candidates[:MAX_URLS]
    if not candidates:
        return
    attempts = [0]

    def fetch(url, **kw):
        attempts[0] += 1
        return client.fetch(url, **kw)

    for url in candidates:
        if ctx.stop.is_set() or attempts[0] >= MAX_ATTEMPTS:
            return
        parts = urllib.parse.urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        path = parts.path or "/"
        base = fetch(url)
        if base.status != 403:
            continue  # state changed since the crawl — nothing to bypass
        # control path: a sibling that must NOT yield the same content
        parent = path.rstrip("/").rsplit("/", 1)[0]
        control = origin + parent + "/reconix-nonexistent-7391"
        won = None  # (label, resp)

        # 1) path mutations (query dropped — ACLs live on the path)
        for label, mpath in _path_variants(path):
            if ctx.stop.is_set() or attempts[0] >= MAX_ATTEMPTS:
                break
            murl = urllib.parse.urlunsplit(
                parts._replace(path=mpath, query=""))
            r = fetch(murl)
            if _content_proof(ctx, base, r):
                won = (f"path mutation ({label})", r, ("path", label))
                break

        # 2) URL-override headers against the site root
        if won is None:
            for hdr in ("X-Original-URL", "X-Rewrite-URL"):
                if ctx.stop.is_set() or attempts[0] >= MAX_ATTEMPTS:
                    break
                r = fetch(origin + "/", headers={hdr: path})
                if _content_proof(ctx, base, r):
                    won = (f"{hdr} header", r, ("root_header", hdr))
                    break

        # 3) trusted-proxy / client-IP headers on the original URL
        if won is None:
            hdrs = [(h, {h: "127.0.0.1"}) for h in _IP_HEADERS]
            hdrs.append(("Referer (self)",
                         {"Referer": origin + path}))
            for label, h in hdrs:
                if ctx.stop.is_set() or attempts[0] >= MAX_ATTEMPTS:
                    break
                r = fetch(url, headers=h)
                if _content_proof(ctx, base, r):
                    won = (f"{label} header", r, ("ip_header", h))
                    break

        # 4) method change
        if won is None and attempts[0] < MAX_ATTEMPTS:
            r = fetch(url, method="POST", data={})
            if _content_proof(ctx, base, r):
                won = ("POST instead of GET", r, ("method", None))

        if won is None:
            continue
        label, r, kind = won

        # catch-all guard: the same trick on a nonexistent sibling
        # must not serve the same content
        if attempts[0] < MAX_ATTEMPTS:
            if kind[0] == "path":
                cpath = urllib.parse.urlsplit(control).path
                cmut = dict(_path_variants(cpath)).get(kind[1], cpath)
                cr = fetch(urllib.parse.urlunsplit(urllib.parse.urlsplit(
                    control)._replace(path=cmut)))
            elif kind[0] == "root_header":
                cr = fetch(origin + "/", headers={
                    kind[1]: urllib.parse.urlsplit(control).path})
            elif kind[0] == "ip_header":
                cr = fetch(control, headers=kind[1])
            else:
                cr = fetch(control, method="POST", data={})
            if cr.status in (200, 201, 206) and \
                    similarity(cr.body or "", r.body or "") > 0.85:
                continue  # catch-all site — not a bypass

        body = r.body or ""
        high = bool(_SENSITIVE.search(path)) or \
            any(m in body.lower() for m in _BODY_MARKERS)
        F.add("High" if high else "Medium", "403 Forbidden Bypass", url,
              f"This URL answers 403 Forbidden to a normal request, "
              f"but the {label} technique retrieved the protected "
              f"content (HTTP {r.status}, {len(body)} bytes). The "
              f"access control is enforced inconsistently — anyone "
              f"can read this page with the same trick.",
              proof=f"GET {path} -> 403 ({len(base.body or '')} "
                    f"bytes); {label} -> {r.status} "
                    f"({len(body)} bytes)",
              resp=r, cwe="CWE-863")
