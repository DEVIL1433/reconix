"""Passive analysis of crawled responses: secrets, source maps, methods,
TLS/redirect posture, stack traces, excessive data exposure, broken links."""
import json
import re
import urllib.parse
from html.parser import HTMLParser

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "High"),
    (r"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}", "Google API key", "Medium"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack token", "High"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key", "Critical"),
    (r"(?i)(?:api[_-]?key|secret|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{12,}['\"]",
     "Hardcoded credential in page/JS", "Medium"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "JWT exposed in page/JS", "Low"),
    (r"(?i)mongodb(\+srv)?://[^\s'\"]+:[^\s'\"]+@", "MongoDB connection string with credentials", "High"),
    (r"(?i)(?:postgres|mysql)://[^\s'\"]+:[^\s'\"]+@", "Database connection string with credentials", "High"),
]
STACK_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at [a-zA-Z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\)", "Java stack trace"),
    (r"Fatal error:.*on line \d+", "PHP fatal error"),
    (r"Microsoft OLE DB|ODBC SQL Server Driver", "ASP/ODBC error"),
    (r"Warning: [a-z_]+\(\) .*on line \d+", "PHP warning with file path"),
]
SENSITIVE_JSON_KEYS = {"password", "passwd", "password_hash", "passwd_hash",
                       "ssn", "credit_card", "card_number", "cvv", "secret",
                       "private_key", "api_key", "token_hash"}


JS_ENDPOINT_RES = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|"""
               r"""\$\.(?:get|post|ajax)|\.open\(\s*['"][A-Z]+['"]\s*,)"""
               r"""\s*\(?\s*[`'"](/[^`'"\s]+)[`'"]"""),
    re.compile(r"""[`'"](/api/[^`'"\s]+)[`'"]"""),
    re.compile(r"""[`'"](/v\d+/[^`'"\s]+)[`'"]"""),
    re.compile(r"""[`'"](/(?:graphql|rest|admin|internal)/[^`'"\s]*)[`'"]"""),
    re.compile(r"""url\s*:\s*[`'"](/[^`'"\s]+)[`'"]"""),
]


def extract_js_endpoints(text, page_url):
    """Pull API endpoints out of JS bundles (incl. template literals)."""
    out = set()
    for rx in JS_ENDPOINT_RES:
        for m in rx.finditer(text or ""):
            ep = m.group(1)
            ep = re.sub(r"\$\{[^}]+\}", "1", ep)   # ${id} -> 1
            ep = ep.split("`")[0].strip()
            if len(ep) > 2 and not ep.endswith(
                    (".js", ".css", ".png", ".svg", ".jpg", ".woff2")):
                out.add(urllib.parse.urljoin(page_url, ep))
    return out


def secrets_scan(ctx, pages, js_urls):
    """Returns API endpoints discovered inside JavaScript / source maps."""
    F, client = ctx.findings, ctx.client
    blobs = [(u, r.body or "") for u, r in pages]
    js_eps = set()
    for js in js_urls[:14]:
        r = client.fetch(js)
        if r.status == 200 and r.body:
            blobs.append((js, r.body))
            js_eps |= extract_js_endpoints(r.body, js)
            # source map exposure
            rm = client.fetch(js + ".map")
            if rm.status == 200 and rm.body and ('"sources"' in rm.body
                                                 or '"mappings"' in rm.body):
                F.add("Medium", "JavaScript Source Map Exposed", js + ".map",
                      "The .map file reveals original source code, comments "
                      "and file structure of the application.",
                      proof=rm.body[:140], resp=rm, cwe="CWE-540")
                try:
                    smap = json.loads(rm.body)
                    for content in smap.get("sourcesContent") or []:
                        if content:
                            js_eps |= extract_js_endpoints(content, js)
                except Exception:
                    pass
    for url, body in blobs:
        for pat, name, sev in SECRET_PATTERNS:
            m = re.search(pat, body)
            if m:
                F.add(sev, f"Sensitive Data Exposure: {name}", url,
                      f"Pattern for {name} found in a publicly served response. "
                      f"Rotate the credential if it is real.",
                      proof=m.group(0)[:80] + "…",
                      dedupe_key=("secret", name, url), cwe="CWE-798")
    return sorted(js_eps)



def methods_check(ctx, base):
    F, client = ctx.findings, ctx.client
    r = client.fetch(base, method="OPTIONS")
    allow = r.header("allow") or r.header("public")
    if allow:
        methods = [m.strip() for m in allow.split(",")]
        risky = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
        if risky:
            F.add("Low", f"Risky HTTP Methods Enabled: {', '.join(risky)}", base,
                  f"OPTIONS reports Allow: {allow}. PUT/DELETE can modify "
                  "resources; TRACE enables cross-site tracing.",
                  proof=f"Allow: {allow}", resp=r, cwe="CWE-650")
    r = client.fetch(base, method="TRACE")
    if r.status == 200 and "TRACE /" in (r.body or ""):
        F.add("Medium", "HTTP TRACE Method Enabled (XST)", base,
              "TRACE echoes the request back; combined with XSS it can leak "
              "HttpOnly cookies on legacy stacks.",
              proof="TRACE request echoed in response", resp=r, cwe="CWE-693")


def transport_check(ctx, base):
    """HTTPS redirect + plaintext-login posture."""
    F, client = ctx.findings, ctx.client
    parts = urllib.parse.urlsplit(base)
    if parts.scheme == "https":
        http_url = f"http://{parts.netloc}{parts.path or '/'}"
        r = client.fetch(http_url)
        loc = r.header("location")
        if not (r.status in (301, 302, 308) and loc.startswith("https://")):
            F.add("Medium", "No HTTP -> HTTPS Redirect", base,
                  "The plain-HTTP version does not force-redirect to HTTPS.",
                  proof=f"GET {http_url} -> {r.status}", resp=r, cwe="CWE-319")
    elif parts.scheme == "http":
        F.add("Info", "Site Served Over Plain HTTP", base,
              "Target is HTTP; if it handles credentials, they travel "
              "unencrypted.", dedupe_key=("plainhttp",), cwe="CWE-319")


def redirect_chain(ctx, base):
    """Follow the chain manually (client doesn't auto-follow) and report."""
    F, client = ctx.findings, ctx.client
    url, chain = base, []
    for _ in range(6):
        r = client.fetch(url)
        chain.append((url, r.status))
        if r.status in (301, 302, 303, 307, 308) and r.header("location"):
            url = urllib.parse.urljoin(url, r.header("location"))
            parts = urllib.parse.urlsplit(url)
            if parts.netloc and parts.netloc != urllib.parse.urlsplit(base).netloc:
                F.add("Info", "Redirect Chain Leaves the Site", base,
                      "Chain: " + " -> ".join(f"{u} [{s}]" for u, s in chain),
                      proof=f"final external: {url}", cwe="CWE-601")
                return
        else:
            break
    if len(chain) > 3:
        F.add("Info", "Long Redirect Chain", base,
              f"{len(chain)} hops: " + " -> ".join(u for u, _s in chain),
              cwe="CWE-400")


def stack_trace_scan(ctx, pages):
    F = ctx.findings
    for url, r in pages:
        for pat, name in STACK_PATTERNS:
            if re.search(pat, r.body or ""):
                F.add("Low", f"Error Disclosure: {name}", url,
                      "Full error details leak internals (paths, framework, "
                      "line numbers) that help an attacker.",
                      proof=re.search(pat, r.body).group(0)[:120],
                      dedupe_key=("stack", name, url), resp=r, cwe="CWE-209")
                break


def cache_control_scan(ctx, pages):
    F = ctx.findings
    for url, r in pages:
        cc = r.header("cache-control")
        has_cookie = any(k.lower() == "set-cookie" for k, _v in r.raw_headers)
        if has_cookie and (not cc or "no-store" not in cc):
            F.add("Low", "Sensitive Page Cacheable", url,
                  "Pages that set cookies lack Cache-Control: no-store — "
                  "sensitive content may persist in browser/proxy caches "
                  "(reported once; observed across the crawl).",
                  proof=f"Cache-Control: {cc or '(absent)'}", resp=r,
                  dedupe_key=("cc",), cwe="CWE-524")


def excessive_data_scan(ctx, pages):
    """JSON responses exposing sensitive fields to any caller."""
    F = ctx.findings
    for url, r in pages:
        ct = r.header("content-type")
        if "json" not in ct:
            continue
        try:
            data = json.loads(r.body)
        except Exception:
            continue
        keys = set()

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.lower() in SENSITIVE_JSON_KEYS:
                        keys.add(k)
                    walk(v)
            elif isinstance(o, list):
                for v in o[:5]:
                    walk(v)
        walk(data)
        if keys:
            F.add("Medium", "API Excessive Data Exposure", url,
                  "The JSON response includes sensitive field(s): "
                  + ", ".join(sorted(keys)) + " — returned to any caller; "
                  "filter server-side, never rely on the client to hide them.",
                  proof="keys: " + ", ".join(sorted(keys)), resp=r,
                  dedupe_key=("excess", url), cwe="CWE-213")


_SRI_VALUE = re.compile(r"^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$")


class _AssetParser(HTMLParser):
    """Collects <script src> and stylesheet <link href> tags with
    their integrity / crossorigin attributes (the crawl parser drops
    both, and this check needs them)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.assets = []  # (kind, url, integrity, crossorigin)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.assets.append(("script", a["src"],
                                a.get("integrity", ""),
                                a.get("crossorigin", "")))
        elif tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower()
            as_attr = (a.get("as") or "").lower()
            if "stylesheet" in rel or ("preload" in rel
                                      and as_attr in ("script", "style")):
                self.assets.append(("stylesheet", a["href"],
                                    a.get("integrity", ""),
                                    a.get("crossorigin", "")))


def third_party_integrity_scan(ctx, pages):
    """Subresource Integrity (SRI) for third-party assets — OWASP
    Top 10:2025 A03/A08 supply-chain coverage, previously absent:
    a script or stylesheet loaded from another origin runs in the
    page's origin, so a compromised CDN (or a hijacked DNS record)
    turns into code execution on this site unless the browser can
    verify the file against a hash the site pinned.

    Passive only: the evidence is the tag itself in a crawled page —
    no third-party asset is fetched. Same-origin assets are skipped
    (SRI buys nothing there: the same origin that serves the page
    serves the file), as are data:/blob: URLs. One finding per
    asset per issue, so a shared header script is not reported once
    per page."""
    F = ctx.findings
    for page_url, r in pages:
        body = r.body if hasattr(r, "body") else ""
        if not body:
            continue
        parser = _AssetParser()
        try:
            parser.feed(body)
        except Exception:
            continue
        page_host = urllib.parse.urlsplit(page_url).netloc.lower()
        for kind, src, integrity, crossorigin in parser.assets:
            asset = urllib.parse.urljoin(page_url, src)
            parts = urllib.parse.urlsplit(asset)
            if parts.scheme not in ("http", "https"):
                continue
            if parts.netloc.lower() == page_host:
                continue
            label = "Script" if kind == "script" else "Stylesheet"
            if not integrity:
                F.add("Medium" if kind == "script" else "Low",
                      f"Third-Party {label} Without Subresource Integrity",
                      page_url,
                      f"This page loads a {kind} from another origin "
                      f"({parts.netloc}) with no integrity attribute. If "
                      "that third party is compromised, its code runs "
                      "here with this site's authority and nothing on "
                      "this page can tell it changed. Pin a hash "
                      "(integrity + crossorigin=\"anonymous\") or "
                      "self-host the file.",
                      proof=f"<{kind} src=\"{asset}\"> — no integrity "
                            f"attribute",
                      param=asset, resp=r, cwe="CWE-829",
                      dedupe_key=("sri-missing", asset))
            elif not all(_SRI_VALUE.match(tok)
                         for tok in integrity.split()):
                F.add("Medium",
                      "Invalid Subresource Integrity Value",
                      page_url,
                      f"The {kind} from {parts.netloc} carries an "
                      "integrity attribute the browser cannot use "
                      "(expected sha256/sha384/sha512 + base64 hash), "
                      "so the file is effectively unverified — the "
                      "same exposure as no integrity at all.",
                      proof=f"integrity=\"{integrity}\"",
                      param=asset, resp=r, cwe="CWE-829",
                      dedupe_key=("sri-invalid", asset))
            elif not crossorigin:
                F.add("Medium",
                      "Subresource Integrity Ignored: Missing crossorigin",
                      page_url,
                      f"The {kind} from {parts.netloc} pins a hash but "
                      "has no crossorigin attribute, so the browser "
                      "does not perform the SRI check on a cross-origin "
                      "fetch and a tampered file still executes. Add "
                      "crossorigin=\"anonymous\".",
                      proof=f"integrity=\"{integrity}\" — no crossorigin",
                      param=asset, resp=r, cwe="CWE-829",
                      dedupe_key=("sri-nocors", asset))


def broken_links_scan(ctx, pages):
    F = ctx.findings
    bad = [u for u, r in pages if r.status in (404, 410)]
    if bad:
        F.add("Info", "Broken Links Found", bad[0],
              f"{len(bad)} crawled URL(s) returned 404/410: "
              + ", ".join(bad[:8]), dedupe_key=("broken",))
