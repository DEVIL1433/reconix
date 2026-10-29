"""Core: findings store with proof + PoC generation, HTML parsing, crawler."""
import hashlib
import html
import json
import re
import shlex
import threading
import urllib.parse
from .explain import explain
from html.parser import HTMLParser


def fingerprint_of(f):
    """Stable identity of a finding across scans (for diff / FP tracking)."""
    raw = f"{f.get('title','')}|{f.get('url','')}|{f.get('param','')}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

REMEDIATION = {
    "SQL Injection": "Use parameterized queries / prepared statements everywhere; never concatenate user input into SQL. Apply least-privilege DB accounts.",
    "Cross-Site Scripting": "Context-aware output encoding on every reflection; deploy a strict Content-Security-Policy as defense in depth.",
    "Command Injection": "Never pass user input to a shell. Use argument arrays without shell=True and an allow-list of permitted values.",
    "Server-Side Template Injection": "Never render user input as a template. Use logic-less templates or sandbox the engine; treat templates as code.",
    "Local File Inclusion": "Never build file paths from user input. Map input to an allow-list of files and confine reads to a base directory.",
    "Server-Side Request Forgery": "Allow-list outbound destinations; block private/loopback/link-local ranges (incl. 169.254.169.254) and re-validate after redirects.",
    "XML External Entity": "Disable DTDs and external entities in the XML parser (disallow DOCTYPE / resolve_entities=False).",
    "Open Redirect": "Never redirect to raw user-supplied URLs. Use an allow-list of internal paths.",
    "CRLF Injection": "Strip CR/LF from any user input placed into response headers; use framework header APIs.",
    "Cross-Origin Resource Sharing": "Never reflect arbitrary Origin values; allow-list trusted origins, especially with credentials.",
    "File Upload": "Validate extension AND content server-side, rename uploads, store outside the web root, never execute files in the upload directory.",
    "JSON Web Token": "Use a strong (>=256-bit) random secret or asymmetric keys; pin the algorithm server-side; never accept alg=none.",
    "GraphQL": "Disable introspection in production; add query depth/cost limits and per-field authorization.",
    "Sensitive File": "Remove the file from the web root, deny access via server config, and rotate any secrets it contained.",
    "Security Header": "Set the header at the server/framework level (see detail) and verify with a response audit.",
    "Cookie": "Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",
    "Directory Listing": "Disable autoindex/directory browsing in the web server configuration.",
    "Host Header Injection": "Validate the Host header against an allow-list; never build absolute URLs (e.g. password resets) from an unvalidated Host.",
    "DOM XSS": "Never assign untrusted data (location.*, postMessage, etc.) to dangerous sinks (innerHTML, document.write, eval). Use textContent and sanitize with DOMPurify where HTML is required.",
    "Version Disclosure": "Suppress version banners (Server, X-Powered-By, generator meta) and patch the disclosed component.",
    "Discovered Content": "Review whether this path should be publicly reachable; protect or remove it.",
    "403 Forbidden Bypass": "Enforce authorization on the origin for every path variant: normalize the path (case, URL encoding, dot segments, trailing separators) BEFORE the access check, and never trust client-supplied URL-override (X-Original-URL / X-Rewrite-URL) or forwarded-IP headers unless they come from a verified proxy. Deny by default.",
}


def remediation_for(title):
    for key, text in REMEDIATION.items():
        if key.lower() in title.lower():
            return text
    return "Review the affected component, validate/encode the implicated input server-side, and retest."


def make_poc(resp, method=None, url=None, data=None):
    """Build curl + python PoCs from the request that proved the finding."""
    if resp is None:
        return "", ""
    req = resp.request_text
    first = req.split("\r\n", 1)[0]
    m = re.match(r"(\w+) (\S+) HTTP", first)
    verb = method or (m.group(1) if m else "GET")
    full_url = url or resp.url
    headers = []
    body = ""
    if "\r\n\r\n" in req:
        head, body = req.split("\r\n\r\n", 1)
    else:
        head = req
    for line in head.split("\r\n")[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            if k.lower() not in ("host", "content-length"):
                headers.append((k, v))
    curl = [f"curl -i -X {verb}"]
    for k, v in headers:
        curl.append(f"  -H {shlex.quote(f'{k}: {v}')}")
    if body:
        curl.append(f"  --data {shlex.quote(body)}")
    curl.append(f"  {shlex.quote(full_url)}")
    curl_cmd = " \\\n".join(curl)
    py = ["import requests", ""]
    hdr_dict = "{" + ", ".join(f"{k!r}: {v!r}" for k, v in headers) + "}"
    if body:
        py.append(f"r = requests.request({verb!r}, {full_url!r}, headers={hdr_dict}, "
                  f"data={body!r}, verify=False)")
    else:
        py.append(f"r = requests.request({verb!r}, {full_url!r}, headers={hdr_dict}, verify=False)")
    py.append("print(r.status_code)")
    py.append("print(r.text[:2000])")
    return curl_cmd, "\n".join(py)


class Findings:
    def __init__(self, on_add=None, suppress=None):
        self.items = []
        self.lock = threading.Lock()
        self.on_add = on_add
        self._seen = set()
        self.suppress = suppress or set()
        self.suppressed_count = 0
        self.suppressed_items = []

    def add(self, severity, title, url, detail, proof="", param="",
            confidence="Confirmed", resp=None, cwe="", dedupe_key=None,
            payload=""):
        key = dedupe_key or (title, url, param)
        with self.lock:
            if key in self._seen:
                return None
            self._seen.add(key)
            fp = fingerprint_of({"title": title, "url": url, "param": param})
            if fp in self.suppress:
                self.suppressed_count += 1
                self.suppressed_items.append(
                    {"title": title, "url": url, "param": param,
                     "severity": severity, "fp": fp})
                return None
            poc_curl, poc_py = make_poc(resp, url=url)
            f = {
                "id": len(self.items) + 1, "fp": fp,
                "severity": severity, "confidence": confidence,
                "title": title, "cwe": cwe, "url": url, "param": param,
                "detail": detail, "about": explain(title),
                "payload": (payload or "")[:1500],
                "proof": (proof or "")[:1500],
                "remediation": remediation_for(title),
                "status_code": resp.status if resp else None,
                "request": resp.request_text if resp else "",
                "response_snippet": (resp.body[:1200] if resp else ""),
                "poc_curl": poc_curl, "poc_python": poc_py,
            }
            self.items.append(f)
            if self.on_add:
                self.on_add(f)
            return f

    def sorted(self):
        return sorted(self.items, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))

    def counts(self):
        c = {s: 0 for s in SEVERITIES}
        for f in self.items:
            c[f["severity"]] = c.get(f["severity"], 0) + 1
        return c


# ---------------------------------------------------------------- parsing

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts = [], [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "GET").upper(),
                          "enctype": a.get("enctype", ""),
                          "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append(
                    {"name": name, "type": (a.get("type") or "text").lower(),
                     "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_page(body):
    p = PageParser()
    try:
        p.feed(body or "")
    except Exception:
        pass
    return p


# ---------------------------------------------------------------- crawler

def crawl(client, base, max_pages=60, max_depth=3, on_page=None):
    base_host = urllib.parse.urlsplit(base).netloc
    seen, queue = set(), [(base, 0)]
    pages, forms, js_urls = [], [], set()
    sitemap = {}
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        url = url.split("#")[0]
        if url in seen:
            continue
        seen.add(url)
        resp = client.fetch(url)
        if resp.status is None:
            continue
        pages.append((url, resp))
        if on_page:
            on_page(url, resp)
        if depth >= max_depth:
            continue
        parsed = parse_page(resp.body)
        for form in parsed.forms:
            forms.append((url, form))
        outlinks = []
        for src in parsed.scripts:
            js = urllib.parse.urljoin(url, src)
            if urllib.parse.urlsplit(js).netloc == base_host:
                js_urls.add(js)
        for href in parsed.links:
            nxt = urllib.parse.urljoin(url, href)
            p = urllib.parse.urlsplit(nxt)
            if p.scheme in ("http", "https") and p.netloc == base_host:
                clean = nxt.split("#")[0]
                outlinks.append(clean)
                if clean not in seen:
                    queue.append((clean, depth + 1))
        sitemap[url] = sorted(set(outlinks))
    return pages, forms, sorted(js_urls), sitemap


def params_of(url):
    return urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                  keep_blank_values=True)


def with_param(url, name, value):
    parts = urllib.parse.urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in
             urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    return urllib.parse.urlunsplit(
        parts._replace(query=urllib.parse.urlencode(pairs)))


def esc(s):
    return html.escape(str(s or ""))
