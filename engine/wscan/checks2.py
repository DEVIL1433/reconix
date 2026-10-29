"""Second-wave checks: CSRF, RFI, NoSQL/LDAP injection, session weaknesses,
default credentials, IDOR (dual session), cache poisoning, rate limiting, race."""
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .core import params_of, parse_page, with_param
from .checks import _sim, smart_value
from .calibrate import normalize as _normalize
from .client import Client as _ThrowawayClient

TOKEN_NAMES = re.compile(r"csrf|xsrf|token|authenticity|__requestverification|"
                         r"_wpnonce|nonce", re.I)
FAILED_WORDS = ("invalid", "incorrect", "failed", "wrong password",
                "authentication failed", "access denied", "bad credentials")
SUCCESS_WORDS = ("logout", "log out", "dashboard", "welcome", "sign out",
                 "my account")


# ------------------------------------------------------------------ CSRF

def csrf_check(ctx, page_url, form):
    F = ctx.findings
    if form["method"] != "POST":
        return
    names = [i["name"] for i in form["inputs"]]
    if any(TOKEN_NAMES.search(n) for n in names):
        return
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)
    inputs = "".join(
        f'<input type="hidden" name="{i["name"]}" value="attacker-controlled">'
        for i in form["inputs"] if i["type"] not in ("submit", "button", "file"))
    poc = (f'<html><body onload="document.forms[0].submit()">'
           f'<form action="{action}" method="POST">{inputs}</form></body></html>')
    f = F.add("Medium", "Possible CSRF (no anti-CSRF token)", action,
              f"The POST form on {page_url} has no anti-CSRF token field "
              f"({', '.join(names) or 'no fields'}). If the session cookie also "
              f"lacks SameSite protection, a malicious page can submit it "
              f"cross-origin. An auto-submit PoC page is attached.",
              proof=f"form fields: {', '.join(names)}", param="(form)",
              confidence="Needs manual confirmation", cwe="CWE-352")
    if f:
        f["poc_html"] = poc
        f["poc_python"] = "# Save the PoC as csrf.html, host it anywhere, and\n" \
                          "# visit it while logged in — the form submits itself."


# ------------------------------------------------------------------ RFI

def rfi_url(ctx, url):
    client, F = ctx.client, ctx.findings
    from .checks import URLISH_NAMES
    for name, orig in params_of(url):
        if name.lower() not in URLISH_NAMES and not orig.startswith(("http",)):
            continue
        token = ctx.oob.new_token()
        probe = ctx.oob.url(token) + "/rfi.txt"
        r = client.fetch(with_param(url, name, probe))
        if r.status and f"OOBMARK-{token}" in (r.body or ""):
            F.add("Critical", "Remote File Inclusion (RFI)", url,
                  f"Parameter '{name}' includes and EXECUTES/EMBEDS a remote "
                  f"file from an attacker server (OOB content in response).",
                  proof=f"OOB content marker OOBMARK-{token} embedded in response",
                  param=name, resp=r, cwe="CWE-98", payload=probe)
            return


# ------------------------------------------------------------------ NoSQL / LDAP

NOSQL_ERRORS = [r"MongoError", r"CastError", r"MongoServerError",
                r"failed to parse.*json", r"\$ne", r"BSON"]
LDAP_ERRORS = [r"LDAP", r"javax\.naming", r"Invalid DN", r"ldap_search",
               r"Operations error", r"ADSI"]


def nosql_url(ctx, url):
    client, F = ctx.client, ctx.findings
    for name, _orig in params_of(url):
        # operator injection via name[$ne]= style params
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        probe_pairs = [(k, v) for k, v in pairs if k != name]
        probe_pairs.append((f"{name}[$ne]", "wscaninvalid"))
        probe_url = urllib.parse.urlunsplit(
            parts._replace(query=urllib.parse.urlencode(probe_pairs)))
        base = client.fetch(url)
        r = client.fetch(probe_url)
        if not (r.status and base.status):
            continue
        hit = next((p for p in NOSQL_ERRORS if re.search(p, r.body or "")), "")
        sim = _sim(ctx, base.body, r.body)
        if hit or (r.status == 200 and sim > 0.9 and len(r.body) > 200):
            F.add("Medium", "Possible NoSQL Injection (operator injection)", url,
                  f"Parameter '{name}' accepts Mongo-style operators "
                  f"({name}[$ne]) — the response "
                  + (f"leaks a driver error ({hit})." if hit else
                     "closely matches the full-result baseline, suggesting the "
                     "operator was evaluated."),
                  proof=hit or f"similarity to baseline: {sim:.2f}",
                  param=name, resp=r, confidence="Needs manual confirmation",
                  cwe="CWE-943", payload=f"{name}[$ne]=wscaninvalid")
            return


def ldap_url(ctx, url):
    client, F = ctx.client, ctx.findings
    for name, orig in params_of(url):
        base = client.fetch(url)
        for probe in ("*", "admin)(&)", ")(|(cn=*))"):
            r = client.fetch(with_param(url, name, probe))
            hit = next((p for p in LDAP_ERRORS
                        if re.search(p, r.body or "", re.I)), "")
            if r.status and hit and hit not in (base.body or ""):
                F.add("Medium", "Possible LDAP Injection", url,
                      f"Wildcard probe in parameter '{name}' triggers an LDAP "
                      f"error/signature ({hit}).",
                      proof=hit, param=name, resp=r, payload=probe,
                      confidence="Needs manual confirmation", cwe="CWE-90")
                return


# ------------------------------------------------------------------ session

def session_checks(ctx, base, pages):
    """Session fixation / rotation heuristics using the crawl cookie jar."""
    F, client = ctx.findings, ctx.client
    cookies = dict(client.cookies())
    if not cookies:
        return
    # does the app hand out a session cookie pre-auth and never rotate it?
    sess = {k: v for k, v in cookies.items()
            if re.search(r"sess|sid|phpsessid|asp\.net_sessionid|jsessionid",
                         k, re.I)}
    if sess:
        name = next(iter(sess))
        F.add("Info", "Session Cookie Issued Pre-Authentication", base,
              f"Cookie '{name}' is set for anonymous visitors. Verify it is "
              f"ROTATED after login — if the same value works post-login, the "
              f"app is open to session fixation.",
              param=f"cookie:{name}",
              confidence="Needs manual confirmation", cwe="CWE-384")


# ------------------------------------------------------------------ default creds

DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                 ("admin", "admin123"), ("administrator", "administrator"),
                 ("root", "root"), ("test", "test"), ("user", "user"),
                 ("demo", "demo"), ("guest", "guest")]


def default_creds_check(ctx, page_url, form):
    """Opt-in only (opts.auth_test). Tries a tiny default-credential list.
    Runs on a THROWAWAY client: posting logins through the shared session
    would contaminate the cookie jar that IDOR/session/matrix phases
    depend on."""
    F = ctx.findings
    client = _ThrowawayClient(proxy=ctx.opts.get("proxy"))
    pw_fields = [i["name"] for i in form["inputs"] if i["type"] == "password"]
    user_fields = [i["name"] for i in form["inputs"]
                   if i["type"] in ("text", "email")]
    if not pw_fields or not user_fields:
        return
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)

    def attempt(user, pw):
        data = {i["name"]: (i["value"] or smart_value(i["name"], i["type"]))
                for i in form["inputs"]
                if i["type"] not in ("submit", "button", "file")}
        data[user_fields[0]] = user
        data[pw_fields[0]] = pw
        if form["method"] == "POST":
            return client.fetch(action, method="POST", data=data)
        return client.fetch(action + "?" + urllib.parse.urlencode(data))

    baseline = attempt("wscan_no_such_user_7391", "wscan_wrong_7391")
    for user, pw in DEFAULT_CREDS:
        r = attempt(user, pw)
        body = (r.body or "").lower()
        failed = any(w in body for w in FAILED_WORDS)
        success_signs = any(w in body for w in SUCCESS_WORDS)
        redirected = r.status in (301, 302, 303) and \
            "login" not in r.header("location")
        differs = abs(len(r.body or "") - len(baseline.body or "")) > 120
        success = (not failed and r.status == 200
                   and (success_signs or redirected or differs))
        if success:
            F.add("Critical", "Default Credentials Accepted", action,
                  f"The login form accepts default credentials "
                  f"'{user}' / '{pw}'. Anyone can sign in.",
                  proof=f"login {user}:{pw} -> HTTP {r.status}, "
                        f"success indicators: {success_signs or redirected}",
                  param=user_fields[0], resp=r, cwe="CWE-798")
            return
        if ctx.stop.is_set():
            return


# ------------------------------------------------------------------ IDOR

def idor_check(ctx, param_urls):
    """Dual-session: replay user A's numeric-ID URLs with session B / anon."""
    F = ctx.findings
    client_b = ctx.client_b
    client_anon = ctx.client_anon
    if client_b is None and client_anon is None:
        return
    import re as _re
    for url in param_urls:
        for name, val in params_of(url):
            if not _re.fullmatch(r"\d{1,10}", val or ""):
                continue
            a = ctx.client.fetch(url)
            if a.status != 200 or len(a.body or "") < 80:
                continue
            for label, other in (("second session", client_b),
                                 ("anonymous", client_anon)):
                if other is None:
                    continue
                b = other.fetch(url)
                if b.status == 200 and _sim(ctx, a.body, b.body) > 0.9:
                    F.add("High", "Possible IDOR / Broken Access Control", url,
                          f"Resource '{name}={val}' fetched with the primary "
                          f"session is equally readable by a {label} "
                          f"(>90% identical response). If the object belongs "
                          f"to the first user, authorization is missing.",
                          proof=f"A vs {label}: both HTTP 200, similarity "
                                f"{_sim(ctx, a.body, b.body):.2f}",
                          param=name, resp=b,
                          confidence="Needs manual confirmation", cwe="CWE-639")
                    break
            # sequential-ID enumerability (same session)
            try:
                nxt = with_param(url, name, str(int(val) + 1))
            except ValueError:
                continue
            r2 = ctx.client.fetch(nxt)
            if r2.status == 200 and len(r2.body or "") > 80 and \
                    _sim(ctx, a.body, r2.body) < 0.98:
                F.add("Info", "Sequential Object IDs Enumerable", url,
                      f"Incrementing '{name}' ({val} -> {int(val)+1}) returns "
                      "another object. Combined with missing authorization "
                      "this is full IDOR enumeration.",
                      param=name, resp=r2, cwe="CWE-639")
            break  # one numeric param per URL is enough


# ------------------------------------------------------------------ cache poisoning

def cache_poison_check(ctx, base):
    F, client = ctx.findings, ctx.client
    poison = "wscan-poison.example"
    client.fetch(base, headers={"X-Forwarded-Host": poison,
                                "X-Host": poison})
    r = client.fetch(base)
    if poison in (r.body or ""):
        F.add("High", "Web Cache Poisoning (unkeyed Host header)", base,
              "A request with a forged X-Forwarded-Host was stored/reflected "
              "such that a subsequent NORMAL request still contains the "
              "attacker host — poisoned cache entry.",
              proof=f"clean follow-up request contains {poison}",
              resp=r, cwe="CWE-525")


# ------------------------------------------------------------------ rate limit / race

def rate_limit_check(ctx, base):
    F, client = ctx.findings, ctx.client
    target = base  # a URL that demonstrably exists — never a guessed path
    statuses = []
    for _ in range(25):
        r = client.fetch(target)
        statuses.append(r.status)
        if r.status is None:
            break
    ok = sum(1 for s in statuses if s == 200)
    if ok >= 25:
        F.add("Info", "No Rate Limiting Observed (burst test)", target,
              "25 rapid requests all succeeded with no throttling (no 429). "
              "If this endpoint is sensitive (login, OTP, search), brute "
              "force is unconstrained.",
              proof=f"statuses: {statuses[:10]}... all 200",
              confidence="Needs manual confirmation", cwe="CWE-770")


def race_check(ctx, param_urls):
    F = ctx.findings
    if not param_urls:
        return
    url = param_urls[0]
    results = {}
    lock = threading.Lock()

    def hit():
        r = ctx.client.fetch(url)
        key = (r.status, hash(_normalize(r.body or "")[:4000]))
        with lock:
            results[key] = results.get(key, 0) + 1
    with ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(lambda _i: hit(), range(12)))
    distinct = [k for k, v in results.items() if k[0] == 200]
    if len(distinct) > 1:
        F.add("Info", "Inconsistent Responses Under Concurrency", url,
              f"12 parallel identical requests produced {len(distinct)} "
              "different successful responses — a possible race condition / "
              "shared-state bug worth manual testing.",
              proof=f"distinct 200-response shapes: {len(distinct)}",
              confidence="Needs manual confirmation", cwe="CWE-362")
