"""403 Access-Control Assessment Engine (Reconix 3.14).

Standalone module — NOT part of any scan profile. It runs only when the
operator opens the 403 Tester, ticks the authorization confirmation,
defines the scope, and starts it against explicit target URLs.

Two modes:

Mode A — 403 Diagnostics. For each URL that answers 403, identify WHO
denied the request (F5 BIG-IP ASM, another CDN/WAF, a reverse proxy,
the application, or an authentication layer — only when evidence
supports it), preserve the exact original response (status, headers,
body, redirect chain, timing, request identifiers), infer the likely
rejection reason, and compare every catalog variant against that
original byte-for-byte where possible (hashes + similarity).

Mode B — Authorized Access-Control Validation (active bypass testing),
in three phases:
  Baseline — establish ground truth: the resource as the authorized
    identity receives it (fingerprinted: body hash, title, marker,
    content-type, size, canonical redirect), the same resource with
    credentials stripped/insufficient (the expected denial), and a
    known-public control resource as a sanity check.
  Probe — fire the bypass matrix (technique catalog, section 2 of the
    design) at the protected resource and its equivalents.
  Verify — every candidate is re-run to a total of 3 observations with
    a nonexistent-path control; the returned artifact must fingerprint-
    match the real resource, not an error/login/cache artifact.

Classifications (3.14):
  bypass_verified        BYPASS_VERIFIED — technique defeated the
                         denial; all gating conditions held (baseline
                         protected, fingerprint match, attributable to
                         the technique, reproducible, control clean)
  bypass_candidate       BYPASS_CANDIDATE — content returned but the
                         verification chain is incomplete
  weakness_verified      ACCESS_CONTROL_WEAKNESS_VERIFIED — a policy
                         violation proven without any bypass technique
                         (e.g. the front door serves the wrong identity)
  misconfig_suspected    ACCESS_CONTROL_MISCONFIGURATION_SUSPECTED
  waf_block              WAF_BLOCK_DETECTED
  auth_required          AUTHENTICATION_REQUIRED
  block_confirmed        BLOCK_CONFIRMED
  inconclusive           INCONCLUSIVE
Confidence is reported as CONFIRMED / LIKELY / SPECULATIVE.
Runs saved by 3.11–3.13 keep their legacy codes and confidence words;
CLASS_LABELS covers both so old reports still render.

Rules: non-destructive, rate-limited per host, bounded request count,
identical requests deduplicated by hash, cancellable mid-run,
owner-approved test accounts and harmless resources only. Write verbs
(PUT/PATCH/DELETE) run by default only in Mode B (whose targets are
the owner's declared harmless resources); in Mode A they stay behind
the explicit write-methods opt-in. The engine never extracts real
credentials or private customer data — proof is the owner's harmless
test resource (marker/fingerprint), nothing else.
Cookies, authorization headers and token-like values are redacted from
every stored snapshot, log line and exported report.
"""
import hashlib
import html
import re
import socket
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .calibrate import Calibrator, similarity, waf_blocked
from .checks4 import _BODY_MARKERS, _SENSITIVE, _is_login_wall, _path_variants
from .client import USER_AGENT, Client, Resp, _decode
from .core import remediation_for

MODULE = "access403"
MAX_URLS = 20

CLASS_LABELS = {
    # 3.13/3.14 taxonomy
    "bypass_verified": "BYPASS_VERIFIED",
    "bypass_candidate": "BYPASS_CANDIDATE",
    "weakness_verified": "ACCESS_CONTROL_WEAKNESS_VERIFIED",
    "misconfig_suspected": "ACCESS_CONTROL_MISCONFIGURATION_SUSPECTED",
    "waf_block": "WAF_BLOCK_DETECTED",
    "auth_required": "AUTHENTICATION_REQUIRED",
    "block_confirmed": "BLOCK_CONFIRMED",
    "inconclusive": "INCONCLUSIVE",
    # legacy codes from 3.11/3.12 runs (stored reports keep rendering)
    "confirmed": "Confirmed unauthorized resource exposure (legacy)",
    "potential": "Potential access-control inconsistency (legacy)",
    "denied": "Access correctly denied (legacy)",
}

_ABOUT = {
    "bypass_verified": "A bypass technique defeated the denial and "
        "the full verification chain held: the baseline proved the "
        "resource is protected, the variant returned the real "
        "resource (fingerprint match — not a login page, error page "
        "or cache artifact), the effect is attributable to the "
        "technique, it reproduced across repeated runs, and the "
        "control stayed clean.",
    "bypass_candidate": "A variant returned content that looks like "
        "the protected resource, but the verification chain did not "
        "fully hold (partial reproducibility, a control that also "
        "served content, or unclear attribution). Treat as a strong "
        "lead and confirm manually before reporting.",
    "weakness_verified": "A controlled test proved the configured "
        "access policy was violated without needing any bypass "
        "technique — the resource was served, through the normal "
        "request path, to an identity the policy denies.",
    "misconfig_suspected": "Enforcement behaved inconsistently — a "
        "status, layer or method result differs from the original or "
        "from the configured policy — but no controlled proof "
        "completed, so a policy violation is suspected, not proven.",
    "waf_block": "A web application firewall or CDN security layer "
        "denied this request before it reached the application. That "
        "tells you the WAF is enforcing, not whether the application's "
        "own access control is correct — and a WAF block can also hit "
        "legitimate users (false positive).",
    "auth_required": "The enforcing layer answered 'log in first' "
        "(401 / WWW-Authenticate / redirect to a login page). "
        "Authorization cannot be judged until an authenticated test "
        "identity is supplied.",
    "block_confirmed": "The request was denied and enforcement was "
        "consistent for this test: same decision as the original "
        "request or exactly what the configured policy expects.",
    "inconclusive": "The test could not reach a verdict — the target "
        "errored, timed out, or changed state while testing, so "
        "nothing is proven either way.",
}

# summary rollup for the UI/report headline
ROLLUP = {
    "verified_bypass": ("bypass_verified",),
    "verified_weakness": ("weakness_verified", "confirmed"),
    "candidates": ("bypass_candidate",),
    "suspected": ("misconfig_suspected", "potential"),
    "waf_blocked": ("waf_block",),
    "auth_required": ("auth_required",),
    "blocked": ("block_confirmed", "denied"),
    "inconclusive": ("inconclusive",),
}

# technique groups (spec section 2) — user-toggleable
GROUPS = ("path", "override", "host", "ip", "methods", "protocol",
          "authctx", "cache", "origin")

_IP_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
               "True-Client-IP", "CF-Connecting-IP",
               "X-Custom-IP-Authorization", "X-Originating-IP")

_SENSITIVE_HEADERS = {"cookie", "set-cookie", "authorization",
                      "x-api-key", "proxy-authorization", "x-auth-token"}
_TOKEN_RE = re.compile(
    r"(?i)\b(sessionid|session|jsessionid|token|api[-_]?key|apikey|"
    r"password|passwd|secret|auth)\b\s*[:=]\s*[\"']?[^\s\"'&;,]+")
_BEARER_RE = re.compile(r"(?i)bearer\s+[a-z0-9._\-+/=]+")
_INTERESTING_HEADERS = ("server", "content-type", "content-length",
                        "location", "www-authenticate", "via", "x-cache",
                        "cf-ray", "cf-cache-status", "age", "x-served-by",
                        "set-cookie", "strict-transport-security",
                        "x-frame-options", "x-request-id", "x-amz-cf-id",
                        "x-iinfo")
_REQUEST_ID_HEADERS = ("x-request-id", "cf-ray", "x-amz-cf-id",
                       "x-amzn-trace-id", "x-correlation-id",
                       "x-transaction-id", "x-iinfo", "request-id",
                       "akamai-x-request-id", "x-akamai-request-id")


# ------------------------------------------------------------------ redaction
def redact_text(s):
    """Mask token-like values in a body/request text snapshot."""
    if not s:
        return s or ""
    s = _BEARER_RE.sub("Bearer ***", s)
    return _TOKEN_RE.sub(lambda m: m.group(0).split("=")[0].split(":")[0]
                         + ("=" if "=" in m.group(0) else ":") + "***", s)


def _snapshot(resp):
    """Redacted, size-capped record of one response (with timing)."""
    if resp is None:
        return {"status": None, "size": 0, "content_type": "",
                "headers": {}, "redirect_to": "", "body": "",
                "request": "", "elapsed_ms": None}
    headers = {}
    for k, v in resp.raw_headers:
        lk = k.lower()
        if lk in _INTERESTING_HEADERS or lk.startswith("x-") \
                or lk.startswith("cf-") or lk.startswith("akamai-"):
            headers[k] = "***" if lk in _SENSITIVE_HEADERS else v
    body = redact_text((resp.body or "")[:4000])
    req = resp.request_text or ""
    req = re.sub(r"(?im)^(Cookie|Authorization|X-Api-Key):.*$",
                 r"\1: ***", req)
    return {"status": resp.status,
            "size": len(resp.body or ""),
            "content_type": resp.header("content-type", ""),
            "headers": headers,
            "redirect_to": resp.header("location", ""),
            "body": body,
            "request": redact_text(req),
            "elapsed_ms": round((resp.elapsed or 0) * 1000)}


# ------------------------------------------------------------------ validation
def validate_url(url):
    """Return (clean_url, error). Only http/https, must have a host."""
    url = (url or "").strip()
    if not url:
        return None, "empty URL"
    if "://" not in url:
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None, f"unsupported scheme in {url!r}"
    if not parts.hostname:
        return None, f"no host in {url!r}"
    return url, None


def _origin_of(url):
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _hostkey(url):
    p = urllib.parse.urlsplit(url)
    return (p.scheme, p.hostname, p.port)


def _body_hash(body):
    return hashlib.sha256((body or "").encode("utf-8", "replace")) \
        .hexdigest()[:16]


# --------------------------------------------------------------- fingerprint
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")


def fingerprint(resp, marker=""):
    """The real resource's identity card (Mode B baseline phase):
    body hash, <title>, marker presence, content-type, size and the
    canonical redirect target."""
    if resp is None:
        return {}
    body = resp.body or ""
    m = _TITLE_RE.search(body)
    return {"sha256": _body_hash(body),
            "title": (m.group(1).strip()[:120] if m else ""),
            "size": len(body),
            "content_type": resp.header("content-type", ""),
            "marker_present": (marker in body) if marker else None,
            "redirect_target": resp.header("location", ""),
            "status": resp.status}


def fingerprint_match(fp, resp, marker=""):
    """Does resp carry the fingerprinted real resource? Marker beats
    heuristics; otherwise exact hash, or title + size-band + type."""
    if not fp or resp is None or resp.status not in (200, 201, 206):
        return False
    body = resp.body or ""
    if marker:
        return marker in body
    if _body_hash(body) == fp.get("sha256"):
        return True
    title = ""
    m = _TITLE_RE.search(body)
    if m:
        title = m.group(1).strip()[:120]
    if fp.get("title") and title == fp["title"] \
            and fp.get("content_type") == resp.header("content-type", ""):
        size = fp.get("size") or 0
        return size > 0 and abs(len(body) - size) <= max(64, size * 0.15)
    return False


# ------------------------------------------------------- source attribution
_F5_SUPPORT_RE = re.compile(r"support\s*ID\s*is:?\s*#?\s*(\d{6,})", re.I)
_F5_BODY_HINTS = ("the requested url was rejected",
                  "please consult with your administrator",
                  "your support id is")
_AKAMAI_REF_RE = re.compile(r"Reference\s*#\s*([0-9a-fA-F.\-]+)")
_LOGIN_PATH_RE = re.compile(r"(?i)/(login|signin|sign-in|auth|sso)\b")


def _header(resp, name):
    return (resp.header(name, "") or "") if resp is not None else ""


def extract_request_ids(resp):
    """Request-correlation identifiers worth recording (§1/§5)."""
    out = {}
    if resp is None:
        return out
    for name in _REQUEST_ID_HEADERS:
        v = _header(resp, name)
        if v:
            out[name] = v
    f5 = f5_diagnostics(resp)
    if f5 and f5.get("support_id"):
        out["f5-support-id"] = f5["support_id"]
    m = _AKAMAI_REF_RE.search(resp.body or "")
    if m:
        out["akamai-reference"] = m.group(1)
    sc = [v.split("=", 1)[0].strip() for k, v in resp.raw_headers
          if k.lower() == "set-cookie" and "=" in v]
    if sc:
        out["set-cookie-names"] = ", ".join(sc[:6])
    return out


def f5_diagnostics(resp):
    """F5 BIG-IP / ASM diagnostics from one response, or None.

    Extracts the ASM support ID (the key an F5 admin uses to find the
    exact event + triggered rule in the ASM event log), the response
    timestamp (Date header + local capture time), the affected URL,
    and the F5 fingerprints present. Cookie NAMES only — never values.
    """
    if resp is None:
        return None
    body = resp.body or ""
    m = _F5_SUPPORT_RE.search(body)
    low = body.lower()
    server = _header(resp, "server")
    cookie_vals = " ".join(v for k, v in resp.raw_headers
                           if k.lower() == "set-cookie")
    asm_cookie = bool(re.search(r"(?i)\bTS[0-9a-f]{6,}\b", cookie_vals))
    bigip_cookie = "bigipserver" in cookie_vals.lower()
    hints = [h for h in _F5_BODY_HINTS if h in low]
    is_f5 = bool(m) or len(hints) >= 2 or "bigip" in server.lower() \
        or asm_cookie or bigip_cookie
    if not is_f5:
        return None
    evidence = []
    if m:
        evidence.append(f"ASM block page carries support ID {m.group(1)}")
    if hints:
        evidence.append("F5 ASM block-page wording: "
                        + "; ".join(hints))
    if "bigip" in server.lower():
        evidence.append(f"Server header: {server}")
    if asm_cookie:
        evidence.append("ASM TS cookie set (name pattern TS…)")
    if bigip_cookie:
        evidence.append("BIGipServer cookie set (name only recorded)")
    return {
        "support_id": m.group(1) if m else "",
        "timestamp": _header(resp, "date")
        or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": resp.url or "",
        "server": server,
        "evidence": evidence,
        "correlation": "In the F5 ASM event log, search this support "
                       "ID to find the exact request, the violation "
                       "and the signature/rule that triggered.",
    }


def correlate_f5_log(f5, log_text):
    """Correlate a denial with an operator-supplied F5 ASM log excerpt
    or policy export (§5). Returns None when no log was supplied.
    Pure function — the excerpt is searched for the support ID and a
    rule/signature hint is extracted from the matching lines."""
    if not f5 or not log_text:
        return None
    sid = f5.get("support_id") or ""
    if not sid:
        return {"matched": False,
                "note": "the block page carried no support ID to "
                        "correlate against the supplied log"}
    lines = [ln.strip() for ln in log_text.splitlines() if sid in ln]
    if not lines:
        return {"matched": False,
                "note": f"support ID {sid} does not appear in the "
                        "supplied log excerpt"}
    excerpt = redact_text(" ".join(lines))[:600]
    m = re.search(r"(?i)(attack signature|signature|violation|rule|"
                  r"policy)[^;,]{0,140}", excerpt)
    return {"matched": True, "excerpt": excerpt,
            "rule_hint": m.group(0).strip() if m else "",
            "note": "the ASM log confirms this exact request was "
                    "blocked by the WAF policy"}


def attribute_source(resp):
    """Who denied (or answered) this request? Evidence-based only.

    Returns {layer, vendor, confidence, evidence}. layer is one of:
    waf, cdn, reverse_proxy, application, authentication, unknown.
    Pure function of the response — unit-testable without a server.
    """
    if resp is None:
        return {"layer": "unknown", "vendor": "", "confidence": "Low",
                "evidence": ["no response received"]}
    ev = []
    body = resp.body or ""
    low = body.lower()
    f5 = f5_diagnostics(resp)
    if f5:
        ev.extend(f5["evidence"])
        return {"layer": "waf", "vendor": "F5 BIG-IP ASM",
                "confidence": "High" if f5.get("support_id") else "Medium",
                "evidence": ev}
    cf_ray = _header(resp, "cf-ray")
    if cf_ray or "cloudflare" in low or "attention required" in low:
        ev.append(f"cf-ray: {cf_ray}" if cf_ray else
                  "Cloudflare wording in body")
        return {"layer": "cdn", "vendor": "Cloudflare",
                "confidence": "High" if cf_ray else "Medium",
                "evidence": ev}
    if _AKAMAI_REF_RE.search(body) or "akamaighost" in \
            _header(resp, "server").lower() \
            or _header(resp, "x-akamai-request-id"):
        ev.append("Akamai reference/host signature")
        return {"layer": "cdn", "vendor": "Akamai",
                "confidence": "Medium", "evidence": ev}
    if _header(resp, "x-iinfo") or "incapsula" in low \
            or "imperva" in low:
        ev.append("Imperva/Incapsula header or incident wording")
        return {"layer": "cdn", "vendor": "Imperva Incapsula",
                "confidence": "Medium", "evidence": ev}
    if _header(resp, "x-amz-cf-id") or "cloudfront" in \
            _header(resp, "x-cache").lower():
        ev.append("CloudFront request id / cache header")
        return {"layer": "cdn", "vendor": "AWS CloudFront",
                "confidence": "Medium", "evidence": ev}
    if "varnish" in _header(resp, "x-cache").lower() \
            or _header(resp, "x-served-by"):
        ev.append("cache/proxy headers (x-cache / x-served-by)")
        return {"layer": "reverse_proxy",
                "vendor": "cache / reverse proxy",
                "confidence": "Medium", "evidence": ev}
    auth = auth_signal(resp)
    if auth:
        ev.append(auth)
        return {"layer": "authentication",
                "vendor": "authentication layer",
                "confidence": "High", "evidence": ev}
    if waf_blocked(resp):
        ev.append("generic WAF block-page wording")
        return {"layer": "waf", "vendor": "WAF (unidentified)",
                "confidence": "Low", "evidence": ev}
    via = _header(resp, "via")
    server = _header(resp, "server")
    if via:
        ev.append(f"Via: {via}")
        return {"layer": "reverse_proxy",
                "vendor": server or "reverse proxy",
                "confidence": "Medium", "evidence": ev}
    ev.append("no edge/WAF signatures; denial carries application "
              "characteristics" + (f" (Server: {server})" if server
                                   else ""))
    return {"layer": "application", "vendor": server or "application",
            "confidence": "Medium", "evidence": ev}


def auth_signal(resp):
    """Why this response reads as 'authenticate first', or ''."""
    if resp is None:
        return ""
    if resp.status == 401 or _header(resp, "www-authenticate"):
        return "401 / WWW-Authenticate present"
    loc = _header(resp, "location")
    if resp.status in (301, 302, 303, 307, 308) and loc \
            and _LOGIN_PATH_RE.search(loc):
        return f"redirect to a login page ({loc})"
    if resp.status in (301, 302, 303, 307, 308) and loc:
        return ""
    if _is_login_wall(resp.body or ""):
        return "login form served instead of the resource"
    return ""


def likely_reasons(resp, attribution):
    """Plain-language likely rejection reasons for a denied response."""
    if resp is None:
        return ["No response was received (connection error or timeout)."]
    layer = (attribution or {}).get("layer", "")
    vendor = (attribution or {}).get("vendor", "")
    reasons = []
    if layer == "waf":
        reasons.append(
            f"{vendor} rejected the request at the edge — a URL ACL, "
            "an attack signature, or a reputation/IP rule in the WAF "
            "policy fired before the application saw the request.")
        if vendor.startswith("F5"):
            reasons.append(
                "For F5 ASM: open the event log with the support ID "
                "to see the exact violation (e.g. 'Illegal URL', "
                "'Attack signature detected') before tuning anything.")
    elif layer == "cdn":
        reasons.append(
            f"{vendor} denied the request at the CDN edge (managed "
            "rule, rate limit, geo/IP rule or bot control).")
    elif layer == "authentication":
        reasons.append(
            "Authentication is required first: the layer is not saying "
            "'your identity may not see this', it is saying 'no "
            "identity was presented'. Authorization can only be "
            "judged with a test account signed in.")
    elif layer == "reverse_proxy":
        reasons.append(
            "A reverse proxy in front of the application denied the "
            "request (proxy ACL / routing rule), so the application "
            "may never have evaluated it.")
    else:
        reasons.append(
            "The application itself returned the denial — a route "
            "guard, framework security rule, or resource-level ACL "
            "decided this identity may not access the resource.")
    if resp.status == 403 and _is_login_wall(resp.body or ""):
        reasons.append("The 403 page is (or embeds) a login wall, "
                       "which blurs auth and authorization signals.")
    return reasons


# ------------------------------------------------------------- classifier
def classify_outcome(*, test_type="", group="", method="GET",
                     base_status=None, resp=None, attribution=None,
                     proof=False, proof_why="", marker=None,
                     guard_ok=None, verify_fetches=0, verify_matches=0,
                     fingerprint_match=None, policy_expected=None,
                     never_protected=False, kind="technique"):
    """Pure verdict logic for one candidate. Unit-testable.

    Verdict gating (spec §3) — BYPASS_VERIFIED requires ALL of:
    baseline protected · the variant returned the real resource
    (fingerprint/marker proof, not a login/error/cache artifact) ·
    the effect attributable to the technique (catch-all guard clean)
    · reproducible (3 of 3 observations) · and, where a policy is
    configured, the access contradicts it. Anything less is a
    CANDIDATE or SUSPECTED. A status change alone never verifies.
    HEAD can never verify (no body by definition). Access to a
    resource that was never protected is not a bypass.
    Identity-kind proofs (no technique involved) verify as
    ACCESS_CONTROL_WEAKNESS_VERIFIED instead of BYPASS_VERIFIED.
    Returns (classification, severity, confidence, reason) with
    confidence in CONFIRMED / LIKELY / SPECULATIVE.
    """
    if resp is None:
        return ("inconclusive", "Info", "SPECULATIVE",
                "no response (timeout, connection error, or the run "
                "was stopped / budget exhausted)")
    if method == "HEAD":
        proof = False   # structural: HEAD carries no body, ever
    attribution = attribution or attribute_source(resp)
    layer = attribution.get("layer", "")
    status = resp.status
    waf_page = layer in ("waf", "cdn") and status in (403, 406, 429, 501) \
        and attribution.get("confidence") in ("High", "Medium")
    auth = auth_signal(resp)

    if proof:
        if fingerprint_match is False:
            return ("misconfig_suspected", "Low", "LIKELY",
                    "content came back, but it does NOT fingerprint-"
                    "match the real resource established in the "
                    "baseline — a different artifact answered (error "
                    "page, login page, cached or unrelated content)")
        if marker is False:
            return ("misconfig_suspected", "Low", "LIKELY",
                    "a 2xx response returned content, but NOT the "
                    "owner's harmless test resource (marker absent) — "
                    "the wrong resource answered, so the policy "
                    "violation is not proven")
        if never_protected and (kind == "technique"
                                or test_type == "auth-context"):
            return ("misconfig_suspected", "Medium", "CONFIRMED",
                    "the variant returned the resource, but the plain "
                    "baseline request returns it too — the resource "
                    "was never protected, so this is a missing access "
                    "control, not a bypass")
        if guard_ok is False:
            return ("bypass_candidate", "Medium", "LIKELY",
                    "the protected content came back, but the same "
                    "technique on a nonexistent sibling path served "
                    "the same content — the effect cannot be cleanly "
                    "attributed to the technique (catch-all behaviour "
                    "is a competing explanation)")
        if verify_fetches >= 3 and verify_matches >= 3:
            code = "weakness_verified" if kind == "identity" \
                else "bypass_verified"
            return (code, "High" if policy_expected == "deny"
                    else "Medium", "CONFIRMED",
                    "verification chain complete: baseline protected, "
                    "the real resource was served (fingerprint/marker "
                    "match), the catch-all control stayed clean, and "
                    "the result reproduced on 3 of 3 observations")
        if verify_matches >= 2:
            return ("bypass_candidate", "Medium", "LIKELY",
                    f"the protected content came back and reproduced "
                    f"on {verify_matches} of {verify_fetches} "
                    "observations — short of the 3-of-3 bar for "
                    "VERIFIED, so this stays a candidate")
        return ("misconfig_suspected", "Low", "LIKELY",
                f"content came back once but reproduced on only "
                f"{verify_matches} of {verify_fetches} observations "
                "— unstable behaviour, not a proven violation")
    # ---- no content proof below this line: nothing is verified ----
    if waf_page:
        return ("waf_block", "Info", "CONFIRMED"
                if attribution.get("vendor") not in
                ("", "WAF (unidentified)") else "LIKELY",
                f"denied by {attribution.get('vendor') or 'a WAF'} "
                "before the application evaluated it")
    if auth:
        return ("auth_required", "Info", "CONFIRMED",
                f"the layer requires authentication first ({auth})")
    if method == "HEAD" and status in (200, 201, 206) \
            and base_status == 403:
        return ("misconfig_suspected", "Low", "LIKELY",
                "HEAD answers success while GET is denied. HEAD has "
                "no body by definition, so no content exposure can be "
                "proven from HEAD alone — but method handling is "
                "inconsistent and a GET-equivalent path must be "
                "checked manually")
    if status in (200, 201, 206) and proof_why == "the site's soft-404 page":
        return ("block_confirmed", "Info", "LIKELY",
                "the variant resolves to the site's soft-404 page — "
                "that spelling does not reach the protected resource")
    if status in (200, 201, 206) and proof_why == "a login wall":
        return ("auth_required", "Info", "CONFIRMED",
                "the variant is answered with a login wall — "
                "authentication is required before authorization "
                "can be judged")
    if status in (200, 201, 206) and proof_why == "empty body":
        return ("block_confirmed", "Info", "LIKELY",
                "answered 200 but returned no content — nothing was "
                "exposed by this variant")
    if status in (200, 201, 206):
        return ("misconfig_suspected", "Low", "SPECULATIVE",
                f"status changed to {status} but the body is "
                f"{proof_why or 'not the protected content'} — a "
                "different status code alone is not a bypass")
    if status is not None and 300 <= status < 400:
        return ("misconfig_suspected", "Info", "SPECULATIVE",
                f"the variant redirects ({status}) to "
                f"{_header(resp, 'location') or '?'} while the "
                "original is denied — where the redirect lands was "
                "not followed, and no content was served")
    if status == base_status:
        return ("block_confirmed", "Info", "CONFIRMED",
                f"answered {status}, the same enforcement decision "
                "as the original request")
    if status in (400, 404, 405, 410, 451):
        return ("block_confirmed", "Info", "LIKELY",
                f"answered {status} — the variant is rejected / not "
                "found and no content was returned")
    if status is not None and status >= 500:
        return ("inconclusive", "Info", "SPECULATIVE",
                f"the server answered {status} (error) — no verdict "
                "can be drawn from an erroring target")
    return ("inconclusive", "Info", "SPECULATIVE",
            f"answered {status}; no content proof either way")


def _comparison(base, r):
    """Original-vs-test comparison block stored on every record,
    byte-for-byte where possible (hashes + exact-match flag)."""
    if base is None or r is None:
        return {}
    bb, rb = base.body or "", r.body or ""
    return {
        "status_changed": base.status != r.status,
        "size_delta": len(rb) - len(bb),
        "similarity": round(similarity(bb, rb), 3),
        "original_sha256": _body_hash(bb),
        "test_sha256": _body_hash(rb),
        "exact_body_match": bb == rb,
        "content_type_changed":
            base.header("content-type", "") != r.header("content-type", ""),
        "redirect_original": base.header("location", ""),
        "redirect_test": r.header("location", ""),
        "layer_original": attribute_source(base).get("layer", ""),
        "layer_test": attribute_source(r).get("layer", ""),
        "elapsed_original_ms": round((base.elapsed or 0) * 1000),
        "elapsed_test_ms": round((r.elapsed or 0) * 1000),
    }


# --------------------------------------------------------------- raw fetch
def _dechunk(data):
    out, i = [], 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if n == 0:
            break
        out.append(data[j + 2:j + 2 + n])
        i = j + 2 + n + 2
    return b"".join(out)


def raw_fetch(url, method="GET", headers=None, version="1.1",
              absolute_form=False, body=b"", cookie=None, timeout=12):
    """Minimal raw-socket fetch for the request forms urllib cannot
    express exactly: HTTP/1.0, an absolute-form request line, a
    lowercase or EMPTY method. Returns a client Resp. Bounded: one
    connection, Connection: close, body capped at 3 MB."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = url if absolute_form else (
        (parts.path or "/") + (("?" + parts.query) if parts.query
                               else ""))
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*",
            "Connection": "close"}
    host_line = parts.netloc
    if cookie:
        hdrs["Cookie"] = cookie
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            host_line = v          # None removes the Host header
        else:
            hdrs[k] = v
    if body:
        hdrs["Content-Length"] = str(len(body))
    lines = [f"{method} {target} HTTP/{version}"]
    if host_line is not None:
        lines.append(f"Host: {host_line}")
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    req_text = "\r\n".join(lines) + "\r\n\r\n"
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(req_text.encode("latin-1", "replace") + body)
        chunks = []
        total = 0
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > 3_200_000:
                break
        sock.close()
        raw = b"".join(chunks)
    except Exception:
        return Resp(None, {}, [], "", url,
                    time.perf_counter() - start, req_text)
    elapsed = time.perf_counter() - start
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        # headerless answer (e.g. an HTTP/0.9-style drop): keep the
        # body, there is simply no status line to report
        rest = raw
    hlines = head.decode("latin-1", "replace").split("\r\n") if sep \
        else []
    status = None
    if hlines and hlines[0].split(" ")[1:2]:
        try:
            status = int(hlines[0].split(" ")[1])
        except ValueError:
            status = None
    raw_headers = []
    for ln in hlines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            raw_headers.append((k, v))
        elif ":" in ln:
            k, v = ln.split(":", 1)
            raw_headers.append((k, v.strip()))
    low = {k.lower(): v for k, v in raw_headers}
    if "chunked" in low.get("transfer-encoding", "").lower():
        rest = _dechunk(rest)
    elif low.get("content-length", "").isdigit():
        rest = rest[:int(low["content-length"])]
    return Resp(status, low, raw_headers, _decode(rest, low), url,
                elapsed, req_text)


# ------------------------------------------------------------------ engine
class _Budget:
    def __init__(self, cap):
        self.cap = cap
        self.used = 0
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            if self.used >= self.cap:
                return False
            self.used += 1
            return True


_IDENTITY_LABELS = {"anon": "anonymous", "role_a": "test account A",
                    "role_b": "test account B"}


def _group_toggles(checks):
    """Normalize technique-group toggles, honoring the legacy 3.11–3.13
    check names as aliases."""
    checks = checks or {}

    def grp(new, *legacy, default=True):
        if new in checks:
            return bool(checks[new])
        for leg in legacy:
            if leg in checks:
                return bool(checks[leg])
        return default

    return {
        "path": grp("path", "equivalents"),
        "override": grp("override"),
        "host": grp("host"),
        "ip": grp("ip", "trusted_headers"),
        "methods": grp("methods"),
        "protocol": grp("protocol"),
        "authctx": grp("authctx", "session"),
        "cache": grp("cache"),
        "origin": grp("origin"),
    }


class Tester:
    """One assessment run. Construct, then .run() (blocking)."""

    def __init__(self, urls, opts=None, stop=None, progress=None):
        opts = opts or {}
        self.urls = urls[:MAX_URLS]
        self.mode = (opts.get("mode") or "diagnostics").lower()
        if self.mode not in ("diagnostics", "validation"):
            self.mode = "diagnostics"
        val = opts.get("validation") or {}
        self.identities = {
            "anon": {"label": _IDENTITY_LABELS["anon"], "cookie": ""},
            "role_a": {"label": val.get("role_a_label")
                       or _IDENTITY_LABELS["role_a"],
                       "cookie": (val.get("role_a_cookie")
                                  or opts.get("cookie") or "").strip()},
            "role_b": {"label": val.get("role_b_label")
                       or _IDENTITY_LABELS["role_b"],
                       "cookie": (val.get("role_b_cookie") or "").strip()},
        }
        self.marker = (val.get("marker") or "").strip()
        self.expect = {"anon": "deny", "role_a": "allow",
                       "role_b": "deny"}
        for k, v in (val.get("expect") or {}).items():
            if k in self.expect and v in ("allow", "deny"):
                self.expect[k] = v
        self.policy = val.get("policy") or {}
        self.cookie = self.identities["role_a"]["cookie"]  # legacy alias
        self.origin = (opts.get("origin") or "").strip()
        self.alt_port = opts.get("alt_port") or None
        self.public_control = (opts.get("public_control") or "").strip()
        self.f5_log = (opts.get("f5_log") or val.get("f5_log")
                       or "")[:200_000]
        self.extra_hosts = {h.strip().lower() for h in
                            (opts.get("allow_hosts") or []) if h.strip()}
        self.concurrency = max(1, min(8, int(opts.get("concurrency") or 3)))
        self.timeout = max(3, min(60, int(opts.get("timeout") or 12)))
        self.checks = opts.get("checks") or {}
        self.groups = _group_toggles(self.checks)
        self.write_methods = bool(self.checks.get("write_methods", False))
        self.budget = _Budget(max(50, min(5000,
                                          int(opts.get("max_requests")
                                              or 600))))
        default_interval = 150 if self.mode == "validation" else 25
        _mi = opts.get("min_interval_ms")
        self.min_interval = max(0, int(default_interval if _mi is None
                                       else _mi)) / 1000.0
        self._rate_lock = threading.Lock()
        self._last_fetch = {}          # per-host rate limiting
        self.stop = stop or threading.Event()
        self.progress = progress or (lambda **kw: None)
        self.records = []
        self.profiles = []
        self.logs = []
        self._lock = threading.Lock()
        self._calibrators = {}
        self.exhausted = False
        self.deduped = 0
        self._fp = {}                  # url -> baseline fingerprint
        self._never_protected = set()  # urls served to the baseline too

    # -- plumbing ------------------------------------------------------
    def _log(self, msg):
        with self._lock:
            self.logs.append(msg)
        self.progress(log=msg)

    def _client(self, cookie=""):
        return Client(cookie=cookie or None, timeout=self.timeout)

    def _identity_client(self, identity):
        return self._client(cookie=self.identities[identity]["cookie"])

    def _throttle(self, url):
        """Per-host rate limit: minimum interval between requests to
        the same host (spec §2 matrix discipline)."""
        if not self.min_interval:
            return
        host = urllib.parse.urlsplit(url).netloc.lower()
        with self._rate_lock:
            wait = self._last_fetch.get(host, 0.0) \
                + self.min_interval - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last_fetch[host] = time.time()

    def _fetch(self, client, url, **kw):
        """Budget- and stop-aware fetch. None = not sent."""
        if self.stop.is_set():
            return None
        if not self.budget.take():
            self.exhausted = True
            return None
        self._throttle(url)
        return client.fetch(url, **kw)

    def _send_tech(self, client, tech):
        """Send one catalog technique (client or raw channel),
        budget-, stop- and rate-limit-aware."""
        if self.stop.is_set():
            return None
        if not self.budget.take():
            self.exhausted = True
            return None
        self._throttle(tech["url"])
        raw = tech.get("raw")
        if raw is not None:
            body = urllib.parse.urlencode(tech["data"]).encode() \
                if tech.get("data") else b""
            return raw_fetch(tech["url"],
                             method=tech.get("method", "GET"),
                             headers=tech.get("headers"),
                             version=raw.get("version", "1.1"),
                             absolute_form=raw.get("absolute_form",
                                                   False),
                             body=body, cookie=tech.get("cookie"),
                             timeout=self.timeout)
        c = client
        if "cookie_override" in tech:
            c = self._client(cookie=tech["cookie_override"])
        return c.fetch(tech["url"], method=tech.get("method", "GET"),
                       headers=tech.get("headers"),
                       data=tech.get("data"))

    def _calibrator(self, client, url):
        key = _origin_of(url)
        with self._lock:
            cal = self._calibrators.get(key)
        if cal is None:
            try:
                cal = Calibrator(client, url)
            except Exception:
                cal = None
            with self._lock:
                self._calibrators[key] = cal
        return cal

    def _in_scope(self, url):
        """Allowlist: the targets' own origins + operator-added hosts."""
        hk = _hostkey(url)
        if hk[1] and hk[1].lower() in self.extra_hosts:
            return True
        return any(_hostkey(u) == hk for u in self.urls)

    def _policy_for(self, url):
        """Effective validation policy for one resource URL."""
        pol = {"marker": self.marker,
               "expect": dict(self.expect),
               "equivalents": []}
        over = self.policy.get(url) or {}
        if over.get("marker"):
            pol["marker"] = over["marker"]
        for k, v in (over.get("expect") or {}).items():
            if k in pol["expect"] and v in ("allow", "deny"):
                pol["expect"][k] = v
        pol["equivalents"] = list(over.get("equivalents") or [])
        return pol

    # -- content proof ---------------------------------------------------
    def _proof(self, cal, base403, r):
        """(ok, why_not) — is r the resource's real content?"""
        if r is None or r.status not in (200, 201, 206):
            return False, "status"
        body = r.body or ""
        if len(body.strip()) < 30:
            return False, "empty body"
        if base403 is not None and base403.status == 403 and \
                similarity(body, base403.body or "") > 0.85:
            return False, "same as the 403 page"
        if cal is not None and cal.is_soft404(r):
            return False, "the site's soft-404 page"
        if _is_login_wall(body):
            return False, "a login wall"
        return True, ""

    def _assess_access(self, cal, base403, r, marker):
        """Access state of one response: granted / denied / auth /
        other / error, plus marker and content-proof facts."""
        if r is None:
            return {"access": "error", "marker_match": None,
                    "proof": False, "proof_why": "no response"}
        marker_match = (marker in (r.body or "")) if marker else None
        if r.status in (200, 201, 206):
            if marker:
                if marker_match:
                    return {"access": "granted", "marker_match": True,
                            "proof": True, "proof_why": ""}
                _ok, why = self._proof(cal, base403, r)
                return {"access": "other", "marker_match": False,
                        "proof": False,
                        "proof_why": why if why in (
                            "the site's soft-404 page", "a login wall",
                            "empty body", "same as the 403 page")
                        else "2xx but the harmless-resource marker is "
                             "absent"}
            ok, why = self._proof(cal, base403, r)
            return {"access": "granted" if ok else "other",
                    "marker_match": None, "proof": ok, "proof_why": why}
        if auth_signal(r):
            return {"access": "auth", "marker_match": marker_match,
                    "proof": False, "proof_why": "authentication required"}
        return {"access": "denied", "marker_match": marker_match,
                "proof": False, "proof_why": f"status {r.status}"}

    def _guard(self, client, tech, won_resp):
        """Catch-all guard: apply the same technique to the control
        URL. True = genuine (the control does NOT serve the content)."""
        g = tech.get("guard")
        if g is None:
            return True
        gtech = {"url": g["url"], "method": g.get("method", "GET"),
                 "headers": g.get("headers"), "data": g.get("data"),
                 "raw": g.get("raw"), "cookie": tech.get("cookie")}
        if "cookie_override" in tech:
            gtech["cookie_override"] = tech["cookie_override"]
        cr = self._send_tech(client, gtech)
        if cr is None or cr.status not in (200, 201, 206):
            return True
        return similarity(cr.body or "", won_resp.body or "") <= 0.85

    # -- records ---------------------------------------------------------
    def _record(self, url, ttype, label, base, r, classification,
                severity, confidence, evidence, hypothesis="",
                expected="", identity="", group="", policy=None,
                reason="", verify=None, fp_match=None):
        attribution = attribute_source(r) if r is not None else {}
        rec = {
            "url": url, "type": ttype, "technique": label,
            "group": group, "mode": self.mode,
            "identity": identity,
            "hypothesis": hypothesis,
            "expected": expected,
            "original": _snapshot(base), "test": _snapshot(r),
            "similarity": round(similarity(base.body or "",
                                           r.body or ""), 3)
            if base is not None and r is not None else None,
            "comparison": _comparison(base, r)
            if base is not None and r is not None else {},
            "layer": attribution.get("layer", ""),
            "vendor": attribution.get("vendor", ""),
            "request_ids": extract_request_ids(r),
            "f5": f5_diagnostics(r) or f5_diagnostics(base),
            "verify": verify or {},
            "fingerprint_match": fp_match,
            "classification": classification,
            "class_label": CLASS_LABELS[classification],
            "severity": severity, "confidence": confidence,
            "evidence": evidence,
            "reason": reason,
            "policy": policy or {},
            "about": _ABOUT[classification],
            "remediation": self._remediation(classification, attribution),
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._lock:
            self.records.append(rec)
        return rec

    @staticmethod
    def _remediation(classification, attribution=None):
        if classification in ("bypass_verified", "bypass_candidate",
                              "weakness_verified",
                              "misconfig_suspected"):
            return remediation_for("403 Forbidden Bypass")
        if classification == "waf_block":
            return ("If legitimate users hit this block, treat it as "
                    "a possible WAF false positive: correlate the "
                    "support/request ID in the WAF event log, identify "
                    "the triggered rule, and tune that rule narrowly — "
                    "do not whitelist the URL or disable the signature "
                    "broadly.")
        if classification == "auth_required":
            return ("No action needed at this layer — authentication "
                    "is being enforced. To judge authorization, re-run "
                    "validation mode with owner-provided test accounts.")
        if classification == "block_confirmed":
            return ("No action needed — enforcement was consistent "
                    "for this test.")
        return ("Re-run when the target is stable; check WAF/rate-"
                "limit logs for the test window.")

    def _judge(self, url, tech, base, r, client, cal, identity="",
               policy_expected=None, kind="technique"):
        """Shared verdict path for catalog candidates in both modes:
        content proof → verify chain (3 observations + control) →
        pure classifier. The exact original response is preserved in
        every record for byte-for-byte comparison."""
        marker = self._policy_for(url)["marker"] \
            if self.mode == "validation" else self.marker
        fp_ref = self._fp.get(url)
        base403 = base if base is not None and base.status == 403 \
            else None
        assess = self._assess_access(cal, base403, r, marker)
        proof = assess["proof"]
        fp_match = None
        if proof:
            if fp_ref:
                fp_match = fingerprint_match(fp_ref, r, marker)
            elif marker:
                fp_match = bool(assess["marker_match"])
        verify_fetches = verify_matches = 0
        guard_ok = None
        if proof:
            verify_fetches = verify_matches = 1
            for _ in range(2):
                if self.stop.is_set() or self.exhausted:
                    break
                r2 = self._send_tech(client, tech)
                if r2 is None:
                    continue
                verify_fetches += 1
                a2 = self._assess_access(cal, base403, r2, marker)
                m2 = a2["proof"]
                if m2 and fp_ref:
                    m2 = fingerprint_match(fp_ref, r2, marker)
                if m2:
                    verify_matches += 1
            guard_ok = self._guard(client, tech, r)
        classification, severity, confidence, reason = classify_outcome(
            test_type=tech["type"], group=tech.get("group", ""),
            method=tech.get("method", "GET"),
            base_status=base.status if base else None, resp=r,
            proof=proof, proof_why=assess["proof_why"],
            marker=assess["marker_match"], guard_ok=guard_ok,
            verify_fetches=verify_fetches, verify_matches=verify_matches,
            fingerprint_match=fp_match,
            policy_expected=policy_expected,
            never_protected=url in self._never_protected, kind=kind)
        if classification in ("bypass_verified", "weakness_verified") \
                and policy_expected is None:
            body = (r.body or "").lower()
            if _SENSITIVE.search(urllib.parse.urlsplit(url).path) \
                    or any(m in body for m in _BODY_MARKERS):
                severity = "High"
        if not proof and r is not None \
                and r.status in (200, 201, 206) and tech.get("plain"):
            # URL-override control: same URL without the header serves
            # the identical page -> the header was ignored, the 200
            # is the landing page, not the protected resource.
            pr = self._fetch(client, tech["plain"]["url"],
                             method=tech.get("method", "GET"))
            if pr is not None and pr.status == r.status and \
                    similarity(pr.body or "", r.body or "") > 0.9:
                classification, severity, confidence = \
                    "block_confirmed", "Info", "CONFIRMED"
                reason = ("the identical URL without the override "
                          "header serves the same page — the header "
                          "was ignored and the 200 is the landing "
                          "page, not the protected resource")
        ev = [f"Original: HTTP {base.status if base else '—'} "
              f"({len(base.body or '') if base else 0} bytes, layer: "
              f"{attribute_source(base).get('layer', '—')}, "
              f"{round((base.elapsed or 0) * 1000) if base else '—'} ms).",
              f"Test: HTTP {r.status if r else '—'} "
              f"({len(r.body or '') if r else 0} bytes, "
              f"{round((r.elapsed or 0) * 1000) if r else '—'} ms).",
              f"Verdict basis: {reason}."]
        if marker:
            ev.append("Harmless-resource marker "
                      + ("MATCHED." if assess["marker_match"] else
                         "not present in the response."))
        if fp_ref:
            ev.append("Baseline fingerprint: sha256 "
                      f"{fp_ref.get('sha256', '')}, title "
                      f"{fp_ref.get('title', '')!r}; this response "
                      + ("MATCHES it." if fp_match else
                         "was not fingerprint-checked." if fp_match is None
                         else "does NOT match it."))
        if proof:
            ev.append(f"Verification: reproduced on {verify_matches} "
                      f"of {verify_fetches} observations; catch-all "
                      f"guard {'passed' if guard_ok else 'FAILED'}.")
        cache_bits = []
        if r is not None:
            for h in ("x-cache", "age", "cf-cache-status"):
                v = r.header(h, "")
                if v:
                    cache_bits.append(f"{h}: {v}")
        if cache_bits:
            ev.append("Cache indicators: " + ", ".join(cache_bits) + ".")
        return self._record(url, tech["type"], tech["label"], base, r,
                            classification, severity, confidence,
                            " ".join(ev),
                            hypothesis=tech.get("hypothesis", ""),
                            expected=tech.get("expected", ""),
                            identity=identity,
                            group=tech.get("group", ""), reason=reason,
                            verify={"observations": verify_fetches,
                                    "matches": verify_matches,
                                    "guard_ok": guard_ok},
                            fp_match=fp_match,
                            policy={"expected": policy_expected}
                            if policy_expected else {})


    # -- baseline profiling (shared by both modes) -----------------------
    def _profile_baseline(self, url, client):
        """Preserve the exact original response and profile it against
        a nonexistent-path control. Returns (profile, base, ctrl, cal).
        """
        cal = self._calibrator(client, url)
        parts = urllib.parse.urlsplit(url)
        origin = _origin_of(url)
        path = parts.path or "/"
        parent = path.rstrip("/").rsplit("/", 1)[0]
        control = origin + parent + "/reconix-nonexistent-7391"
        base = self._fetch(client, url)
        if base is None:
            return ({"url": url, "note": "not fetched (stopped or "
                     "request budget used)"}, None, None, cal)
        ctrl = self._fetch(client, control)
        attribution = attribute_source(base)
        f5 = f5_diagnostics(base)
        if f5 and self.f5_log:
            f5["log_correlation"] = correlate_f5_log(f5, self.f5_log)
        profile = {
            "url": url,
            "baseline_status": base.status,
            "baseline_size": len(base.body or ""),
            "baseline_elapsed_ms": round((base.elapsed or 0) * 1000),
            "baseline_fingerprint": fingerprint(base),
            "control_status": ctrl.status if ctrl else None,
            "control_url": control,
            "server": base.header("server", ""),
            "edge_headers": {k: v for k, v in
                             (("via", base.header("via")),
                              ("x-cache", base.header("x-cache")),
                              ("cf-ray", base.header("cf-ray")),
                              ("x-served-by", base.header("x-served-by")))
                             if v},
            "redirect_to": base.header("location", ""),
            "redirect_chain": [],
            "auth_required": bool(auth_signal(base)),
            "custom_error_page": bool(
                ctrl is not None and ctrl.status == base.status == 403
                and similarity(ctrl.body or "", base.body or "") > 0.9),
            "waf_block_page": waf_blocked(base),
            "attribution": attribution,
            "request_ids": extract_request_ids(base),
            "f5": f5,
            "likely_reasons": likely_reasons(base, attribution),
            "notes": [],
        }
        if base.status in (301, 302, 303, 307, 308) \
                and profile["redirect_to"]:
            hops = [{"status": base.status, "url": url,
                     "location": profile["redirect_to"]}]
            cur, seen = base, {url}
            for _ in range(5):
                nxt = urllib.parse.urljoin(cur.url or url,
                                           cur.header("location", ""))
                if not nxt or nxt in seen \
                        or not self._in_scope(nxt):
                    break
                seen.add(nxt)
                r = self._fetch(client, nxt)
                if r is None:
                    break
                hops.append({"status": r.status, "url": nxt,
                             "location": r.header("location", "")})
                if r.status not in (301, 302, 303, 307, 308) \
                        or not r.header("location"):
                    break
                cur = r
            profile["redirect_chain"] = hops
        if profile["custom_error_page"]:
            profile["notes"].append(
                "A nonexistent path returns the identical 403 body — "
                "this may be a generic/custom error page rather than an "
                "access-control decision for this resource.")
        if profile["redirect_to"]:
            profile["notes"].append(
                f"Baseline answers with a redirect to "
                f"{profile['redirect_to']} (chain of "
                f"{len(profile['redirect_chain'])} hop(s) recorded).")
        if profile["auth_required"]:
            profile["notes"].append(
                "The resource signals an authentication requirement "
                "(401 / WWW-Authenticate / login redirect).")
        if attribution["layer"] in ("waf", "cdn"):
            profile["notes"].append(
                f"Denial source looks like {attribution['vendor']} "
                f"({attribution['layer']}, confidence "
                f"{attribution['confidence']}): "
                + "; ".join(attribution["evidence"]))
        if f5:
            profile["notes"].append(
                f"F5 ASM support ID for the baseline denial: "
                f"{f5.get('support_id') or 'not present'} "
                f"(correlate it in the ASM event log).")
            corr = f5.get("log_correlation") or {}
            if corr.get("matched"):
                profile["notes"].append(
                    "The supplied F5 log excerpt contains this "
                    "support ID — the ASM policy block is confirmed "
                    "by the log"
                    + (f" (rule hint: {corr['rule_hint']})"
                       if corr.get("rule_hint") else "")
                    + ". The baseline request was a plain benign GET, "
                      "so if this URL is meant to be reachable, treat "
                      "it as a confirmed false positive and tune "
                      "that rule narrowly.")
            elif corr:
                profile["notes"].append(
                    "The supplied F5 log excerpt does not mention "
                    "this support ID.")
        return profile, base, ctrl, cal

    # -- technique catalog (spec §2) ---------------------------------------
    @staticmethod
    def _path_variants_full(path):
        """label -> mutated path: the checks4 base set plus the §2A
        additions (trailing dot, parent traversal, case forms,
        %2e / %c0%ae forms, matrix params, .html, /index)."""
        out = dict(_path_variants(path))
        segs = [s for s in path.split("/") if s]
        if segs:
            first = segs[0]
            out.setdefault("trailing dot", path + ".")
            out.setdefault("parent traversal",
                           "/" + first + "/.." + path)
            out.setdefault("capitalized first segment",
                           path.replace("/" + first,
                                        "/" + first.capitalize(), 1))
            out.setdefault("mixed case first segment",
                           path.replace("/" + first,
                                        "/" + first.swapcase(), 1))
            out.setdefault("encoded dot segment", "/%2e" + path)
            out.setdefault("overlong UTF-8 dot (%c0%ae)",
                           "/%c0%ae" + path)
            out.setdefault("matrix param ;foo=bar", path + ";foo=bar")
            out.setdefault("jsessionid matrix param",
                           path + ";jsessionid=RECONIXTEST")
            out.setdefault(".html extension", path + ".html")
            out.setdefault("index append", path + "/index")
            if len(segs) > 1:
                out.setdefault("encoded slash (%2f)",
                               "/" + first + "%2f"
                               + path[len(first) + 1:])
        return out

    def _catalog(self, url, parts, origin, path, control, identity,
                 cookie=""):
        """The bypass matrix for one identity context. Every entry
        carries its group, hypothesis and expected outcome; identical
        requests are deduplicated by the runner."""
        techs = []
        parent = path.rstrip("/").rsplit("/", 1)[0] or "/"
        cpath = urllib.parse.urlsplit(control).path
        DENIED = "denied with no protected content — the same " \
                 "enforcement decision as the original"

        def add(group, ttype, label, turl, hypothesis, headers=None,
                method="GET", data=None, raw=None, guard=None,
                plain=None, cookie_override=None, kind=None,
                policy_expected=None):
            t = {"group": group, "type": ttype, "label": label,
                 "url": turl, "headers": headers, "method": method,
                 "data": data, "raw": raw, "guard": guard,
                 "plain": plain, "identity": identity,
                 "hypothesis": hypothesis, "expected": DENIED}
            if cookie:
                t["cookie"] = cookie
            if cookie_override is not None:
                t["cookie_override"] = cookie_override
            if kind:
                t["kind"] = kind
            if policy_expected:
                t["policy_expected"] = policy_expected
            techs.append(t)

        def G(gurl, headers=None, method="GET", data=None, raw=None):
            return {"url": gurl, "headers": headers, "method": method,
                    "data": data, "raw": raw}

        def with_path(p):
            return urllib.parse.urlunsplit(parts._replace(path=p,
                                                          query=""))

        # ---- A. path & URL normalization ----
        if self.groups["path"]:
            variants = self._path_variants_full(path)
            cvariants = self._path_variants_full(cpath)
            for label, mpath in variants.items():
                add("path", "path-normalization",
                    f"path spelling ({label})", with_path(mpath),
                    "If path normalization is consistent, alternate "
                    "spellings of the same resource must be authorized "
                    "exactly like the canonical path.",
                    guard=G(with_path(cvariants.get(label, cpath))))
            # ---- H (cache). cache-deception spellings live here ----
            if self.groups["cache"]:
                for suffix in ("/reconix-cache.css", ".css"):
                    add("cache", "cache",
                        f"cache-deception spelling ({path}{suffix})",
                        with_path(path + suffix),
                        "Cache deception: if a static-looking suffix "
                        "makes the application serve the private "
                        "resource while the edge treats the URL as a "
                        "cacheable asset, the private response can be "
                        "stored and later served to anonymous users.",
                        guard=G(with_path(cpath + suffix)))
        # ---- B. path/route override headers ----
        if self.groups["override"]:
            for hdr in ("X-Original-URL", "X-Rewrite-URL",
                        "X-Original-Path"):
                add("override", "url-override", f"{hdr} header",
                    origin + "/",
                    "A proxy must not let URL-override headers "
                    "substitute a different routing/authorization "
                    "decision for the protected path.",
                    headers={hdr: path},
                    guard=G(origin + "/", headers={hdr: cpath}),
                    plain={"url": origin + "/", "headers": None})
            add("override", "url-override", "X-Forwarded-Prefix header",
                url,
                "A forwarded-prefix header must not rewrite the "
                "path the application authorizes.",
                headers={"X-Forwarded-Prefix": parent},
                guard=G(control, headers={"X-Forwarded-Prefix": parent}))
            add("override", "url-override", "Referer (self)", url,
                "Referer must not influence authorization.",
                headers={"Referer": origin + path},
                guard=G(control, headers={"Referer": origin + path}))
        # ---- C. host & proxy headers ----
        if self.groups["host"]:
            for hdr, val in (("X-Forwarded-Host", "internal.local"),
                             ("X-Host", "127.0.0.1"),
                             ("X-Forwarded-Server", "localhost"),
                             ("X-Forwarded-Proto",
                              "http" if parts.scheme == "https"
                              else "https")):
                add("host", "host-header", f"{hdr}: {val}", url,
                    "Host/proto forwarding headers must not change "
                    "which virtual host or security context serves "
                    "the protected resource.",
                    headers={hdr: val},
                    guard=G(control, headers={hdr: val}))
            netloc = parts.netloc
            host_only = parts.hostname or ""
            port_part = f":{parts.port}" if parts.port else ""
            host_variants = {
                "uppercase host": host_only.upper() + port_part,
                "explicit default port":
                    host_only + (":443" if parts.scheme == "https"
                                 else ":80"),
                "trailing-dot host": host_only + "." + port_part,
            }
            for label, nn in host_variants.items():
                if nn == netloc:
                    continue
                add("host", "host-header", f"host variation ({label})",
                    urllib.parse.urlunsplit(
                        parts._replace(netloc=nn)),
                    "Virtual-host routing must authorize the same "
                    "resource identically however the host is spelled.",
                    guard=G(urllib.parse.urlunsplit(
                        urllib.parse.urlsplit(control)._replace(
                            netloc=nn))))
        # ---- D. client-IP headers ----
        if self.groups["ip"]:
            forms = {
                "X-Forwarded-For": ["127.0.0.1", "10.1.2.3",
                                    "192.168.1.1", "::1",
                                    "127.0.0.1, 10.1.2.3",
                                    "10.1.2.3, 127.0.0.1"],
            }
            for h in _IP_HEADERS:
                for val in forms.get(h, ["127.0.0.1", "10.1.2.3"]):
                    add("ip", "ip-header", f"{h}: {val}", url,
                        "Client-IP headers are authoritative ONLY "
                        "when an IP-based ACL exists and the edge "
                        "does not strip them. Spoofing one must not "
                        "change authorization — and only the "
                        "protected content coming back proves it did.",
                        headers={h: val},
                        guard=G(control, headers={h: val}))
        # ---- E. method & verb tampering ----
        if self.groups["methods"]:
            write_ok = self.mode == "validation" or self.write_methods
            verbs = [("POST", {}), ("HEAD", None),
                     ("OPTIONS", None), ("TRACE", None)]
            if write_ok:
                verbs += [("PUT", {}), ("PATCH", {}), ("DELETE", None)]
            for m, data in verbs:
                add("methods", "method", f"{m} instead of GET", url,
                    "Methods must be authorized consistently"
                    + ("; HEAD is GET without a body by definition, "
                       "so a HEAD success can never by itself prove "
                       "content exposure." if m == "HEAD" else
                       ": a different verb must not retrieve or "
                       "affect what GET may not."),
                    method=m, data=data,
                    guard=G(control, method=m, data=data))
            for hdr, fake in (("X-HTTP-Method-Override", "DELETE"),
                              ("X-Method-Override", "PUT"),
                              ("X-HTTP-Method", "PATCH")):
                add("methods", "verb-override",
                    f"GET + {hdr}: {fake}", url,
                    "Method-override headers must not let a benign "
                    "GET be dispatched as a privileged verb.",
                    headers={hdr: fake},
                    guard=G(control, headers={hdr: fake}))
            add("methods", "method", "lowercase method (get)", url,
                "Method tokens are case-sensitive; a lowercase verb "
                "must not fall into a different (unauthenticated) "
                "handler.",
                method="get", guard=G(control, method="get"))
            add("methods", "method", "custom verb (RECONIX)", url,
                "Unknown verbs must be rejected, not routed to a "
                "default handler that skips authorization.",
                method="RECONIX", guard=G(control, method="RECONIX"))
            add("methods", "method", "empty method", url,
                "A malformed (empty) method must be rejected, not "
                "routed around authorization.",
                method="", raw={"version": "1.1"},
                guard=G(control, method="",
                        raw={"version": "1.1"}))
        # ---- F. protocol & connection ----
        if self.groups["protocol"]:
            add("protocol", "protocol", "HTTP/1.0 request", url,
                "Older protocol versions must pass the same "
                "authorization; some stacks route 1.0 traffic to "
                "legacy handlers.",
                raw={"version": "1.0"},
                guard=G(control, raw={"version": "1.0"}))
            add("protocol", "protocol",
                "absolute-form request line", url,
                "An absolute-form request target must be authorized "
                "like the origin-form equivalent; some proxies and "
                "origins disagree about which path it names.",
                raw={"version": "1.1", "absolute_form": True},
                guard=G(control,
                        raw={"version": "1.1", "absolute_form": True}))
            add("protocol", "protocol", "HTTP/1.0 without Host header",
                url,
                "A request with no Host header must not land on a "
                "default virtual host that skips the ACL.",
                raw={"version": "1.0"}, headers={"Host": None},
                guard=G(control, raw={"version": "1.0"},
                        headers={"Host": None}))
        # ---- G. auth-context variation ----
        if self.groups["authctx"] and cookie:
            pairs = [p.strip() for p in cookie.split(";") if p.strip()]

            def degrade(fn):
                out = []
                for p in pairs:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        out.append(f"{k}={fn(v)}")
                    else:
                        out.append(fn(p))
                return "; ".join(out)

            add("authctx", "auth-context",
                "partial session cookie (truncated values)", url,
                "A truncated session token must not authenticate — "
                "session validation must be exact, not prefix-based.",
                cookie_override=degrade(
                    lambda v: v[:max(1, int(len(v) * 0.6))]),
                kind="identity", policy_expected="deny")
            add("authctx", "auth-context",
                "stale session cookie (mutated values)", url,
                "A mutated/stale session token must not authenticate "
                "— the server must validate the exact token, "
                "including its expiry/integrity.",
                cookie_override=degrade(lambda v: v + "-stale"),
                kind="identity", policy_expected="deny")
            if len(pairs) > 1:
                add("authctx", "auth-context",
                    "partial session cookie (first pair only)", url,
                    "A partial cookie set must not authenticate when "
                    "the session needs all of its parts.",
                    cookie_override=pairs[0],
                    kind="identity", policy_expected="deny")
        # degraded-cookie tests belong to the identity that owns the
        # cookie, not to the anonymous battery context
        for t in techs:
            if t["group"] != "authctx" or not cookie:
                continue
            if cookie == self.identities["role_a"]["cookie"]:
                t["identity"] = "role_a"
            elif cookie == self.identities["role_b"]["cookie"]:
                t["identity"] = "role_b"
        return techs

    def _dedupe_plan(self, techs):
        """Drop identical planned requests — dedupe by hash of
        method + URL + normalized headers + body + channel (§2)."""
        seen, out = set(), []
        for t in techs:
            norm = sorted((k.lower(), v) for k, v in
                          (t.get("headers") or {}).items())
            key_src = repr((t.get("identity", "anon"),
                            t.get("method", "GET"), t["url"], norm,
                            repr(t.get("data")), repr(t.get("raw")),
                            t.get("cookie_override")))
            key = hashlib.sha256(key_src.encode()).hexdigest()
            if key in seen:
                self.deduped += 1
                continue
            seen.add(key)
            out.append(t)
        return out

    def _run_catalog(self, client, cal, url, base, techs, identity,
                     default_policy=None):
        for tech in self._dedupe_plan(techs):
            if self.stop.is_set() or self.exhausted:
                break
            r = self._send_tech(client, tech)
            if r is None:
                continue
            self._judge(url, tech, base, r, client, cal,
                        identity=tech.get("identity") or identity,
                        policy_expected=tech.get("policy_expected",
                                                 default_policy),
                        kind=tech.get("kind", "technique"))


    # -- shared passes -------------------------------------------------------
    def _session_pass(self, url, parts, origin, path, control,
                      base, profile):
        """Diagnostics comparison: supplied test account (role A)
        against the anonymous baseline."""
        sclient = self._identity_client("role_a")
        sb = self._fetch(sclient, url)
        if sb is None:
            return
        label_a = self.identities["role_a"]["label"]
        profile["session_status"] = sb.status
        profile["session_size"] = len(sb.body or "")
        cal = self._calibrators.get(_origin_of(url))
        assess = self._assess_access(cal, base, sb, "")
        profile["session_can_access"] = bool(assess["proof"])
        profile.setdefault("identities", []).append({
            "identity": "role_a", "label": label_a, "status": sb.status,
            "access": assess["access"]})
        profile["notes"].append(
            f"As {label_a} the baseline answers {sb.status} "
            f"({len(sb.body or '')} bytes) vs {base.status} anonymous"
            + (" — the test account CAN legitimately open this "
               "resource, so any anonymous success is a genuine "
               "exposure." if assess["proof"] else
               " — even the supplied test account is denied."))
        if sb.status != 403:
            return
        for label, mpath in list(_path_variants(path))[:4]:
            if self.stop.is_set() or self.exhausted:
                return
            murl = urllib.parse.urlunsplit(parts._replace(path=mpath,
                                                          query=""))
            r = self._fetch(sclient, murl)
            if r is not None and r.status in (200, 201, 206):
                ok, _w = self._proof(cal, base, r)
                if ok:
                    self._record(
                        url, "session",
                        f"as {label_a} + path spelling ({label})",
                        base, r, "misconfig_suspected", "Medium",
                        "LIKELY",
                        "Anonymous requests are denied, and the plain "
                        f"{label_a} request is 403, but {label_a} plus "
                        "a path spelling returns the content — "
                        "enforcement differs by path spelling for "
                        "authenticated users. (Suspected, not "
                        "verified: no owner policy/marker was "
                        "configured for this diagnostics run.)",
                        hypothesis="Path spelling must not change the "
                                   "authorization decision for a "
                                   "signed-in identity either.",
                        expected="403 for every spelling",
                        identity="role_a", group="authctx")
                    return

    def _origin_pass(self, url, parts, path, base, cal,
                     identity="anon", client=None):
        origin = self.origin
        if "://" not in origin:
            origin = "http://" + origin
        oparts = urllib.parse.urlsplit(origin)
        ourl = urllib.parse.urlunsplit(
            oparts._replace(path=path, query="", fragment=""))
        oclient = client or self._client()
        tech = {"group": "origin", "type": "origin",
                "label": f"direct origin request ({oparts.netloc})",
                "url": ourl, "method": "GET",
                "headers": {"Host": parts.netloc}, "data": None,
                "raw": None, "guard": None,
                "hypothesis": "If access policy is configured at the "
                              "edge only, asking the origin directly "
                              "(with the target's Host header) must "
                              "still be denied — the ACL must live at "
                              "the origin too, or the origin must not "
                              "be reachable.",
                "expected": "denied at the origin as well"}
        r = self._send_tech(oclient, tech)
        if r is None:
            return
        self._judge(url, tech, base, r, oclient, cal, identity=identity,
                    policy_expected="deny"
                    if self.mode == "validation" else None)

    def _altport_pass(self, url, parts, path, base, cal,
                      identity="anon", client=None):
        p = urllib.parse.urlsplit(url)
        aurl = urllib.parse.urlunsplit(
            p._replace(netloc=f"{p.hostname}:{self.alt_port}"))
        tech = {"group": "origin", "type": "origin",
                "label": f"alternate port ({self.alt_port})",
                "url": aurl, "method": "GET",
                "headers": {"Host": parts.netloc}, "data": None,
                "raw": None, "guard": None,
                "hypothesis": "The same application on an alternate "
                              "port must enforce the same policy — "
                              "alternate listeners often skip the "
                              "proxy and its ACLs.",
                "expected": "denied on the alternate port as well"}
        r = self._send_tech(client or self._client(), tech)
        if r is None:
            return
        self._judge(url, tech, base, r, client or self._client(), cal,
                    identity=identity,
                    policy_expected="deny"
                    if self.mode == "validation" else None)

    # -- Mode A: diagnostics ----------------------------------------------
    def analyze_url(self, url):
        if not self._in_scope(url):
            self._log(f"out of scope, skipped: {url}")
            return
        client = self._client()
        profile, base, ctrl, cal = self._profile_baseline(url, client)
        if base is None:
            self.profiles.append(profile)
            return
        parts = urllib.parse.urlsplit(url)
        origin = _origin_of(url)
        path = parts.path or "/"
        control = profile["control_url"]

        if base.status != 403:
            profile["notes"].append(
                f"Baseline is HTTP {base.status}, not 403 — the state "
                f"changed since discovery; variant results are shown "
                f"for reference only.")
            self.profiles.append(profile)
            self._record(url, "baseline", "original request", base,
                         base, "inconclusive", "Info", "SPECULATIVE",
                         f"Baseline returned {base.status} instead of "
                         f"the expected 403.",
                         hypothesis="The target was reported to "
                                    "answer 403 to a plain request.",
                         expected="403 denial from an identifiable "
                                  "layer")
            return

        # anonymous battery: NO cookie anywhere near it — the raw
        # channel stamps the context cookie onto its requests, so an
        # "anonymous" test carrying the session cookie would be a
        # false context (this bug class is why auth-context tests
        # are built as a separate pass below)
        techs = self._catalog(url, parts, origin, path, control,
                              "anon", cookie="")
        self._run_catalog(client, cal, url, base, techs, "anon")
        if self.cookie and self.groups["authctx"]:
            atechs = [t for t in self._catalog(
                url, parts, origin, path, control, "anon",
                cookie=self.cookie) if t["group"] == "authctx"]
            self._run_catalog(client, cal, url, base, atechs, "anon")
            self._session_pass(url, parts, origin, path, control,
                               base, profile)
        if self.groups["origin"]:
            if self.origin:
                self._origin_pass(url, parts, path, base, cal)
            if self.alt_port:
                self._altport_pass(url, parts, path, base, cal)
        self.profiles.append(profile)

    # -- Mode B: authorized access-control validation ----------------------
    def analyze_validation_url(self, url):
        if not self._in_scope(url):
            self._log(f"out of scope, skipped: {url}")
            return
        pol = self._policy_for(url)
        marker = pol["marker"]
        anon = self._identity_client("anon")
        profile, base, ctrl, cal = self._profile_baseline(url, anon)
        if base is None:
            self.profiles.append(profile)
            return
        parts = urllib.parse.urlsplit(url)
        origin = _origin_of(url)
        path = parts.path or "/"
        control = profile["control_url"]
        profile["mode"] = "validation"
        profile["policy"] = {"expect": pol["expect"],
                             "marker_configured": bool(marker),
                             "equivalents_supplied":
                                 len(pol["equivalents"])}
        base403 = base if base.status == 403 else None

        # ---- Baseline phase, part 1: public control sanity check ----
        pc_url = self.public_control or (origin + "/")
        if pc_url != url:
            pcr = self._fetch(anon, pc_url)
            if pcr is not None:
                pc_attr = attribute_source(pcr)
                profile["public_control"] = {
                    "url": pc_url, "status": pcr.status,
                    "layer": pc_attr.get("layer", "")}
                if pc_attr.get("layer") in ("waf", "cdn"):
                    profile["notes"].append(
                        "The known-public control resource is ALSO "
                        f"answered by {pc_attr.get('vendor')} — the "
                        "edge may be blocking this test client "
                        "generally, so read denials with care.")

        # ---- Baseline phase, part 2: identity ground truth -----------
        matrix = []
        clients = {"anon": anon}
        granted_resp = {}
        for ident in ("anon", "role_a", "role_b"):
            if ident != "anon" and not self.identities[ident]["cookie"]:
                continue
            client = clients.get(ident) or self._identity_client(ident)
            clients[ident] = client
            resp = base if ident == "anon" else self._fetch(client, url)
            if resp is None:
                continue
            assess = self._assess_access(cal, base403, resp, marker)
            expected = pol["expect"][ident]
            actual = assess["access"]
            match = (expected == "allow" and actual == "granted") or \
                    (expected == "deny"
                     and actual in ("denied", "auth"))
            matrix.append({
                "identity": ident,
                "label": self.identities[ident]["label"],
                "status": resp.status, "access": actual,
                "expected": expected, "match": match,
                "layer": attribute_source(resp).get("layer", "")})
            if actual == "granted":
                granted_resp[ident] = resp
            if match:
                continue
            label = self.identities[ident]["label"]
            if expected == "allow":
                self._record(
                    url, "auth-state",
                    f"policy mismatch — {label} should be ALLOWED",
                    base, resp, "misconfig_suspected", "Low",
                    "CONFIRMED",
                    f"The configured policy says {label} may access "
                    f"this resource, but the request was answered "
                    f"{resp.status} (access state: {actual}). Either "
                    f"the policy or the enforcement is wrong — the "
                    f"owner's own test account cannot reach what it "
                    f"should.",
                    hypothesis="Enforcement must match the configured "
                               "policy for every identity, in both "
                               "directions.",
                    expected=f"{label}: access granted",
                    identity=ident, group="authctx",
                    policy={"expected": "allow", "actual": actual})
            else:
                tech = {"group": "authctx", "type": "auth-state",
                        "label": f"policy violation — {label} is "
                                 f"served the resource but policy "
                                 f"says DENY",
                        "url": url, "method": "GET", "headers": None,
                        "data": None, "raw": None,
                        "guard": {"url": control, "headers": None,
                                  "method": "GET", "data": None,
                                  "raw": None},
                        "hypothesis": "An identity the configured "
                                      "policy denies must not be "
                                      "served the resource.",
                        "expected": f"{label}: denied"}
                self._judge(url, tech, base, resp, client, cal,
                            identity=ident, policy_expected="deny",
                            kind="identity")
        profile["matrix"] = matrix
        profile["identities"] = [
            {"identity": m["identity"], "label": m["label"],
             "status": m["status"], "access": m["access"]}
            for m in matrix]
        mismatches = sum(1 for m in matrix if not m["match"])
        profile["notes"].append(
            f"Validation matrix: {mismatches} of {len(matrix)} "
            f"identity results contradict the configured policy."
            if mismatches else
            "Validation matrix: every identity result matches the "
            "configured policy.")

        # ---- Baseline phase, part 3: fingerprint + protection --------
        fp = None
        for ident in ("role_a", "role_b", "anon"):
            if ident in granted_resp:
                fp = fingerprint(granted_resp[ident], marker)
                break
        if fp:
            self._fp[url] = fp
            profile["fingerprint"] = {
                k: fp.get(k) for k in
                ("sha256", "title", "size", "content_type",
                 "marker_present", "redirect_target")}
        anon_row = next((m for m in matrix
                         if m["identity"] == "anon"), None)
        protected = not (anon_row and anon_row["access"] == "granted")
        profile["protected_baseline"] = protected
        if not protected:
            self._never_protected.add(url)
            profile["notes"].append(
                "The plain anonymous baseline already returns this "
                "resource — it was never protected. Technique results "
                "below are therefore capped at SUSPECTED (a missing "
                "access control is not a 'bypass'); the front-door "
                "policy violation itself is recorded in the matrix.")

        # ---- Probe phase: bypass matrix per policy-denied identity ---
        denied_ids = [i for i in ("anon", "role_a", "role_b")
                      if pol["expect"][i] == "deny"
                      and (i == "anon" or self.identities[i]["cookie"])]
        for ident in denied_ids:
            if self.stop.is_set() or self.exhausted:
                break
            client = clients.get(ident) or self._identity_client(ident)
            clients[ident] = client
            techs = self._catalog(url, parts, origin, path, control,
                                  ident,
                                  cookie=self.identities[ident]["cookie"])
            techs = [t for t in techs if t["group"] != "authctx"]
            self._run_catalog(client, cal, url, base, techs, ident,
                              default_policy="deny")
        # ---- Probe phase: degraded auth contexts of supplied ids -----
        if self.groups["authctx"]:
            for ident in ("role_a", "role_b"):
                ck = self.identities[ident]["cookie"]
                if not ck or self.stop.is_set() or self.exhausted:
                    continue
                client = clients.get(ident) \
                    or self._identity_client(ident)
                clients[ident] = client
                techs = [t for t in self._catalog(
                    url, parts, origin, path, control, ident,
                    cookie=ck) if t["group"] == "authctx"]
                self._run_catalog(client, cal, url, base, techs, ident,
                                  default_policy="deny")
        # ---- owner-supplied equivalent resources ----------------------
        for eq in pol["equivalents"]:
            if self.stop.is_set() or self.exhausted:
                break
            self._equivalent_pass(url, eq, pol, cal, base, base403,
                                  marker, control)
        # ---- edge vs origin under the policy ---------------------------
        if self.groups["origin"]:
            if self.origin:
                self._origin_pass(url, parts, path, base, cal)
            if self.alt_port:
                self._altport_pass(url, parts, path, base, cal)
        self.profiles.append(profile)

    def _equivalent_pass(self, url, eq, pol, cal, base, base403,
                         marker, control):
        """One owner-supplied equivalent resource, tested as
        anonymous (the canonical denied identity). Sameness with the
        canonical resource must be established first — via the
        baseline fingerprint — otherwise the result is inconclusive
        by design."""
        clean, err = validate_url(eq)
        if err or not self._in_scope(clean):
            self._record(url, "equivalent",
                         f"equivalent resource {eq}", base, None,
                         "inconclusive", "Info", "SPECULATIVE",
                         f"Equivalent {eq!r} is invalid or outside "
                         f"the defined scope and was not requested.",
                         group="path")
            return
        fp = self._fp.get(url)
        same = None
        allow_id = next((i for i in ("role_a", "role_b", "anon")
                         if pol["expect"][i] == "allow"
                         and (i == "anon"
                              or self.identities[i]["cookie"])), None)
        if allow_id is not None:
            aclient = self._identity_client(allow_id)
            ar = self._fetch(aclient, clean)
            if ar is not None and ar.status in (200, 201, 206):
                if fp:
                    same = fingerprint_match(fp, ar, marker)
                elif marker:
                    same = marker in (ar.body or "")
        anon = self._identity_client("anon")
        r = self._fetch(anon, clean)
        if r is None:
            return
        if same is False:
            self._record(url, "equivalent",
                         f"equivalent resource {clean}", base, r,
                         "inconclusive", "Info", "SPECULATIVE",
                         "The supplied equivalent could not be proven "
                         "to be the same resource (the allowed "
                         "identity's response did not fingerprint-"
                         "match), so its behaviour proves nothing "
                         "about consistency.",
                         group="path")
            return
        tech = {"group": "path", "type": "equivalent",
                "label": f"equivalent resource {clean} as anonymous",
                "url": clean, "method": "GET", "headers": None,
                "data": None, "raw": None,
                "guard": {"url": control, "headers": None,
                          "method": "GET", "data": None, "raw": None},
                "hypothesis": "Equivalent spellings/URLs of the same "
                              "resource must enforce the same policy "
                              "for the same identity.",
                "expected": "anonymous: denied"}
        self._judge(url, tech, base, r, anon, cal, identity="anon",
                    policy_expected="deny")


    # -- driver -------------------------------------------------------------
    def run(self):
        mode_word = "validation" if self.mode == "validation" \
            else "diagnostics"
        self._log(f"mode: {mode_word} · targets: {len(self.urls)} · "
                  f"budget: {self.budget.cap} requests · rate limit: "
                  f"{round(self.min_interval * 1000)} ms per host")
        if self.mode == "validation":
            self._log("policy: "
                      + ", ".join(f"{i}={self.expect[i]}"
                                  for i in ("anon", "role_a", "role_b"))
                      + (" · harmless-resource marker configured"
                         if self.marker else
                         " · WARNING: no marker set — verification "
                         "relies on content fingerprints only"))
        fn = self.analyze_validation_url \
            if self.mode == "validation" else self.analyze_url
        done, total = 0, len(self.urls)
        if total:
            self.progress(done=0, total=total)
        if self.concurrency > 1 and total > 1:
            with ThreadPoolExecutor(
                    max_workers=self.concurrency) as ex:
                futs = [ex.submit(fn, u) for u in self.urls]
                for f in futs:
                    try:
                        f.result()
                    except Exception:
                        pass
                    done += 1
                    self.progress(done=done, total=total)
        else:
            for u in self.urls:
                if self.stop.is_set():
                    break
                try:
                    fn(u)
                except Exception:
                    pass
                done += 1
                self.progress(done=done, total=total)
        order = {"bypass_verified": 0, "weakness_verified": 0,
                 "confirmed": 0, "bypass_candidate": 1,
                 "misconfig_suspected": 2, "potential": 2,
                 "waf_block": 3, "auth_required": 4,
                 "inconclusive": 5, "block_confirmed": 6, "denied": 6}
        self.records.sort(key=lambda r: (
            order.get(r["classification"], 9), r["url"], r["technique"]))
        summary = {}
        rollup = {k: 0 for k in ROLLUP}
        for r in self.records:
            summary[r["classification"]] = \
                summary.get(r["classification"], 0) + 1
            for k, codes in ROLLUP.items():
                if r["classification"] in codes:
                    rollup[k] += 1
        rollup["verified"] = rollup["verified_bypass"] \
            + rollup["verified_weakness"]
        if self.exhausted:
            self._log("request budget reached — remaining URLs/tests "
                      "were skipped")
        return {
            "module": MODULE, "version": "3.14",
            "mode": self.mode,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "targets": list(self.urls),
            "profiles": self.profiles,
            "records": self.records,
            "summary": summary,
            "rollup": rollup,
            "requests_used": self.budget.used,
            "deduped_tests": self.deduped,
            "stopped": self.stop.is_set() and done < total,
            "options": {
                "groups": self.groups,
                "identities_supplied": {
                    i: bool(self.identities[i]["cookie"])
                    for i in ("role_a", "role_b")},
                "identity_labels": {i: self.identities[i]["label"]
                                    for i in
                                    ("anon", "role_a", "role_b")},
                "marker_configured": bool(self.marker),
                "min_interval_ms": round(self.min_interval * 1000),
                "origin_supplied": bool(self.origin),
                "alt_port": self.alt_port,
                "public_control_supplied": bool(self.public_control),
                "f5_log_supplied": bool(self.f5_log),
                "max_requests": self.budget.cap,
            },
            "log": self.logs,
        }


def analyze(urls, opts=None, stop=None, progress=None):
    return Tester(urls, opts, stop=stop, progress=progress).run()


# ------------------------------------------------------------ HTML report
_CLASS_COLORS = {
    "bypass_verified": "#b42318", "weakness_verified": "#b42318",
    "confirmed": "#b42318", "bypass_candidate": "#dc6803",
    "misconfig_suspected": "#dc6803", "potential": "#dc6803",
    "waf_block": "#175cd3", "auth_required": "#6941c6",
    "block_confirmed": "#067647", "denied": "#067647",
    "inconclusive": "#667085",
}


def to_html(run):
    esc = html.escape
    counts = run.get("summary", {})
    roll = run.get("rollup", {})
    chips = []
    for k, word in (("verified_bypass", "BYPASS_VERIFIED"),
                    ("verified_weakness", "WEAKNESS_VERIFIED"),
                    ("candidates", "BYPASS_CANDIDATE"),
                    ("suspected", "SUSPECTED"),
                    ("waf_blocked", "WAF_BLOCK_DETECTED"),
                    ("auth_required", "AUTHENTICATION_REQUIRED"),
                    ("blocked", "BLOCK_CONFIRMED"),
                    ("inconclusive", "INCONCLUSIVE")):
        chips.append(f"<span class='chip'>{word}: "
                     f"<b>{roll.get(k, 0)}</b></span>")
    prof_rows = []
    for p in run.get("profiles", []):
        a = p.get("attribution") or {}
        src = (esc(a.get("vendor", "")) + " (" + esc(a.get("layer", ""))
               + ")") if a else "—"
        f5 = p.get("f5") or {}
        f5txt = ""
        if f5:
            f5txt = f"<br>F5 support ID: {esc(f5.get('support_id') or '—')}"
            corr = f5.get("log_correlation") or {}
            if corr.get("matched"):
                f5txt += " — confirmed in the supplied ASM log excerpt"
        reasons = "<br>".join("• " + esc(x)
                              for x in p.get("likely_reasons", []))
        extra = ""
        if p.get("fingerprint"):
            fp = p["fingerprint"]
            extra = (f"<br>Resource fingerprint: sha256 "
                     f"{esc(fp.get('sha256') or '')}, title "
                     f"{esc(fp.get('title') or '—')}, "
                     f"{fp.get('size')} bytes")
        if p.get("public_control"):
            pcx = p["public_control"]
            extra += (f"<br>Public control: {pcx.get('status')} "
                      f"({esc(pcx.get('layer') or '')})")
        prof_rows.append(
            f"<tr><td>{esc(p['url'])}</td>"
            f"<td>{p.get('baseline_status')}<br>"
            f"<small>{p.get('baseline_elapsed_ms', '—')} ms</small></td>"
            f"<td>{src}{f5txt}{extra}</td>"
            f"<td>{esc('; '.join(p.get('notes', [])))}</td>"
            f"<td>{reasons}</td></tr>")
    matrix_sec = ""
    for p in run.get("profiles", []):
        if not p.get("matrix"):
            continue
        rows = "".join(
            f"<tr><td>{esc(m['label'])}</td><td>{esc(m['expected'])}"
            f"</td><td>{m['status']} / {esc(m['access'])}</td>"
            f"<td>{'match' if m['match'] else 'MISMATCH'}</td></tr>"
            for m in p["matrix"])
        matrix_sec += (f"<h3>Validation matrix — {esc(p['url'])}</h3>"
                       f"<table><tr><th>Identity</th><th>Expected</th>"
                       f"<th>Observed</th><th>Result</th></tr>"
                       f"{rows}</table>")
    f5_sec = ""
    for p in run.get("profiles", []):
        d = p.get("f5")
        if not d:
            continue
        ev = "<br>".join("• " + esc(x) for x in d.get("evidence", []))
        f5_sec += (
            f"<tr><td>{esc(p['url'])}</td>"
            f"<td>{esc(d.get('support_id') or '—')}</td>"
            f"<td>{esc(d.get('timestamp', ''))}</td>"
            f"<td>{esc(d.get('server', ''))}</td><td>{ev}</td></tr>")
    if f5_sec:
        f5_sec = ("<h3>F5 WAF diagnostics</h3><table><tr><th>URL</th>"
                  "<th>Support ID</th><th>Time (response Date)</th>"
                  "<th>Server</th><th>Indicators</th></tr>"
                  + f5_sec + "</table><p>Correlate each support ID in "
                  "the F5 ASM event log to see the triggered rule. If "
                  "the blocked traffic was legitimate, tune that rule "
                  "narrowly — confirmed false positives only.</p>")
    detail = ""
    for code in ("bypass_verified", "weakness_verified", "confirmed",
                 "bypass_candidate", "misconfig_suspected", "potential",
                 "waf_block"):
        recs = [r for r in run["records"]
                if r["classification"] == code]
        if not recs:
            continue
        items = ""
        for r in recs:
            ver = r.get("verify") or {}
            ver_txt = ""
            if ver.get("observations"):
                ver_txt = (f"<p><b>Verification:</b> reproduced on "
                           f"{ver.get('matches')} of "
                           f"{ver.get('observations')} observations; "
                           f"catch-all guard "
                           f"{'passed' if ver.get('guard_ok') else 'FAILED or n/a'}; "
                           f"fingerprint match: {r.get('fingerprint_match')}</p>")
            items += (
                f"<div class='f'><h4>{esc(r['url'])} — "
                f"{esc(r['technique'])}</h4>"
                f"<p><b>{r['class_label']}</b> · severity "
                f"{esc(r['severity'])} · confidence "
                f"{esc(r['confidence'])} · group "
                f"{esc(r.get('group', ''))} · identity "
                f"{esc(r.get('identity', '') or '—')}</p>"
                + (f"<p><b>Hypothesis:</b> {esc(r['hypothesis'])}</p>"
                   if r.get("hypothesis") else "")
                + ver_txt
                + f"<p>{esc(r['evidence'])}</p>"
                + (f"<p><b>F5 support ID:</b> "
                   f"{esc(r['f5']['support_id'])}</p>"
                   if r.get("f5") and r["f5"].get("support_id") else "")
                + f"<p><b>What to do:</b> {esc(r['remediation'])}</p>"
                f"<details><summary>Original vs test (redacted)</"
                f"summary><pre>{esc(r['original']['request'])}</pre>"
                f"<pre>HTTP {r['test']['status']}\n"
                f"{esc(r['test']['body'])}</pre></details></div>")
        detail += (f"<h3>{CLASS_LABELS[code]} "
                   f"({counts.get(code, 0)})</h3>{items}")
    rows = []
    for r in run["records"]:
        color = _CLASS_COLORS.get(r["classification"], "#333")
        rows.append(
            f"<tr><td>{esc(r['url'])}</td>"
            f"<td>{esc(r.get('group', ''))}<br>"
            f"<small>{esc(r['technique'])}</small></td>"
            f"<td>{esc(r.get('identity', '') or '—')}</td>"
            f"<td>{r['original']['status']} → {r['test']['status']}</td>"
            f"<td style='color:{color}'><b>{r['class_label']}</b><br>"
            f"<small>{esc(r['confidence'])}</small></td></tr>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Reconix 3.14 — 403 Access-Control Assessment</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1d2939}}
table{{border-collapse:collapse;width:100%;margin:10px 0 20px}}
td,th{{border:1px solid #d0d5dd;padding:6px 8px;font-size:13px;
text-align:left;vertical-align:top}}
.chip{{display:inline-block;background:#eef4ff;border:1px solid #b2ccff;
border-radius:12px;padding:3px 10px;margin:2px;font-size:12px}}
.f{{border:1px solid #d0d5dd;border-left:4px solid #b42318;
padding:10px 14px;margin:10px 0}}
pre{{background:#f8fafc;padding:8px;overflow:auto;font-size:11px;
white-space:pre-wrap}}
</style></head><body>
<h2>403 Access-Control Assessment — {esc(run.get('mode', ''))} mode</h2>
<p>Reconix 3.14 · {esc(run.get('started_at', ''))} · 
targets: {len(run.get('targets', []))} · requests used: 
{run.get('requests_used', 0)} · identical tests deduplicated: 
{run.get('deduped_tests', 0)}</p>
<p>{' '.join(chips)}</p>
<h3>Profiles — who denied the original request</h3>
<table><tr><th>URL</th><th>Original</th><th>Denial source</th>
<th>Notes</th><th>Likely reasons</th></tr>{''.join(prof_rows)}</table>
{matrix_sec}{f5_sec}{detail}
<h3>All tests</h3>
<table><tr><th>URL</th><th>Group / Technique</th><th>Identity</th>
<th>Status</th><th>Verdict</th></tr>{''.join(rows)}</table>
</body></html>"""
