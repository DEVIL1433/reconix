"""Accuracy layer: per-target calibration, similarity, confirmation.

Real apps are noisy: soft-404s return HTTP 200 with a 'not found' page,
pages embed rotating CSRF tokens and timestamps, and WAFs block probes.
Calibrating against the target's baseline behaviour before testing is
what separates a scanner that cries wolf from one that's right.
"""
import difflib
import random
import re
import statistics
import urllib.parse

VOLATILE_RES = [re.compile(p) for p in [
    r"\b[0-9a-f]{32,}\b",                                   # md5/sha tokens
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b",
    r"\b\d{2}:\d{2}:\d{2}\b", r"\b\d{10,13}\b",             # times / epochs
    r"(?i)(csrf|authenticity|__requestverification|nonce|token)"
    r"[^a-z0-9]{0,8}[a-z0-9_\-+/=]{8,}",
    r"\b[a-zA-Z0-9_\-]{24,}\b",                             # opaque ids
]]


def normalize(body):
    """Strip volatile content so two responses can be compared fairly."""
    if not body:
        return ""
    out = body
    for r in VOLATILE_RES:
        out = r.sub("\x00", out)
    out = re.sub(r"\s+", " ", out)
    return out


def _window(s, cap=12000):
    """Head+tail window so differences deep in large pages still count."""
    if len(s) <= cap:
        return s
    half = cap // 2
    return s[:half] + s[-half:]


def similarity(a, b):
    """0..1 similarity of two bodies AFTER volatile-content stripping."""
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, _window(na), _window(nb)).ratio()


def median_time(samples):
    return statistics.median(samples) if samples else 0.0


WAF_BLOCK_HINTS = ("request blocked", "attention required", "access denied",
                   "incident id", "cloudflare", "imperva", "incapsula",
                   "mod_security", "web application firewall", "blocked by",
                   "security policy", "malicious request", "ray id")


def waf_blocked(resp):
    """Heuristic: did a WAF (not the app) reject this probe?"""
    if resp is None or resp.status is None:
        return False
    if resp.status in (403, 406, 501, 429) :
        body = (resp.body or "").lower()
        hdrs = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
        if any(h in body or h in hdrs.lower() for h in WAF_BLOCK_HINTS):
            return True
        # a bare 403 on an attack payload, where the baseline was reachable,
        # is suggestive but not conclusive — treat 406/501 as blocks too
        return resp.status in (406, 501)
    return False


def confirm(send, predicate, attempts=3, need=2):
    """Reproducibility gate: run send() up to `attempts` times; the check
    is confirmed when `predicate(resp)` holds at least `need` times.
    Returns (ok, successes, last_resp)."""
    hits, last = 0, None
    for _ in range(attempts):
        last = send()
        if last is not None and predicate(last):
            hits += 1
            if hits >= need:
                return True, hits, last
    return hits >= need, hits, last


class Calibrator:
    """Learns the target's baseline: soft-404 behaviour and page noise."""

    def __init__(self, client, base):
        parts = urllib.parse.urlsplit(base)
        self.root = f"{parts.scheme}://{parts.netloc}"
        tag = random.randint(100000, 999999)
        r1 = client.fetch(f"{self.root}/wsx-missing-{tag}")
        r2 = client.fetch(f"{self.root}/wsx-dir-{tag}/wsx-missing-{tag}")
        self.soft404_status = r1.status
        self.soft404_body = r1.body or ""
        self.soft404_body2 = r2.body or ""
        b1 = client.fetch(base)
        b2 = client.fetch(base)
        self.noise = 1.0 - similarity(b1.body or "", b2.body or "") \
            if b1.body and b2.body else 0.0
        self.summary = (f"soft-404 status={self.soft404_status}, "
                        f"page noise={self.noise:.0%}")

    def is_soft404(self, resp):
        """True when a 200 response is really the app's 'not found' page."""
        if resp is None or resp.status is None:
            return True
        if self.soft404_status and resp.status == self.soft404_status \
                and self.soft404_status not in (200,):
            return False  # the app uses real status codes for misses
        if resp.status != 200:
            return False
        sim = max(similarity(resp.body or "", self.soft404_body),
                  similarity(resp.body or "", self.soft404_body2))
        return sim > 0.88

    def genuinely_different(self, body_a, body_b, margin=0.12):
        """True when two bodies differ beyond the target's own noise."""
        return similarity(body_a, body_b) < 1.0 - max(self.noise, 0.02) - margin
