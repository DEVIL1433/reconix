"""Subdomain takeover checks (proof-only).

A subdomain whose DNS points at a third-party hosting service that no
longer has an account / project for it can be claimed by anyone who
registers that name on the service — full control of content served
under the victim's subdomain. This module detects that state, but a
fingerprint match alone is NEVER reported:

  1. Enumerate subdomains from the scan's own scope (recon results,
     crawled hosts, hostnames mentioned in crawled pages). No live
     DNS brute-forcing or CT-log queries happen here — the engine
     supplies what it already discovered.
  2. Resolve each subdomain's CNAME target (injectable resolver; the
     default uses the system resolver's canonical name, which is the
     closest stdlib approximation to a CNAME lookup — see
     :func:`default_resolver`).
  3. Match the CNAME (or the subdomain itself, for subdomains that
     live directly under a service domain, e.g. ``x.github.io``)
     against the documented fingerprint list below.
  4. PROVE it: fetch the subdomain itself twice. Only if BOTH fetches
     return the service's unclaimed/available signature does a
     finding fire. A fingerprint match whose live page shows anything
     else (a real site, a generic error, a transient failure) is
     silently dropped — the signature must reproduce.

Nothing here claims anything: the "claim check" is the service's own
unclaimed page, read, never a registration attempt. No finding is
emitted for a subdomain that cannot be fetched (status None), and
fetching only happens for fingerprint-matched hosts, so a scan never
spams every discovered subdomain with requests.

Test seam: ``resolver`` maps a hostname to its CNAME target (or None),
and ``fetcher`` maps a URL to ``(status, body)`` (or a Resp-like
object). The engine path passes neither and uses the real client.
"""

import re
import socket
import urllib.parse

# ---------------------------------------------------------------- fingerprints
# Each entry: service name, CNAME/host suffixes that identify the
# service, and the exact phrases the service itself serves when the
# name is UNCLAIMED. Signatures are matched case-insensitively and
# must reproduce on two consecutive fetches (see prove_takeover).
# A signature was only included when it is specific to the unclaimed
# state — generic "404" / "Not Found" text is deliberately absent,
# because a claimed site can serve a 404 page for other reasons.
FINGERPRINTS = (
    {
        "service": "GitHub Pages",
        "suffixes": (".github.io",),
        "signatures": ("There isn't a GitHub Pages site here",
                       "404: There isn't a GitHub Pages site here"),
        "statuses": (200, 404),
    },
    {
        "service": "Heroku",
        "suffixes": (".herokuapp.com",),
        "signatures": ("No such app",
                       "There's nothing here, yet."),
        "statuses": (200, 404),
    },
    {
        "service": "AWS S3",
        "suffixes": (".s3.amazonaws.com", ".s3-website-us-east-1.amazonaws.com",
                     ".s3-website.amazonaws.com"),
        "signatures": ("NoSuchBucket",
                       "The specified bucket does not exist"),
        "statuses": (200, 403, 404),
    },
    {
        "service": "AWS CloudFront",
        "suffixes": (".cloudfront.net",),
        "signatures": ("The request could not be satisfied",),
        "statuses": (403,),
    },
    {
        "service": "Google Cloud Storage",
        "suffixes": (".storage.googleapis.com",),
        "signatures": ("NoSuchBucket",
                       "The specified bucket does not exist"),
        "statuses": (200, 403, 404),
    },
    {
        "service": "Azure Web Apps",
        "suffixes": (".azurewebsites.net",),
        "signatures": ("Error 404 - Web app not found",
                       "Web app not found"),
        "statuses": (200, 404),
    },
    {
        "service": "Azure Blob Storage",
        "suffixes": (".blob.core.windows.net",),
        "signatures": ("ContainerNotFound", "BlobNotFound",
                       "The specified blob does not exist"),
        "statuses": (404,),
    },
    {
        "service": "Shopify",
        "suffixes": (".myshopify.com",),
        "signatures": ("Sorry, this shop is currently unavailable",),
        "statuses": (200, 404),
    },
    {
        "service": "Netlify",
        "suffixes": (".netlify.app",),
        "signatures": ("Site not found",),
        "statuses": (200, 404),
    },
    {
        "service": "Vercel",
        "suffixes": (".vercel.app",),
        "signatures": ("DEPLOYMENT_NOT_FOUND",),
        "statuses": (404,),
    },
    {
        "service": "Surge",
        "suffixes": (".surge.sh",),
        "signatures": ("project not found",),
        "statuses": (200, 404),
    },
)


def match_fingerprint(cname_or_host):
    """Return the fingerprint dict for a CNAME target / hostname, or None.

    Matching is by suffix, so ``foo.github.io`` and
    ``foo.github.io.`` (trailing dot from DNS) both match, while
    ``notgithub.io.evil.example`` does not.
    """
    if not cname_or_host:
        return None
    host = cname_or_host.strip().rstrip(".").lower()
    for fp in FINGERPRINTS:
        for suffix in fp["suffixes"]:
            if host == suffix.lstrip(".") or host.endswith(suffix):
                return fp
    return None


def default_resolver(host):
    """Best-effort stdlib CNAME lookup.

    The stdlib has no DNS-record API. ``gethostbyname_ex`` returns the
    canonical name as its first element on resolvers that expose the
    CNAME chain, which is the closest available approximation; when it
    returns the queried name itself (or fails), there is no usable
    CNAME and None is returned rather than guessing. The engine may
    pass a real DNS resolver via ``takeover_check(resolver=...)``.
    """
    try:
        canonical, _aliases, _addrs = socket.gethostbyname_ex(host)
    except Exception:
        return None
    if canonical and canonical.rstrip(".").lower() != host.lower():
        return canonical
    return None


# ---------------------------------------------------------------- enumeration

_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+([a-z]{2,})\b", re.I)


def _registrable(domain):
    """Last two labels of a domain (``app.example.co.uk`` -> ``co.uk``
    is wrong for multi-part suffixes, but enumeration only needs a
    suffix to match against — see collect_subdomains docstring)."""
    parts = (domain or "").strip().rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def collect_subdomains(base, pages=None, recon_subdomains=None,
                       extra_texts=None):
    """Subdomains of the target's domain, from scan-local data only.

    Sources, in order: explicit recon results (CT/DNS, supplied by the
    engine), hostnames of crawled page URLs, and hostnames mentioned
    in crawled page bodies / supplied texts. The base host itself is
    included when it appears in those sources, since a dangling base
    record is just as claimable. Nothing here touches the network.
    """
    domain = _registrable(urllib.parse.urlsplit(base).hostname or "")
    if not domain:
        return []
    found = set()
    for sub in recon_subdomains or []:
        sub = (sub or "").strip().rstrip(".").lower()
        if sub.endswith("." + domain) or sub == domain:
            found.add(sub)
    texts = []
    for url, resp in pages or []:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host.endswith("." + domain) or host == domain:
            found.add(host.lower())
        texts.append(getattr(resp, "body", "") or "")
    texts.extend(extra_texts or [])
    for text in texts:
        for m in _HOST_RE.finditer(text or ""):
            host = m.group(0).lower()
            if host.endswith("." + domain):
                found.add(host)
    return sorted(found)


# ---------------------------------------------------------------- proof

def _fetch(ctx, url, fetcher):
    """Normalize a fetch to (status, body, resp-or-None)."""
    if fetcher is not None:
        out = fetcher(url)
        if isinstance(out, tuple):
            status, body = out[0], out[1] if len(out) > 1 else ""
            return status, body or "", None
        return getattr(out, "status", None), getattr(out, "body", "") or "", out
    r = ctx.client.fetch(url)
    return r.status, r.body or "", r


def _signature_in(body, fp):
    low = (body or "").lower()
    for sig in fp["signatures"]:
        if sig.lower() in low:
            return sig
    return ""


def prove_takeover(ctx, subdomain, fp, fetcher=None):
    """Two-fetch proof. Returns (proved, signature, excerpt, resp).

    Both fetches must return a status the service uses for unclaimed
    names AND contain the same unclaimed signature. One transient
    unclaimed-looking page (deploy in progress, WAF hiccup) is not
    proof, and a signature on an unexpected status is not proof.
    """
    scheme = urllib.parse.urlsplit(ctx.base).scheme or "https"
    url = f"{scheme}://{subdomain}/"
    status1, body1, resp1 = _fetch(ctx, url, fetcher)
    sig = _signature_in(body1, fp)
    if status1 is None or status1 not in fp["statuses"] or not sig:
        return False, "", "", None
    # Fallback: some services only answer plain HTTP for unclaimed names.
    status2, body2, resp2 = _fetch(ctx, url, fetcher)
    if status2 is None or status2 not in fp["statuses"]:
        return False, "", "", None
    if sig.lower() not in (body2 or "").lower():
        return False, "", "", None
    idx = (body1 or "").lower().find(sig.lower())
    excerpt = (body1 or "")[max(0, idx - 40):idx + len(sig) + 40].strip()
    return True, sig, excerpt, resp1


def takeover_check(ctx, subdomains=None, pages=None, resolver=None,
                   fetcher=None):
    """Emit one High finding per PROVEN takeoverable subdomain.

    ``subdomains`` defaults to :func:`collect_subdomains` over the
    base + crawled pages + ``ctx.opts["recon_subdomains"]`` (the
    engine passes its recon result there). ``resolver`` defaults to
    :func:`default_resolver`. Returns the list of findings added.
    """
    if subdomains is None:
        recon_subs = (ctx.opts or {}).get("recon_subdomains") or \
            (ctx.opts or {}).get("subdomains") or []
        subdomains = collect_subdomains(ctx.base, pages=pages,
                                        recon_subdomains=recon_subs)
    resolve = resolver or default_resolver
    added = []
    for sub in subdomains:
        if ctx.stop.is_set() if hasattr(ctx, "stop") else False:
            break
        try:
            cname = resolve(sub)
        except Exception:
            continue
        fp = match_fingerprint(cname) or match_fingerprint(sub)
        if fp is None:
            continue
        proved, sig, excerpt, resp = prove_takeover(ctx, sub, fp,
                                                    fetcher=fetcher)
        if not proved:
            continue
        target = cname or sub
        f = ctx.findings.add(
            "High", "Subdomain Takeover (proven, unclaimed service)", sub,
            f"Subdomain {sub} resolves to {target} ({fp['service']}), "
            f"and the service itself reports the name as unclaimed on "
            f"two consecutive fetches — anyone can register it on "
            f"{fp['service']} and serve content under this subdomain. "
            f"Remove the dangling DNS record or reclaim the name on "
            f"the service immediately.",
            proof=f"CNAME: {target} | service: {fp['service']} | "
                  f"unclaimed signature: {sig!r} | response excerpt: "
                  f"{excerpt[:300]}",
            param=target, resp=resp,
            cwe="", dedupe_key=("takeover", sub))
        if f is not None:
            added.append(f)
    return added
