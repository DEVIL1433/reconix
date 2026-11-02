"""Exposed cloud storage checks — PASSIVE / SAFE reads only.

What this module does: unauthenticated GET requests to see whether a
storage bucket, container or file tied to the target is publicly
readable. What it never does: writes, deletes, authenticated calls,
or any destructive listing beyond the single read that proves the
exposure. Bucket/container *listing* endpoints are only probed with
the provider's public list operation (the same GET a browser would
make); object reads are only made for URLs the crawled site itself
references, or for a bucket listing that was just proven public.

A finding requires a PROVEN public read, never a bucket-name guess:

* Bucket/container listing: HTTP 200 AND a provider listing marker
  in the body (S3 ``<ListBucketResult>``, Azure
  ``EnumerationResults``, GCS ``storage#objects``/``items``) AND no
  provider error marker. A 403/404, or a 200 carrying an error
  document (``NoSuchBucket``, ``AccessDenied``,
  ``ContainerNotFound``, ...), is not a finding.
* Referenced file: HTTP 200 AND a non-empty body AND no provider
  error marker. The URL came from the target's own pages/JS, so a
  successful anonymous read of it is itself the exposure; a bucket
  root URL still needs a listing marker (a generic 200 from a
  website endpoint is not proof of storage exposure).

Test seam: ``fetcher`` maps a URL to ``(status, body)`` (or a
Resp-like object). The engine path passes none and uses the real
client (GET only, no redirects followed — the client never follows
redirects, so a redirect to a sign-in page cannot be mistaken for
a public read).
"""

import re
import urllib.parse

# ---------------------------------------------------------------- error markers
# If any of these appear in a response body, the read did NOT prove
# public access, whatever the status code says.
ERROR_MARKERS = (
    "NoSuchBucket", "NoSuchKey", "AccessDenied", "InvalidAccessKeyId",
    "SignatureDoesNotMatch", "ContainerNotFound", "BlobNotFound",
    "ResourceNotFound", "AuthenticationFailed", "AuthorizationFailure",
    "AuthorizationPermissionMismatch", "No such object",
    "does not have storage.objects", "The specified bucket does not exist",
    "The specified blob does not exist",
    "The specified container does not exist",
)

_LISTING_MARKERS = {
    "s3": ("<ListBucketResult", "<Contents>",),
    "azure": ("EnumerationResults", "<Blobs>",),
    "gcs": ('"kind": "storage#objects"', '"items":', "<ListBucketResult",),
}

_SENSITIVE_FILE_RES = (
    re.compile(r"\.env(\.|$)", re.I),
    re.compile(r"\.(pem|key|p12|pfx|sql|bak|backup|dump|gz|zip)$", re.I),
    re.compile(r"(credentials|secret|private|passwd|password|config\.json$)",
               re.I),
)

# References to cloud storage inside crawled pages / JS.
_REFERENCE_RES = (
    re.compile(r"https?://[A-Za-z0-9.\-]+\.s3[.\-][A-Za-z0-9.\-/_\?=&%]+"),
    re.compile(r"https?://s3[.\-][A-Za-z0-9.\-]+/[^\"'\s<>]+"),
    re.compile(r"https?://storage\.googleapis\.com/[^\"'\s<>]+"),
    re.compile(r"https?://[A-Za-z0-9.\-]+\.blob\.core\.windows\.net/[^\"'\s<>]+"),
    re.compile(r"https?://[A-Za-z0-9.\-]+\.s3\.amazonaws\.com/[^\"'\s<>]+"),
)

# Naming variants derived from one domain label, e.g. example.com ->
# example, example-assets, example-uploads, ... (capped by the caller).
_BUCKET_SUFFIXES = ("", "-assets", "-static", "-media", "-uploads",
                    "-files", "-data", "-backup", "-backups", "-prod",
                    "-production", "-public", "-website", "-site",
                    "-images", "-docs", "-downloads", "-content", "-cdn",
                    "-storage")
_AZURE_CONTAINERS = ("public", "static", "media", "uploads", "assets",
                     "files", "data", "content", "images", "backup")


def _has_error(body):
    return any(m in (body or "") for m in ERROR_MARKERS)


def _is_listing(body, provider):
    if _has_error(body):
        return False
    return any(m in (body or "") for m in _LISTING_MARKERS[provider])


def candidate_bucket_names(domain, extra=None):
    """Bucket-name candidates from a domain label + extras.

    ``domain`` may be a full host (``app.example.com`` -> base label
    ``example`` from the registrable domain, plus the full subdomain
    label joined with hyphens). Only naming patterns are generated;
    nothing is probed here."""
    host = (domain or "").strip().rstrip(".").lower()
    host = host[4:] if host.startswith("www.") else host
    parts = host.split(".")
    labels = []
    if len(parts) >= 2:
        labels.append(parts[-2])                    # registrable label
        if len(parts) > 2:
            labels.append("-".join(parts[:-2] + [parts[-2]]))
    elif parts:
        labels.append(parts[0])
    out = set()
    for label in labels:
        for suffix in _BUCKET_SUFFIXES:
            name = label + suffix
            if 3 <= len(name) <= 63 and re.fullmatch(r"[a-z0-9][a-z0-9.\-]*",
                                                     name):
                out.add(name)
    for name in extra or []:
        name = (name or "").strip().lower()
        if name:
            out.add(name)
    return sorted(out)


def extract_cloud_references(text):
    """Cloud-storage URLs mentioned in a page / JS blob (deduped)."""
    out = []
    seen = set()
    for rx in _REFERENCE_RES:
        for m in rx.finditer(text or ""):
            url = m.group(0).rstrip(".,);]}")
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def _fetch(ctx, url, fetcher):
    if fetcher is not None:
        out = fetcher(url)
        if isinstance(out, tuple):
            return out[0], (out[1] if len(out) > 1 else "") or "", None
        return getattr(out, "status", None), getattr(out, "body", "") or "", out
    r = ctx.client.fetch(url)
    return r.status, r.body or "", r


def _provider_of(url):
    low = url.lower()
    if "blob.core.windows.net" in low:
        return "azure"
    if "storage.googleapis.com" in low:
        return "gcs"
    return "s3"


def _sensitive_file(url):
    path = urllib.parse.urlsplit(url).path
    return any(rx.search(path) for rx in _SENSITIVE_FILE_RES)


def _add(ctx, severity, title, url, detail, proof, resp, param):
    return ctx.findings.add(severity, title, url, detail, proof=proof,
                            param=param, resp=resp, cwe="CWE-200",
                            dedupe_key=("cloud", title, url))


def check_cloud_buckets(ctx, bucket_names, fetcher=None):
    """Probe S3 + GCS bucket listings for each name. Returns findings."""
    added = []
    for name in bucket_names or []:
        if hasattr(ctx, "stop") and ctx.stop.is_set():
            break
        for url, provider in (
                (f"https://{name}.s3.amazonaws.com/", "s3"),
                (f"https://s3.amazonaws.com/{name}/", "s3"),
                (f"https://storage.googleapis.com/{name}/", "gcs")):
            status, body, resp = _fetch(ctx, url, fetcher)
            if status == 200 and _is_listing(body, provider):
                excerpt = body[:300].replace("\n", " ")
                f = _add(ctx, "High",
                         "Publicly Accessible Cloud Storage Bucket", url,
                         f"Storage bucket '{name}' ({provider.upper()}) "
                         f"allows unauthenticated listing: its contents "
                         f"are enumerable by anyone. Restrict the bucket "
                         f"policy / ACL to authenticated principals and "
                         f"audit what was exposed.",
                         proof=f"GET {url} -> 200, listing marker present: "
                               f"{excerpt}",
                         resp=resp, param=name)
                if f is not None:
                    added.append(f)
                break  # one proof per bucket is enough
    return added


def check_azure_containers(ctx, accounts, containers=None, fetcher=None):
    """Probe Azure blob containers (public list operation only)."""
    added = []
    for account in accounts or []:
        for container in containers or _AZURE_CONTAINERS:
            if hasattr(ctx, "stop") and ctx.stop.is_set():
                break
            url = (f"https://{account}.blob.core.windows.net/{container}"
                   f"?resttype=container&comp=list")
            status, body, resp = _fetch(ctx, url, fetcher)
            if status == 200 and _is_listing(body, "azure"):
                f = _add(ctx, "High",
                         "Publicly Accessible Cloud Storage Bucket", url,
                         f"Azure blob container '{container}' on account "
                         f"'{account}' allows unauthenticated listing. "
                         f"Restrict container access to private and audit "
                         f"what was exposed.",
                         proof=f"GET {url} -> 200, EnumerationResults "
                               f"present: {body[:300].replace(chr(10), ' ')}",
                         resp=resp, param=f"{account}/{container}")
                if f is not None:
                    added.append(f)
    return added


def check_cloud_references(ctx, urls, fetcher=None):
    """Probe storage URLs the target itself references. A 200 with
    content (and no error marker) proves a public read; a bucket-root
    URL additionally needs a listing marker."""
    added = []
    for url in urls or []:
        if hasattr(ctx, "stop") and ctx.stop.is_set():
            break
        provider = _provider_of(url)
        status, body, resp = _fetch(ctx, url, fetcher)
        if status != 200 or not (body or "").strip() or _has_error(body):
            continue
        path = urllib.parse.urlsplit(url).path.strip("/")
        if not path or path in ("",) or \
                (provider == "s3" and "/" not in path):
            # Bucket root: a bare 200 is not proof (website endpoints
            # answer 200 too) — require a listing marker.
            if not _is_listing(body, provider):
                continue
            title = "Publicly Accessible Cloud Storage Bucket"
            sev = "High"
            detail = (f"Referenced storage location {url} allows "
                      f"unauthenticated listing.")
        else:
            title = "Publicly Readable Cloud Storage File"
            sev = "High" if _sensitive_file(url) else "Medium"
            detail = (f"File {url} referenced by the target is readable "
                      f"without authentication — anyone can download it."
                      + (" The filename suggests sensitive content; "
                         "treat it as exposed and rotate anything it "
                         "contained." if sev == "High" else ""))
        f = _add(ctx, sev, title, url, detail,
                 proof=f"GET {url} -> 200, {len(body)} bytes returned: "
                       f"{body[:200].replace(chr(10), ' ')}",
                 resp=resp, param=url)
        if f is not None:
            added.append(f)
    return added


def cloud_check(ctx, pages=None, buckets=None, fetcher=None):
    """Orchestrator: domain-derived buckets (S3/GCS, capped at 40),
    Azure accounts (first 5 derived names x default containers), and
    every cloud reference found in crawled pages. Returns findings."""
    host = urllib.parse.urlsplit(ctx.base).hostname or ""
    if buckets is None:
        buckets = candidate_bucket_names(host)[:40]
    added = []
    added.extend(check_cloud_buckets(ctx, buckets, fetcher=fetcher))
    added.extend(check_azure_containers(
        ctx, candidate_bucket_names(host)[:5], fetcher=fetcher))
    refs = []
    for _url, resp in pages or []:
        refs.extend(extract_cloud_references(getattr(resp, "body", "") or ""))
    # References may also hide in JS bundles the engine already
    # fetched; the engine passes those page bodies via `pages`.
    added.extend(check_cloud_references(ctx, sorted(set(refs)),
                                        fetcher=fetcher))
    return added
