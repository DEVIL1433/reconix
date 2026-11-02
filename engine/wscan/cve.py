"""CVE matching for detected technology versions — ADVISORIES ONLY.

When Reconix fingerprints a technology + version (see
``wscan/recon.py: fingerprint()`` — its ``tech`` list and ``versions``
dict, plus raw ``Server``/``X-Powered-By`` banner strings), this module
looks up known CVEs for that product version and returns them as
informational advisories.

SEPARATION CONTRACT (read before integrating):
  * Every entry carries ``kind == "cve_advisory"`` and
    ``is_finding == False``. Advisories must NEVER be passed to
    ``Findings.add``, must NEVER appear in ``counts`` / ``groups`` /
    ``risk_score``, and must be rendered in a separate "CVE advisories
    (informational only)" report section. A banner version match is not
    a confirmed vulnerability — distro vendors backport fixes without
    changing the version string (the same caveat ``recon.py`` already
    states for its banner-based CVE flags).
  * Nothing here invents a CVE: advisories come only from the feed
    response (or the local cache of a previous feed response).

DATA SOURCE (documented, cacheable):
  * Primary: NVD API 2.0, CPE/product-version query —
    ``https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=
    cpe:2.3:a:<vendor>:<product>:<version>``. The CPE name scopes the
    query to that product version, so no local version-range math is
    attempted (NVD's own version-range data decides the match).
  * NVD rate limits (documented by NVD): unauthenticated ~5 requests
    per 30 s; with an API key (``apiKey`` header) ~50 per 30 s. The
    caller may pass ``api_key``; no key is stored anywhere by this
    module.
  * Local cache: a JSON file (default ``cve_cache.json`` beside the
    ``wscan`` package, overridable per call) keyed by
    ``vendor:product@version``. ``CACHE_TTL_SECONDS`` (7 days) bounds
    how long a cached answer is trusted; stale entries are refetched,
    and a failed refetch with only a stale entry yields "no CVE data
    available", never the stale answer presented as fresh.
  * Offline / feed error -> ``status == "unavailable"`` with a
    "no CVE data available" note. Never a scan failure, never invented
    CVEs.

Stdlib only (urllib, json). No network is needed to import or test
this module: pass a ``fetcher`` test seam.
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_USER_AGENT = "Reconix/4.0 (CVE advisory lookup)"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days: repeat lookups work offline
FETCH_TIMEOUT = 15  # seconds per NVD request
MAX_REFERENCES = 10

# Normalised tech name -> (CPE vendor, CPE product). Keys are lowercased
# and stripped of spaces, dots and dashes where ambiguous; see
# _normalise_name(). Covers the names recon.py's TECH_SIGNATURES and
# fingerprint() actually produce, plus common Server-banner products.
CPE_MAP = {
    "apache": ("apache", "http_server"),
    "apachehttpserver": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apachetomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "joomla": ("joomla", "joomla"),
    "drupal": ("drupal", "drupal"),
    "magento": ("magento", "magento"),
    "shopify": ("shopify", "shopify"),
    "ghost": ("ghost", "ghost"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("twbs", "bootstrap"),
    "openssl": ("openssl", "openssl"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoftiis": ("microsoft", "internet_information_services"),
    "express": ("expressjs", "express"),
    "expressnode": ("expressjs", "express"),
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "react": ("facebook", "react"),
    "angular": ("angular", "angular"),
    "vue": ("vuejs", "vue"),
    "vuejs": ("vuejs", "vue"),
    "nextjs": ("vercel", "next.js"),
    "aspnet": ("microsoft", "asp.net"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "python": ("python", "python"),
    "nodejs": ("nodejs", "node.js"),
    "node": ("nodejs", "node.js"),
}

# "Name/1.2.3", "Name 1.2.3", "Name 1.0.1f" — also tolerates a trailing
# "(...)" distro/build suffix, which is stripped, not treated as version.
_TECH_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9 .#+_-]+?)\s*[/ ]\s*v?"
    r"(?P<version>\d+(?:\.\d+)*(?:[a-z]\d*)?)\s*(?:\(.*\))?\s*$")


def _normalise_name(name):
    return re.sub(r"[\s._-]+", "", str(name or "").strip().lower())


def parse_tech_string(text):
    """Split a fingerprinted tech string into (name, version|None).

    Handles Server-banner forms ("Apache/2.4.49", "nginx/1.18.0",
    "OpenSSL/1.0.1f", "Microsoft-IIS/7.5") and generator forms
    ("WordPress 5.8.1"). A bare name with no version returns
    ``(name, None)``; an empty/whitespace string returns ``(None, None)``.
    """
    text = (text or "").strip()
    if not text:
        return None, None
    m = _TECH_RE.match(text)
    if m:
        return m.group("name").strip(), m.group("version")
    return text, None


def tech_to_cpe(name):
    """Map a technology name to a (vendor, product) CPE pair, or None.

    Unknown products return None (no guessed CPE, no invented query)
    — the caller reports "no CPE mapping" for that tech.
    """
    norm = _normalise_name(name)
    if norm in CPE_MAP:
        return CPE_MAP[norm]
    if norm.startswith("apache") and "tomcat" not in norm:
        return ("apache", "http_server")
    return None


def build_nvd_cpe(vendor, product, version):
    """CPE 2.3 name for an exact product version (spaces -> underscores)."""
    product = str(product).replace(" ", "_")
    vendor = str(vendor).replace(" ", "_")
    return f"cpe:2.3:a:{vendor}:{product}:{version}"


def build_nvd_url(vendor, product, version, results_per_page=50):
    """Full NVD API 2.0 URL for a CPE product-version query."""
    qs = urllib.parse.urlencode({
        "cpeName": build_nvd_cpe(vendor, product, version),
        "resultsPerPage": int(results_per_page),
    })
    return f"{NVD_API_URL}?{qs}"


# ------------------------------------------------------------------ parsing

def _best_cvss(cve):
    """Pick the strongest CVSS entry NVD provides: v3.1 > v3.0 > v2.0."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            return score, data.get("baseSeverity") or ""
    return None, ""


def _severity_label(score, base_severity):
    if base_severity:
        label = str(base_severity).capitalize()
        if label in ("Critical", "High", "Medium", "Low"):
            return label
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def parse_nvd_response(data):
    """NVD API 2.0 payload (dict, JSON str or bytes) -> advisory dicts.

    Each advisory: CVE ID, severity score + label, description and
    references, plus the separation markers. Malformed payloads yield
    an empty list, never an exception.
    """
    if isinstance(data, (bytes, str)):
        try:
            data = json.loads(data)
        except Exception:
            return []
    if not isinstance(data, dict):
        return []
    advisories = []
    for entry in data.get("vulnerabilities") or []:
        cve = (entry or {}).get("cve") or {}
        cve_id = cve.get("id") or ""
        if not cve_id:
            continue
        description = ""
        for d in cve.get("descriptions") or []:
            if (d or {}).get("lang") == "en":
                description = d.get("value") or ""
                break
        if not description and cve.get("descriptions"):
            description = (cve["descriptions"][0] or {}).get("value") or ""
        score, base_sev = _best_cvss(cve)
        references = []
        for ref in cve.get("references") or []:
            url = (ref or {}).get("url")
            if url:
                references.append(url)
        advisories.append({
            "kind": "cve_advisory",
            "is_finding": False,
            "source": "NVD API 2.0",
            "cve_id": cve_id,
            "severity": _severity_label(score, base_sev),
            "cvss_score": score,
            "description": description[:1000],
            "references": references[:MAX_REFERENCES],
            "published": cve.get("published") or "",
        })
    return advisories


# ------------------------------------------------------------------ cache

def default_cache_path():
    """Default cache file: ``cve_cache.json`` beside app.py / scans.db
    (the install root, derived from this file's location — never a
    hard-coded absolute path)."""
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "cve_cache.json")


def load_cache(path):
    """Read the JSON cache file; corrupt/missing files yield {}."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cache(path, data):
    """Best-effort cache write — a failed write never fails a lookup."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except Exception:
        pass


def _cache_key(vendor, product, version):
    return f"{vendor}:{product}@{version}"


def _cache_get(cache, key, now):
    entry = cache.get(key) if isinstance(cache, dict) else None
    if not isinstance(entry, dict):
        return None
    fetched_at = entry.get("fetched_at")
    if not isinstance(fetched_at, (int, float)):
        return None
    if now - fetched_at > CACHE_TTL_SECONDS:
        return None  # stale: must be refetched, never served as fresh
    adv = entry.get("advisories")
    return adv if isinstance(adv, list) else None


# ------------------------------------------------------------------ fetching

def _default_fetcher(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _coerce_payload(payload):
    """A fetcher may return a dict or raw JSON — normalise to a dict."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, (bytes, str)):
        try:
            data = json.loads(payload)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def lookup_cves_for_tech(tech_name, version=None, cache_path=None,
                         fetcher=None, api_key=None, use_cache=True,
                         now=None):
    """Look up CVEs for one technology + version. Never raises.

    Returns ``{"tech", "product", "version", "status", "note",
    "advisories", "from_cache"}`` where status is one of: ``ok``
    (fresh feed answer), ``cached`` (fresh cache answer), ``no_data``
    (feed answered, no CVEs for this version), ``unavailable`` (feed
    unreachable/error — "no CVE data available"), ``no_version``,
    ``no_mapping``. ``fetcher`` seam: ``fetcher(url, headers, timeout)``
    returning a dict or raw JSON (defaults to the real NVD fetch).
    """
    now = time.time() if now is None else now
    cache_path = cache_path or default_cache_path()
    tech_label = str(tech_name or "").strip()
    if not version:
        return {"tech": tech_label, "product": None, "version": None,
                "status": "no_version",
                "note": ("No version detected for "
                         f"{tech_label or 'this technology'} — CVE lookup "
                         "needs a version."),
                "advisories": [], "from_cache": False}
    cpe = tech_to_cpe(tech_label)
    if cpe is None:
        return {"tech": tech_label, "product": None, "version": version,
                "status": "no_mapping",
                "note": (f"No CPE mapping for {tech_label} — CVE lookup "
                         "skipped (no guessed product identifier)."),
                "advisories": [], "from_cache": False}
    vendor, product = cpe
    key = _cache_key(vendor, product, version)
    cache = load_cache(cache_path) if use_cache else {}
    if use_cache:
        hit = _cache_get(cache, key, now)
        if hit is not None:
            return {"tech": tech_label, "product": f"{vendor}:{product}",
                    "version": version, "status": "cached",
                    "note": "Served from local CVE cache.",
                    "advisories": hit, "from_cache": True}
    url = build_nvd_url(vendor, product, version)
    headers = {"User-Agent": NVD_USER_AGENT,
               "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    fetch = fetcher or _default_fetcher
    try:
        advisories = parse_nvd_response(_coerce_payload(
            fetch(url, headers, FETCH_TIMEOUT)))
    except Exception as e:
        return {"tech": tech_label, "product": f"{vendor}:{product}",
                "version": version, "status": "unavailable",
                "note": (f"No CVE data available for {tech_label} "
                         f"{version} (NVD feed unreachable: {e})."),
                "advisories": [], "from_cache": False}
    if use_cache:
        cache[key] = {"fetched_at": now, "advisories": advisories}
        save_cache(cache_path, cache)
    if not advisories:
        return {"tech": tech_label, "product": f"{vendor}:{product}",
                "version": version, "status": "no_data",
                "note": (f"No known CVEs returned by NVD for {tech_label} "
                         f"{version}."),
                "advisories": [], "from_cache": False}
    return {"tech": tech_label, "product": f"{vendor}:{product}",
            "version": version, "status": "ok", "note": None,
            "advisories": advisories, "from_cache": False}


# ------------------------------------------------------- fingerprint driver

def lookup_cves_for_fingerprint(fingerprint, cache_path=None,
                                fetcher=None, api_key=None):
    """CVE advisories for a whole recon fingerprint. Never raises.

    ``fingerprint`` is the dict ``recon.py: fingerprint()`` returns:
    ``{"tech": [...], "versions": {...}, "generator": "..."}``. Each
    tech string is version-parsed; the ``versions`` dict (canonical
    names like "jQuery" -> "1.12.4") adds or overrides versions. Each
    distinct product+version is queried once. Returns ``{"advisories":
    [...flat, each annotated with "tech" and "detected_version"...],
    "by_tech": {label: lookup result}, "notes": [...]}`` — advisories
    only, never findings.
    """
    fingerprint = fingerprint or {}
    wanted = {}  # (vendor, product, version) -> display label
    for tech in fingerprint.get("tech") or []:
        name, version = parse_tech_string(tech)
        if name and version:
            wanted.setdefault((name, version), tech)
    for name, version in (fingerprint.get("versions") or {}).items():
        if name and version:
            wanted.setdefault((name, version), name)
    gen = fingerprint.get("generator") or ""
    if gen:
        name, version = parse_tech_string(gen)
        if name and version:
            wanted.setdefault((name, version), gen)
    by_tech, flat, notes = {}, [], []
    for (name, version), label in sorted(wanted.items()):
        try:
            result = lookup_cves_for_tech(
                name, version, cache_path=cache_path,
                fetcher=fetcher, api_key=api_key)
        except Exception as e:  # belt and braces: lookup never raises
            result = {"tech": label, "product": None, "version": version,
                      "status": "unavailable",
                      "note": f"No CVE data available ({e}).",
                      "advisories": [], "from_cache": False}
        by_tech[label] = result
        if result["note"] and result["status"] not in ("cached",):
            notes.append(result["note"])
        for adv in result["advisories"]:
            entry = dict(adv)
            entry["tech"] = result["tech"]
            entry["detected_version"] = version
            flat.append(entry)
    return {"advisories": flat, "by_tech": by_tech, "notes": notes}


# ------------------------------------------------------- report rendering
# The report layer renders this section SEPARATELY from findings:
# advisories are informational context for a detected version, not
# vulnerabilities Reconix has proven on the target.

def cve_section(fingerprint_result):
    """Fingerprint lookup result -> report-section dict (advisories only)."""
    result = fingerprint_result or {}
    return {
        "title": "CVE advisories (informational only — not findings)",
        "count": len(result.get("advisories") or []),
        "advisories": list(result.get("advisories") or []),
        "notes": list(result.get("notes") or []),
    }


def format_cve_section(fingerprint_result):
    """Plain-text lines for the separate CVE advisory section."""
    sec = cve_section(fingerprint_result)
    lines = [f"CVE advisories ({sec['count']}) — informational only, "
             "not findings"]
    for note in sec["notes"]:
        lines.append(f"  Note: {note}")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
             "Unknown": 4, "Info": 5}
    for adv in sorted(sec["advisories"],
                      key=lambda a: (order.get(a["severity"], 9),
                                     a["cve_id"])):
        score = (f" CVSS {adv['cvss_score']}" if adv["cvss_score"]
                 is not None else "")
        lines.append(f"  [{adv['severity']}{score}] {adv['cve_id']} "
                     f"({adv.get('tech', '')} "
                     f"{adv.get('detected_version', '')})")
        if adv["description"]:
            lines.append(f"    {adv['description'][:200]}")
    return lines
