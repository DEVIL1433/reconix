"""CMS check packs (Reconix proof-only pack): WordPress, Joomla, Drupal.

HONESTY RULE, enforced structurally: a version number alone NEVER
becomes a ctx.findings vulnerability. Version claims and plugin/theme
enumeration live ONLY in the returned summary dict as items with
"kind": "advisory", so the report layer can render them separately
from findings. Only PROVEN items reach ctx.findings:

  * an exposed file that is actually reachable with real content
    (config WITH secrets -> Critical; readme/license -> Low)
  * user enumeration that actually returns user data (REST JSON list
    or an author-archive redirect carrying a username)
  * login username enumeration PROVEN by an error-message differential
    (known user -> bad-password error, unknown user -> unknown-user
    error, same wrong password)
  * XML-RPC actually answering as an XML-RPC server -> Low

Detection inputs: generator tags, readme/changelog files, asset
version strings, HTML/asset references, and a small curated set of
common plugin/theme paths. Stdlib only.

Integration entry point: cms_scan(ctx, base, pages=None).
"""
import json
import re
import urllib.parse

WP_PLUGINS = ("akismet", "contact-form-7", "woocommerce", "jetpack",
              "wordfence", "elementor", "yoast", "all-in-one-seo-pack",
              "wpforms-lite", "really-simple-ssl", "updraftplus",
              "w3-total-cache")
WP_THEMES = ("twentytwentyfour", "twentytwentythree", "twentytwentytwo",
             "astra", "oceanwp", "generatepress", "divi", "avada")

LOGIN_PATHS = {"wordpress": "/wp-login.php",
               "joomla": "/administrator/",
               "drupal": "/user/login"}

EXPOSED_FILES = {
    "wordpress": (("/readme.html", "readme"), ("/license.txt", "license"),
                  ("/wp-config.php", "config"), ("/xmlrpc.php", "xmlrpc")),
    "joomla": (("/README.txt", "readme"), ("/LICENSE.txt", "license"),
               ("/configuration.php", "config"),
               ("/administrator/manifests/files/joomla.xml", "manifest")),
    "drupal": (("/core/CHANGELOG.txt", "changelog"),
               ("/LICENSE.txt", "license"),
               ("/core/INSTALL.txt", "readme"),
               ("/sites/default/settings.php", "config")),
}

SECRET_MARKERS = ("DB_PASSWORD", "DB_USER", "define(", "password",
                  "$databases", "hash_salt")


# ------------------------------------------------------------- detection

def detect_cms_from_text(body, headers=None):
    """Pure detection from one page body (+ optional headers dict).
    Returns (cms, confidence, signals) with cms in
    wordpress|joomla|drupal|''."""
    body = body or ""
    signals = []
    if re.search(r"wp-content|wp-includes|wp-json|/wp-login", body):
        signals.append("wp-content/wp-includes/wp-json reference")
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content='
                  r'["\']([^"\']+)["\']', body, re.I)
    if m:
        signals.append(f"generator: {m.group(1)}")
        gen = m.group(1).lower()
        if "wordpress" in gen:
            return "wordpress", "high", signals
        if "joomla" in gen:
            return "joomla", "high", signals
        if "drupal" in gen:
            return "drupal", "high", signals
    if re.search(r"/media/system/js|com_content|option=com_", body):
        signals.append("Joomla media/component reference")
        return "joomla", "medium", signals
    if re.search(r"/sites/default/files|Drupal\.settings|drupal\.js",
                 body):
        signals.append("Drupal sites/settings reference")
        return "drupal", "medium", signals
    if signals:
        return "wordpress", "medium", signals
    return "", "none", signals


def extract_wp_assets(body):
    """(plugins, themes) referenced in HTML/asset URLs."""
    body = body or ""
    plugins = sorted(set(re.findall(
        r"wp-content/plugins/([^/\"'?\s]+)", body)))
    themes = sorted(set(re.findall(
        r"wp-content/themes/([^/\"'?\s]+)", body)))
    return plugins, themes


def extract_joomla_components(body):
    body = body or ""
    return sorted(set(re.findall(r"com_([a-z0-9_]+)", body)))


def extract_drupal_modules(body):
    body = body or ""
    mods = set(re.findall(r"modules/(?:contrib/)?([^/\"'?\s]+)", body))
    mods |= set(re.findall(r"sites/all/modules/[^/]+/([^/\"'?\s]+)", body))
    return sorted(mods)


def _version_from_generator(body):
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content='
                  r'["\'](?:WordPress|Joomla!|Drupal)\s+([0-9][0-9a-zA-Z.\-]*)'
                  r'["\']', body or "", re.I)
    return m.group(1) if m else None


def _version_from_asset_strings(body):
    """Most common ?ver=X.Y on wp-includes / core asset URLs."""
    vers = re.findall(r"(?:wp-includes|wp-content|core|sites)[^\"'\s]*"
                      r"[?&]ver=([0-9][0-9a-zA-Z.\-]*)", body or "")
    if not vers:
        return None
    return max(set(vers), key=vers.count)


def detect_version(ctx, base, cms):
    """Version detection only. Returns {version, source, evidence} or
    None. Callers must treat this as ADVISORY, never as a finding."""
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    home = ctx.client.fetch(base)
    v = _version_from_generator(home.body)
    if v:
        return {"version": v, "source": base,
                "evidence": f"generator tag reports version {v}"}
    v = _version_from_asset_strings(home.body)
    if v:
        return {"version": v, "source": base,
                "evidence": f"asset ?ver={v} on page assets"}
    probes = {"wordpress": [("/readme.html",
                             r"Version\s+([0-9][0-9a-zA-Z.\-]*)")],
              "joomla": [("/administrator/manifests/files/joomla.xml",
                          r"<version>([^<]+)</version>"),
                         ("/README.txt", r"Joomla!\s+([0-9][0-9a-zA-Z.\-]*)")],
              "drupal": [("/core/CHANGELOG.txt",
                          r"Drupal\s+([0-9][0-9a-zA-Z.\-]*)")]}.get(cms, [])
    for path, pattern in probes:
        r = ctx.client.fetch(root + path)
        if r.status == 200 and r.body:
            m = re.search(pattern, r.body)
            if m:
                return {"version": m.group(1).strip(),
                        "source": root + path,
                        "evidence": (r.body or "")[:200]}
    return None


# ------------------------------------------------------------ enumeration

def enumerate_plugins_themes(ctx, base, cms, pages=None):
    """Plugins/themes from HTML/asset references, plus a small curated
    set of common-path readme probes (200 + plugin content required).
    Returns (plugins, themes_or_components) — enumeration only."""
    plugins, themes = set(), set()
    for _u, r in (pages or []):
        body = r.body or ""
        if cms == "wordpress":
            p, t = extract_wp_assets(body)
            plugins |= set(p)
            themes |= set(t)
        elif cms == "joomla":
            plugins |= set(extract_joomla_components(body))
        elif cms == "drupal":
            plugins |= set(extract_drupal_modules(body))
    if cms == "wordpress" and not ctx.stop.is_set():
        parts = urllib.parse.urlsplit(base)
        root = f"{parts.scheme}://{parts.netloc}"
        for name in WP_PLUGINS:
            r = ctx.client.fetch(
                f"{root}/wp-content/plugins/{name}/readme.txt")
            if r.status == 200 and r.body and (
                    "Stable tag" in r.body or name.replace("-", " ") in
                    r.body.lower() or "===" in r.body[:200]):
                plugins.add(name)
        for name in WP_THEMES:
            r = ctx.client.fetch(
                f"{root}/wp-content/themes/{name}/style.css")
            if r.status == 200 and r.body and "Theme Name" in r.body:
                themes.add(name)
    return sorted(plugins), sorted(themes)


# ------------------------------------------------------------ proven items

def exposed_files_check(ctx, base, cms):
    """Reachable exposed files. Config counts ONLY when its body
    actually carries secret markers; a 403/empty PHP file is not a
    finding. Returns the list of reachable-file records."""
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    reachable = []
    for path, kind in EXPOSED_FILES.get(cms, ()):
        if ctx.stop.is_set():
            break
        url = root + path
        r = ctx.client.fetch(url)
        if r.status != 200 or not (r.body or "").strip():
            continue
        rec = {"path": path, "kind": kind, "url": url}
        reachable.append(rec)
        if kind == "config":
            if any(m in r.body for m in SECRET_MARKERS):
                ctx.findings.add(
                    "Critical", "CMS Configuration File Exposed", url,
                    "A CMS configuration file is publicly readable AND "
                    "contains secret material — credentials/salts in the "
                    "response body prove exposure, not just reachability.",
                    proof=(r.body or "")[:300], resp=r, cwe="CWE-200")
            continue  # config without secrets: recorded, not a finding
        if kind == "xmlrpc":
            if "xml-rpc" in r.body.lower() or "XML-RPC" in r.body:
                ctx.findings.add(
                    "Low", "WordPress XML-RPC Enabled", url,
                    "xmlrpc.php answers as an XML-RPC server. It enables "
                    "brute-force amplification (system.multicall) and "
                    "pingback abuse; disable it if unused.",
                    proof=(r.body or "")[:200], resp=r, cwe="CWE-200")
            continue
        if kind in ("readme", "license", "changelog", "manifest"):
            ctx.findings.add(
                "Low", "CMS Information File Exposed", url,
                f"A CMS {kind} file is publicly reachable and discloses "
                "version/build information useful for targeting.",
                proof=(r.body or "")[:200], resp=r, cwe="CWE-200")
    return reachable


def _login_error_class(body):
    low = (body or "").lower()
    if re.search(r"invalid username|unknown username|no such user|"
                 r"user does not exist|invalid user", low):
        return "unknown_user"
    if re.search(r"password.*(incorrect|wrong|invalid)|incorrect password|"
                 r"wrong password", low):
        return "bad_password"
    return "other"


def user_enumeration_check(ctx, base, cms):
    """User enumeration ONLY where it is a real disclosure:
    WordPress REST users JSON, or the ?author=N redirect to a real
    author archive. Returns enumerated usernames."""
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    users = []
    if cms == "wordpress":
        r = ctx.client.fetch(root + "/wp-json/wp/v2/users")
        try:
            data = json.loads(r.body or "")
        except Exception:
            data = None
        if r.status == 200 and isinstance(data, list) and data:
            slugs = [d.get("slug") for d in data
                     if isinstance(d, dict) and d.get("slug")]
            if slugs:
                users = slugs
                ctx.findings.add(
                    "Medium", "WordPress User Enumeration (REST API)", 
                    root + "/wp-json/wp/v2/users",
                    "The REST users endpoint returns real usernames "
                    "without authentication — usernames for login "
                    "brute-force, handed over in one request.",
                    proof=f"users returned: {', '.join(slugs[:10])}",
                    resp=r, cwe="CWE-200")
                return users
        # Fallback: ?author=1 redirect to /author/<slug>/
        r = ctx.client.fetch(root + "/?author=1")
        loc = ""
        for k, v in r.raw_headers:
            if k.lower() == "location":
                loc = v
        m = re.search(r"/author/([^/]+)/?", loc or "")
        if r.status in (301, 302) and m:
            users = [m.group(1)]
            ctx.findings.add(
                "Medium", "WordPress User Enumeration (author redirect)",
                root + "/?author=1",
                "The ?author=1 redirect exposes a real username in the "
                "author-archive URL — a classic enumeration vector.",
                proof=f"redirect Location: {loc}", resp=r, cwe="CWE-200")
    elif cms == "drupal":
        r = ctx.client.fetch(root + "/jsonapi/user/user")
        try:
            data = json.loads(r.body or "")
        except Exception:
            data = None
        items = (data or {}).get("data") if isinstance(data, dict) else None
        if r.status == 200 and isinstance(items, list) and items:
            names = [i.get("attributes", {}).get("name") for i in items
                     if isinstance(i, dict)]
            names = [n for n in names if n]
            if names:
                users = names
                ctx.findings.add(
                    "Medium", "Drupal User Enumeration (JSON:API)", 
                    root + "/jsonapi/user/user",
                    "The JSON:API users collection returns real "
                    "usernames without authentication.",
                    proof=f"users returned: {', '.join(names[:10])}",
                    resp=r, cwe="CWE-200")
    return users


def login_hardening_check(ctx, base, cms, known_users=None):
    """Login-page signals (advisory dict) + a PROVEN login username
    enumeration via error differential, only when a known username
    and an unknown username give different error classes for the
    same wrong password. Returns the signals dict."""
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    login_url = root + LOGIN_PATHS.get(cms, "/login")
    r = ctx.client.fetch(login_url)
    body = r.body or ""
    signals = {"login_url": login_url, "reachable": r.status == 200,
               "has_form": "<form" in body.lower(),
               "has_captcha": bool(re.search(
                   r"recaptcha|hcaptcha|turnstile", body, re.I)),
               "has_2fa_hint": bool(re.search(
                   r"two.factor|2fa|authenticator", body, re.I))}
    if signals["has_form"] and known_users:
        known = known_users[0]
        rk = ctx.client.fetch(login_url, method="POST",
                              data={"log": known, "pwd": "reconix-wrong-7391",
                                    "username": known,
                                    "password": "reconix-wrong-7391"})
        ru = ctx.client.fetch(login_url, method="POST",
                              data={"log": "reconix-no-such-user-7391",
                                    "pwd": "reconix-wrong-7391",
                                    "username": "reconix-no-such-user-7391",
                                    "password": "reconix-wrong-7391"})
        ck, cu = _login_error_class(rk.body), _login_error_class(ru.body)
        signals["login_error_differential"] = (ck, cu)
        if ck == "bad_password" and cu == "unknown_user":
            ctx.findings.add(
                "Medium", "Login Username Enumeration (error differential)",
                login_url,
                "Login errors distinguish a valid username (bad-password "
                "error) from an invalid one (unknown-user error) for the "
                "same wrong password — usernames can be confirmed one "
                "by one.",
                proof=f"known user '{known}' -> bad-password error; "
                      f"unknown user -> unknown-user error",
                param="log", resp=rk, cwe="CWE-200")
    return signals


# ------------------------------------------------------------- entry point

def cms_scan(ctx, base, pages=None):
    """Detect the CMS, then run version detection (advisory),
    enumeration (advisory), and the proven weak-spot checks.
    Returns the full summary dict. ADVISORY items in the summary are
    NOT ctx.findings — the report layer must render them separately."""
    if pages is None:
        r = ctx.client.fetch(base)
        pages = [(base, r)]
    home_body = pages[0][1].body if pages else ""
    cms, confidence, signals = detect_cms_from_text(home_body)
    if not cms:
        # Second chance: probe the CMS tell-tale paths directly.
        parts = urllib.parse.urlsplit(base)
        root = f"{parts.scheme}://{parts.netloc}"
        for probe_path, guess in (
                ("/wp-json/", "wordpress"), ("/wp-login.php", "wordpress"),
                ("/administrator/", "joomla"), ("/user/login", "drupal")):
            rr = ctx.client.fetch(root + probe_path)
            if rr.status == 200 and rr.body:
                cms, confidence = guess, "low"
                signals.append(f"reachable tell-tale path {probe_path}")
                break
    before = len(ctx.findings.items)
    version = detect_version(ctx, base, cms) if cms else None
    plugins, themes = enumerate_plugins_themes(ctx, base, cms, pages) \
        if cms else ([], [])
    exposed = exposed_files_check(ctx, base, cms) if cms else []
    users = user_enumeration_check(ctx, base, cms) if cms else []
    login_signals = login_hardening_check(ctx, base, cms, users) \
        if cms else {}
    advisories = []
    if version:
        advisories.append({
            "kind": "advisory",
            "title": f"CMS Version Disclosed: {cms} {version['version']}",
            "version": version["version"], "source": version["source"],
            "detail": "Version disclosure only. This is NOT a "
                      "vulnerability finding: it becomes actionable only "
                      "with a proven reachable vulnerable endpoint or "
                      "exposed file. Evidence: "
                      f"{version['evidence'][:200]}"})
    if plugins or themes:
        advisories.append({
            "kind": "advisory",
            "title": "CMS Plugins/Themes Enumerated",
            "plugins": plugins, "themes": themes,
            "detail": "Enumeration only, from HTML/asset references and "
                      "common readme paths. A plugin/theme name alone is "
                      "not a vulnerability."})
    return {"cms": cms, "confidence": confidence, "signals": signals,
            "version": version, "plugins": plugins, "themes": themes,
            "exposed_files": exposed, "users": users,
            "login_signals": login_signals, "advisories": advisories,
            "findings_added": len(ctx.findings.items) - before}
