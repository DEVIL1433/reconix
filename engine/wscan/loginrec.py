"""Login recorder — record a login once, reuse the session for scans.

Replaces pasted-cookie-only auth. A login is recorded either

* scripted: a step list (goto / fill / click / wait) driven through the
  existing browser engine (Playwright/Chromium, see wscan/browser.py),
  or
* interactive: the user logs in by hand in a browser window and the
  caller captures the finished state with capture_from_driver().

What is recorded is ONLY the session: cookies + localStorage tokens.
A password is NEVER stored: password-field values are stripped from
every recorded artefact (saved file, returned session dict, emitted
messages), password-named localStorage keys are dropped, and any cookie
or token whose value equals a password typed during recording is
dropped too. Passwords exist only transiently, in memory, while the
browser performs the login itself — exactly like a human typing them.

Session-store choice: a plain JSON file next to scans.db
(``<webscan root>/sessions/<name>.json``, mode 0600, atomic write),
NOT a scans.db table. Rationale: the store must be readable without
the app server, must never be mixed into scan history / reports (which
are the things that get exported and shared), and needs no schema
migration — app.py is untouched by this module. The file holds session
material only (cookies/tokens); it is still sensitive — treat it like
a cookie jar, never attach it to a report or share it.

Role model (engine's existing sessions, see wscan/engine.py Ctx):
an authenticated scan has ONE primary client (ctx.client, opts
"cookie"), an optional second-user client (ctx.client_b, opts
"cookie_b", for IDOR / role checks) and an anonymous client
(ctx.client_anon, a fresh client with NO session). A recorded session
fills the PRIMARY role by default; a second recording, made under a
different account, fills the SECOND-USER role. A recorded session
never fills the anonymous role — anonymous means no session at all,
and opts_for_session() refuses role="anon" rather than silently
downgrading an authenticated session to an anonymous-looking one.

Expiry: check_session() probes the recorded session against a live
URL (default: the recorded origin). A 401/403, or a probe page that
shows a login form, means the session is dead and the result carries
the exact signal "session expired, re-record". An unreachable probe
is NOT expiry (needs_rerecord=False) — a dead network must not make
the user re-record a healthy session.

Stdlib only. No network access except the probe / the browser driver
the caller supplies; tests use a fake driver + loopback stub servers.
"""

import json
import os
import time
import urllib.parse

from .client import Client
from .core import parse_page

VERSION = 1
EXPIRED_MESSAGE = "session expired, re-record"

# Directory next to scans.db (webscan root / sessions).
DEFAULT_SESSION_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")

_PASSWORD_HINTS = ("password", "passwd", "pwd", "passcode")


class RecorderError(Exception):
    """Bad steps, unavailable browser engine, or an unusable session."""


class SessionExpired(Exception):
    """Raised by assert_alive() when a session is dead (see
    EXPIRED_MESSAGE)."""


class RecorderUnavailable(RecorderError):
    """The browser engine (Playwright/Chromium) is not installed."""


# ------------------------------------------------------------------ steps

def _is_password_field(selector_or_field, step_type=""):
    """True for password inputs: explicit type, or a name/selector
    mentioning password/passwd/pwd."""
    if (step_type or "").lower() == "password":
        return True
    low = (selector_or_field or "").lower()
    return any(h in low for h in _PASSWORD_HINTS)


def _field_of(step):
    return step.get("field") or step.get("selector") or ""


def sanitize_steps(steps):
    """Copy of a step list with every password-field value stripped.
    The step shape is kept (so a re-run knows a password goes there)
    but the value is gone — nothing recorded ever carries it."""
    out = []
    for step in steps or []:
        step = dict(step)
        if step.get("action") in ("fill", "type") and _is_password_field(
                _field_of(step), step.get("type", "")):
            step["value"] = ""
            step["redacted"] = True
        out.append(step)
    return out


def _password_values(steps):
    """Password values typed during recording — memory-only, used
    solely to drop any captured cookie/token that repeats one."""
    vals = set()
    for step in steps or []:
        if step.get("action") in ("fill", "type") and _is_password_field(
                _field_of(step), step.get("type", "")):
            v = step.get("value")
            if isinstance(v, str) and v:
                vals.add(v)
    return vals


# ------------------------------------------------------------- driver API

class Driver:
    """Protocol a recorder driver implements (duck-typed, not ABC, so
    tests can pass a fake without subclassing):

      goto(url)                 navigate
      fill(selector, value)     type into a field
      click(selector)           activate a control
      wait(ms)                  pause
      cookies() -> [ {name, value, domain?, path?, expires?} ]
      local_storage() -> {key: value}   (optional: {} if unsupported)
      url() -> current URL string       (optional: "" if unsupported)
    """

    def local_storage(self):
        return {}

    def url(self):
        return ""


def playwright_driver(page):
    """Adapt a Playwright page to the driver protocol (the same
    Chromium engine wscan/browser.py uses)."""

    class _PlaywrightDriver(Driver):
        def goto(self, url):
            page.goto(url, wait_until="domcontentloaded", timeout=30000)

        def fill(self, selector, value):
            try:
                page.fill(selector, value, timeout=10000)
            except Exception:
                page.locator(selector).fill(value, timeout=10000)

        def click(self, selector):
            try:
                page.click(selector, timeout=10000)
            except Exception:
                page.locator(selector).click(timeout=10000)

        def wait(self, ms):
            page.wait_for_timeout(ms)

        def cookies(self):
            try:
                return [{"name": c.get("name", ""),
                         "value": c.get("value", ""),
                         "domain": c.get("domain", ""),
                         "path": c.get("path", "/"),
                         "expires": c.get("expires", -1)}
                        for c in page.context.cookies()]
            except Exception:
                return []

        def local_storage(self):
            try:
                return page.evaluate(
                    "() => { const o = {}; for (let i = 0; i < "
                    "localStorage.length; i++) { const k = "
                    "localStorage.key(i); o[k] = localStorage.getItem(k); }"
                    " return o; }") or {}
            except Exception:
                return {}

        def url(self):
            try:
                return page.url or ""
            except Exception:
                return ""

    return _PlaywrightDriver()


def record_with_browser(steps, base_url="", headless=False):
    """Run steps in a real Chromium window the user can watch (and,
    for interactive use, take over), then capture the session. The
    caller owns the returned session dict — save it with
    save_session(). Raises RecorderUnavailable without Playwright."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        raise RecorderUnavailable(
            "Playwright/Chromium is not installed — install it "
            "(pip install playwright && playwright install chromium) "
            "or record with a driver object instead.")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            if base_url:
                page.goto(base_url, wait_until="domcontentloaded",
                          timeout=30000)
            return record_session(steps, playwright_driver(page))
        finally:
            browser.close()


# ------------------------------------------------------------- recording

def _sanitize_session(session):
    """Defence in depth: strip password material from a session dict
    (re-applied on save AND load, so a hand-edited file cannot smuggle
    a password into the store)."""
    session = dict(session)
    session["steps_recorded"] = sanitize_steps(
        session.get("steps_recorded") or [])
    cookies = []
    for c in session.get("cookies") or []:
        c = dict(c)
        if _is_password_field(c.get("name", "")):
            continue
        if c.get("name") and c.get("value") is not None:
            cookies.append(c)
    session["cookies"] = cookies
    tokens = {}
    for k, v in (session.get("tokens") or {}).items():
        if _is_password_field(k):
            continue
        tokens[k] = v
    session["tokens"] = tokens
    return session


def capture_from_driver(driver, origin="", name="", probe_url="",
                        password_values=None, steps_recorded=None):
    """Capture the driver's CURRENT state as a session dict. This is
    the interactive path: after the user has logged in by hand, call
    this — no steps are run. Also the final step of record_session()."""
    pw_values = set(password_values or [])
    try:
        cookies = driver.cookies() or []
    except Exception:
        cookies = []
    clean_cookies = []
    for c in cookies:
        if not isinstance(c, dict):
            continue
        cname, cval = c.get("name", ""), c.get("value", "")
        if not cname or cval is None or str(cval) == "":
            continue
        if _is_password_field(cname):
            continue
        if str(cval) in pw_values:
            continue  # a cookie echoing the password is not a session
        clean_cookies.append({
            "name": cname, "value": str(cval),
            "domain": c.get("domain", ""), "path": c.get("path", "/"),
            "expires": c.get("expires", -1)})
    try:
        storage = driver.local_storage() or {}
    except Exception:
        storage = {}
    tokens = {}
    if isinstance(storage, dict):
        for k, v in storage.items():
            if _is_password_field(k):
                continue
            if isinstance(v, str) and v in pw_values:
                continue
            tokens[str(k)] = v
    current = ""
    try:
        current = driver.url() or ""
    except Exception:
        current = ""
    if not origin:
        src = current or next(
            (s.get("url", "") for s in (steps_recorded or [])
             if s.get("action") == "goto"), "") or ""
        if src:
            parts = urllib.parse.urlsplit(src)
            origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc \
                else ""
    return {
        "version": VERSION, "name": name or "", "origin": origin,
        "role": "primary",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cookies": clean_cookies, "tokens": tokens,
        "probe_url": probe_url or "",
        "steps_recorded": sanitize_steps(steps_recorded or []),
    }


def record_session(steps, driver, name="", probe_url="", emit=None):
    """Run scripted steps through the driver, capture the resulting
    session. Returns the session dict (password values already
    stripped — see module docstring). Raises RecorderError on an
    unknown step action; a driver failure propagates so the caller
    knows the recording did not happen (a half-recorded session is
    never returned as if it were good)."""
    steps = list(steps or [])
    pw_values = _password_values(steps)
    try:
        for step in steps:
            action = (step or {}).get("action")
            if action == "goto":
                driver.goto(step.get("url", ""))
            elif action in ("fill", "type"):
                driver.fill(_field_of(step), step.get("value", ""))
            elif action == "click":
                driver.click(_field_of(step))
            elif action == "wait":
                ms = step.get("ms")
                if ms is None:
                    ms = int(float(step.get("seconds", 0)) * 1000)
                driver.wait(int(ms))
            else:
                raise RecorderError(f"unknown login step action: {action!r}")
    finally:
        # Password values live only for the duration of the run.
        captured_pw = set(pw_values)
        pw_values = set()
    session = capture_from_driver(
        driver, name=name, probe_url=probe_url,
        password_values=captured_pw, steps_recorded=steps)
    if emit:
        emit(f"Login recorded: {len(session['cookies'])} cookie(s), "
             f"{len(session['tokens'])} stored token(s) "
             f"from {session['origin'] or 'unknown origin'}")
    return session


# ------------------------------------------------------------- persistence

def session_path(name, base_dir=None):
    """Safe filename for a session name. Path separators and '..'
    are rejected outright — a session name must never escape the
    session directory."""
    if not name or "/" in name or "\\" in name or ".." in name:
        raise RecorderError(
            f"invalid session name (no paths allowed): {name!r}")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    if not safe or safe in (".", ".."):
        raise RecorderError(f"invalid session name: {name!r}")
    if not safe.endswith(".json"):
        safe += ".json"
    return os.path.join(base_dir or DEFAULT_SESSION_DIR, safe)


def save_session(session, path=None, name=None, base_dir=None):
    """Persist a session (sanitized again first) with an atomic write
    and owner-only permissions. Returns the file path."""
    clean = _sanitize_session(session)
    if path is None:
        path = session_path(name or clean.get("name") or "default",
                            base_dir)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + f".tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def load_session(path_or_name, base_dir=None):
    """Load a session by file path or by stored name. The result is
    re-sanitized, so loading can never surface password material."""
    if os.path.isfile(path_or_name):
        path = path_or_name
    else:
        path = session_path(path_or_name, base_dir)
    with open(path, encoding="utf-8") as fh:
        session = json.load(fh)
    if not isinstance(session, dict) or "cookies" not in session:
        raise RecorderError(f"not a recorded session file: {path}")
    return _sanitize_session(session)


def list_sessions(base_dir=None):
    directory = base_dir or DEFAULT_SESSION_DIR
    if not os.path.isdir(directory):
        return []
    return sorted(f[:-5] for f in os.listdir(directory)
                  if f.endswith(".json"))


def delete_session(path_or_name, base_dir=None):
    if os.path.isfile(path_or_name):
        path = path_or_name
    else:
        path = session_path(path_or_name, base_dir)
    os.unlink(path)


# ------------------------------------------------------------- replay

def _cookie_live(cookie):
    expires = cookie.get("expires", -1)
    if isinstance(expires, (int, float)) and expires > 0:
        return expires > time.time()
    return True  # session cookie / no expiry recorded: assume live


def cookie_header(session):
    """'Cookie' header value for a recorded session (live cookies
    only — expired ones are left out, never sent)."""
    parts = []
    for c in (session or {}).get("cookies") or []:
        if c.get("name") and c.get("value") is not None \
                and _cookie_live(c):
            parts.append(f"{c['name']}={c['value']}")
    return "; ".join(parts)


def token_headers(session):
    """Opt-in Authorization header from a stored bearer-style token
    (access_token / auth_token / jwt / bearer_token in localStorage).
    Empty when no such token is stored. attach_to_client() does NOT
    apply this automatically — HTTP scans authenticate by cookie, and
    a token header must be the caller's explicit choice."""
    tokens = (session or {}).get("tokens") or {}
    if isinstance(tokens, dict) and "localStorage" in tokens \
            and isinstance(tokens["localStorage"], dict):
        tokens = tokens["localStorage"]
    for key in tokens:
        low = key.lower()
        if low in ("access_token", "access-token", "auth_token",
                   "authtoken", "id_token", "jwt", "bearer_token") \
                or "access_token" in low or "auth_token" in low \
                or "bearer" in low:
            val = tokens[key]
            if isinstance(val, str) and val and not any(
                    ch.isspace() for ch in val):
                return {"Authorization": f"Bearer {val}"}
    return {}


def attach_to_client(client, session):
    """Attach a recorded session to an engine Client (sets its Cookie
    header). Returns the client, for chaining."""
    header = cookie_header(session)
    if header:
        client.headers["Cookie"] = header
    return client


def client_from_session(session, **kwargs):
    """A fresh engine Client carrying the recorded session."""
    header = cookie_header(session)
    return Client(cookie=header or None, **kwargs)


def opts_for_session(session, role=None):
    """Scan opts carrying the recorded session. role 'primary' (the
    default) -> opts['cookie'] = the engine's main client; role
    'second' -> opts['cookie_b'] = the second-user client used by IDOR
    and role checks. Any other role (including 'anon') is refused:
    the anonymous client must stay a fresh, session-less client."""
    role = role or (session or {}).get("role") or "primary"
    header = cookie_header(session)
    if role == "primary":
        return {"cookie": header} if header else {}
    if role == "second":
        return {"cookie_b": header} if header else {}
    raise RecorderError(
        f"a recorded session cannot fill role {role!r}: it fills "
        "'primary' (or 'second' for a second account); the anonymous "
        "client is always a fresh client with no session")


def apply_to_opts(opts, session, role=None):
    """opts dict (a copy) with the recorded session applied — the
    engine hook: run_scan(target, apply_to_opts(opts, session))."""
    out = dict(opts or {})
    out.update(opts_for_session(session, role))
    return out


# ------------------------------------------------------------- expiry

def is_expired_offline(session):
    """Cookie-expiry-only check, no network: True when the session
    holds no usable material, or every dated cookie has expired."""
    cookies = (session or {}).get("cookies") or []
    tokens = (session or {}).get("tokens") or {}
    if not cookies and not tokens:
        return True
    dated = [c for c in cookies
             if isinstance(c.get("expires", -1), (int, float))
             and c.get("expires", -1) > 0]
    if dated and all(not _cookie_live(c) for c in dated):
        return True
    return False


def check_session(session, probe_url=None, client=None, probe=True):
    """Expiry verdict for a recorded session.

    Returns {"alive", "needs_rerecord", "signal", "reason",
    "probe_url", "status"}. When the session is dead, "signal" is
    exactly EXPIRED_MESSAGE ("session expired, re-record") — the
    string the UI shows and the engine watchdog acts on. When the
    probe is unreachable, needs_rerecord is False: that is a network
    problem, not a dead session."""
    probe_url = probe_url or (session or {}).get("probe_url") \
        or ((session or {}).get("origin") or "").rstrip("/") + "/"
    if not probe or not probe_url:
        dead = is_expired_offline(session)
        return {
            "alive": not dead, "needs_rerecord": dead,
            "signal": EXPIRED_MESSAGE if dead else "",
            "reason": ("no live probe run; stored session material is "
                       "absent or expired" if dead else
                       "stored session material present (no live probe "
                       "run)"),
            "probe_url": probe_url, "status": None}
    if is_expired_offline(session) and not (session or {}).get("tokens"):
        # No usable material, or dated cookies all expired with no
        # token to fall back on: the probe would only confirm it.
        has_any = bool((session or {}).get("cookies"))
        return {"alive": False, "needs_rerecord": True,
                "signal": EXPIRED_MESSAGE,
                "reason": ("stored cookies have expired" if has_any else
                           "no session cookies or tokens stored"),
                "probe_url": probe_url, "status": None}
    probe_client = client if client is not None \
        else client_from_session(session)
    resp = probe_client.fetch(probe_url)
    if resp.status is None:
        return {"alive": False, "needs_rerecord": False, "signal": "",
                "reason": "probe unreachable (target did not respond)",
                "probe_url": probe_url, "status": None}
    if resp.status in (401, 403):
        return {"alive": False, "needs_rerecord": True,
                "signal": EXPIRED_MESSAGE,
                "reason": f"probe returned HTTP {resp.status}",
                "probe_url": probe_url, "status": resp.status}
    has_login_form = any(
        i["type"] == "password" for form in parse_page(resp.body).forms
        for i in form["inputs"])
    if has_login_form:
        return {"alive": False, "needs_rerecord": True,
                "signal": EXPIRED_MESSAGE,
                "reason": "probe shows a login form (session no longer "
                          "authenticated)",
                "probe_url": probe_url, "status": resp.status}
    return {"alive": True, "needs_rerecord": False, "signal": "",
            "reason": f"probe returned HTTP {resp.status} without a "
                      "login form",
            "probe_url": probe_url, "status": resp.status}


def session_alive(session, probe_url=None, client=None, probe=True):
    """Boolean wrapper around check_session()."""
    return bool(check_session(session, probe_url, client, probe)["alive"])


def assert_alive(session, probe_url=None, client=None, probe=True):
    """Raise SessionExpired(EXPIRED_MESSAGE + reason) when the session
    is dead; return the check dict otherwise. Engine-watchdog hook."""
    result = check_session(session, probe_url, client, probe)
    if result["needs_rerecord"]:
        raise SessionExpired(f"{EXPIRED_MESSAGE}: {result['reason']}")
    return result
