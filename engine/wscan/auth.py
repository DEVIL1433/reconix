"""Auth/session helpers: programmatic login for authenticated scanning."""
import urllib.parse

from .core import parse_page


def _find_login_form(client, login_url):
    r = client.fetch(login_url)
    parsed = parse_page(r.body)
    for form in parsed.forms:
        types = {i["name"]: i["type"] for i in form["inputs"]}
        if "password" in types.values():
            return login_url, form
    # fall back: any form on the page
    if parsed.forms:
        return login_url, parsed.forms[0]
    return login_url, None


def perform_login(client, cfg, emit=lambda m: None):
    """cfg: {login_url, username, password, user_field?, pass_field?,
             success_marker?}. Returns True on apparent success."""
    login_url = cfg.get("login_url")
    if not login_url:
        return False
    page_url, form = _find_login_form(client, login_url)
    if not form:
        emit("Auth: no login form found")
        return False
    user_field = cfg.get("user_field")
    pass_field = cfg.get("pass_field")
    data = {}
    for i in form["inputs"]:
        if i["type"] == "password" and not pass_field:
            pass_field = i["name"]
        elif i["type"] in ("text", "email") and not user_field:
            user_field = i["name"]
        if i["type"] not in ("submit", "button"):
            data[i["name"]] = i["value"] or ""
    if not user_field or not pass_field:
        emit("Auth: could not identify user/pass fields")
        return False
    before = dict(client.cookies())
    data[user_field] = cfg.get("username", "")
    data[pass_field] = cfg.get("password", "")
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)
    if form["method"] == "POST":
        r = client.fetch(action, method="POST", data=data)
    else:
        r = client.fetch(action + "?" + urllib.parse.urlencode(data))
    after = dict(client.cookies())
    marker = cfg.get("success_marker", "")
    ok = False
    if marker and marker in (r.body or ""):
        ok = True
    elif before != after:
        ok = True
    elif r.status in (301, 302, 303) and "login" not in r.header("location"):
        ok = True
    elif not any(w in (r.body or "").lower()
                 for w in ("invalid password", "login failed",
                           "incorrect password", "authentication failed")):
        ok = r.status == 200
    emit(f"Auth: login as {cfg.get('username')} -> {'ok' if ok else 'FAILED'}")
    return ok


def session_alive(client, probe_url, login_markers=("login", "sign in", "signin")):
    """Heuristic: an authed page that now shows a login form = dead session."""
    r = client.fetch(probe_url)
    if r.status in (401, 403):
        return False
    parsed = parse_page(r.body)
    for form in parsed.forms:
        if any(i["type"] == "password" for i in form["inputs"]):
            return False
    return True
