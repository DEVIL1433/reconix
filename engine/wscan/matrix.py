"""Permission matrix: fetch every crawled page as anonymous / user /
second user / admin and compare — finds broken access control at scale."""
import re
import urllib.parse

from .checks import _sim, _similar
from .client import Client

RESTRICTED_PATH = ("/admin", "/account", "/settings", "/profile",
                   "/dashboard", "/manage", "/console", "/backend")
RESTRICTED_WORDS = ("logout", "sign out", "user management",
                    "admin panel", "control panel")


def _looks_restricted(url, body):
    path = urllib.parse.urlsplit(url).path.lower()
    if any(p in path for p in RESTRICTED_PATH):
        return True
    # ignore words that only appear inside links ("Admin panel" nav links
    # exist on plenty of public pages)
    import re as _re
    text = _re.sub(r"<a\b[^>]*>.*?</a>", "", body or "", flags=_re.I | _re.S)
    low = text.lower()
    return any(w in low for w in RESTRICTED_WORDS) and "login" not in path


def build(ctx, pages, limit=60):
    F = ctx.findings
    sessions = [("anonymous", Client(proxy=ctx.opts.get("proxy"))),
                ("primary", ctx.client)]
    if ctx.client_b is not None:
        sessions.append(("second user", ctx.client_b))
    admin_client = None
    if ctx.opts.get("cookie_admin"):
        admin_client = Client(cookie=ctx.opts["cookie_admin"],
                              proxy=ctx.opts.get("proxy"))
        sessions.append(("admin", admin_client))
    matrix = []
    page_map = {u: r for u, r in pages}
    for url, primary_resp in pages[:limit]:
        row = {"url": url, "results": {}}
        bodies = {}
        for label, client in sessions:
            if label == "primary":
                r = primary_resp
            else:
                r = client.fetch(url)
            row["results"][label] = {"status": r.status,
                                     "length": len(r.body or "")}
            bodies[label] = r.body or ""
        matrix.append(row)
        user_body = bodies.get("primary", "")
        restricted = _looks_restricted(url, user_body)
        # anonymous reaching restricted content identical to a logged-in view
        anon = row["results"].get("anonymous", {})
        if restricted and anon.get("status") == 200 and \
                _sim(ctx, bodies.get("anonymous", ""), user_body) > 0.85 and \
                len(user_body) > 120:
            F.add("High", "Restricted Page Accessible Without Authentication",
                  url,
                  "An anonymous request receives the same content as the "
                  "authenticated session on a page that appears restricted "
                  "(admin/account area markers).",
                  proof=f"anon vs user similarity "
                        f"{_sim(ctx, bodies.get('anonymous',''), user_body):.2f}, "
                        f"both HTTP 200",
                  confidence="Needs manual confirmation", cwe="CWE-862")
        # second user reading the primary user's own data (horizontal
        # privilege escalation / BOLA): private content — anonymous does
        # NOT get it — yet another user's session gets all of it.
        second = row["results"].get("second user", {})
        if second.get("status") == 200 and "second user" in bodies \
                and len(user_body) > 120 \
                and _sim(ctx, bodies["second user"], user_body) > 0.90 \
                and _sim(ctx, bodies.get("anonymous", ""), user_body) < 0.90:
            path_id = re.search(r"/\d{1,}(/|$)",
                                urllib.parse.urlsplit(url).path)
            if _looks_restricted(url, user_body) or path_id:
                F.add("High",
                      "User Data Accessible to Another User (BOLA)",
                      url,
                      "A second user's session receives the primary "
                      "user's content on a user-specific page — the "
                      "server checks that SOME user is logged in, not "
                      "that the object belongs to them.",
                      proof=f"second-user vs owner similarity "
                            f"{_sim(ctx, bodies['second user'], user_body):.2f}, "
                            f"anonymous similarity "
                            f"{_sim(ctx, bodies.get('anonymous', ''), user_body):.2f}",
                      confidence="Needs manual confirmation",
                      cwe="CWE-639")
        # anonymous reading API data the logged-in session gets
        has_auth = bool(ctx.opts.get("cookie") or ctx.auth_cfg
                        or ctx.opts.get("cookie_admin"))
        ctype = (primary_resp.header("content-type") or "").lower()
        is_data = "json" in ctype or (user_body or "").lstrip()[:1] in "[{"
        if has_auth and is_data and anon.get("status") == 200 \
                and len(bodies.get("anonymous", "")) > 200 \
                and _sim(ctx, bodies.get("anonymous", ""), user_body) > 0.90:
            F.add("High", "API Data Accessible Without Authentication",
                  url,
                  "An unauthenticated request receives the same data "
                  "response as the authenticated session on an API/data "
                  "endpoint — the endpoint performs no authentication "
                  "check of its own.",
                  proof=f"anon vs user similarity "
                        f"{_sim(ctx, bodies.get('anonymous', ''), user_body):.2f}, "
                        f"both HTTP 200, {len(bodies.get('anonymous', ''))} bytes",
                  confidence="Needs manual confirmation", cwe="CWE-862")
        # non-admin reaching admin-area content
        path = urllib.parse.urlsplit(url).path.lower()
        if admin_client is not None and "/admin" in path:
            admin_body = bodies.get("admin", "")
            for label in ("primary", "second user"):
                if label in bodies and \
                        row["results"][label]["status"] == 200 and \
                        _sim(ctx, bodies[label], admin_body) > 0.85 and \
                        len(admin_body) > 120:
                    F.add("High", "Admin Page Accessible to Non-Admin Session",
                          url,
                          f"The {label} session receives admin-area content "
                          f"indistinguishable from the admin session's.",
                          proof=f"{label} vs admin similarity "
                                f"{_sim(ctx, bodies[label], admin_body):.2f}",
                          confidence="Needs manual confirmation",
                          cwe="CWE-862")
    return matrix
