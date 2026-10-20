"""Attack chaining: correlate individual findings into the paths a
pentester would actually walk.

Scanners list twenty small bugs; hackers chain three of them into a
breach. Each rule below combines findings that are already confirmed
(or clearly evidenced) on the same host — plus, where relevant, the
external-recon map and the crawled URL surface — and emits one chain
finding that names the end-to-end path. Components stay in the report;
the chain explains why together they are worse than the sum.
"""
import urllib.parse


def _host(u):
    return urllib.parse.urlsplit(u or "").netloc


def _titled(items, *subs):
    low = [s.lower() for s in subs]
    return [f for f in items if any(s in (f.get("title") or "").lower()
                                     for s in low)]


def correlate(ctx, extrecon=None, page_urls=None):
    F = ctx.findings
    items = list(F.items)
    if len(items) < 1:
        return []
    made = []

    def chain(sev, title, url, detail, comps, cwe=""):
        conf = "Confirmed" if comps and all(
            c.get("confidence") == "Confirmed" for c in comps) \
            else "Needs manual confirmation"
        f = F.add(sev, title, url, detail,
                  proof="Chain components: " + "; ".join(
                      f"#{c['id']} {c['title']}" for c in comps),
                  confidence=conf, cwe=cwe)
        if f:
            f["is_chain"] = True
            f["chain_of"] = [c.get("fp") for c in comps]
            made.append(f)
        return f

    by_host = {}
    for f in items:
        by_host.setdefault(_host(f.get("url")), []).append(f)

    for host, fs in by_host.items():
        # XSS + session cookie readable by JS = hijack, not just popup
        xss = _titled(fs, "cross-site scripting")
        httponly = _titled(fs, "httponly")
        if xss and httponly:
            chain("High", "Attack Chain: XSS -> Session Hijacking",
                  xss[0]["url"],
                  "A cross-site scripting flaw on this host meets a "
                  "session cookie with no HttpOnly flag: injected script "
                  "can read the cookie and hand the victim's live session "
                  "to an attacker. Together this is account takeover, "
                  "not a pop-up demo.",
                  [xss[0], httponly[0]], "CWE-79")

        # Credentialed CORS + any access-control break = cross-site theft
        cors = [f for f in _titled(fs, "cross-origin resource sharing")
                if "ACAC=true" in (f.get("proof") or "")
                or "reflect" in (f.get("proof") or "").lower()]
        access = _titled(fs, "idor", "broken access control",
                         "accessible without authentication",
                         "accessible to non-admin", "another user")
        if cors and access:
            chain("Critical",
                  "Attack Chain: CORS + Broken Access Control -> "
                  "Cross-Site Data Theft",
                  cors[0]["url"],
                  "The API reflects arbitrary origins WITH credentials "
                  "while access control is already broken: any website a "
                  "logged-in user visits can read their data cross-origin "
                  "and exfiltrate it. No user interaction beyond "
                  "browsing is needed.",
                  [cors[0], access[0]], "CWE-942")

        # Forgeable JWT + a real API flaw = full API compromise
        jwt = [f for f in _titled(fs, "json web token")
               if f.get("severity") in ("High", "Critical")]
        api = [f for f in _titled(fs, "api", "graphql")
               if f.get("severity") in ("Medium", "High", "Critical")]
        if jwt and api:
            chain("High", "Attack Chain: Forgeable JWT -> Full API Access",
                  jwt[0]["url"],
                  "Tokens on this host can be forged (weak/none "
                  "algorithm) and the API already shows exploitable "
                  "weaknesses: an attacker mints an admin token and "
                  "walks the API as any user.",
                  [jwt[0], api[0]], "CWE-347")

        # Exposed config file + leaked secrets = credential compromise
        exposed = _titled(fs, "sensitive file", ".env", ".git")
        secrets = _titled(fs, "secret", "api key", "credential")
        if exposed and secrets and exposed[0] is not secrets[0]:
            chain("High",
                  "Attack Chain: Exposed Config + Leaked Secrets -> "
                  "Credential Compromise",
                  exposed[0]["url"],
                  "Configuration/source files are web-accessible AND "
                  "secrets were observed in served content: assume every "
                  "credential in the exposed material is compromised "
                  "and rotate it; the exposure path gives attackers "
                  "the map as well as the keys.",
                  [exposed[0], secrets[0]], "CWE-200")

        # Open redirect sitting on an auth flow = token theft pivot
        redir = _titled(fs, "open redirect")
        if redir and page_urls:
            auth_urls = [u for u in page_urls if _host(u) == host and any(
                k in u.lower() for k in ("oauth", "authorize", "sso",
                                         "login", "callback"))]
            if auth_urls:
                chain("Medium",
                      "Attack Chain: Open Redirect on an Auth Flow -> "
                      "Token Theft Pivot",
                      redir[0]["url"],
                      "An open redirect exists alongside authentication "
                      f"URLs (e.g. {auth_urls[0]}): OAuth/SSO flows that "
                      "pass through the redirect can be steered to an "
                      "attacker domain, harvesting authorization codes "
                      "or tokens mid-login.",
                      [redir[0]], "CWE-601")

        # SSRF + a mapped internal estate = pivot, not just a fetch
        ssrf = _titled(fs, "server-side request forgery")
        if ssrf and extrecon:
            assets = extrecon.get("assets") or []
            subs = extrecon.get("subdomains") or []
            others = [a for a in assets
                      if (a.get("host") or "") != host.split(":")[0]]
            if others or len(subs) > 3:
                chain("Critical",
                      "Attack Chain: SSRF -> Internal Network Pivot",
                      ssrf[0]["url"],
                      "The server can be made to fetch arbitrary URLs, "
                      "and external recon mapped "
                      f"{len(others)} related host(s) and "
                      f"{len(subs)} subdomain(s): the SSRF becomes a "
                      "pivot into internal services that were never "
                      "meant to be reachable from the internet.",
                      [ssrf[0]], "CWE-918")
    return made
