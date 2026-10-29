"""Reporting: risk score, plain-language explanations, executive summary,
CSV export, and a dependency-free PDF generator."""
import csv
import io
import re

WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 1}

EXPLAIN = {
    "sql injection": "Attackers can read, modify or delete the database behind the site — including customer records and passwords — by typing database commands into a form field or URL.",
    "cross-site scripting": "Attackers can run their own code in visitors' browsers, stealing sessions, defacing pages or redirecting users to scams.",
    "command injection": "Attackers can run operating-system commands on the server itself — effectively full control of the machine.",
    "template injection": "Attackers can take over the page-rendering engine, which usually leads to running code on the server.",
    "local file inclusion": "Attackers can read files from the server (passwords, source code, configuration) that were never meant to be public.",
    "path traversal": "Attackers can read files from the server (passwords, source code, configuration) that were never meant to be public.",
    "server-side request forgery": "Attackers can make the server contact internal systems it can reach — a stepping stone into the private network and cloud accounts.",
    "xml external entity": "Attackers can read server files or make the server call internal systems by feeding it malicious XML.",
    "file upload": "Attackers can upload files to the server; if those files can be executed, the server is fully compromised.",
    "json web token": "Login tokens can be forged, letting an attacker sign in as any user — including administrators.",
    "open redirect": "Links on the real site can bounce visitors to a fake site, powering convincing phishing.",
    "cross-origin": "Other websites can read this site's data in a visitor's browser, breaking the usual isolation between sites.",
    "csrf": "A malicious page can trick a logged-in user's browser into performing actions (changes, purchases) without their knowledge.",
    "idor": "Users may be able to view or change other users' data simply by changing a number in the address bar.",
    "access control": "Users may be able to reach data or functions that should require higher privileges.",
    "sensitive": "Information that should not be public is reachable — it can include passwords, keys or internal documents.",
    "secret": "A credential appears to be exposed publicly; anyone who finds it can use it.",
    "header": "A browser security feature is not switched on, removing a layer of protection.",
    "cookie": "A login cookie lacks a standard protection flag, making session theft easier.",
    "graphql": "The full map of the site's data API is public, making targeted attacks much easier.",
    "default credentials": "The site accepts a factory-default username and password — anyone can log in.",
    "cache poisoning": "Attackers may be able to poison the shared cache so every visitor receives malicious content.",
    "prototype pollution": "Attackers can change values the app trusts — prices, roles, admin flags — by polluting the shared object every other object is built from.",
    "deserialization": "Attackers can make the server rebuild a crafted object from user input, which can lead to running code on the server itself.",
    "rate limiting": "Nothing slows down automated guessing, so passwords or codes can be tried millions of times.",
    "tls": "The encryption certificate has a problem, which can expose traffic or trigger browser warnings.",
    "certificate": "The encryption certificate has a problem, which can expose traffic or trigger browser warnings.",
}


def explain(title):
    low = title.lower()
    for key, text in EXPLAIN.items():
        if key in low:
            return text
    return "A security weakness was found that should be reviewed and fixed by the development team."


# Plain-language "what attacks can be performed" lines per weakness class
# (3.21 simple finding view). Matched by title keyword first (same style
# as EXPLAIN), then by CWE. Bullets stay class-true: they describe what
# this kind of weakness allows, in "can" language — never a claim that
# it was done on this target beyond what the proof shows.
ATTACKS = {
    "sql injection": [
        "Steal the whole database — names, emails, password hashes — table by table",
        "Log in as any user, including admin, without a password (' OR 1=1--)",
        "Change or delete data in the database",
        "In some setups, read server files or run commands and take the server over",
    ],
    "cross-site scripting": [
        "Run their own script in a visitor's browser, on the real site",
        "Steal a logged-in user's session and act as them",
        "Deface the page, or redirect visitors to a fake login/scam page",
        "Capture what the user types (keystrokes, form data)",
    ],
    "command injection": [
        "Run operating-system commands on the server itself",
        "Read, change or delete any file the server user can reach",
        "Use the server as a stepping stone into the internal network",
        "Install a backdoor and keep control after the visit",
    ],
    "template injection": [
        "Execute code inside the page-rendering engine",
        "Usually escalates to full remote code execution on the server",
        "Read server configuration and secrets from the app process",
    ],
    "local file inclusion": [
        "Read files from the server — source code, configuration, password files",
        "Chain with an upload or log poisoning to run code on the server",
        "Expose credentials that unlock other systems",
    ],
    "path traversal": [
        "Read files outside the web folder — source code, configuration, password files",
        "Download backups or data files never meant to be public",
        "Expose credentials that unlock other systems",
    ],
    "server-side request forgery": [
        "Make the server call internal systems only it can reach",
        "Read cloud metadata — temporary cloud credentials (169.254.169.254)",
        "Scan and map the internal network from the server's position",
        "Reach internal admin panels that trust the server's address",
    ],
    "prototype pollution": [
        "Change values the app trusts — prices, roles, admin flags — without logging in",
        "Turn a harmless page into stored script execution for every visitor",
        "Bypass security checks that read settings from merged objects",
        "In server-side cases, escalate to full remote code execution",
    ],
    "deserialization": [
        "Run code on the server by feeding it a crafted serialized object",
        "Read files and secrets from the server process",
        "Delete or change data the app trusts",
        "Take the server over completely in the worst case",
    ],
    "xml external entity": [
        "Read files from the server through crafted XML",
        "Make the server call internal systems (SSRF from inside)",
        "In some parsers, exhaust the server with entity-expansion (DoS)",
    ],
    "file upload": [
        "Upload a web shell and run commands on the server",
        "Host phishing pages or malware on the trusted domain",
        "Overwrite or replace existing files in some setups",
        "Bypass content checks by disguising the file type",
    ],
    "json web token": [
        "Forge a login token and sign in as any user — including admin",
        "Extend a session forever by editing the expiry",
        "Change own role/claims (e.g. user to admin) where verification is weak",
    ],
    "open redirect": [
        "Send victims a link on the real domain that lands on a fake site",
        "Power convincing phishing (the link starts on the trusted domain)",
        "Steal login tokens in OAuth flows that return through the redirect",
    ],
    "cross-origin": [
        "Read this site's data from another website in the victim's browser",
        "Call the API as the logged-in victim (with their session)",
        "Steal tokens or personal data returned by API responses",
    ],
    "cors": [
        "Read this site's data from another website in the victim's browser",
        "Call the API as the logged-in victim (with their session)",
        "Steal tokens or personal data returned by API responses",
    ],
    "csrf": [
        "Trick a logged-in user's browser into doing actions without their knowledge",
        "Change account settings, email or password from a malicious page",
        "Make purchases or transfers the user never intended",
    ],
    "cross-site request forgery": [
        "Trick a logged-in user's browser into doing actions without their knowledge",
        "Change account settings, email or password from a malicious page",
        "Make purchases or transfers the user never intended",
    ],
    "idor": [
        "View other users' data by changing a number in the address bar",
        "Change or delete other users' records the same way",
        "Walk through every record one by one (enumeration)",
    ],
    "bola": [
        "View other users' data by changing an object ID in the request",
        "Change or delete other users' records the same way",
        "Walk through every record one by one (enumeration)",
    ],
    "access control": [
        "Reach pages or functions meant for higher-privilege users",
        "Read or change data the account should never see",
        "Use hidden/admin endpoints that were only 'protected' by not linking them",
    ],
    "403": [
        "Reach a page the server tried to forbid, using an alternate spelling or header the rules miss",
        "Read content that was blocked by address rules but not by real login checks",
    ],
    "default credentials": [
        "Log in with the factory username/password anyone can look up",
        "Take over the admin panel if it is a privileged account",
        "Use the same password to try neighbouring systems",
    ],
    "graphql": [
        "Query data the interface never shows, using the public schema map",
        "Pull whole object lists (users, orders) through nested queries",
        "In some setups, change data through exposed mutations",
    ],
    "sensitive": [
        "Read information that was never meant to be public",
        "Harvest keys, tokens or internal addresses for the next attack step",
        "Learn internal structure (paths, versions, usernames) to aim attacks",
    ],
    "secret": [
        "Use the exposed credential exactly as its owner could",
        "Reach the connected service (cloud, database, email) with its rights",
        "Pivot to anything else that reuses the same secret",
    ],
    "api key": [
        "Call the API as the key's owner, possibly with billing or admin rights",
        "Read or change the data the key can reach",
    ],
    "header": [
        "Missing browser protections make other attacks easier (clickjacking, script injection, sniffing)",
        "Frame the site inside a fake page and trick clicks (when frame protection is missing)",
        "Downgrade or expose traffic on first visit (when HSTS is missing)",
    ],
    "clickjacking": [
        "Hide the real page under a fake one and trick users into clicking real buttons",
        "Make a logged-in user perform actions (settings changes, approvals) unknowingly",
    ],
    "cookie": [
        "Steal the session cookie more easily (script access or plain-HTTP sniffing)",
        "Replay the cookie to hijack the logged-in session",
    ],
    "session": [
        "Hijack or predict a user's session and act as them",
        "Stay logged in as the victim after they believe they logged out (fixation/weak expiry)",
    ],
    "cache poisoning": [
        "Store a malicious response in the shared cache so every visitor gets it",
        "Deface pages or inject scripts for all users of the cached URL",
    ],
    "cache deception": [
        "Trick the cache into storing a logged-in user's private page",
        "Read that cached private page without any login",
    ],
    "rate limit": [
        "Guess passwords, OTPs or codes millions of times with nothing slowing it down",
        "Enumerate valid usernames/accounts at full speed",
    ],
    "no rate": [
        "Guess passwords, OTPs or codes millions of times with nothing slowing it down",
        "Enumerate valid usernames/accounts at full speed",
    ],
    "brute": [
        "Guess passwords, OTPs or codes with automated attempts",
        "Spray common passwords across many accounts",
    ],
    "tls": [
        "Intercept or read traffic when users ignore certificate warnings",
        "Impersonate the site with a look-alike certificate setup",
    ],
    "certificate": [
        "Intercept or read traffic when users ignore certificate warnings",
        "Impersonate the site with a look-alike certificate setup",
    ],
    "plain http": [
        "Read or alter traffic between the user and the site on open networks",
        "Steal login details or session cookies sent without encryption",
    ],
    "staging": [
        "Attack the weaker copy of the site — test/staging systems often have debug on and real data",
        "Find test accounts or default passwords that the live site removed",
        "Learn the application's internals from the less-protected copy",
    ],
    "development": [
        "Attack the weaker copy of the site — dev/test systems often have debug on and real data",
        "Find test accounts or default passwords that the live site removed",
    ],
    "directory listing": [
        "Browse the server's folders like a file manager",
        "Find backups, logs, configs and uploads that were never linked",
    ],
    "source map": [
        "Rebuild the site's original source code from the published map",
        "Find hidden endpoints, comments and logic to aim further attacks",
    ],
    "stack trace": [
        "Learn the framework, file paths and library versions from error pages",
        "Use exposed internals to pick a known exploit for that exact version",
    ],
    "debug": [
        "Read diagnostic pages that expose configuration, sessions or internal state",
        "Use debug functions that were never meant to be reachable in production",
    ],
    "websocket": [
        "Connect without proper login checks and read or send messages as another user",
        "Inject messages into live sessions (chat, trading, notifications)",
    ],
    "smuggling": [
        "Slip a hidden request past the front server into another user's response",
        "Poison queues/caches, steal other users' requests and credentials",
        "Bypass front-end access rules by desyncing the two servers",
    ],
    "host header": [
        "Poison password-reset emails so the reset link points to the attacker's site",
        "Poison the cache with pages carrying the attacker's host",
        "Reach internal virtual hosts that share the same server",
    ],
    "takeover": [
        "Claim the abandoned external service and serve content on this subdomain",
        "Phish or steal cookies under the trusted subdomain",
    ],
    "private ip": [
        "Map the internal network's addressing from public DNS",
        "Aim SSRF and internal attacks at the real private ranges",
    ],
    "spf": [
        "Send email that passes as this domain when SPF/DMARC is missing or weak",
        "Run phishing and invoice-fraud campaigns under the trusted domain",
    ],
    "dmarc": [
        "Send email that passes as this domain when DMARC is missing or weak",
        "Run phishing and invoice-fraud campaigns under the trusted domain",
    ],
    "email": [
        "Send email that passes as this domain when authentication records are weak",
        "Run phishing campaigns under the trusted domain",
    ],
    "password": [
        "Get into accounts protected by a weak or exposed password path",
        "Reset or recover accounts that should not be reachable",
    ],
    "login": [
        "Attack the sign-in flow — guessing, bypass or session tricks",
        "Enumerate which usernames/emails are registered from differing responses",
    ],
    "enumeration": [
        "Build a list of valid accounts/IDs for targeted attacks",
        "Feed the list into password spraying or phishing",
    ],
    "disclosure": [
        "Read information that helps plan the next attack (versions, paths, users)",
        "Harvest exposed data directly where the disclosure includes records or keys",
    ],
    "exposed": [
        "Reach something that was meant to be internal or restricted",
        "Use the exposed service/data as the foothold for the next step",
    ],
    "backup": [
        "Download the backup and read everything in it offline",
        "Recover credentials, source code or database dumps from old copies",
    ],
    ".git": [
        "Rebuild the full source code from the exposed repository data",
        "Find secrets, credentials and history committed by mistake",
    ],
    "git": [
        "Rebuild the full source code from the exposed repository data",
        "Find secrets, credentials and history committed by mistake",
    ],
}

ATTACKS_BY_CWE = {
    "CWE-89": "sql injection", "CWE-79": "cross-site scripting",
    "CWE-78": "command injection", "CWE-918": "server-side request forgery",
    "CWE-22": "path traversal", "CWE-601": "open redirect",
    "CWE-352": "csrf", "CWE-639": "idor", "CWE-862": "access control",
    "CWE-863": "access control", "CWE-434": "file upload",
    "CWE-611": "xml external entity", "CWE-347": "json web token",
    "CWE-798": "default credentials", "CWE-942": "cross-origin",
    "CWE-1004": "cookie", "CWE-614": "cookie",
    "CWE-770": "rate limit", "CWE-307": "brute",
    "CWE-295": "tls", "CWE-319": "plain http",
    "CWE-200": "sensitive", "CWE-209": "stack trace",
    "CWE-215": "sensitive", "CWE-359": "sensitive",
    "CWE-538": "sensitive", "CWE-548": "directory listing",
    "CWE-693": "header", "CWE-1021": "clickjacking",
    "CWE-113": "header", "CWE-524": "cache deception",
    "CWE-444": "smuggling", "CWE-16": "header",
    "CWE-1321": "prototype pollution", "CWE-502": "deserialization",
}


def attacks_for(finding):
    """Plain 'what attacks can be performed' bullets for a finding."""
    low = (finding.get("title") or "").lower()
    for key, lines in ATTACKS.items():
        if key in low:
            return list(lines)
    key = ATTACKS_BY_CWE.get((finding.get("cwe") or "").upper())
    if key:
        return list(ATTACKS[key])
    return []


SEV_ORDER = {s: i for i, s in enumerate(
    ("Critical", "High", "Medium", "Low", "Info"))}


def group_findings(findings):
    """Root-cause grouping: one issue, many instances."""
    groups = {}
    for f in findings:
        g = groups.setdefault(f["title"], {
            "title": f["title"], "severity": f["severity"],
            "cwe": f.get("cwe", ""), "count": 0, "urls": [], "params": []})
        g["count"] += 1
        if f["url"] not in g["urls"]:
            g["urls"].append(f["url"])
        if f.get("param") and f["param"] not in g["params"]:
            g["params"].append(f["param"])
    out = sorted(groups.values(),
                 key=lambda g: (SEV_ORDER.get(g["severity"], 9), -g["count"]))
    for g in out:
        g["urls"] = g["urls"][:12]
    return out


def risk_score(findings):
    score = min(100, sum(WEIGHTS.get(f["severity"], 0) for f in findings))
    grade = ("Critical risk" if score >= 70 else
             "High risk" if score >= 45 else
             "Moderate risk" if score >= 25 else
             "Low risk" if score >= 8 else "Minimal risk")
    return score, grade


def executive_summary(result):
    counts = result.get("counts", {})
    score, grade = risk_score(result.get("findings", []))
    lines = [
        f"Target: {result.get('target')}",
        f"Overall risk score: {score}/100 ({grade})",
        f"Findings: {len(result.get('findings', []))} total — "
        + ", ".join(f"{k}: {v}" for k, v in counts.items() if v),
        "",
        "What matters most (in plain language):",
    ]
    top = sorted(result.get("findings", []),
                 key=lambda f: -WEIGHTS.get(f["severity"], 0))[:5]
    for i, f in enumerate(top, 1):
        lines.append(f"{i}. [{f['severity']}] {f['title']} — {explain(f['title'])}")
    if result.get("recon", {}).get("fingerprint"):
        fp = result["recon"]["fingerprint"]
        if fp.get("tech"):
            lines.append("")
            lines.append("Technology seen: " + ", ".join(fp["tech"][:10]))
    return "\n".join(lines)


def to_csv(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "confidence", "title", "cwe", "url", "parameter",
                "detail", "proof", "remediation", "payload"])
    for f in findings:
        w.writerow([f["severity"], f["confidence"], f["title"], f.get("cwe", ""),
                    f["url"], f.get("param", ""), f["detail"], f.get("proof", ""),
                    f["remediation"], f.get("payload", "")])
    return buf.getvalue()


# ---------------------------------------------------------------- mini PDF

def _pdf_escape(s):
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)
    return (s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
             .encode("latin-1", errors="replace").decode("latin-1"))


def _wrap(text, width=96):
    out = []
    for para in str(text).split("\n"):
        line = ""
        for word in para.split():
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        out.append(line)
    return out


def to_pdf(result):
    """Minimal valid PDF: summary page + one block per finding."""
    lines = ["Reconix 3.28 - Vulnerability Report", ""]
    lines += _wrap(executive_summary(result))
    lines += ["", "=" * 90, ""]
    for f in result.get("findings", []):
        lines.append(f"[{f['severity']}] {f['title']}  ({f.get('cwe','')})")
        lines.append(f"URL: {f['url']}")
        if f.get("param"):
            lines.append(f"Parameter: {f['param']}")
        if f.get("payload"):
            lines += _wrap(f"Payload: {f['payload']}")
        lines += _wrap(f"Detail: {f['detail']}")
        _atk = attacks_for(f)
        if _atk:
            lines.append("What attacks can be performed:")
            lines += _wrap("; ".join(_atk))
        if f.get("proof"):
            lines += _wrap(f"Proof: {f['proof']}")
        lines += _wrap(f"Remediation: {f['remediation']}")
        lines.append("")
    mx = result.get("permission_matrix") or []
    if mx:
        lines += ["", "Permission matrix (who can see what)", ""]
        for row in mx:
            parts = []
            for label, v in (row.get("results") or {}).items():
                parts.append(f"{label}: {v.get('status', '—')} "
                             f"({v.get('length', 0)} B)")
            lines += _wrap(f"{row.get('url', '')} | " + " | ".join(parts))
        lines.append("")
    # paginate: 52 lines/page
    pages = [lines[i:i + 52] for i in range(0, len(lines), 52)] or [["(empty)"]]
    objects = []
    # 1: catalog, 2: pages, 3: font
    content_ids = []
    objs = {}
    next_id = 4
    page_ids = []
    for page_lines in pages:
        cid = next_id; next_id += 1
        pid = next_id; next_id += 1
        content_ids.append(cid)
        page_ids.append(pid)
        stream = ["BT", "/F1 10 Tf", "14 TL", "50 780 Td"]
        for ln in page_lines:
            stream.append(f"({_pdf_escape(ln)}) Tj")
            stream.append("T*")
        stream.append("ET")
        data = "\n".join(stream).encode("latin-1", errors="replace")
        objs[cid] = b"<< /Length " + str(len(data)).encode() + b" >>\nstream\n" \
            + data + b"\nendstream"
        objs[pid] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                     f"/Contents {cid} 0 R /Resources << /Font << /F1 3 0 R >> "
                     f">> >>").encode()
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{p} 0 R" for p in page_ids)
    objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    objs[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for oid in sorted(objs):
        offsets[oid] = len(out)
        out += f"{oid} 0 obj\n".encode() + objs[oid] + b"\nendobj\n"
    xref_at = len(out)
    max_id = max(objs)
    out += f"xref\n0 {max_id + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for oid in range(1, max_id + 1):
        out += f"{offsets[oid]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF").encode()
    return bytes(out)
