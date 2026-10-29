"""External reconnaissance / EASM engine.

Discovers an organization's internet-facing attack surface before scanning:
subdomains (CT logs + multiple passive sources + DNS brute force +
permutations), full DNS intelligence (SPF/DKIM/DMARC/DNSSEC), IP/ASN
intelligence, certificate intelligence, subdomain-takeover candidates,
cloud-asset references, email patterns, exposed services, and a
risk-prioritised asset inventory with cross-scan change tracking.

DNS is resolved via DNS-over-HTTPS (no extra dependencies, works where
UDP/53 is filtered). All sources degrade gracefully when unreachable.
"""
import base64
import http.client
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

UA = {"User-Agent": "Reconix/3.28 (authorized external recon)"}
DOH_ENDPOINTS = ["https://dns.google/resolve",
                 "https://cloudflare-dns.com/dns-query"]
MULTI_SUFFIX = {"co.uk", "org.uk", "com.au", "net.au", "co.in", "firm.in",
                "com.br", "com.cn", "com.tw", "co.jp", "co.kr", "com.mx",
                "co.za", "com.sg", "com.hk", "co.nz", "com.ar", "gov.in",
                "ac.in", "edu.in", "res.in", "gen.in", "ind.in", "net.in",
                "org.in", "com.co", "com.pl", "com.tr", "com.my", "com.ph"}
BRUTE_WORDS = [
    "www", "mail", "webmail", "ftp", "admin", "administrator", "portal",
    "api", "api2", "app", "apps", "dev", "development", "stage", "staging",
    "test", "testing", "qa", "uat", "demo", "beta", "alpha", "prod",
    "production", "old", "new", "backup", "bak", "db", "database", "sql",
    "mysql", "vpn", "remote", "citrix", "gateway", "proxy", "firewall",
    "ns", "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap", "exchange",
    "owa", "autodiscover", "lyncdiscover", "sip", "blog", "shop", "store",
    "support", "help", "helpdesk", "docs", "wiki", "intranet", "internal",
    "corp", "extranet", "partner", "partners", "vendor", "secure", "ssl",
    "login", "auth", "sso", "id", "accounts", "account", "my", "dashboard",
    "panel", "cpanel", "whm", "jenkins", "git", "gitlab", "bitbucket",
    "jira", "confluence", "ci", "build", "deploy", "docker", "k8s",
    "monitor", "status", "metrics", "grafana", "cdn", "static", "assets",
    "media", "images", "img", "files", "download", "upload", "cloud",
    "s3", "storage", "backup1", "server", "server1", "web", "web1", "host",
    "in", "us", "eu", "asia", "india", "uk", "de", "fr", "mobile", "m",
    "crm", "erp", "hr", "payroll", "mail1", "mail2", "relay", "edge",
    "origin", "direct", "backend", "frontend", "sandbox", "playground",
]
ENV_WORDS = ("dev", "stage", "staging", "test", "qa", "uat", "demo",
             "beta", "sandbox", "internal", "intranet", "admin", "backup",
             "old", "temp", "tmp", "private")
TAKEOVER_CNAME = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("herokudns.com", "No such app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("amazonaws.com", "NoSuchBucket"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.net", "404 Web Site not found"),
    ("netlify.app", "Not Found - Request ID"),
    ("vercel.app", "The deployment could not be found"),
    ("ghost.io", "The thing you were looking for is no longer here"),
    ("myshopify.com", "Sorry, this shop is currently unavailable"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("pantheonsite.io", "The gods are wise"),
    ("readme.io", "Project not found"),
    ("statuspage.io", "page not found"),
    ("zendesk.com", "Help Center closed"),
    ("unbouncepages.com", "The requested URL was not found"),
    ("wpengine.com", "not configured to serve traffic"),
    ("fastly.net", "Fastly error: unknown domain"),
]
CLOUD_PATTERNS = [
    (r"[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com", "AWS S3"),
    (r"[a-z0-9.\-]+\.storage\.googleapis\.com", "Google Cloud Storage"),
    (r"[a-z0-9.\-]+\.blob\.core\.windows\.net", "Azure Blob Storage"),
    (r"[a-z0-9.\-]+\.firebaseio\.com", "Firebase"),
    (r"[a-z0-9.\-]+\.appspot\.com", "Google App Engine"),
    (r"[a-z0-9.\-]+\.cloudfront\.net", "AWS CloudFront"),
    (r"[a-z0-9.\-]+\.digitaloceanspaces\.com", "DigitalOcean Spaces"),
    (r"[a-z0-9.\-]+\.azurewebsites\.net", "Azure App Service"),
    (r"[a-z0-9.\-]+\.herokuapp\.com", "Heroku"),
    (r"[a-z0-9.\-]+\.supabase\.co", "Supabase"),
]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1",
                  "s1", "mail", "dkim", "mandrill", "smtp", "amazonses"]
CDN_ORGS = ("cloudflare", "akamai", "fastly", "cloudfront", "amazon",
            "google", "incapsula", "imperva", "sucuri", "stackpath",
            "keycdn", "bunnycdn", "limelight", "edgio", "gcore")
PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|"
                        r"169\.254\.|::1|fe80:)")


# ---------------------------------------------------------------- DNS core

_doh_lock = threading.Lock()
_doh_idx = [0]

# Per-thread keep-alive DoH connections: a fresh TLS handshake per query
# made enumeration crawl (measured ~5 min for a 60-word brute stage).
# http.client connections are not thread-safe, hence thread-local storage.
_doh_local = threading.local()
_doh_down = {}            # endpoint -> monotonic deadline while backed off
_doh_down_lock = threading.Lock()


def _doh_conn(base):
    conns = getattr(_doh_local, "conns", None)
    if conns is None:
        conns = _doh_local.conns = {}
    conn = conns.get(base)
    if conn is None:
        u = urllib.parse.urlsplit(base)
        proxy = None
        try:
            proxies = urllib.request.getproxies()
            proxy = proxies.get("https") or proxies.get("http")
            if proxy and urllib.request.proxy_bypass(u.hostname):
                proxy = None
        except Exception:
            proxy = None
        if proxy:
            p = urllib.parse.urlsplit(
                proxy if "://" in proxy else "http://" + proxy)
            conn = http.client.HTTPSConnection(p.hostname, p.port or 8080,
                                               timeout=8)
            headers = {}
            if p.username:
                cred = base64.b64encode(
                    f"{urllib.parse.unquote(p.username)}:"
                    f"{urllib.parse.unquote(p.password or '')}".encode()
                ).decode()
                headers["Proxy-Authorization"] = f"Basic {cred}"
            conn.set_tunnel(u.hostname, u.port or 443, headers)
        else:
            conn = http.client.HTTPSConnection(u.hostname, u.port or 443,
                                               timeout=8)
        conns[base] = conn
    return conn


def _doh_drop(base):
    conns = getattr(_doh_local, "conns", None)
    if conns and base in conns:
        try:
            conns[base].close()
        except Exception:
            pass
        conns.pop(base, None)


def _doh_mark_down(base, secs=30):
    with _doh_down_lock:
        _doh_down[base] = time.monotonic() + secs


def _doh_is_down(base):
    with _doh_down_lock:
        return time.monotonic() < _doh_down.get(base, 0)


def dns_query(name, rtype):
    """Resolve via DNS-over-HTTPS. Returns (answers, ad_flag).

    Endpoints rotate per query; an endpoint that fails twice in a row is
    backed off for 30 s so a dead or slow resolver stops taxing every
    lookup. Connections are pooled per thread (keep-alive) — see _doh_conn.
    """
    n = len(DOH_ENDPOINTS)
    with _doh_lock:
        start = _doh_idx[0] % n
        _doh_idx[0] += 1
    order = [DOH_ENDPOINTS[(start + i) % n] for i in range(n)]
    order.sort(key=_doh_is_down)  # healthy endpoints first, down ones last
    for base in order:
        u = urllib.parse.urlsplit(base)
        path = f"{u.path}?name={urllib.parse.quote(name)}&type={rtype}"
        for attempt in range(2):
            try:
                conn = _doh_conn(base)
                conn.request("GET", path, headers={
                    **UA, "Accept": "application/dns-json"})
                resp = conn.getresponse()
                body = resp.read()
                if resp.status != 200:
                    raise OSError(f"DoH HTTP {resp.status}")
                data = json.loads(body.decode(errors="replace"))
                answers = [str(a.get("data", "")).strip().rstrip(".")
                           for a in data.get("Answer", [])]
                return answers, bool(data.get("AD"))
            except Exception:
                _doh_drop(base)
                if attempt == 1:
                    _doh_mark_down(base)
    return [], False


def resolve_host(name):
    a, _ = dns_query(name, "A")
    aaaa, _ = dns_query(name, "AAAA")
    return ([x for x in a if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)],
            [x for x in aaaa if ":" in x
             and re.match(r"^[0-9a-fA-F:]+$", x)])


def _belongs(name, domain):
    return name == domain or name.endswith("." + domain)


def root_domain(host):
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail2 = ".".join(labels[-2:])
    if tail2 in MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail2


def _is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return ":" in host


# ---------------------------------------------------------------- sources

def _http_text(url, timeout=12):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="replace")


def src_crtsh(domain, out):
    try:
        data = json.loads(_http_text(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20))
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if _belongs(name, domain):
                    out.add(name)
    except Exception as e:
        return f"src_crtsh: {e}"


def src_certspotter(domain, out):
    try:
        data = json.loads(_http_text(
            "https://api.certspotter.com/v1/issuances?domain="
            f"{domain}&include_subdomains=true&expand=dns_names",
            timeout=15))
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.lower().lstrip("*.")
                if _belongs(name, domain):
                    out.add(name)
    except Exception as e:
        return f"src_certspotter: {e}"


def src_hackertarget(domain, out):
    try:
        text = _http_text(
            f"https://api.hackertarget.com/hostsearch/?q={domain}")
        for line in text.splitlines():
            name = line.split(",")[0].strip().lower()
            if _belongs(name, domain):
                out.add(name)
    except Exception as e:
        return f"src_hackertarget: {e}"


def src_rapiddns(domain, out):
    try:
        text = _http_text(f"https://rapiddns.io/subdomain/{domain}",
                          timeout=15)
        for name in set(re.findall(
                r"([a-z0-9.\-]+\." + re.escape(domain) + r")",
                text.lower())):
            out.add(name.strip("."))
    except Exception as e:
        return f"src_rapiddns: {e}"


def src_urlscan(domain, out):
    try:
        data = json.loads(_http_text(
            "https://urlscan.io/api/v1/search/?q=domain:"
            f"{domain}&size=100", timeout=15))
        for res in data.get("results", []):
            for key in ("page", "task"):
                name = (res.get(key) or {}).get("domain", "")
                if name and _belongs(name.lower(), domain):
                    out.add(name.lower())
    except Exception as e:
        return f"src_urlscan: {e}"


PASSIVE_SOURCES = [src_crtsh, src_certspotter, src_hackertarget,
                   src_rapiddns, src_urlscan]


# ---------------------------------------------------------------- enum

def _resolve_or_none(name):
    a, aaaa = resolve_host(name)
    return (name, a, aaaa) if (a or aaaa) else None


def enumerate_subdomains(domain, emit, max_brute=140):
    """Returns (hosts:set, wildcard:bool)."""
    hosts = {domain}
    emit("ExtRecon: passive subdomain sources (CT logs, certspotter, "
         "hackertarget, rapiddns, urlscan)...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        src_errors = [e for e in ex.map(lambda fn: fn(domain, hosts),
                                         PASSIVE_SOURCES) if e]
    emit(f"ExtRecon: {len(hosts)} hostnames from passive sources.")
    if len(src_errors) == len(PASSIVE_SOURCES):
        emit("ExtRecon WARNING: ALL passive sources failed (no internet? "
             "rate-limited?) — results rest on DNS brute force only: "
             + "; ".join(src_errors))
    # wildcard detection
    import random as _r
    probe = f"wsx{_r.randint(100000, 999999)}-nonexistent.{domain}"
    probe_a, probe_aaaa = resolve_host(probe)
    wildcard = bool(probe_a or probe_aaaa)
    if wildcard:
        emit("ExtRecon: wildcard DNS detected — brute results will be "
             "filtered against the wildcard address set.")
        wild_ips = set(probe_a)
    else:
        wild_ips = set()
    words = BRUTE_WORDS[:max_brute]
    emit(f"ExtRecon: DNS brute force ({len(words)} words)...")
    found = {}
    names = [f"{w}.{domain}" for w in words]
    done = 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_resolve_or_none, nm) for nm in names]
        for fut in as_completed(futs):
            done += 1
            if done % 25 == 0 or done == len(names):
                emit(f"ExtRecon: DNS brute force {done}/{len(names)}...")
            res = fut.result()
            if res:
                name, a, aaaa = res
                if wildcard and a and set(a) <= wild_ips:
                    continue
                hosts.add(name)
                found[name] = (a, aaaa)
    # permutations / mutations of discovered names
    bases = [h for h in hosts if h != domain]
    candidates = set()
    envs = ["dev", "stage", "staging", "test", "qa", "uat", "prod", "api",
            "app", "admin", "beta", "new", "old", "v2", "v1"]
    for h in bases[:60]:
        first = h.split(".")[0]
        stem = re.sub(r"(dev|stage|staging|test|qa|uat|prod|beta|api|app|"
                      r"admin|new|old|v\d+)$", "", first).rstrip("-")
        for env in envs:
            if stem and stem != first:
                candidates.add(f"{stem}-{env}.{domain}")
                candidates.add(f"{stem}{env}.{domain}")
            candidates.add(f"{env}-{first}.{domain}")
            candidates.add(f"{first}-{env}.{domain}")
    candidates = {c for c in candidates if c not in hosts}
    if candidates:
        todo_list = sorted(candidates)[:250]
        emit(f"ExtRecon: resolving {len(todo_list)} permutations "
             f"(of {len(candidates)} generated)...")
        done = 0
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(_resolve_or_none, nm) for nm in todo_list]
            for fut in as_completed(futs):
                done += 1
                if done % 50 == 0 or done == len(todo_list):
                    emit(f"ExtRecon: permutations {done}/{len(todo_list)}...")
                res = fut.result()
                if res:
                    name, a, aaaa = res
                    if wildcard and a and set(a) <= wild_ips:
                        continue
                    hosts.add(name)
                    found[name] = (a, aaaa)
    # one recursive level: prefixes on discovered subdomain parents
    parents = sorted({h for h in hosts if h.count(".") >=
                      domain.count(".") + 1})[:15]
    rec_words = ["dev", "test", "api", "app", "admin", "internal", "vpn",
                 "mail", "web", "db", "stage"]
    rec_cands = {f"{w}.{p}" for p in parents for w in rec_words} - hosts
    if rec_cands:
        todo_list = sorted(rec_cands)
        emit(f"ExtRecon: resolving {len(todo_list)} recursive names...")
        done = 0
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(_resolve_or_none, nm) for nm in todo_list]
            for fut in as_completed(futs):
                done += 1
                if done % 50 == 0 or done == len(todo_list):
                    emit(f"ExtRecon: recursive {done}/{len(todo_list)}...")
                res = fut.result()
                if res:
                    hosts.add(res[0])
                    found[res[0]] = (res[1], res[2])
    emit(f"ExtRecon: {len(hosts)} total hostnames after enumeration.")
    return hosts, wildcard, found


# ---------------------------------------------------------------- DNS intel

def dns_intelligence(domain, F, emit):
    intel = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
        ans, _ad = dns_query(domain, rtype)
        intel[rtype] = ans
    # DNSSEC: DS/DNSKEY presence or AD flag
    ds, _ = dns_query(domain, "DS")
    dnskey, ad = dns_query(domain, "DNSKEY")
    intel["dnssec"] = bool(ds or dnskey or ad)
    intel["ptr"] = {}
    # SPF
    txts = intel.get("TXT", [])
    spf = next((t for t in txts if t.lower().startswith('"v=spf1')
                or t.lower().startswith("v=spf1")), "")
    spf = spf.strip('"')
    intel["spf"] = spf
    if not spf:
        F.add("Low", "Email Security: No SPF Record", f"dns://{domain}",
              "The domain publishes no SPF record — anyone can spoof "
              "email from this domain more easily.",
              proof=f"TXT records: {txts[:3]}", dedupe_key=("spf", "none"),
              cwe="CWE-290")
    elif spf.rstrip().endswith("+all"):
        F.add("Medium", "Email Security: SPF +all (allows anyone)", 
              f"dns://{domain}",
              "SPF ends with +all, authorising ANY server to send mail "
              "for this domain.", proof=spf, dedupe_key=("spf", "plusall"),
              cwe="CWE-290")
    elif spf.rstrip().endswith("?all"):
        F.add("Low", "Email Security: SPF neutral (?all)", f"dns://{domain}",
              "SPF ends with ?all (neutral) — weak sender policy.",
              proof=spf, dedupe_key=("spf", "neutral"), cwe="CWE-290")
    _mech = {t.split(":")[0].split("=")[0].lstrip("+-~?").lower()
             for t in spf.split()}
    if sum(1 for t in spf.split()
           if t.split(":")[0].split("=")[0].lstrip("+-~?").lower()
           in ("include", "a", "mx", "ptr", "exists", "redirect")) > 10:
        F.add("Info", "SPF May Exceed 10-Lookup Limit", f"dns://{domain}",
              "More than 10 DNS-lookup mechanisms can make SPF fail "
              "(permerror).", proof=spf, dedupe_key=("spf", "lookups"))
    # DMARC
    dmarc_ans, _ = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = next((t.strip('"') for t in dmarc_ans
                  if "v=dmarc1" in t.lower()), "")
    intel["dmarc"] = dmarc
    if not dmarc:
        F.add("Medium", "Email Security: No DMARC Record", f"dns://{domain}",
              "No DMARC policy at _dmarc — spoofed mail from this domain "
              "faces no handling policy, and the org gets no reports.",
              dedupe_key=("dmarc", "none"), cwe="CWE-290")
    elif "p=none" in dmarc.replace(" ", ""):
        F.add("Low", "Email Security: DMARC in Monitor-Only Mode (p=none)",
              f"dns://{domain}",
              "DMARC exists but p=none — spoofed mail is still delivered.",
              proof=dmarc, dedupe_key=("dmarc", "pnone"), cwe="CWE-290")
    # DKIM selectors (an empty p= means a REVOKED key — not active DKIM)
    found_dkim, revoked_dkim = [], []
    for sel in DKIM_SELECTORS:
        ans, _ = dns_query(f"{sel}._domainkey.{domain}", "TXT")
        for a in ans:
            low = a.lower()
            if "v=dkim1" in low or "p=" in low:
                m = re.search(r"p=\s*([A-Za-z0-9+/=]+)", a)
                if m and len(m.group(1)) > 12:
                    found_dkim.append(sel)
                else:
                    revoked_dkim.append(sel)
                break
    intel["dkim_selectors"] = found_dkim
    intel["dkim_revoked_selectors"] = revoked_dkim
    return intel


def takeover_and_dangling(F, client, assets):
    """assets: {host: {"cname": str}} — mutate with findings."""
    for host, data in assets.items():
        cname = (data.get("cname") or "").lower()
        if not cname:
            continue
        target_ips, _ = resolve_host(cname)
        if not target_ips:
            F.add("Medium", "Dangling DNS Record (possible takeover)",
                  f"dns://{host}",
                  f"{host} is a CNAME to {cname}, which no longer resolves. "
                  "If the underlying service can be re-registered, this "
                  "subdomain can be taken over.",
                  proof=f"CNAME {host} -> {cname} (NXDOMAIN/unresolvable)",
                  dedupe_key=("dangling", host), cwe="CWE-350")
            data["dangling"] = True
            continue
        for suffix, fingerprint in TAKEOVER_CNAME:
            if cname.endswith(suffix):
                r = client.fetch(f"http://{host}/")
                body = r.body or ""
                if fingerprint.lower() in body.lower():
                    F.add("High", "Subdomain Takeover Candidate",
                          f"http://{host}/",
                          f"{host} points to {suffix} ({cname}) and the "
                          f"service responds with its unclaimed fingerprint "
                          f"('{fingerprint[:40]}...'). An attacker may be "
                          "able to claim this subdomain.",
                          proof=f"CNAME -> {cname}; service fingerprint "
                                f"matched",
                          resp=r, dedupe_key=("takeover", host),
                          cwe="CWE-350")
                    data["takeover_candidate"] = True
                elif r.status == 404:
                    # a bare 404 is NOT proof of claimability — a claimed
                    # service can 404 its root. Report as unverified.
                    F.add("Low", "Possible Subdomain Takeover (unverified)",
                          f"http://{host}/",
                          f"{host} points to {suffix} ({cname}) and the root "
                          "returns 404 without the provider's unclaimed "
                          "fingerprint. Verify claimability manually before "
                          "reporting.",
                          proof=f"CNAME -> {cname}; HTTP 404, no fingerprint",
                          resp=r, dedupe_key=("takeover404", host),
                          confidence="Needs manual confirmation",
                          cwe="CWE-350")
                    data["takeover_unverified"] = True
                break


# ---------------------------------------------------------------- IP intel

def ip_intelligence(ips, emit):
    """Batch ASN/org/geo via ip-api (free, no key). Returns {ip: info}."""
    out = {}
    ips = [i for i in dict.fromkeys(ips) if not PRIVATE_IP.match(i)]
    for i in range(0, len(ips), 90):
        batch = ips[i:i + 90]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,query,country,city,"
                "isp,org,as,hosting,proxy",
                data=json.dumps(batch).encode(),
                headers={**UA, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                for item in json.loads(r.read().decode(errors="replace")):
                    if item.get("status") == "success":
                        out[item["query"]] = {
                            "country": item.get("country", ""),
                            "city": item.get("city", ""),
                            "isp": item.get("isp", ""),
                            "org": item.get("org", ""),
                            "asn": item.get("as", ""),
                            "hosting": bool(item.get("hosting")),
                        }
        except Exception:
            # per-IP fallback
            for ip in batch:
                try:
                    data = json.loads(_http_text(
                        f"https://ipwho.is/{ip}", timeout=8))
                    conn = data.get("connection") or {}
                    out[ip] = {"country": data.get("country", ""),
                               "city": data.get("city", ""),
                               "isp": conn.get("isp", ""),
                               "org": conn.get("org", ""),
                               "asn": f"AS{conn.get('asn', '')}",
                               "hosting": False}
                except Exception:
                    pass
    return out


def ptr_lookup(ip):
    ans, _ = dns_query(
        ".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR")
    return ans[0] if ans else ""


# ---------------------------------------------------------------- certs

def certificate_intelligence(domain, F, hosts):
    """CT-log certificate collection + TLS posture per key host."""
    certs = []
    seen_serials = {}
    for src_url in (
            f"https://crt.sh/?q=%25.{domain}&output=json",):
        try:
            data = json.loads(_http_text(src_url, timeout=20))
        except Exception:
            data = []
        for entry in data[:800]:
            serial = entry.get("serial_number", "")
            sans = [n.strip().lower().lstrip("*.")
                    for n in entry.get("name_value", "").split("\n")]
            cert = {"issuer": entry.get("issuer_name", "")[:80],
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "serial": serial, "sans": sans[:12]}
            certs.append(cert)
            seen_serials.setdefault(serial, set()).update(
                s for s in sans if s in hosts)
    certs.sort(key=lambda c: c.get("not_after", ""), reverse=True)
    now = datetime.now(timezone.utc)
    for cert in certs[:300]:
        try:
            exp = datetime.fromisoformat(
                cert["not_after"].replace("Z", "+00:00"))
        except Exception:
            continue
        days = (exp - now).days
        cert["days_left"] = days
        label = cert["sans"][0] if cert["sans"] else domain
        if days < 0:
            F.add("High", "Expired Certificate in CT Logs",
                  f"dns://{domain}",
                  f"A certificate for {label} expired {-days} day(s) ago "
                  f"(issuer {cert['issuer']}). If still deployed, browsers "
                  "will warn or block.",
                  proof=f"not_after={cert['not_after']} serial={cert['serial'][:16]}",
                  dedupe_key=("cert-exp", cert["serial"]), cwe="CWE-295")
        elif days < 30:
            F.add("Low", "Certificate Expiring Soon (CT)",
                  f"dns://{domain}",
                  f"Certificate for {label} expires in {days} day(s).",
                  proof=f"not_after={cert['not_after']}",
                  dedupe_key=("cert-soon", cert["serial"]), cwe="CWE-295")
    reused = {s: hs for s, hs in seen_serials.items() if len(hs) > 1}
    return {"certificates": certs[:100], "unique_serials": len(seen_serials),
            "reused_across_hosts": {k: sorted(v) for k, v in
                                    list(reused.items())[:10]}}


def tls_posture(host):
    """Negotiated protocol + legacy-protocol acceptance for one host."""
    import ssl as _ssl
    out = {}
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["protocol"] = s.version()
                out["cipher"] = s.cipher()[0] if s.cipher() else ""
    except Exception as e:
        out["error"] = str(e)[:80]
        return out
    # legacy protocol acceptance
    for name, version in (("TLSv1.1", _ssl.TLSVersion.TLSv1_1),
                          ("TLSv1.0", _ssl.TLSVersion.TLSv1)):
        try:
            c2 = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            c2.check_hostname = False
            c2.verify_mode = _ssl.CERT_NONE
            c2.minimum_version = version
            c2.maximum_version = version
            with socket.create_connection((host, 443), timeout=5) as raw:
                with c2.wrap_socket(raw, server_hostname=host):
                    out[f"accepts_{name}"] = True
        except Exception:
            out[f"accepts_{name}"] = False
    return out


# ---------------------------------------------------------------- cloud/email

def cloud_and_email_harvest(pages):
    """pages: [(url, body)] — cloud endpoints + public emails."""
    clouds, emails = {}, {}
    for url, body in pages:
        text = body or ""
        for pat, kind in CLOUD_PATTERNS:
            for m in re.findall(pat, text):
                clouds.setdefault(m, {"kind": kind, "found_on": url})
        for m in re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
            if not m.lower().endswith((".png", ".jpg", ".gif")):
                emails[m.lower()] = url
    patterns = set()
    for e in emails:
        local, _, dom = e.partition("@")
        if "." in local:
            patterns.add(f"first.last@{dom}")
        elif len(local) > 3:
            patterns.add(f"firstname@{dom}")
    return ({"cloud_assets": [{"endpoint": k, **v} for k, v in
                              sorted(clouds.items())],
             "emails": [{"email": k, "found_on": v} for k, v in
                        sorted(emails.items())[:50]],
             "email_patterns": sorted(patterns)})


def check_cloud_exposure(F, client, cloud_assets):
    for asset in cloud_assets[:8]:
        ep = asset["endpoint"]
        if "s3" in asset["kind"].lower() or "storage" in asset["kind"]:
            r = client.fetch(f"https://{ep}/")
            if r.status == 200 and ("ListBucketResult" in (r.body or "")
                                    or "<Contents>" in (r.body or "")):
                F.add("High", "Public Cloud Storage Listing",
                      f"https://{ep}/",
                      "The cloud storage endpoint allows anonymous listing "
                      "of its contents.",
                      proof=(r.body or "")[:160], resp=r,
                      dedupe_key=("bucket", ep), cwe="CWE-200")
                asset["public_listing"] = True
            elif r.status == 200:
                asset["public_read_root"] = True


# ---------------------------------------------------------------- inventory

def _asset_risk(asset, findings_by_host):
    score = 0
    for f in findings_by_host.get(asset["host"], []):
        score += {"Critical": 40, "High": 25, "Medium": 12, "Low": 5,
                  "Info": 1}.get(f, 0)
    labels = asset["host"].split(".")[0]
    if any(w in labels for w in ENV_WORDS):
        score += 10
    if asset.get("takeover_candidate") or asset.get("dangling"):
        score += 30
    if any(p in (21, 22, 3306, 5432, 6379, 9200, 27017, 3389)
           for p in asset.get("ports", [])):
        score += 15
    return min(100, score)


def build_inventory(domain, hosts, resolved, ipinfo, fingerprints, F_items,
                    state):
    findings_by_host = {}
    for f in F_items:
        url = f.get("url", "")
        host = urllib.parse.urlsplit(url).hostname or ""
        findings_by_host.setdefault(host, []).append(f["severity"])
    assets = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    prev_assets = (state.get("domains", {}).get(domain, {})
                   .get("assets", {}))
    for host in sorted(hosts):
        ips, aaaa = resolved.get(host, ([], []))
        orgs, asns, countries = set(), set(), set()
        cdn = False
        provider = ""
        for ip in ips:
            info = ipinfo.get(ip, {})
            if info.get("org"):
                orgs.add(info["org"])
            if info.get("asn"):
                asns.add(info["asn"])
            if info.get("country"):
                countries.add(info["country"])
            hay = (info.get("org", "") + " " + info.get("isp", "")).lower()
            if any(c in hay for c in CDN_ORGS):
                cdn = True
            if "amazon" in hay:
                provider = "AWS"
            elif "google" in hay:
                provider = "Google Cloud"
            elif "microsoft" in hay or "azure" in hay:
                provider = "Azure"
            elif "cloudflare" in hay:
                provider = "Cloudflare"
            elif "digitalocean" in hay:
                provider = "DigitalOcean"
        prev = prev_assets.get(host, {})
        asset = {
            "host": host, "ips": ips, "ipv6": aaaa,
            "org": sorted(orgs), "asn": sorted(asns),
            "country": sorted(countries), "cdn": cdn,
            "cloud_provider": provider,
            "ports": prev.get("ports", []),
            "tech": fingerprints.get(host, []),
            "first_seen": prev.get("first_seen", now),
            "last_seen": now,
            "is_new": host not in prev_assets,
            "env": next((w for w in ENV_WORDS
                         if host.split(".")[0].endswith(w)
                         or host.split(".")[0] == w), ""),
        }
        asset["risk"] = _asset_risk(asset, findings_by_host)
        assets.append(asset)
    return assets


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"domains": {}}


def save_state(path, state):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
    except Exception:
        pass


def diff_inventory(state, domain, assets, ipinfo):
    """Compare against stored snapshot; returns change summary + updates
    state in place."""
    dom_state = state.setdefault("domains", {}).setdefault(domain, {})
    prev = dom_state.get("assets", {})
    cur = {a["host"]: a for a in assets}
    changes = {
        "new_assets": sorted(set(cur) - set(prev)),
        "removed_assets": sorted(set(prev) - set(cur)),
        "new_ports": {},
        "ip_changes": {},
        "provider_changes": {},
    }
    for host, a in cur.items():
        if host in prev:
            new_ports = sorted(set(a.get("ports", []))
                               - set(prev[host].get("ports", [])))
            if new_ports:
                changes["new_ports"][host] = new_ports
            if set(a.get("ips", [])) != set(prev[host].get("ips", [])):
                changes["ip_changes"][host] = {
                    "from": prev[host].get("ips", []), "to": a.get("ips", [])}
            if a.get("org") != prev[host].get("org"):
                changes["provider_changes"][host] = {
                    "from": prev[host].get("org", []), "to": a.get("org", [])}
    dom_state["assets"] = cur
    dom_state["last_run"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")
    return changes


# ---------------------------------------------------------------- main

EXPOSURE_PROBES = [
    ("/actuator", "Status/metrics endpoint"), ("/actuator/env", "Actuator env"),
    ("/metrics", "Metrics page"), ("/server-status", "Apache server-status"),
    ("/swagger-ui.html", "API documentation"), ("/swagger-ui/", "API documentation"),
    ("/api-docs", "API documentation"), ("/graphql", "GraphQL endpoint"),
    ("/graphiql", "GraphQL IDE"), ("/phpmyadmin/", "phpMyAdmin"),
    ("/adminer.php", "Adminer"), ("/_debug", "Debug endpoint"),
    ("/debug", "Debug endpoint"), ("/elmah.axd", "ELMAH logs"),
    ("/telescope", "Laravel Telescope"), ("/horizon", "Laravel Horizon"),
    ("/wp-admin/", "WordPress admin"), ("/administrator/", "Joomla admin"),
    ("/user/login", "Login page"), ("/login", "Login page"),
    ("/admin", "Admin panel"), ("/console", "Console"),
    ("/jenkins", "Jenkins"), ("/sonarqube", "SonarQube"),
]


def run_extrecon(ctx, target, opts=None):
    """Entry point. Returns the extrecon result dict; emits findings."""
    opts = opts or {}
    F, client = ctx.findings, ctx.client
    emit = ctx.emit
    parts = urllib.parse.urlsplit(target)
    host = (parts.hostname or "").lower()
    result = {"target": target, "host": host}
    if _is_ip(host) or host in ("localhost",) or "." not in host:
        emit("ExtRecon: target is an IP/localhost — external recon applies "
             "to domains; running DNS/TLS basics only.")
        result["skipped"] = "ip-or-localhost"
        result["assets"] = []
        return result
    domain = root_domain(host)
    result["root_domain"] = domain
    emit(f"ExtRecon: root domain {domain}")
    hosts, wildcard, resolved = enumerate_subdomains(
        domain, emit, max_brute=int(opts.get("extrecon_brute", 140)))
    result["wildcard_dns"] = wildcard
    # resolve everything found by passive sources too (cap for sanity)
    unresolved = [h for h in hosts if h not in resolved][:400]
    if unresolved:
        emit(f"ExtRecon: resolving {len(unresolved)} discovered "
             "hostnames...")
        done = 0
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(_resolve_or_none, nm) for nm in unresolved]
            for fut in as_completed(futs):
                done += 1
                if done % 50 == 0 or done == len(unresolved):
                    emit(f"ExtRecon: host resolution {done}/"
                         f"{len(unresolved)}...")
                res = fut.result()
                if res:
                    resolved[res[0]] = (res[1], res[2])
    live_hosts = {h: v for h, v in resolved.items() if v[0] or v[1]}
    result["hosts_found"] = len(hosts)
    result["hosts_live"] = len(live_hosts)
    # CNAMEs for takeover/dangling analysis
    assets_dns = {}
    for h in list(live_hosts)[:150]:
        cname, _ = dns_query(h, "CNAME")
        assets_dns[h] = {"cname": cname[0] if cname else "",
                         "ips": live_hosts[h][0]}
        # internal exposure: public DNS -> private IP
        priv = [ip for ip in live_hosts[h][0] if PRIVATE_IP.match(ip)]
        if priv:
            F.add("Medium", "Public DNS Resolves to Private IP",
                  f"dns://{h}",
                  f"{h} resolves to private address(es) {priv} in PUBLIC "
                  "DNS — internal addressing is disclosed and may aid "
                  "SSRF/intranet mapping.",
                  proof=f"{h} A: {', '.join(priv)}",
                  dedupe_key=("privip", h), cwe="CWE-200")
    takeover_and_dangling(F, client, assets_dns)
    result["dns"] = dns_intelligence(domain, F, emit)
    emit("ExtRecon: DNS intelligence done (records, SPF/DMARC/DKIM/DNSSEC).")
    # reverse DNS for root IPs
    root_ips = live_hosts.get(domain, ([], []))[0]
    result["dns"]["ptr"] = {ip: ptr_lookup(ip) for ip in root_ips[:4]}
    # IP intelligence
    all_ips = sorted({ip for ips, _ in live_hosts.values() for ip in ips})
    emit(f"ExtRecon: IP intelligence for {len(all_ips)} addresses...")
    ipinfo = ip_intelligence(all_ips, emit)
    result["ip_intel"] = ipinfo
    # certificates
    emit("ExtRecon: certificate intelligence (CT logs)...")
    result["certificates"] = certificate_intelligence(domain, F, hosts)
    # TLS posture + tech fingerprint for the main host (+www)
    from .recon import fingerprint, port_scan
    result["tls"] = {}
    for h in dict.fromkeys([host, f"www.{domain}", domain]):
        if h in live_hosts or h == host:
            result["tls"][h] = tls_posture(h)
            if result["tls"][h].get("accepts_TLSv1.0") or \
                    result["tls"][h].get("accepts_TLSv1.1"):
                F.add("Medium", "Weak TLS: Legacy Protocol Accepted",
                      f"https://{h}/",
                      f"{h} accepts "
                      f"{'TLS 1.0 ' if result['tls'][h].get('accepts_TLSv1.0') else ''}"
                      f"{'TLS 1.1' if result['tls'][h].get('accepts_TLSv1.1') else ''}"
                      " — deprecated protocols weaken transport security.",
                      proof=str(result["tls"][h]), resp=None,
                      dedupe_key=("tlslegacy", h), cwe="CWE-327")
    fingerprints = {}
    base_resp = client.fetch(target)
    if base_resp.status:
        fp = fingerprint(base_resp, [(target, base_resp)])
        fingerprints[host] = fp["tech"]
        result["fingerprint"] = fp
    # port scan: root host + up to 6 non-CDN subdomains
    emit("ExtRecon: port scan (authorized, top ports) on key assets...")
    scanned = {}
    scan_targets = [domain] + [h for h in list(live_hosts)[:40]
                               if not any(w in h for w in
                                          ("mail", "ns", "ftp"))][:6]
    for h in dict.fromkeys(scan_targets):
        ports = port_scan(h)
        scanned[h] = [p["port"] for p in ports]
    result["port_scan"] = scanned
    # exposure probes on the main target
    emit("ExtRecon: web exposure discovery (admin/API/docs/status)...")
    exposed = []
    root = f"{parts.scheme}://{parts.netloc}"
    for path, label in EXPOSURE_PROBES:
        r = client.fetch(root + path)
        if r.status in (200, 401, 403):
            exposed.append({"url": root + path, "label": label,
                            "status": r.status})
            if label in ("Actuator env",):
                F.add("High", "Actuator Environment Exposed", root + path,
                      "Spring Boot Actuator /env discloses configuration "
                      "and often secrets.", proof=(r.body or "")[:160],
                      resp=r, dedupe_key=("actenv",), cwe="CWE-200")
    result["exposure"] = exposed
    # robots/sitemap hints
    for name in ("robots.txt", "sitemap.xml"):
        r = client.fetch(f"{root}/{name}")
        if r.status == 200 and r.body:
            disallowed = re.findall(r"(?im)^disallow:\s*(\S+)", r.body)
            interesting = [d for d in disallowed
                           if any(k in d for k in ("admin", "api", "private",
                                                   "internal", "backup",
                                                   "config", ".git"))]
            if interesting:
                F.add("Info", f"Sensitive Paths Disclosed in {name}", 
                      f"{root}/{name}",
                      "robots/sitemap entries reveal non-public paths: "
                      + ", ".join(interesting[:8]),
                      proof="; ".join(interesting[:5]), resp=r,
                      dedupe_key=("robots", name), cwe="CWE-200")
            result[name] = {"entries": len(disallowed)}
    # cloud + email harvest from the landing page
    harvest = cloud_and_email_harvest([(target, base_resp.body or "")])
    check_cloud_exposure(F, client, harvest["cloud_assets"])
    result["cloud"] = harvest["cloud_assets"]
    result["emails"] = harvest["emails"]
    result["email_patterns"] = harvest["email_patterns"]
    if harvest["emails"]:
        F.add("Info", "Public Email Addresses Discovered", target,
              f"{len(harvest['emails'])} email address(es) visible on the "
              f"site (phishing surface): "
              + ", ".join(e['email'] for e in harvest['emails'][:6]),
              dedupe_key=("emails",), cwe="CWE-200")
    # development/staging exposure summary
    dev_hosts = sorted(h for h in live_hosts
                       if any(w in h.split(".")[0] for w in ENV_WORDS))
    result["dev_hosts"] = dev_hosts
    if dev_hosts:
        F.add("Info", "Development/Staging Hosts Exposed", f"dns://{domain}",
              "Non-production hosts are internet-facing: "
              + ", ".join(dev_hosts[:10])
              + ". These often run weaker auth and debug settings.",
              dedupe_key=("devhosts",), cwe="CWE-200")
    # inventory + change tracking
    state_path = opts.get("inventory_file") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "inventory.json")
    state = load_state(state_path)
    assets = build_inventory(domain, set(live_hosts), live_hosts, ipinfo,
                             fingerprints, F.items, state)
    _sev_by_host = {}
    for f in F.items:
        _h = urllib.parse.urlsplit(f.get("url", "")).hostname or ""
        _sev_by_host.setdefault(_h, []).append(f["severity"])
    for a in assets:
        a["ports"] = scanned.get(a["host"], a.get("ports", []))
        a["risk"] = _asset_risk(a, _sev_by_host)
    changes = diff_inventory(state, domain, assets, ipinfo)
    save_state(state_path, state)
    result["assets"] = sorted(assets, key=lambda a: -a["risk"])
    result["changes"] = changes
    result["unknown_assets"] = [a["host"] for a in assets if a["is_new"]]
    emit(f"ExtRecon done: {len(assets)} assets "
         f"({len(changes['new_assets'])} new), "
         f"{len(result['certificates']['certificates'])} certificates, "
         f"{len(all_ips)} IPs.")
    return result
