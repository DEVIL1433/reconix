"""Reconnaissance: DNS, subdomains, ports, tech/CMS fingerprint, TLS, WHOIS, WAF."""
import json
import re
import socket
import time
import ssl
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306,
                3389, 5432, 5900, 8000, 8080, 8443, 8888, 9090, 27017]
SUBDOMAIN_WORDS = ["www", "mail", "ftp", "admin", "dev", "staging", "test",
                   "api", "app", "portal", "blog", "shop", "vpn", "remote",
                   "ns1", "ns2", "webmail", "secure", "beta", "old", "backup",
                   "cpanel", "dashboard", "git", "jenkins", "db", "mysql"]
WAF_SIGNATURES = [
    (r"cloudflare", "Cloudflare"), (r"sucuri", "Sucuri"),
    (r"incapsula|imperva", "Imperva Incapsula"), (r"akamai", "Akamai"),
    (r"mod_security|modsecurity", "ModSecurity"), (r"barracuda", "Barracuda"),
    (r"\bf5\b|big-?ip|\basm\b", "F5 BIG-IP"), (r"awsalb|awselb", "AWS ALB/CloudFront"),
    (r"fastly", "Fastly"), (r"stackpath", "StackPath"),
]
TECH_SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress"), (r"joomla|/media/jui/", "Joomla"),
    (r"drupal", "Drupal"), (r"magento|mage/", "Magento"),
    (r"shopify", "Shopify"), (r"ghost/", "Ghost"),
    (r"__next_data__|_next/static", "Next.js"), (r"ng-app|angular", "Angular"),
    (r"data-reactroot|react", "React"), (r"__vue__|vue\.js", "Vue.js"),
    (r"laravel", "Laravel"), (r"django|csrftoken", "Django"),
    (r"asp\.net|__viewstate", "ASP.NET"), (r"express", "Express/Node"),
    (r"jquery[- ]?(\d+\.\d+\.\d+)", "jQuery"),
    (r"bootstrap[- ]?(\d+\.\d+\.\d+)", "Bootstrap"),
]
# (tech-regex, min-safe-version-note, cve, severity) — evidence-based version flags
CVE_MAP = [
    (r"Apache/2\.4\.49\b", "CVE-2021-41773", "Critical",
     "Apache 2.4.49 path traversal -> RCE (CVE-2021-41773)."),
    (r"Apache/2\.4\.50\b", "CVE-2021-42013", "Critical",
     "Apache 2.4.50 incomplete fix — still traversable (CVE-2021-42013)."),
    (r"Apache/2\.2\.", "CVE-2011-3192", "High", "Apache 2.2 is EOL and vulnerable."),
    (r"PHP/5\.", "EOL", "Medium", "PHP 5.x is end-of-life; no security patches."),
    (r"PHP/7\.[0-2]\.", "EOL", "Medium", "PHP <=7.2 is end-of-life."),
    (r"jQuery 1\.", "CVE-2020-11022", "Medium",
     "jQuery 1.x has known XSS issues (CVE-2020-11022/11023)."),
    (r"jQuery 2\.", "CVE-2020-11022", "Medium",
     "jQuery 2.x has known XSS issues (CVE-2020-11022/11023)."),
    (r"jQuery 3\.[0-4]\.", "CVE-2020-11022", "Medium",
     "jQuery <3.5 has known XSS issues (CVE-2020-11022/11023)."),
    (r"Bootstrap 3\.", "CVE-2019-8331", "Low", "Bootstrap 3.x XSS (CVE-2019-8331)."),
    (r"OpenSSL/1\.0\.1[a-f]?\b", "CVE-2014-0160", "Critical",
     "OpenSSL 1.0.1 — Heartbleed (CVE-2014-0160)."),
    (r"Microsoft-IIS/6\.0", "CVE-2017-7269", "Critical",
     "IIS 6.0 WebDAV RCE (CVE-2017-7269)."),
    (r"Microsoft-IIS/[7]\.", "EOL", "Medium", "IIS 7.x is end-of-life."),
    (r"nginx/1\.[0-9]\.", "OLD", "Info", "Very old nginx branch; check patch level."),
]


def _is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def dns_lookup(host):
    out = {"host": host, "ips": [], "dns_note": ""}
    try:
        out["ips"] = sorted({ai[4][0] for ai in
                             socket.getaddrinfo(host, None)})
    except Exception as e:
        out["dns_note"] = str(e)
    return out


def subdomain_enum(domain, timeout=4):
    found = set()
    if _is_ip(domain) or "." not in domain or domain in ("localhost",):
        return []
    # CT logs
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "Reconix/3.20"})
        with urllib.request.urlopen(req, timeout=8) as r:
            for entry in json.loads(r.read().decode(errors="replace")):
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith("." + domain):
                        found.add(name)
    except Exception:
        pass
    # DNS brute force
    def probe(word):
        sub = f"{word}.{domain}"
        try:
            # NOTE: never socket.setdefaulttimeout() here — it mutates
            # process-global state and silently retimes every other
            # socket in the scanner. The system resolver has its own
            # timeouts; the thread pool bounds the blast radius.
            socket.gethostbyname(sub)
            return sub
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(probe, SUBDOMAIN_WORDS):
            if res:
                found.add(res)
    return sorted(found)[:100]


def port_scan(host, ports=COMMON_PORTS, timeout=1.2):
    results = []
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(1.0)
            banner = ""
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(120).decode(errors="replace").strip()
            except Exception:
                pass
            s.close()
            with lock:
                results.append({"port": port, "banner": banner[:100]})
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(probe, ports))
    return sorted(results, key=lambda p: p["port"])


def tls_analysis(host, port=443):
    out = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["protocol"] = s.version()
                out["cipher"] = s.cipher()[0] if s.cipher() else ""
                cert = s.getpeercert(binary_form=False) or {}
                out["subject"] = str(cert.get("subject", ""))
                out["issuer"] = str(cert.get("issuer", ""))
                out["not_after"] = cert.get("notAfter", "")
                out["not_before"] = cert.get("notBefore", "")
                try:
                    sans = [v for k, v in cert.get("subjectAltName", [])
                            if k == "DNS"]
                    out["sans"] = sans[:10]
                except Exception:
                    out["sans"] = []
                if out["not_after"]:
                    try:
                        exp = datetime.strptime(out["not_after"],
                                                "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        out["days_left"] = (exp - datetime.now(timezone.utc)).days
                    except Exception:
                        pass
    except Exception as e:
        out["error"] = str(e)
    return out


def whois_lookup(domain, timeout=6):
    if _is_ip(domain) or "." not in domain:
        return {}
    try:
        def query(server, q):
            s = socket.create_connection((server, 43), timeout=timeout)
            s.sendall((q + "\r\n").encode())
            data = b""
            deadline = time.time() + 20
            while len(data) < 65536 and time.time() < deadline:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            return data.decode(errors="replace")
        resp = query("whois.iana.org", domain)
        m = re.search(r"refer:\s*(\S+)", resp)
        if m:
            resp = query(m.group(1), domain)
        out = {}
        for key, pat in (("registrar", r"registrar:\s*(.+)"),
                         ("expires", r"(?:expiry date|expiration date|registry expiry date):\s*(.+)"),
                         ("created", r"(?:creation date|created):\s*(.+)"),
                         ("registrant_org", r"registrant organization:\s*(.+)")):
            mm = re.search(pat, resp, re.I)
            if mm:
                out[key] = mm.group(1).strip()[:120]
        return out
    except Exception:
        return {}


def fingerprint(base_resp, pages):
    tech = set()
    hay = ""
    if base_resp is not None:
        hay += " ".join(f"{k}: {v}" for k, v in base_resp.raw_headers)
        hay += " " + (base_resp.body or "")[:60000]
    for _u, r in pages[:8]:
        hay += " " + (r.body or "")[:20000]
        hay += " " + " ".join(src for src in
                              re.findall(r'src="([^"]+)"', r.body or ""))
    versions = {}
    for pat, name in TECH_SIGNATURES:
        m = re.search(pat, hay, re.I)
        if m:
            tech.add(name)
            if m.groups() and m.group(1):
                versions[name] = m.group(1)
    if base_resp is not None:
        server = base_resp.header("server")
        powered = base_resp.header("x-powered-by")
        if server:
            tech.add(server)
        if powered:
            tech.add(powered)
    waf = []
    header_hay = hay[:8000]
    for pat, name in WAF_SIGNATURES:
        if re.search(pat, header_hay, re.I):
            waf.append(name)
    gen = re.search(r'<meta[^>]+name="generator"[^>]+content="([^"]+)"', hay, re.I)
    cms_version = gen.group(1) if gen else ""
    return {"tech": sorted(tech), "versions": versions, "waf": waf,
            "generator": cms_version}


def run_recon(ctx, base):
    """Returns a recon dict; also emits findings for ports/TLS/CVE/tech."""
    F, client = ctx.findings, ctx.client
    parts = urllib.parse.urlsplit(base)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    recon = {"host": host}
    emit = ctx.emit if hasattr(ctx, "emit") else (lambda m: None)
    emit(f"Recon: DNS/TLS/tech for {host}")
    recon["dns"] = dns_lookup(host)
    recon["subdomains"] = subdomain_enum(host)
    if recon["subdomains"]:
        F.add("Info", "Subdomains Discovered", base,
              f"{len(recon['subdomains'])} subdomain(s) found via CT logs / DNS: "
              + ", ".join(recon["subdomains"][:15]),
              dedupe_key=("recon", "subs"))
    base_resp = client.fetch(base)
    pages = [(base, base_resp)] if base_resp.status else []
    recon["fingerprint"] = fingerprint(base_resp, pages)
    for w in recon["fingerprint"]["waf"]:
        F.add("Info", f"WAF/CDN Detected: {w}", base,
              "A WAF/CDN signature was seen in response headers; expect some "
              "payloads to be filtered.", dedupe_key=("waf", w))
    tech_str = " ".join(recon["fingerprint"]["tech"]) + " " + \
        recon["fingerprint"]["generator"]
    for pat, cve, sev, note in CVE_MAP:
        if re.search(pat, tech_str):
            distro = any(d in tech_str for d in
                         ("Debian", "Ubuntu", "Red Hat", "CentOS", "(Win32)"))
            F.add(sev, f"Known Vulnerable Component ({cve})", base,
                  note + f" Evidence: {re.search(pat, tech_str).group(0)}."
                  " CONFIDENCE: this match is banner/version-based. "
                  + ("The banner indicates a distribution build — distro "
                     "vendors BACKPORT security fixes without changing the "
                     "version string, so this may already be patched. "
                     "Verify before reporting."
                     if distro else
                     "Confirm the exact build before reporting."),
                  proof=f"matched {pat} in fingerprint: {tech_str[:160]}",
                  confidence="Possible (banner-based)",
                  cwe="CWE-1104", dedupe_key=("cve", cve, pat))
    emit("Recon: port scan (top ports)")
    scan_ports = list(dict.fromkeys(COMMON_PORTS + [port]))
    recon["ports"] = port_scan(host, ports=scan_ports)
    for p in recon["ports"]:
        if p["port"] not in (80, 443, port):
            F.add("Info", f"Open Port Discovered: {p['port']}", base,
                  f"Service listening on {host}:{p['port']}"
                  + (f" — banner: {p['banner']}" if p["banner"] else ""),
                  dedupe_key=("port", p["port"]))
    if parts.scheme == "https" or port == 443:
        recon["tls"] = tls_analysis(host, 443 if port in (443, 80) else port)
        tls = recon["tls"]
        if tls.get("days_left") is not None:
            if tls["days_left"] < 0:
                F.add("High", "TLS Certificate Expired", base,
                      f"Certificate expired {-tls['days_left']} day(s) ago.",
                      proof=f"notAfter={tls.get('not_after')}", cwe="CWE-295")
            elif tls["days_left"] < 30:
                F.add("Low", "TLS Certificate Expiring Soon", base,
                      f"Certificate expires in {tls['days_left']} day(s).",
                      proof=f"notAfter={tls.get('not_after')}", cwe="CWE-295")
        if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            F.add("Medium", "Weak TLS Protocol", base,
                  f"Server negotiated {tls['protocol']}.",
                  proof=f"protocol={tls.get('protocol')}", cwe="CWE-327")
    else:
        recon["tls"] = {}
    recon["whois"] = whois_lookup(host)
    return recon
