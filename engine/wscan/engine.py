"""Scan engine v3: recon -> crawl -> passive -> active checks -> OOB -> report.
Profiles select check subsets; every phase honours the stop event and the
false-positive suppression set."""
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import (api_scan, auth, bizlogic as bizlogic_mod,
               browser as browser_mod, chains as chains_mod, checks,
               checks2, checks3, checks4,
               extrecon as extrecon_mod,
               har as har_mod, integrations, matrix as matrix_mod, passive,
               proof as proof_mod,
               recon as recon_mod, rules as rules_mod)
from .calibrate import Calibrator
from .client import Client, redirect_location
from .core import Findings, crawl, fingerprint_of, params_of, parse_page
from .oob import OOBServer
from .report3 import group_findings, risk_score

PROFILES = {
    "quick": ["recon", "headers", "dom", "cors", "hostheader", "passive",
              "discovery", "graphql", "jwt", "csrf", "rules", "bypass403"],
    "full": ["recon", "headers", "dom", "cors", "hostheader", "passive",
             "sqli", "xss", "cmdi", "ssti", "lfi", "redirect", "crlf", "ssrf",
             "forms", "upload", "xxe", "graphql", "jwt", "discovery",
             "csrf", "rfi", "nosql", "ldap", "session", "idor",
             "cachepoison", "ratelimit", "race", "rules", "api",
             "browser", "matrix", "extrecon", "smuggling", "websocket",
             "bypass403", "bizlogic", "proof", "chains"],
    "api": ["recon", "headers", "cors", "passive", "graphql", "jwt", "api",
            "ratelimit", "rules", "websocket", "smuggling", "bypass403"],
    "passive": ["recon", "headers", "passive", "discovery", "rules"],
    "recon": ["extrecon", "headers", "passive", "rules"],
}


class Ctx:
    def __init__(self, client, findings, oob, base, opts, emit):
        self.client = client
        self.findings = findings
        self.oob = oob
        self.base = base
        self.opts = opts
        self.emit = emit
        self.oob_pending = []
        self.stop = opts.get("_stop") or threading.Event()
        self.extra = opts.get("extra_payloads") or {}
        self.calibrator = None    # per-target accuracy calibration
        self.progress = lambda pct, label="": None  # set by run_scan
        self.auth_cfg = None      # for the session watchdog
        self.baseline_error_urls = set()  # pages with SQL errors at crawl
        self._time_stats = {}             # per-URL timing baseline cache
        self.client_b = None      # second session (IDOR)
        self.client_anon = None   # unauthenticated client (IDOR)


def _parse_request(text, page_url):
    """Rebuild (method, url, headers, body) from a stored request."""
    try:
        head, _, body = (text or "").partition("\r\n\r\n")
        lines = head.split("\r\n")
        method, path = lines[0].split(" ", 2)[:2]
        parts = urllib.parse.urlsplit(page_url)
        url = f"{parts.scheme}://{parts.netloc}{path}"
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                if k.strip().lower() not in ("host", "content-length",
                                             "connection"):
                    headers[k.strip()] = v.strip()
        return method, url, headers, (body.encode() if body else None)
    except Exception:
        return None


def _verify_findings(ctx, items):
    """False-positive hunter: replay each confirmed finding's original
    request once. If the evidence is gone (404, the site's not-found
    page, or the proof tokens no longer reproduce), flag the finding
    as a suspected false positive instead of hiding it."""
    for f in items:
        if ctx.stop.is_set():
            return
        req = f.get("request") or ""
        if not req or f.get("confidence") != "Confirmed":
            continue
        if "out-of-band" in f["title"].lower() or \
                "OOB" in (f.get("proof") or "") or \
                "called back" in (f.get("proof") or ""):
            continue  # OOB evidence is server-side ground truth
        parsed = _parse_request(req, f["url"])
        if not parsed:
            continue
        method, url, headers, body = parsed
        r = ctx.client.fetch(url, method=method, headers=headers,
                             raw_body=body)
        if r.status is None:
            continue
        reason = ""
        if r.status in (404, 410) and f.get("status_code") == 200:
            reason = f"replay now returns HTTP {r.status}"
        elif ctx.calibrator and ctx.calibrator.is_soft404(r):
            reason = "replay returns the site's not-found page"
        else:
            tokens = {t for t in re.findall(r"[A-Za-z0-9_]{8,}",
                                            f.get("proof") or "")
                      if t in (f.get("response_snippet") or "")}
            if tokens and not any(t in (r.body or "") for t in tokens):
                reason = "proof evidence not reproduced on replay"
        if reason:
            f["fp_suspect"] = True
            f["fp_reason"] = reason


def run_scan(target, opts=None, on_event=None):
    opts = opts or {}
    profile = opts.get("profile", "full")
    enabled = set(opts.get("checks") or PROFILES.get(profile, PROFILES["full"]))
    max_pages = int(opts.get("max_pages", 60))
    max_depth = int(opts.get("max_depth", 3))
    threads = int(opts.get("threads", 6))
    started = time.time()

    def emit(kind, msg, finding=None):
        if on_event:
            on_event(kind, msg, finding)
        if kind == "finding" and finding:
            param = f"  [param: {finding['param']}]" if finding.get("param") else ""
            print(f"  [{finding['severity'].upper():8}] {finding['title']}  ->  "
                  f"{finding['url']}{param}")
        elif kind == "phase":
            print(f"[*] {msg}")

    findings = Findings(on_add=lambda f: emit("finding", f["title"], f),
                        suppress=opts.get("suppress"))
    client = Client(extra_headers=opts.get("headers") or None,
                    cookie=opts.get("cookie"),
                    proxy=opts.get("proxy"),
                    delay=float(opts.get("delay", 0) or 0))
    oob = OOBServer().start()
    ctx = Ctx(client, findings, oob, target, opts,
              lambda m: emit("phase", m))

    _pct = [0]
    _mile = [0]

    def progress(pct, label=""):
        pct = max(0, min(100, int(pct)))
        if pct < _pct[0]:
            pct = _pct[0]  # monotonic: the bar never runs backwards
        _pct[0] = pct
        if on_event:
            on_event("progress", label, {"pct": pct})
        elif pct >= _mile[0] + 10:
            _mile[0] = pct
            print(f"[*] Progress: {pct}% {label}")
    ctx.progress = progress
    progress(2, "Probing target")
    if opts.get("cookie_b"):
        ctx.client_b = Client(cookie=opts["cookie_b"], proxy=opts.get("proxy"))
    if opts.get("idor_anon"):
        ctx.client_anon = Client(proxy=opts.get("proxy"))
    # WAF-adaptive mode (default on): clients pace themselves and route
    # benign traffic around WAF blocks once a WAF engages; blocked
    # attack checks get a quiet-retry pass near the end of the scan.
    _waf_on = opts.get("waf_adaptive") is not False
    for _c in (client, ctx.client_b, ctx.client_anon):
        if _c is not None:
            _c.adaptive = _waf_on
    if opts.get("bizlogic") is False:
        enabled.discard("bizlogic")
    _shots_dir = opts.get("shots_dir") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "screenshots", time.strftime("%Y%m%d-%H%M%S"))

    emit("phase", f"Target {target} — profile '{profile}', "
                  f"OOB listener on {oob.host}:{oob.port}")
    probe = client.fetch(target)
    if probe.status is None:
        oob.stop()
        return {"target": target, "error": "Target unreachable",
                "findings": [], "counts": findings.counts(), "pages": 0}

    # ---- scheme-upgrade rebase ---------------------------------------
    # An http:// target whose root redirects to https:// on the same
    # host would otherwise scan an empty shell: every real page is
    # cross-scheme and falls out of crawl scope (seen live 2026-10-16:
    # 1 page / 10 findings over http where https found 483).
    if target.startswith("http://"):
        _loc = redirect_location(target)
        if _loc:
            _t = urllib.parse.urlsplit(target)
            _l = urllib.parse.urlsplit(_loc)
            if _l.scheme == "https" and _l.netloc == _t.netloc:
                target = urllib.parse.urlunsplit(
                    ("https", _t.netloc, _t.path, _t.query, ""))
                ctx.base = target
                emit("phase", "Target redirects http -> https — "
                     f"continuing with {target} so crawling follows "
                     "the site's real scheme.")

    # ---- authentication (stored session) ------------------------------
    if opts.get("auth"):
        cfg = dict(opts["auth"])
        cfg.setdefault("login_url",
                       target.rstrip("/") + "/login")
        ctx.auth_cfg = cfg
        auth.perform_login(client, cfg, emit=lambda m: emit("phase", m))

    # ---- calibration: learn soft-404 + page noise before judging -------
    try:
        ctx.calibrator = Calibrator(client, target)
        emit("phase", f"Calibration: {ctx.calibrator.summary}")
    except Exception:
        ctx.calibrator = None

    _guard_counter = [0]

    def session_guard():
        """Watchdog: a dead session silently invalidates authenticated
        scanning — detect it and re-login instead of scanning logged-out
        pages and reporting nonsense."""
        if not ctx.auth_cfg:
            return
        try:
            if not auth.session_alive(client, target):
                emit("phase", "Session watchdog: session expired — "
                              "re-authenticating...")
                auth.perform_login(client, ctx.auth_cfg,
                                   emit=lambda m: emit("phase", m))
        except Exception:
            pass

    def _crawl_hook(url, resp):
        _guard_counter[0] += 1
        n = _guard_counter[0]
        progress(_crawl_lo + (45 - _crawl_lo) * min(1.0, n / max(1, max_pages)),
                 f"Crawling site ({n} pages)")
        if n % 15 == 0:
            session_guard()

    result_recon = {}
    result_matrix = []
    result_extrecon = {}
    tested_urls = set()
    tested_forms = set()
    _crawl_lo = 20 if "extrecon" in enabled else 5
    if "extrecon" in enabled and not ctx.stop.is_set():
        progress(5, "External reconnaissance")
        emit("phase", "External reconnaissance (attack surface discovery)...")
        try:
            result_extrecon = extrecon_mod.run_extrecon(ctx, target, opts)
        except Exception as e:
            emit("phase", f"ExtRecon partial failure: {e}")
    progress(18, "Reconnaissance")
    if "recon" in enabled and not ctx.stop.is_set():
        emit("phase", "Reconnaissance (DNS, subdomains, ports, TLS, tech)...")
        try:
            result_recon = recon_mod.run_recon(ctx, target)
        except Exception as e:
            emit("phase", f"Recon partial failure: {e}")

    emit("phase", f"Crawling (max {max_pages} pages, depth {max_depth})...")
    pages, forms, js_urls, sitemap = crawl(client, target, max_pages,
                                           max_depth, on_page=_crawl_hook)
    emit("phase", f"Crawled {len(pages)} pages, {len(forms)} forms, "
                  f"{len(js_urls)} JS files.")
    page_urls = [u for u, _ in pages]
    param_urls = [u for u, _ in pages if params_of(u)]
    ctx.baseline_error_urls = {u for u, r in pages
                               if checks._sql_error_in(r.body)}
    _ws_urls = set()
    for _u, _r in pages:
        for _m in re.finditer(r"wss?://[^\s\"'<>]+", _r.body or ""):
            _ws_urls.add(_m.group(0))
    if _ws_urls:
        ctx.extra["ws_urls"] = sorted(_ws_urls)[:5]

    # ---- resume seeding: a previous scan's known surface ---------------
    seed_urls = opts.get("seed_urls") or []
    if seed_urls and not ctx.stop.is_set():
        have = {u for u, _ in pages}
        added = 0
        for u in seed_urls:
            if u not in have and urllib.parse.urlsplit(u).netloc == \
                    urllib.parse.urlsplit(target).netloc:
                r = client.fetch(u)
                if r.status:
                    pages.append((u, r))
                    have.add(u)
                    added += 1
                    for _frm in parse_page(r.body).forms:
                        forms.append((u, _frm))
        if added:
            emit("phase", f"Resume: re-seeded {added} known page(s) "
                          "from the earlier scan's site map.")
            page_urls = [u for u, _ in pages]
            param_urls = [u for u, _ in pages if params_of(u)]

    # ---- HAR seeding (imported traffic becomes scan surface) -------------
    har_text = opts.get("har_text")
    if not har_text and opts.get("har_file"):
        try:
            with open(opts["har_file"], encoding="utf-8",
                      errors="replace") as fh:
                har_text = fh.read()
        except Exception:
            har_text = None
    if har_text:
        seeded = har_mod.parse_har(har_text)
        have = {u for u, _ in pages}
        added = 0
        for u in seeded["pages"]:
            if u not in have and urllib.parse.urlsplit(u).netloc == \
                    urllib.parse.urlsplit(target).netloc:
                r = client.fetch(u)
                if r.status:
                    pages.append((u, r))
                    have.add(u)
                    added += 1
        form_actions = {urllib.parse.urljoin(p, f["action"]) for p, f in forms}
        for page_url, form in seeded["forms"]:
            if form["action"] not in form_actions:
                forms.append((page_url, form))
        emit("phase", f"HAR import: {seeded['entries']} entries, "
                      f"{added} extra pages, {len(seeded['forms'])} forms.")
        page_urls = [u for u, _ in pages]
        param_urls = [u for u, _ in pages if params_of(u)]
    har_steps = har_mod.parse_har_steps(har_text) if har_text else []

    # ---- browser engine (renders pages, SPA routes, DOM-XSS proof) ------
    browser_summary = {}
    if "browser" in enabled and not ctx.stop.is_set():
        shots_dir = _shots_dir
        progress(47, "Browser engine")
        emit("phase", "Browser engine (Chromium rendering)...")
        # visit a mix: param pages (XSS confirmation) AND plain pages
        # (SPA routes only exist as plain pages — their XHR traffic is
        # part of the crawl surface now)
        _visit = list(dict.fromkeys(
            param_urls[:8] + page_urls))[:24]
        browser_summary = browser_mod.browser_scan(
            ctx, _visit, shots_dir=shots_dir, max_pages=24)
        have = {u for u, _ in pages}
        for u in browser_summary.get("extra_links", [])[:10]:
            if u not in have:
                r = client.fetch(u)
                if r.status:
                    pages.append((u, r))
                    have.add(u)
        if browser_summary.get("extra_links"):
            page_urls = [u for u, _ in pages]
            param_urls = [u for u, _ in pages if params_of(u)]
        _xhr_added = 0
        for u in browser_summary.get("xhr_urls", [])[:15]:
            if u not in have and urllib.parse.urlsplit(u).netloc == \
                    urllib.parse.urlsplit(target).netloc:
                r = client.fetch(u)
                if r.status:
                    pages.append((u, r))
                    have.add(u)
                    _xhr_added += 1
        if _xhr_added:
            emit("phase", f"Browser XHR: {_xhr_added} live API call(s) "
                          f"captured from the running app.")
            page_urls = [u for u, _ in pages]
            param_urls = [u for u, _ in pages if params_of(u)]

    # ---- recursive discovery: find hidden dirs, brute-force inside
    # them, and merge everything found into the scan surface -----------
    if "discovery" in enabled and not ctx.stop.is_set():
        progress(50, "Recursive discovery")
        emit("phase", "Recursive content discovery (directories + "
                      "what's inside them)...")
        _words = set()
        for _u in page_urls:
            for _seg in urllib.parse.urlsplit(_u).path.split("/"):
                _w = _seg.split(".")[0].strip().lower()
                if 3 <= len(_w) <= 24 and _w.isalpha():
                    _words.add(_w)
        for _pu, _form in forms:
            for _i in _form["inputs"]:
                _n = (_i["name"] or "").lower()
                if 3 <= len(_n) <= 24 and _n.isalpha():
                    _words.add(_n)
        _crawled = {urllib.parse.urlsplit(_u).path.strip("/")
                    for _u in page_urls}
        _learned = sorted(w for w in _words if w not in _crawled)[:120]
        _seed = set()
        for _u in page_urls:
            _segs = [s for s in urllib.parse.urlsplit(_u).path.split("/")
                     if s]
            for _i in range(1, len(_segs)):
                _seed.add("/".join(_segs[:_i]))
        _disc = checks.discovery_check(ctx, target, _learned,
                                       sorted(_seed)[:8])
        _have = {u for u, _ in pages}
        _added = 0
        for _u in _disc or []:
            if _u not in _have and not ctx.stop.is_set():
                _r = client.fetch(_u)
                if _r.status == 200 and _r.body:
                    pages.append((_u, _r))
                    _have.add(_u)
                    _added += 1
                    for _frm in parse_page(_r.body).forms:
                        forms.append((_u, _frm))
        if _added:
            emit("phase", f"Discovery merged {_added} hidden page(s) "
                          f"into the scan surface.")
            page_urls = [u for u, _ in pages]
            param_urls = [u for u, _ in pages if params_of(u)]

    # ---- passive layer --------------------------------------------------
    if "headers" in enabled:
        checks.headers_check(ctx, pages)
        checks.dir_listing_check(ctx, pages)
    if "dom" in enabled:
        checks.dom_xss_check(ctx, pages, js_urls)
    if "cors" in enabled:
        for u in [target] + param_urls[:5]:
            checks.cors_check(ctx, u)
    if "hostheader" in enabled:
        checks.host_header_check(ctx, target)
        checks2.cache_poison_check(ctx, target) if "cachepoison" in enabled else None
    if "passive" in enabled and not ctx.stop.is_set():
        progress(52, "Passive analysis")
        emit("phase", "Passive analysis (secrets, source maps, methods, "
                      "cache, stack traces, data exposure)...")
        js_eps = passive.secrets_scan(ctx, pages, js_urls)
        for ep in (js_eps or [])[:25]:
            if ep not in {u for u, _ in pages} and len(pages) < max_pages + 25:
                r = client.fetch(ep)
                if r.status:
                    pages.append((ep, r))
                    _pa = parse_page(r.body)
                    for form in _pa.forms:
                        forms.append((ep, form))
        if js_eps:
            emit("phase", f"JS analysis: {len(js_eps)} API endpoint(s) "
                          f"extracted from JavaScript/source maps.")
            page_urls = [u for u, _ in pages]
            param_urls = [u for u, _ in pages if params_of(u)]
        passive.methods_check(ctx, target)
        passive.transport_check(ctx, target)
        passive.redirect_chain(ctx, target)
        passive.stack_trace_scan(ctx, pages)
        passive.cache_control_scan(ctx, pages)
        passive.excessive_data_scan(ctx, pages)
        passive.broken_links_scan(ctx, pages)

    session_guard()
    # ---- active injection layer -----------------------------------------
    url_checks = []
    if "sqli" in enabled:
        url_checks.append(checks.sqli_url)
    if "xss" in enabled:
        url_checks.append(checks.xss_url)
    if "cmdi" in enabled:
        url_checks.append(checks.cmdi_url)
    if "ssti" in enabled:
        url_checks.append(checks.ssti_url)
    if "lfi" in enabled:
        url_checks.append(checks.lfi_url)
    if "redirect" in enabled:
        url_checks.append(checks.redirect_url)
    if "crlf" in enabled:
        url_checks.append(checks.crlf_url)
    if "ssrf" in enabled:
        url_checks.append(checks.ssrf_url)
    if "rfi" in enabled:
        url_checks.append(checks2.rfi_url)
    if "nosql" in enabled:
        url_checks.append(checks2.nosql_url)
    if "ldap" in enabled:
        url_checks.append(checks2.ldap_url)
    if url_checks and not ctx.stop.is_set():
        emit("phase", f"Active checks on {len(param_urls)} parameterized "
                      f"URLs ({len(url_checks)} check types)...")
        jobs = {}
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for u in param_urls:
                for fn in url_checks:
                    jobs[ex.submit(fn, ctx, u)] = u
            _done = 0
            for j in as_completed(jobs):
                _done += 1
                tested_urls.add(jobs[j])
                progress(55 + 25 * _done / max(1, len(jobs)),
                         f"Active checks ({_done}/{len(jobs)})")
                try:
                    j.result()
                except Exception:
                    pass

    session_guard()
    # ---- forms ------------------------------------------------------------
    if forms and not ctx.stop.is_set():
        emit("phase", f"Testing {len(forms)} forms...")
        with ThreadPoolExecutor(max_workers=max(2, threads // 2)) as ex:
            futs = {}
            for _fi, (page_url, form) in enumerate(forms):
                if "forms" in enabled:
                    futs[ex.submit(checks.forms_check, ctx, page_url,
                                   form, page_urls)] = _fi
                if "upload" in enabled:
                    futs[ex.submit(checks.upload_check, ctx,
                                   page_url, form)] = _fi
                if "csrf" in enabled:
                    futs[ex.submit(checks2.csrf_check, ctx, page_url,
                                   form)] = _fi
                if opts.get("auth_test"):
                    futs[ex.submit(checks2.default_creds_check, ctx,
                                   page_url, form)] = _fi
            _fdone = 0
            for j in as_completed(futs):
                _fdone += 1
                tested_forms.add(futs[j])
                progress(80 + 6 * _fdone / max(1, len(futs)),
                         "Testing forms")
                try:
                    j.result()
                except Exception:
                    pass

    # ---- business logic: attack the recorded workflow itself ---------
    if "bizlogic" in enabled and not ctx.stop.is_set():
        if har_steps:
            progress(84, "Business-logic attacks")
            emit("phase", "Business-logic attacks on the recorded "
                          "workflow (step-skip / replay / tampering)...")
            try:
                bizlogic_mod.run(ctx, har_steps)
            except Exception as e:
                emit("phase", f"Business-logic partial failure: {e}")
        elif opts.get("har_file") or opts.get("har_text"):
            emit("phase", "Business-logic: the supplied HAR contains no "
                          "state-changing steps — skipped.")

    # ---- session / IDOR / misc ---------------------------------------------
    if "session" in enabled:
        checks2.session_checks(ctx, target, pages)
    if "idor" in enabled and (ctx.client_b or ctx.client_anon) \
            and not ctx.stop.is_set():
        emit("phase", "IDOR / access-control checks (dual session)...")
        checks2.idor_check(ctx, param_urls)
    if "matrix" in enabled and not ctx.stop.is_set():
        emit("phase", "Permission matrix (anon vs user vs admin)...")
        result_matrix = matrix_mod.build(ctx, pages)
    if "ratelimit" in enabled:
        checks2.rate_limit_check(ctx, target)
    if "race" in enabled:
        checks2.race_check(ctx, param_urls)
    if "bypass403" in enabled and not ctx.stop.is_set():
        emit("phase", "403 bypass attempts (path / header / method "
                      "evasion on forbidden pages)...")
        checks4.bypass403_check(ctx, pages)

    # ---- WAF quiet-retry: blocked checks get one slow second pass -----
    if _waf_on and not ctx.stop.is_set():
        _blocked = sorted({f["url"] for f in findings.items
                           if f["title"].startswith("WAF Interference")})
        if _blocked:
            emit("phase", f"WAF quiet-retry: re-testing "
                          f"{min(len(_blocked), 5)} WAF-blocked URL(s) "
                          "at human pace (1s+ between requests)...")
            _before = len(findings.items)
            _old_delay = client.delay
            client.delay = max(_old_delay, 1.0)
            try:
                for _u in _blocked[:5]:
                    if ctx.stop.is_set():
                        break
                    if "sqli" in enabled:
                        checks.sqli_url(ctx, _u)
                    if "xss" in enabled:
                        checks.xss_url(ctx, _u)
            finally:
                client.delay = _old_delay
            emit("phase", f"WAF quiet-retry done: "
                          f"{len(findings.items) - _before} new "
                          "finding(s) past the WAF.")

    # ---- API ---------------------------------------------------------------
    api_eps = []
    progress(88, "API checks")
    if "api" in enabled and not ctx.stop.is_set():
        emit("phase", "API security checks...")
        spec_url = opts.get("openapi") or api_scan.discover_openapi(ctx, target)
        if spec_url:
            api_eps = api_scan.load_openapi(ctx, spec_url)
            emit("phase", f"OpenAPI: {len(api_eps)} endpoints imported.")
            api_scan.fuzz_endpoints(ctx, api_eps)

    # ---- XXE / GraphQL / JWT / discovery / rules ---------------------------
    if "xxe" in enabled and not ctx.stop.is_set():
        checks.xxe_check(ctx, page_urls, forms)
    if "graphql" in enabled:
        checks.graphql_check(ctx, target)
        checks3.graphql_deep_check(ctx, target)
    if "websocket" in enabled and not ctx.stop.is_set():
        emit("phase", "WebSocket security checks...")
        checks3.websocket_check(ctx, target)
    if "smuggling" in enabled and not ctx.stop.is_set():
        emit("phase", "HTTP request smuggling probes...")
        checks3.smuggling_check(ctx, target)
    if "jwt" in enabled:
        checks.jwt_check(ctx, pages)
    if "rules" in enabled:
        loaded = rules_mod.load_rules(opts.get("rules_dir"))
        if loaded:
            emit("phase", f"Applying {len(loaded)} custom rule(s)...")
            rules_mod.apply_rules(ctx, pages, loaded)

    # ---- external scanner bridges -------------------------------------------
    progress(97, "Final checks")
    if not ctx.stop.is_set() and (opts.get("nuclei") or opts.get("nuclei_file")
                                  or opts.get("zap_url")):
        emit("phase", "External scanners (Nuclei / ZAP)...")
        if opts.get("nuclei_file"):
            n = integrations.import_nuclei_jsonl(ctx, opts["nuclei_file"])
            emit("phase", f"Nuclei import: {n} new finding(s).")
        if opts.get("nuclei"):
            n = integrations.run_nuclei(ctx, target)
            emit("phase", f"Nuclei run: {n} new finding(s).")
        if opts.get("zap_url"):
            n = integrations.zap_alerts(ctx, target, opts["zap_url"],
                                        opts.get("zap_key", ""))
            emit("phase", f"ZAP import: {n} new finding(s).")

    # ---- OOB resolution ------------------------------------------------------
    if ctx.oob_pending and not ctx.stop.is_set():
        emit("phase", "Waiting for out-of-band callbacks...")
        deadline = time.time() + 6
        while time.time() < deadline:
            if all(oob.get_hits(p["token"]) for p in ctx.oob_pending):
                break
            time.sleep(0.4)
        checks.finalize_oob(ctx)
    oob.stop()

    # ---- auto-proof: upgrade detections into demonstrations ------------
    if "proof" in enabled and not ctx.stop.is_set():
        progress(98, "Auto-proof")
        emit("phase", "Auto-proof (demonstrating impact of confirmed "
                      "findings)...")
        try:
            proof_mod.prove(ctx)
        except Exception as e:
            emit("phase", f"Auto-proof partial failure: {e}")

    # ---- attack chaining: assemble the paths between findings ---------
    if "chains" in enabled and not ctx.stop.is_set():
        try:
            _made = chains_mod.correlate(ctx, extrecon=result_extrecon,
                                         page_urls=page_urls)
            if _made:
                emit("phase", f"Attack chaining: {len(_made)} chain(s) "
                              "assembled from the individual findings.")
        except Exception as e:
            emit("phase", f"Attack chaining partial failure: {e}")

    session_guard()
    items = findings.sorted()
    _verify_findings(ctx, items)

    # ---- evidence screenshots for the serious findings ------------------
    if "browser" in enabled and not ctx.stop.is_set():
        try:
            _shots = browser_mod.capture_findings(ctx, items, _shots_dir,
                                                  limit=8)
            if _shots:
                browser_summary.setdefault("screenshots", []).extend(_shots)
                emit("phase", f"Evidence screenshots: {len(_shots)} "
                              "finding page(s) captured.")
        except Exception:
            pass
    _waf_urls = {f["url"] for f in items
                 if f["title"].startswith("WAF Interference")}
    coverage = {"pages_crawled": len(pages),
                "param_urls": len(param_urls),
                "param_urls_tested": len(tested_urls),
                "forms": len(forms), "forms_tested": len(tested_forms),
                "waf_blocked": len(_waf_urls),
                "suppressed": findings.suppressed_count,
                "auto_proven": sum(1 for f in items
                                   if f.get("proof_verified")),
                "chains": sum(1 for f in items if f.get("is_chain")),
                "fp_suspects": sum(1 for f in items
                                   if f.get("fp_suspect"))}
    emit("phase", f"Coverage: tested {len(tested_urls)}/{len(param_urls)} "
                  f"param URLs, {len(tested_forms)}/{len(forms)} forms; "
                  f"{len(_waf_urls)} WAF-blocked; "
                  f"{findings.suppressed_count} known-FP suppressed.")
    score, grade = risk_score(items)
    result = {
        "target": target, "profile": profile,
        "pages": len(pages), "forms": len(forms),
        "findings": items, "counts": findings.counts(),
        "suppressed_fp": findings.suppressed_count,
        "recon": result_recon, "sitemap": sitemap,
        "extrecon": result_extrecon,
        "permission_matrix": result_matrix,
        "browser": browser_summary,
        "screenshots": browser_summary.get("screenshots", []),
        "report_meta": {"company": opts.get("company", ""),
                        "logo_data": opts.get("logo_data", ""),
                        "client": opts.get("client_name", ""),
                        "profile": profile, "scope": target},
        "risk_score": score, "risk_grade": grade,
        "groups": group_findings(items),
        "coverage": coverage,
        "suppressed_findings": findings.suppressed_items,
        "calibration": (ctx.calibrator.summary if ctx.calibrator else ""),
        "duration_s": round(time.time() - started, 1),
        "stopped": bool(ctx.stop.is_set()),
        "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    result["har"] = har_mod.build_har(pages, items)
    emit("phase", f"Done in {result['duration_s']}s. {len(items)} findings, "
                  f"risk {score}/100 ({grade}).")
    progress(100, 'Done')
    return result


def diff_scans(old, new):
    """Compare two scan results by finding fingerprint."""
    old_fp = {fingerprint_of(f): f for f in old.get("findings", [])}
    new_fp = {fingerprint_of(f): f for f in new.get("findings", [])}
    return {
        "new": [f for k, f in new_fp.items() if k not in old_fp],
        "fixed": [f for k, f in old_fp.items() if k not in new_fp],
        "still_open": [f for k, f in new_fp.items() if k in old_fp],
    }
