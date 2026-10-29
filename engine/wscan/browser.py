"""Browser engine (optional, Playwright): renders pages with real Chromium —
SPA link discovery, DOM-XSS *execution* proof, and screenshot evidence.
Degrades gracefully when Playwright/Chromium is not installed."""
import os
import urllib.parse

from .core import params_of, with_param

try:
    from playwright.sync_api import sync_playwright
    _OK = True
except Exception:
    _OK = False


def available():
    return _OK


def _seed_cookies(context, cookie_header, base):
    if not cookie_header:
        return
    parts = urllib.parse.urlsplit(base)
    cookies = []
    for pair in cookie_header.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies.append({"name": k, "value": v, "url":
                            f"{parts.scheme}://{parts.netloc}/"})
    if cookies:
        try:
            context.add_cookies(cookies)
        except Exception:
            pass


def _probe_payload(probe_url, name):
    """Recover the injected value from a probe URL built by with_param."""
    if name == "(fragment)":
        return "#" + probe_url.split("#", 1)[1] if "#" in probe_url else ""
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(probe_url).query)
    v = q.get(name)
    return v[0] if v else ""


def browser_scan(ctx, page_urls, shots_dir=None, max_pages=12):
    """Returns {visited, extra_links, screenshots}. Emits findings for
    browser-confirmed XSS (payload actually executed in Chromium)."""
    out = {"visited": 0, "extra_links": [], "screenshots": [],
           "xhr_urls": []}
    if not _OK:
        ctx.emit("Browser engine: Playwright not installed — skipped "
                 "(pip install playwright && playwright install chromium)")
        return out
    F = ctx.findings
    base_host = urllib.parse.urlsplit(ctx.base).netloc
    targets = [ctx.base] + [u for u in page_urls if u != ctx.base]
    targets = targets[:max_pages]
    if shots_dir:
        os.makedirs(shots_dir, exist_ok=True)
    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            _seed_cookies(context, ctx.opts.get("cookie"), ctx.base)
            page = context.new_page()
            _xhr = []
            page.on("request", lambda req: _xhr.append(req.url)
                    if req.resource_type in ("xhr", "fetch") else None)
            dialogs = []
            page.on("dialog", lambda d: (dialogs.append(d.message),
                                         d.dismiss()))
            for url in targets:
                if ctx.stop.is_set():
                    break
                try:
                    page.goto(url, timeout=12000,
                              wait_until="domcontentloaded")
                    page.wait_for_timeout(600)
                except Exception:
                    continue
                out["visited"] += 1
                # rendered link discovery (SPA routes)
                try:
                    links = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)")
                except Exception:
                    links = []
                for link in links:
                    p = urllib.parse.urlsplit(link)
                    if p.netloc == base_host and \
                            link.split("#")[0] not in targets:
                        out["extra_links"].append(link.split("#")[0])
                # screenshot of the landing page
                if shots_dir and url == ctx.base:
                    shot = os.path.join(shots_dir, "landing.png")
                    try:
                        page.screenshot(path=shot)
                        out["screenshots"].append({"url": url, "file": shot})
                    except Exception:
                        pass
                # ---- execution-proof XSS probes ----
                probes = []
                for name, _v in params_of(url):
                    probes.append((name, with_param(
                        url, name,
                        f'wscan"><svg onload="document.documentElement.'
                        f'setAttribute(\'data-wsx\',\'{name}\')">')))
                if not params_of(url):
                    probes.append(("(fragment)", url.split("#")[0] +
                                   '#<svg onload="document.documentElement.'
                                   'setAttribute(\'data-wsx\',\'frag\')">'))
                for name, probe_url in probes[:3]:
                    try:
                        page.goto(probe_url, timeout=10000,
                                  wait_until="domcontentloaded")
                        page.wait_for_timeout(500)
                        marker = page.evaluate(
                            "document.documentElement.getAttribute('data-wsx')")
                    except Exception:
                        marker = None
                    if marker:
                        shot = ""
                        if shots_dir:
                            shot = os.path.join(
                                shots_dir, f"xss-{out['visited']}-{name}.png"
                                .replace("/", "_"))
                            try:
                                page.screenshot(path=shot)
                                out["screenshots"].append(
                                    {"url": url, "file": shot})
                            except Exception:
                                shot = ""
                        f = F.add(
                            "High", "Cross-Site Scripting (browser-confirmed)",
                            url,
                            "The payload EXECUTED in a real Chromium browser: "
                            "it set a marker attribute on the page's root "
                            "element. This is not reflection-pattern matching — "
                            "JavaScript ran in the page context.",
                            proof=f"Chromium executed payload; "
                                  f"data-wsx='{marker}'",
                            param=name if name != "(fragment)" else "",
                            resp=None, cwe="CWE-79",
                            payload=_probe_payload(probe_url, name))
                        if f and shot:
                            f["screenshot"] = shot
                        break
            browser.close()
            browser = None
    except Exception as e:
        ctx.emit(f"Browser engine error: {e}")
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
    out["extra_links"] = sorted(set(out["extra_links"]))[:30]
    out["xhr_urls"] = sorted(set(_xhr))[:40] if "_xhr" in dir() else []
    return out


def capture_findings(ctx, items, shots_dir, limit=8):
    """Evidence screenshots: render the page behind the most serious
    GET findings and attach the shot to each finding, so the report
    carries visual proof instead of only text. Returns shot records."""
    out = []
    if not _OK or not shots_dir:
        return out
    targets = []
    for f in items:
        if f.get("screenshot") or f.get("is_chain"):
            continue
        if f.get("severity") not in ("Critical", "High", "Medium"):
            continue
        req = f.get("request") or "GET"
        if not req.startswith("GET"):
            continue
        targets.append(f)
        if len(targets) >= limit:
            break
    if not targets:
        return out
    os.makedirs(shots_dir, exist_ok=True)
    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            _seed_cookies(context, ctx.opts.get("cookie"), ctx.base)
            page = context.new_page()
            for f in targets:
                if ctx.stop.is_set():
                    break
                try:
                    page.goto(f["url"], timeout=10000,
                              wait_until="domcontentloaded")
                    page.wait_for_timeout(400)
                    shot = os.path.join(shots_dir,
                                        f"finding-{f['id']}.png")
                    page.screenshot(path=shot)
                    f["screenshot"] = shot
                    out.append({"url": f["url"], "file": shot,
                                "finding": f["id"]})
                except Exception:
                    continue
            browser.close()
            browser = None
    except Exception:
        pass
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
    return out
