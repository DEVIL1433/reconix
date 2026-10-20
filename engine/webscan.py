#!/usr/bin/env python3
"""
Reconix 3.20 — deep web vulnerability scanner with proof-based findings + EASM.

  CLI:    python3 webscan.py http://127.0.0.1:8080 --profile full
  Web UI: python3 app.py            -> http://127.0.0.1:8777

Profiles: quick | full | api | passive
CI:     --fail-on High  (exit 2 if any finding >= severity)
Zero dependencies — Python 3.8+ stdlib only. Scan only targets you own
or are authorized to test.
"""
import argparse
import json
import os
import sys

try:  # Windows consoles default to cp1252 — findings contain →, — etc.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wscan.core import SEVERITIES, SEV_ORDER, esc   # noqa: E402
from wscan.engine import PROFILES, run_scan          # noqa: E402
from wscan.report3 import attacks_for, executive_summary, to_csv, to_pdf  # noqa: E402
from wscan.rules import load_payloads                # noqa: E402

COLORS = {"Critical": "\033[95m", "High": "\033[91m", "Medium": "\033[93m",
          "Low": "\033[96m", "Info": "\033[90m"}


def print_summary(result):
    c = result["counts"]
    print("\n===== SUMMARY =====")
    print("  " + "  ".join(f"{COLORS[s]}{s}: {c.get(s, 0)}\033[0m" for s in SEVERITIES))
    print(f"  Total: {len(result['findings'])} findings on {result['pages']} pages "
          f"| risk {result.get('risk_score', 0)}/100 ({result.get('risk_grade', '')}) "
          f"| {result.get('duration_s', '?')}s")
    _sus = [f for f in result["findings"] if f.get("fp_suspect")]
    if _sus:
        print(f"  Suspected false positives ({len(_sus)}):")
        for f in _sus[:10]:
            print(f"    ? {f['title']} — {f.get('fp_reason', '')}")
    _sup = result.get("suppressed_findings") or []
    if _sup:
        print(f"  Suppressed as known false positives ({len(_sup)}):")
        for f in _sup[:10]:
            print(f"    - {f['title']} @ {f['url']}")


def write_html(result, path):
    rows = ""
    for f in result["findings"]:
        color = {"Critical": "#f4534a", "High": "#f59e0b", "Medium": "#eab308",
                 "Low": "#22c55e", "Info": "#8e8e96"}[f["severity"]]
        atk = attacks_for(f)
        tech = (
            (f"<p><b>Request (the one that found it):</b></p><pre>{esc(f['request'])}</pre>" if f.get("request") else "")
            + (f"<p><b>Response (excerpt):</b></p><pre>{esc(f['response_snippet'])}</pre>" if f.get("response_snippet") else "")
            + (f"<p><b>PoC (curl):</b></p><pre>{esc(f['poc_curl'])}</pre>" if f.get("poc_curl") else "")
            + (f"<p><b>PoC (python):</b></p><pre>{esc(f['poc_python'])}</pre>" if f.get("poc_python") else "")
            + (f"<p><b>PoC (auto-submit page):</b></p><pre>{esc(f['poc_html'])}</pre>" if f.get("poc_html") else ""))
        rows += (
            f"<details><summary><b style='color:{color}'>{f['severity']}</b> "
            f"{esc(f['title'])} — <code>{esc(f['url'])}</code></summary>"
            + (f"<div class='rrow'><div class='rlab'>What</div><div>{esc(f['about'])}</div></div>" if f.get("about") else f"<div class='rrow'><div class='rlab'>What</div><div>{esc(f['detail'])}</div></div>")
            + f"<div class='rrow'><div class='rlab'>Where</div><div><code>{esc(f['url'])}</code>"
            + (f"<br>Input: <code>{esc(f['param'])}</code>" if f.get("param") else "")
            + f"<br><span class='mut'>Confidence: {esc(f['confidence'])}"
            + (f" · CWE: {esc(f['cwe'])}" if f.get("cwe") else "")
            + "</span></div></div>"
            + (f"<div class='rrow'><div class='rlab'>Why</div><div>{esc(f['detail'])}</div></div>" if f.get("about") else "")
            + (f"<div class='rrow'><div class='rlab'>Attacks</div><ul class='atk'>"
               + "".join(f"<li>{esc(a)}</li>" for a in atk) + "</ul></div>" if atk else "")
            + (f"<div class='rrow'><div class='rlab'>Proof</div><div class='rproof'>{esc(f['proof'])}</div></div>" if f.get("proof") else "")
            + (f"<div class='rrow'><div class='rlab'>Proof</div><div class='rproof'>{esc(f['proof_data'])}</div></div>" if f.get("proof_data") else "")
            + f"<div class='rrow'><div class='rlab'>Fix</div><div class='rfix'>{esc(f['remediation'])}</div></div>"
            + (f"<details class='tech'><summary>Technical details — request, response, proof-of-concept</summary>{tech}</details>" if tech else "")
            + "</details>")
    c = result["counts"]
    meta = result.get("report_meta") or {}
    cover = ""
    if meta.get("company") or meta.get("client"):
        cover = ("<div style='border:1px solid #2a2a2e;padding:1.2rem;border-radius:8px;margin-bottom:1rem'>"
                 + (f"<img src='{meta['logo_data']}' style='max-height:64px'><br>" if meta.get("logo_data") else "")
                 + (f"<div style='font-size:22px;font-weight:800;color:#fafafa'>{esc(meta['company'])}</div>" if meta.get("company") else "")
                 + "<div style='font-size:18px;font-weight:700;margin-top:4px'>Web Application Security Assessment</div>"
                 + (f"<div>Prepared for: <b>{esc(meta['client'])}</b></div>" if meta.get("client") else "")
                 + "<div style='color:#f4534a;font-weight:700;margin-top:6px'>CONFIDENTIAL</div></div>")
    methodology = ("<h2>Scope &amp; methodology</h2><div class='exec'>Scope: "
                   + esc(result['target']) + " — automated assessment with Reconix "
                   "(recon, crawling, passive analysis, active proof-based checks, "
                   "out-of-band verification, browser confirmation where available). "
                   "Findings marked 'Needs manual confirmation' require analyst validation.</div>")
    tracker_rows = "".join(
        f"<tr><td>{i}</td><td>{esc(f['title'])}</td><td>{f['severity']}</td>"
        f"<td>{esc(f.get('status','open'))}</td><td></td><td></td></tr>"
        for i, f in enumerate(result["findings"], 1))
    tracker = ("<h2>Remediation tracker</h2><table border='1' cellspacing='0' "
               "cellpadding='6' style='border-collapse:collapse;width:100%'>"
               "<tr><th>#</th><th>Finding</th><th>Severity</th><th>Status</th>"
               f"<th>Owner</th><th>Target date</th></tr>{tracker_rows}</table>")
    exec_sum = esc(executive_summary(result)).replace("\n", "<br>")
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Reconix report — {esc(result['target'])}</title>
<style>body{{font-family:'Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;font-size:14.5px;line-height:1.6;margin:2rem;background:#0a0a0b;color:#d4d4d8}}
h1{{color:#fafafa;border-bottom:1px solid #232326;padding-bottom:.4rem;font-weight:600}}
h2{{color:#fafafa;font-weight:600}}
details{{background:#101012;border:1px solid #232326;border-radius:8px;padding:.7rem 1.1rem;margin:.6rem 0}}
details.tech{{background:transparent;border:none;border-top:1px solid #232326;border-radius:0;padding:.5rem 0 0;margin-top:.4rem}}
details.tech>summary{{color:#71717a;font-size:12.5px}}
summary{{cursor:pointer}}
pre{{background:#0b0b0d;border:1px solid #232326;border-radius:6px;padding:.6rem;overflow:auto;font-family:Consolas,'Courier New',monospace;font-size:12.5px;line-height:1.5;color:#b9b9c0}}code{{word-break:break-all;color:#e4e4e7}}
.exec{{background:#101012;border:1px solid #232326;border-radius:8px;padding:1rem}}
.rrow{{display:grid;grid-template-columns:110px 1fr;gap:14px;padding:11px 0;border-top:1px solid #1d1d20;align-items:start}}
.rlab{{font-size:11px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase;color:#e4e4e7;padding-top:3px}}
.mut{{color:#8e8e96}}
.atk{{list-style:none;margin:0;padding:0}}
.atk li{{padding:2px 0 2px 15px;position:relative}}
.atk li:before{{content:"";position:absolute;left:0;top:10px;width:5px;height:5px;border-radius:50%;background:#fafafa}}
.rproof{{font-family:Consolas,'Courier New',monospace;font-size:12.5px;color:#b9b9c0;white-space:pre-wrap;word-break:break-word}}
.rfix{{color:#a3e635}}
table{{border-collapse:collapse}}
th,td{{border-color:#232326 !important}}
th{{color:#8e8e96;text-align:left}}
a{{color:#93c5fd}}</style></head>
<body>{cover}<h1>Reconix 3.20 report</h1>
<p>Target: <code>{esc(result['target'])}</code> · Profile: {esc(result.get('profile',''))} ·
Pages: {result['pages']} · Findings: {len(result['findings'])}
(Critical {c.get('Critical',0)}, High {c.get('High',0)}, Medium {c.get('Medium',0)},
Low {c.get('Low',0)}, Info {c.get('Info',0)}) · Risk {result.get('risk_score',0)}/100 ·
{esc(result.get('finished_at',''))}</p>
<h2>Executive summary</h2><div class="exec">{exec_sum}</div>
{methodology}
<h2>Findings</h2>{rows}{tracker}</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    ap = argparse.ArgumentParser(description="Reconix 3.20 — deep web vulnerability scanner")
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("--benchmark", action="store_true",
                    help="run the accuracy benchmark (recall on the test "
                         "target + precision on a false-positive bait "
                         "server) and exit")
    ap.add_argument("--profile", choices=list(PROFILES), default="full")
    ap.add_argument("--checks", help="comma-separated check keys (overrides profile)")
    ap.add_argument("--max-pages", type=int, default=60)
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--cookie")
    ap.add_argument("--cookie-b", help="second session cookie (IDOR checks)")
    ap.add_argument("--idor-anon", action="store_true",
                    help="also replay ID URLs anonymously")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--proxy", help="upstream proxy, e.g. http://127.0.0.1:8080 (Burp)")
    ap.add_argument("--delay", type=float, default=0, help="seconds between requests")
    ap.add_argument("--auth-user"); ap.add_argument("--auth-pass")
    ap.add_argument("--auth-login-url")
    ap.add_argument("--auth-test", action="store_true",
                    help="try default credentials on login forms")
    ap.add_argument("--openapi", help="OpenAPI/Swagger JSON URL to import")
    ap.add_argument("--rules-dir", help="folder of JSON detection rules")
    ap.add_argument("--payloads-xss", help="file with extra XSS payloads (1/line)")
    ap.add_argument("--fail-on", choices=list(SEVERITIES),
                    help="exit 2 if any finding at/above this severity (CI mode)")
    ap.add_argument("-o", "--output", help="HTML report path")
    ap.add_argument("--json", help="JSON report path")
    ap.add_argument("--csv", help="CSV report path")
    ap.add_argument("--pdf", help="PDF report path")
    ap.add_argument("--docx", help="DOCX report path (client pack)")
    ap.add_argument("--company", help="your company name for report cover")
    ap.add_argument("--client-name", help="client name for report cover")
    ap.add_argument("--logo", help="logo image path (embedded in HTML report)")
    ap.add_argument("--har", help="HAR file to seed the scan from captured traffic")
    ap.add_argument("--har-out", help="export scan traffic/findings as HAR")
    ap.add_argument("--nuclei", action="store_true", help="also run Nuclei if installed")
    ap.add_argument("--nuclei-file", help="import a Nuclei JSONL results file")
    ap.add_argument("--zap-url", help="running ZAP API base, e.g. http://127.0.0.1:8090")
    ap.add_argument("--zap-key", default="")
    ap.add_argument("--cookie-admin", help="admin session cookie (permission matrix)")
    ap.add_argument("--retest", help="re-test findings from a previous JSON report and exit")
    args = ap.parse_args()
    if args.benchmark:
        from wscan.benchmark import run_benchmark
        run_benchmark()
        return
    if not args.target:
        ap.error("target is required (or use --benchmark)")

    from wscan.client import ensure_url_scheme
    target = ensure_url_scheme(args.target)
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.retest:
        from wscan.client import Client as _C
        from wscan.retest import retest_finding
        with open(args.retest, encoding="utf-8") as fh:
            prev = json.load(fh)
        client = _C(cookie=args.cookie)
        for f in prev.get("findings", []):
            v = retest_finding(client, f)
            print(f"  [{v['verdict']:16}] {f['severity']:8} {f['title']} — {v['detail']}")
        return 0
    opts = {
        "profile": args.profile, "max_pages": args.max_pages,
        "max_depth": args.max_depth, "threads": args.threads,
        "cookie": args.cookie, "cookie_b": args.cookie_b,
        "idor_anon": args.idor_anon, "headers": headers,
        "proxy": args.proxy, "delay": args.delay,
        "auth_test": args.auth_test, "openapi": args.openapi,
        "rules_dir": args.rules_dir,
        "extra_payloads": {"xss": load_payloads(args.payloads_xss)},
        "company": args.company or "", "client_name": args.client_name or "",
        "har_file": args.har, "nuclei": args.nuclei,
        "nuclei_file": args.nuclei_file, "zap_url": args.zap_url,
        "zap_key": args.zap_key, "cookie_admin": args.cookie_admin,
    }
    if args.logo:
        import base64 as _b64
        import mimetypes as _mt
        try:
            with open(args.logo, "rb") as fh:
                mime = _mt.guess_type(args.logo)[0] or "image/png"
                opts["logo_data"] = f"data:{mime};base64," + _b64.b64encode(fh.read()).decode()
        except Exception:
            pass
    if args.checks:
        opts["checks"] = [c.strip() for c in args.checks.split(",") if c.strip()]
    if args.auth_user and args.auth_pass:
        opts["auth"] = {"username": args.auth_user, "password": args.auth_pass,
                        "login_url": args.auth_login_url or target.rstrip("/") + "/login"}
    result = run_scan(target, opts)
    if result.get("error"):
        print(f"[!] {result['error']}")
        return 1
    print_summary(result)
    if args.output:
        write_html(result, args.output)
        print(f"[*] HTML report: {args.output}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[*] JSON report: {args.json}")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as fh:
            fh.write(to_csv(result["findings"]))
        print(f"[*] CSV report: {args.csv}")
    if args.pdf:
        with open(args.pdf, "wb") as fh:
            fh.write(to_pdf(result))
        print(f"[*] PDF report: {args.pdf}")
    if args.docx:
        from wscan.report_docx import to_docx
        with open(args.docx, "wb") as fh:
            fh.write(to_docx(result))
        print(f"[*] DOCX report: {args.docx}")
    if args.har_out:
        with open(args.har_out, "w", encoding="utf-8") as fh:
            fh.write(result.get("har", "{}"))
        print(f"[*] HAR export: {args.har_out}")
    if args.fail_on:
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f["severity"]] <= limit for f in result["findings"]):
            print(f"[!] fail-on {args.fail_on}: matching findings present")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
