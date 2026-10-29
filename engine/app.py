#!/usr/bin/env python3
"""
Reconix web interface — dashboard on http://127.0.0.1:8777

Features: projects, scan profiles, live progress (expand-safe), risk score,
finding management (status / notes / false-positive suppression), scan
diffing, HTTP repeater, scheduled scans (+webhook alerts), trends, site map,
CSV/PDF/HTML/JSON reports, optional API token. Stdlib only; SQLite storage.
"""
import argparse
import base64
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wscan.client import Client, ensure_url_scheme          # noqa: E402
from wscan.core import fingerprint_of    # noqa: E402
from wscan.engine import diff_scans, run_scan   # noqa: E402
from wscan.report3 import attacks_for, to_csv, to_pdf        # noqa: E402
from wscan.report_docx import to_docx          # noqa: E402
from wscan.retest import retest_finding        # noqa: E402

try:
    from wscan import access403 as _a403   # standalone 403 Tester module
except Exception:                          # a broken module must never
    _a403 = None                           # take the scanner down with it

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
from webscan import write_html           # noqa: E402

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")


def _asset_uri(name):
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "assets", name)
        with open(p, "rb") as fh:
            return "data:image/png;base64," + base64.b64encode(
                fh.read()).decode()
    except Exception:
        return ""


MARK_URI = _asset_uri("reconix-mark.png")
LOCKUP_URI = _asset_uri("reconix-lockup.png")
LIVE = {}
LIVE_LOCK = threading.Lock()
A403 = {}
A403_LOCK = threading.Lock()


def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, target TEXT, started TEXT, finished TEXT,
        status TEXT, result TEXT, project TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT, client TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS finding_meta (
        target TEXT, fp TEXT, status TEXT, notes TEXT,
        PRIMARY KEY (target, fp))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY, target TEXT, interval_hours REAL,
        opts TEXT, last_run TEXT, enabled INTEGER)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        domain TEXT, host TEXT, data TEXT, first_seen TEXT, last_seen TEXT,
        PRIMARY KEY (domain, host))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS repeater_log (
        id TEXT PRIMARY KEY, created TEXT, name TEXT, request TEXT,
        response TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS a403_runs (
        id TEXT PRIMARY KEY, target TEXT, started TEXT, finished TEXT,
        status TEXT, result TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS retest_runs (
        id TEXT PRIMARY KEY, scan_id TEXT, target TEXT, started TEXT,
        finished TEXT, status TEXT, result TEXT)""")
    # migrate older scans tables
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN project TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN opts TEXT")
    except Exception:
        pass
    return conn


def _asset_cleanup(conn, removed_targets):
    """Drop attack-surface inventory that no stored scan covers anymore.

    Assets live in their own table (a persistent inventory kept for
    cross-scan diffing), keyed by root domain — deleting scan rows alone
    used to leave them behind, so the Attack Surface page kept showing
    results after History was cleared. Rule: if no scans remain, the
    whole inventory goes; otherwise only the root domains whose scans
    were all removed. Returns how many asset rows were deleted.
    """
    from urllib.parse import urlparse

    from wscan.extrecon import root_domain

    def _root(target):
        t = target or ""
        host = urlparse(t if "://" in t else "https://" + t).hostname or ""
        return root_domain(host) if host else ""

    remaining = [r[0] for r in conn.execute("SELECT target FROM scans")]
    if not remaining:
        n = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        conn.execute("DELETE FROM assets")
        return n
    covered = {_root(t) for t in remaining} - {""}
    gone = {_root(t) for t in removed_targets} - covered - {""}
    n = 0
    for d in gone:
        n += conn.execute("DELETE FROM assets WHERE domain=?",
                          (d,)).rowcount
    return n


def get_setting(key, default=""):
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(key, value):
    conn = db()
    conn.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()


def ensure_api_token():
    """First-run loopback auth: a fresh install has no token, which
    leaves the whole local API open to any local process. Generate a
    per-install random token once and keep it in the settings table
    (the app's private data directory — never in the repo, never in
    git). The token is delivered to the user's browser only by
    injection into the served HTML page, never via an API endpoint."""
    token = get_setting("api_token")
    if not token:
        token = secrets.token_urlsafe(32)
        set_setting("api_token", token)
    return token


def fp_suppress_set(target):
    conn = db()
    rows = conn.execute(
        "SELECT fp FROM finding_meta WHERE target=? AND status='fp'",
        (target,)).fetchall()
    conn.close()
    return {r[0] for r in rows}


def save_scan(scan_id, target, started, status, result=None, project="",
              opts_json=None):
    conn = db()
    if opts_json is None:
        row = conn.execute("SELECT opts FROM scans WHERE id=?",
                           (scan_id,)).fetchone()
        opts_json = row[0] if row else None
    conn.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)",
                 (scan_id, target, started,
                  result.get("finished_at") if result else None, status,
                  json.dumps(result) if result else None, project,
                  opts_json))
    conn.commit()
    conn.close()


def fire_webhook(result):
    url = get_setting("webhook_url")
    if not url or not result:
        return
    changes = result.get("changes") or {}
    if result.get("counts", {}).get("Critical", 0) < 1 \
            and not changes.get("has_changes"):
        return
    try:
        text = (f"Reconix: {result['counts'].get('Critical', 0)} CRITICAL "
                f"finding(s) on {result['target']} "
                f"(risk {result.get('risk_score')}/100)")
        if changes.get("has_changes"):
            bits = []
            if changes.get("new_serious_findings"):
                bits.append("new serious: " + ", ".join(
                    changes["new_serious_findings"][:4]))
            if changes.get("new_subdomains"):
                bits.append("new subdomains: " + ", ".join(
                    changes["new_subdomains"][:4]))
            if changes.get("new_ports"):
                bits.append("new ports: " + ", ".join(
                    str(p) for p in changes["new_ports"][:6]))
            if changes.get("new_endpoints"):
                bits.append(f"{len(changes['new_endpoints'])} new endpoint(s)")
            if changes.get("new_tech"):
                bits.append("new tech: " + ", ".join(changes["new_tech"][:4]))
            text += " | Surface changes — " + "; ".join(bits)
        payload = json.dumps({
            "text": text, "target": result["target"],
            "counts": result["counts"], "changes": changes}).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass


def compute_changes(target, result, scan_id=None):
    """Attack-surface diff vs the previous completed scan of this target."""
    changes = {"has_changes": False}
    try:
        conn = db()
        rows = conn.execute(
            "SELECT id, result FROM scans WHERE target=? AND status='done' "
            "ORDER BY started DESC, rowid DESC LIMIT 5", (target,)).fetchall()
        conn.close()
        prev = None
        for rid, rj in rows:
            if rj and rid != scan_id:
                prev = json.loads(rj)
                break
        if not prev:
            return changes
        cur_fp = {f.get("fp") for f in result.get("findings", [])}
        prev_fp = {f.get("fp") for f in prev.get("findings", [])}
        new_crit = [f["title"] for f in result.get("findings", [])
                    if f.get("fp") not in prev_fp
                    and f["severity"] in ("Critical", "High")]
        changes["new_serious_findings"] = new_crit
        pr, cr = prev.get("recon") or {}, result.get("recon") or {}
        changes["new_subdomains"] = sorted(
            set(cr.get("subdomains", [])) - set(pr.get("subdomains", [])))
        changes["new_ports"] = sorted(
            {p["port"] for p in cr.get("ports", [])}
            - {p["port"] for p in pr.get("ports", [])})
        changes["new_endpoints"] = sorted(
            set((result.get("sitemap") or {}).keys())
            - set((prev.get("sitemap") or {}).keys()))[:20]
        pext = prev.get("extrecon") or {}
        cext = result.get("extrecon") or {}
        if cext:
            p_hosts = {a["host"] for a in pext.get("assets", [])}
            c_hosts = {a["host"] for a in cext.get("assets", [])}
            changes["new_assets"] = sorted(c_hosts - p_hosts)[:20]
            changes["removed_assets"] = sorted(p_hosts - c_hosts)[:20]
            if changes["new_assets"] or changes["removed_assets"]:
                changes["has_changes"] = True
        ptech = set((pr.get("fingerprint") or {}).get("tech", []))
        ctech = set((cr.get("fingerprint") or {}).get("tech", []))
        changes["new_tech"] = sorted(ctech - ptech)
        changes["has_changes"] = any([
            changes["new_serious_findings"], changes["new_subdomains"],
            changes["new_ports"], changes["new_endpoints"],
            changes["new_tech"]])
    except Exception:
        pass
    return changes


SCAN_QUEUE = []          # [{scan_id, target, opts, project}]
QUEUE_LOCK = threading.Lock()
MAX_CONCURRENT_SCANS = 2
_SECRET_OPT_KEYS = ("cookie", "cookie_b", "cookie_admin")


def _redact_opts(opts):
    """Opts as stored in SQLite for queue persistence / resume: secret
    values are replaced by a marker, never written to disk."""
    out = {}
    for k, v in (opts or {}).items():
        if k.startswith("_") or k == "suppress":
            continue
        if k in _SECRET_OPT_KEYS:
            out[k] = "__stored__" if v else v
        elif k == "auth" and isinstance(v, dict):
            a = dict(v)
            if a.get("password"):
                a["password"] = "__stored__"
            out[k] = a
        else:
            out[k] = v
    return out


def _scan_key(target, opts):
    return (target, (opts or {}).get("profile", "full"))


def launch_scan(target, opts, project=""):
    """Dedupe + queue gate for scan starts. The same target+profile can
    never run twice: an identical start returns the existing scan.
    Beyond MAX_CONCURRENT_SCANS, scans queue and start automatically
    as slots free up. Returns (scan_id, state) with state in
    started | queued | duplicate."""
    target = ensure_url_scheme(target)
    key = _scan_key(target, opts)
    scan_id = uuid.uuid4().hex[:12]
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    with QUEUE_LOCK:
        with LIVE_LOCK:
            for sid, st in LIVE.items():
                if st.get("status") in ("running", "queued") \
                        and st.get("scan_key") == key:
                    return sid, "duplicate"
            running = sum(1 for st in LIVE.values()
                          if st.get("status") == "running")
        if running >= MAX_CONCURRENT_SCANS:
            SCAN_QUEUE.append({"scan_id": scan_id, "target": target,
                               "opts": opts, "project": project})
            with LIVE_LOCK:
                LIVE[scan_id] = {
                    "id": scan_id, "target": target, "status": "queued",
                    "started": started,
                    "phase": "Queued — waiting for a free scan slot",
                    "progress": 0, "progress_label": "queued",
                    "findings": [], "log": [], "stop_event": None,
                    "project": project, "scan_key": key}
            save_scan(scan_id, target, started, "queued",
                      project=project,
                      opts_json=json.dumps(_redact_opts(opts)))
            return scan_id, "queued"
        threading.Thread(target=run_scan_thread,
                         args=(scan_id, target, opts, project),
                         daemon=True).start()
        return scan_id, "started"


def pump_queue():
    """Start queued scans while slots are free (called as scans end)."""
    with QUEUE_LOCK:
        while SCAN_QUEUE:
            with LIVE_LOCK:
                running = sum(1 for st in LIVE.values()
                              if st.get("status") == "running")
            if running >= MAX_CONCURRENT_SCANS:
                return
            job = SCAN_QUEUE.pop(0)
            threading.Thread(target=run_scan_thread,
                             args=(job["scan_id"], job["target"],
                                   job["opts"], job["project"]),
                             daemon=True).start()


def run_scan_thread(scan_id, target, opts, project=""):
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    stop_event = threading.Event()
    opts = dict(opts)
    opts["_stop"] = stop_event
    opts["suppress"] = fp_suppress_set(target)
    opts.setdefault("rules_dir", RULES_DIR)
    if not opts.get("company"):
        opts["company"] = get_setting("company_name")
    if not opts.get("logo_data") and LOCKUP_URI and \
            not get_setting("logo_path"):
        opts["logo_data"] = LOCKUP_URI
    if not opts.get("logo_data") and get_setting("logo_path"):
        try:
            import base64 as _b64
            import mimetypes as _mt
            _lp = get_setting("logo_path")
            with open(_lp, "rb") as fh:
                opts["logo_data"] = (f"data:{_mt.guess_type(_lp)[0] or 'image/png'}"
                                      ";base64," + _b64.b64encode(fh.read()).decode())
        except Exception:
            pass

    def on_event(kind, msg, finding=None):
        with LIVE_LOCK:
            st = LIVE.get(scan_id)
            if not st:
                return
            if kind == "phase":
                st["phase"] = msg
                st["log"].append(msg)
            elif kind == "progress":
                st["progress"] = (finding or {}).get("pct", 0)
                if msg:
                    st["progress_label"] = msg
            elif kind == "finding" and finding:
                st["findings"].append(finding)
            st["log"] = st["log"][-60:]

    with LIVE_LOCK:
        LIVE[scan_id] = {"id": scan_id, "target": target, "status": "running",
                         "started": started, "phase": "starting",
                         "progress": 0, "progress_label": "",
                         "findings": [], "log": [], "stop_event": stop_event,
                         "project": project,
                         "scan_key": _scan_key(target, opts)}
    save_scan(scan_id, target, started, "running", project=project,
              opts_json=json.dumps(_redact_opts(opts)))
    # false-positive memory: verdicts from earlier scans of this target
    # suppress the same findings before the engine even starts
    try:
        _c = db()
        _fps = [r[0] for r in _c.execute(
            "SELECT fp FROM finding_meta WHERE target=? AND status='fp'",
            (target,)).fetchall()]
        _c.close()
        if _fps:
            opts["suppress"] = set(_fps)
    except Exception:
        pass
    try:
        result = run_scan(target, opts, on_event=on_event)
        status = "error" if result.get("error") else "done"
    except Exception as e:
        result = {"target": target, "error": str(e), "findings": [],
                  "counts": {}, "pages": 0,
                  "finished_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        status = "error"
    if status == "done":
        ext = result.get("extrecon") or {}
        if ext.get("assets"):
            try:
                conn = db()
                for a in ext["assets"]:
                    conn.execute(
                        "INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?)",
                        (ext.get("root_domain", ""), a["host"],
                         json.dumps(a), a.get("first_seen", ""),
                         a.get("last_seen", "")))
                conn.commit()
                conn.close()
            except Exception:
                pass
        result["changes"] = compute_changes(target, result, scan_id)
        if result["changes"].get("has_changes"):
            save_scan(scan_id, target, started, status, result, project)
    save_scan(scan_id, target, started, status, result, project)
    fire_webhook(result)
    with LIVE_LOCK:
        LIVE.pop(scan_id, None)  # results live in SQLite now — don't leak
    pump_queue()


def _save_retest(run_id, scan_id, target, started, status, result):
    conn = db()
    conn.execute("INSERT OR REPLACE INTO retest_runs VALUES (?,?,?,?,?,?,?)",
                 (run_id, scan_id, target, started,
                  time.strftime("%Y-%m-%d %H:%M:%S"), status,
                  json.dumps(result) if result else None))
    conn.commit()
    conn.close()


def run_retest_thread(run_id, scan_id):
    """One-click Verify-Fix retest of EVERY finding in a stored scan."""
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = db()
    row = conn.execute("SELECT target, result FROM scans WHERE id=?",
                       (scan_id,)).fetchone()
    conn.close()
    if not row or not row[1]:
        _save_retest(run_id, scan_id, "", started, "error",
                     {"error": "scan has no stored results"})
        return
    target = row[0]
    try:
        findings = json.loads(row[1]).get("findings", [])
    except Exception:
        findings = []
    client = Client()
    verdicts = []
    for f in findings:
        try:
            v = retest_finding(client, f)
        except Exception as e:
            v = {"verdict": "Changed", "detail": f"retest error: {e}"}
        verdicts.append({"id": f.get("id"), "title": f.get("title"),
                         "url": f.get("url"),
                         "severity": f.get("severity"),
                         "verdict": v["verdict"], "detail": v["detail"]})
    counts = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    _save_retest(run_id, scan_id, target, started, "done",
                 {"verdicts": verdicts, "counts": counts})


def scheduler_loop():
    while True:
        time.sleep(45)
        try:
            conn = db()
            rows = conn.execute(
                "SELECT id, target, interval_hours, opts, last_run FROM "
                "schedules WHERE enabled=1").fetchall()
            conn.close()
            now = time.time()
            for sid, target, hours, opts_json, last_run in rows:
                target = ensure_url_scheme(target)
                due = True
                if last_run:
                    last = time.mktime(time.strptime(last_run,
                                                     "%Y-%m-%d %H:%M:%S"))
                    due = (now - last) >= float(hours) * 3600
                if due:
                    with LIVE_LOCK:
                        already = any(
                            st.get("status") == "running"
                            and st.get("target") == target
                            for st in LIVE.values())
                    if already:
                        continue  # previous run still going — skip cycle
                    scan_id = uuid.uuid4().hex[:12]
                    conn = db()
                    conn.execute("UPDATE schedules SET last_run=? WHERE id=?",
                                 (time.strftime("%Y-%m-%d %H:%M:%S"), sid))
                    conn.commit()
                    conn.close()
                    threading.Thread(
                        target=run_scan_thread,
                        args=(scan_id, target, json.loads(opts_json or "{}")),
                        daemon=True).start()
        except Exception:
            pass


UI = r"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Reconix 3.28 — Vulnerability Scanner & Attack Surface</title>
<style>
:root{--bg:#0a0a0b;--panel:#101012;--panel2:#141416;--line:#232326;--txt:#dcdce0;
--mut:#8e8e96;--crit:#f4534a;--high:#f59e0b;--med:#eab308;--low:#22c55e;--info:#8e8e96;--navy:#f2f2f4}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,Roboto,'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.55;background:var(--bg);color:var(--txt);display:flex;min-height:100vh}
aside{width:224px;flex:none;background:var(--panel);border-right:1px solid var(--line);position:sticky;top:0;height:100vh;display:flex;flex-direction:column}
.logo{font-size:23px;font-weight:800;letter-spacing:.01em;color:var(--navy);padding:16px 18px 4px}
.logo .xgrad{color:#fafafa}
.logo .ver{font-size:13px;font-weight:700;color:var(--mut);vertical-align:super}
.logo span{color:#71717a}
.tagline{color:var(--mut);font-size:10px;letter-spacing:.22em;padding:0 18px 14px;border-bottom:1px solid var(--line)}
nav{padding:10px 8px;flex:1;overflow:auto}
nav button{display:flex;width:100%;align-items:center;gap:9px;background:none;border:0;border-left:3px solid transparent;color:var(--txt);font-size:14px;font-weight:600;padding:10px 12px;cursor:pointer;border-radius:0 8px 8px 0;text-align:left}
nav button:hover{background:var(--panel2)}
nav button.active{background:#161618;border-left-color:#fafafa;color:#fafafa}
nav .badge{background:#26262a;color:#e4e4e7;font-size:11px;border-radius:9px;padding:0 7px;margin-left:auto}
.sidefoot{padding:12px 18px;border-top:1px solid var(--line)}
.wrap{flex:1;min-width:0}
.topbar{display:flex;align-items:center;gap:12px;background:var(--panel);border-bottom:1px solid var(--line);padding:10px 22px;position:sticky;top:0;z-index:5}
.topbar h2{margin:0;font-size:17px;color:var(--navy)}
main{max-width:1240px;margin:0 auto;padding:24px 26px}
.view{display:none}.view.active{display:block}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select,button{font-family:inherit}
input[type=text],input[type=password],select,textarea{background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:10px;border-radius:8px;font-size:14px}
input[type=text]{flex:1;min-width:200px}
input[type=number]{width:80px;background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:9px;border-radius:8px}
label{font-size:12px;color:var(--mut)}
button{background:#fafafa;color:#0a0a0b;border:0;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer}
button.alt{background:#1b1b1e;color:#e4e4e7;border:1px solid #2a2a2e;padding:9px 14px}
button.danger{background:#b3261e;color:#fff}
button:disabled{opacity:.5;cursor:wait}
.stats{display:flex;gap:10px;flex-wrap:wrap}
.stat{flex:1;min-width:100px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
.stat b{font-size:26px;display:block;font-weight:700;color:var(--navy)}
.finding{border:1px solid var(--line);border-left-width:3px;border-radius:8px;margin:12px 0;background:#0c0c0e}
.finding summary{cursor:pointer;padding:14px 16px;list-style:none;font-size:15px}
.finding .body{padding:0 16px 16px}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 8px;border-radius:20px;letter-spacing:.5px;border:1px solid transparent}
.crit{background:rgba(244,83,74,.13);color:#f4534a;border-color:rgba(244,83,74,.45)}.high{background:rgba(245,158,11,.12);color:#f59e0b;border-color:rgba(245,158,11,.4)}.med{background:rgba(234,179,8,.12);color:#eab308;border-color:rgba(234,179,8,.4)}.low{background:rgba(34,197,94,.12);color:#4ade80;border-color:rgba(34,197,94,.4)}.info{background:rgba(142,142,150,.12);color:#a1a1aa;border-color:rgba(142,142,150,.35)}
.conf{color:var(--mut);font-size:12px;margin-left:8px}
pre{background:#0b0b0d;border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font-family:'Cascadia Code',Consolas,'Courier New',monospace;font-size:12.5px;line-height:1.5;white-space:pre-wrap;word-break:break-all}
h3{color:var(--navy);font-weight:700;letter-spacing:.01em}
h4{margin:14px 0 6px;color:#8e8e96;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.log{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;color:var(--mut);max-height:150px;overflow:auto}
.pbar{height:6px;background:#1f1f22;border-radius:3px;overflow:hidden;margin:6px 0 4px}
.pfill{height:100%;width:0%;background:#fafafa;border-radius:3px;transition:width .5s ease}
.pmeta{font-size:13px;color:var(--mut);margin-bottom:6px}
.pmeta b{color:#fafafa;font-size:14px}
.about{background:#101418;border-left:3px solid #3f3f46;padding:7px 10px;border-radius:0 8px 8px 0;margin:8px 0;font-size:13.5px}
table{width:100%;border-collapse:collapse}
td,th{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
th{text-transform:uppercase;font-size:11px;letter-spacing:.06em;color:var(--mut);font-weight:700}
a{color:#93c5fd;cursor:pointer}
.proof{border-left:3px solid #22c55e;padding-left:10px}
.hidden{display:none}.muted{color:var(--mut);font-size:12px}
textarea{width:100%;font-family:'Cascadia Code',Consolas,monospace;font-size:12.5px;line-height:1.5}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:860px){.grid2{grid-template-columns:1fr}body{flex-direction:column}aside{width:100%;height:auto;position:static}nav{display:flex;overflow:auto}nav button{white-space:nowrap}}
.pill{display:inline-block;background:#1b1b1e;color:#d4d4d8;border:1px solid #2a2a2e;border-radius:9px;padding:0 8px;font-size:11px;font-weight:700}
.pill.new{background:rgba(34,197,94,.15);color:#4ade80;border-color:rgba(34,197,94,.4)}
.riskbar{height:8px;border-radius:4px;background:#1f1f22;overflow:hidden;min-width:70px}
.riskbar i{display:block;height:100%}
.dl-add{background:rgba(34,197,94,.14)}.dl-del{background:rgba(244,83,74,.14)}
.cls-confirmed{color:var(--crit);font-weight:700}.cls-potential{color:var(--med);font-weight:700}
.cls-denied{color:#4ade80;font-weight:700}.cls-inconclusive{color:var(--info);font-weight:700}
.cls-bypass_verified{color:var(--crit);font-weight:700}.cls-weakness_verified{color:var(--crit);font-weight:700}.cls-bypass_candidate{color:#f59e0b;font-weight:700}.cls-misconfig_suspected{color:var(--med);font-weight:700}
.cls-waf_block{color:#a78bfa;font-weight:700}.cls-auth_required{color:var(--info);font-weight:700}
.cls-block_confirmed{color:#4ade80;font-weight:700}
.modebtn{padding:7px 16px;border:1px solid var(--line);background:var(--panel2);border-radius:8px;cursor:pointer;font-weight:600;color:var(--txt)}
.modebtn.on{background:#fafafa;color:#0a0a0b;border-color:#fafafa}
pre .hk{color:var(--navy);font-weight:700}
.secttl{font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:var(--navy);margin:22px 0 10px;border-bottom:1px solid var(--line);padding-bottom:5px}
.fgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:860px){.fgrid{grid-template-columns:1fr}}
.fld label{display:block;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);margin-bottom:5px}
.fld input{width:100%}
.fld input[type=number]{width:100%}
.fld .hint{font-size:11.5px;color:var(--mut);margin-top:4px}
.tgl{display:inline-flex;align-items:center;gap:7px;background:var(--panel2);border:1px solid var(--line);border-radius:16px;padding:6px 13px;font-size:13px;font-weight:600;cursor:pointer;color:var(--txt)}
.tgl input{accent-color:var(--navy);width:15px;height:15px}
.authstrip{display:flex;gap:10px;align-items:flex-start;background:rgba(234,179,8,.07);border:1px solid rgba(234,179,8,.35);border-radius:8px;padding:11px 13px;margin-top:16px}
.authstrip input{width:17px;height:17px;margin-top:1px;accent-color:#b3261e;flex:none}
.howto{font-size:13px;color:var(--mut);margin:6px 0 2px;padding-left:18px}
.howto li{margin:4px 0}
.sumchip{display:inline-block;border-radius:11px;padding:3px 11px;font-size:12px;font-weight:700;color:#fff;margin:0 6px 6px 0}
.jrow{display:grid;grid-template-columns:132px 1fr;gap:18px;padding:16px 0;border-top:1px solid var(--line);align-items:start}
.jrow:first-child{border-top:none;padding-top:4px}
.jlab{font-size:11px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase;color:#e4e4e7;padding-top:3px}
.jlab span{display:block;color:#5b5b63;font-weight:500;letter-spacing:.3px;text-transform:none;margin-top:3px;font-size:11.5px}
.jtxt{font-size:14px;line-height:1.65;color:var(--txt)}
.jtxt .mono{font-family:'Cascadia Code',Consolas,monospace;font-size:12.5px;color:#e4e4e7;word-break:break-all}
.atk{list-style:none;margin:0;padding:0}
.atk li{font-size:14px;line-height:1.55;padding:3px 0 3px 16px;position:relative;color:var(--txt)}
.atk li:before{content:"";position:absolute;left:0;top:10px;width:5px;height:5px;border-radius:50%;background:#fafafa}
.jfix{font-size:14px;line-height:1.6;color:#a3e635}
.jproof{font-family:'Cascadia Code',Consolas,monospace;font-size:12.5px;line-height:1.65;color:#b9b9c0;white-space:pre-wrap;word-break:break-word}
.jpayload{font-family:'Cascadia Code',Consolas,monospace;font-size:12.5px;line-height:1.65;color:#e4e4e7;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:9px 11px;white-space:pre-wrap;word-break:break-word}
.tech{margin-top:8px;border-top:1px solid var(--line);padding-top:10px}
.tech>summary{cursor:pointer;color:#71717a;font-size:12.5px;list-style:none}
@media(max-width:860px){.jrow{grid-template-columns:1fr;gap:5px}}
.cf-overlay{position:fixed;inset:0;background:rgba(4,4,6,.68);display:flex;align-items:center;justify-content:center;z-index:60}
.cf-overlay.hidden{display:none}
.cf-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;width:min(430px,92vw);box-shadow:0 18px 50px rgba(0,0,0,.55)}
.cf-title{font-size:15px;font-weight:800;margin-bottom:6px}
.cf-msg{color:var(--mut);font-size:13.5px;line-height:1.55;white-space:pre-wrap}
.cf-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:70;max-width:min(430px,90vw)}
.toast{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--low);color:var(--txt);padding:11px 14px;border-radius:9px;font-size:13.5px;cursor:pointer;box-shadow:0 10px 30px rgba(0,0,0,.5);opacity:1;transition:opacity .3s}
.toast.err{border-left-color:var(--crit)}
.toast.out{opacity:0}

</style></head><body>
<aside>
  <div class="logo">RECONI<span class="xgrad">X</span> <span class="ver">3.28</span></div>
  <div class="tagline">DISCOVER · SCAN · SECURE</div>
  <nav id="nav">
    <button data-view="dashboard" class="active" onclick="show('dashboard')">Dashboard</button>
    <button data-view="scanner" onclick="show('scanner')">Scanner</button>
    <button data-view="surface" onclick="show('surface')">Attack Surface <span class="badge" id="sfBadge">0</span></button>
    <button data-view="findings" onclick="show('findings')">Findings</button>
    <button data-view="repeater" onclick="show('repeater')">Repeater</button>
    <button data-view="a403" onclick="show('a403')">403 Tester</button>
    <button data-view="automation" onclick="show('automation')">Schedules &amp; Rules</button>
    <button data-view="history" onclick="show('history')">History</button>
    <button data-view="settings" onclick="show('settings')">Settings</button>
  </nav>
  <div class="sidefoot"><input type="text" id="apiToken" placeholder="API token (if set)" style="width:100%;min-width:0;flex:none" onchange="localStorage.setItem('wscan_token',this.value)"></div>
</aside>
<div class="wrap">
<div class="topbar"><h2 id="viewTitle">Dashboard</h2><span class="muted" id="topSub">Proof-based scanning with external reconnaissance</span></div>
<main>

<!-- ================= DASHBOARD ================= -->
<section class="view active" id="view-dashboard">
  <div class="stats" id="dashStats"></div>
  <div class="grid2" style="margin-top:16px">
    <div class="card"><h3 style="margin:4px 0 10px">Current target</h3><div id="dashRecent"></div></div>
    <div class="card"><h3 style="margin:4px 0 10px">Risk trend <span class="muted" id="trendNote"></span></h3><div id="trend"></div>
    <div class="muted">Highest-risk assets right now:</div><div id="dashAssets"></div></div>
  </div>
</section>

<!-- ================= SCANNER ================= -->
<section class="view" id="view-scanner">
<div class="card">
  <div class="row">
    <input type="text" id="target" placeholder="http://127.0.0.1:8080  or  https://example.com">
    <select id="profile"><option value="full">Full scan (incl. external recon)</option><option value="recon">External recon only</option><option value="quick">Quick</option><option value="api">API</option><option value="passive">Passive only</option></select>
    <select id="project"><option value="">No project</option></select>
    <button id="scanBtn" onclick="startScan()">&#9654; Start Scan</button>
    <button id="vaptBtn" onclick="startVapt()" title="Full profile scan; the PDF report downloads automatically when it finishes">&#9654; Run Full VAPT</button>
    <button id="stopBtn" class="danger hidden" onclick="stopScan()">&#9632; Stop</button>
  </div>
  <div class="row" style="margin-top:10px">
    <label>Max pages <input type="number" id="maxPages" value="60"></label>
    <label>Depth <input type="number" id="maxDepth" value="3"></label>
    <label>Threads <input type="number" id="threads" value="6"></label>
    <label style="flex:1">Cookie <input type="text" id="cookie" placeholder="session=..."></label>
  </div>
  <details style="margin-top:10px"><summary class="muted">Advanced: proxy, IDOR, auth, API spec, integrations</summary>
    <div class="row" style="margin-top:8px">
      <label style="flex:1">Proxy (Burp) <input type="text" id="proxy" placeholder="http://127.0.0.1:8080"></label>
      <label style="flex:1">Cookie B (IDOR) <input type="text" id="cookieB" placeholder="second user's session"></label>
      <label><input type="checkbox" id="idorAnon"> IDOR anon</label>
      <label><input type="checkbox" id="authTest"> Default-creds test</label>
    </div>
    <div class="row" style="margin-top:8px">
      <label style="flex:1">Auth user <input type="text" id="authUser"></label>
      <label style="flex:1">Auth pass <input type="password" id="authPass"></label>
      <label style="flex:1">Login URL <input type="text" id="authUrl" placeholder="(default /login)"></label>
      <label style="flex:1">OpenAPI URL <input type="text" id="openapi" placeholder="https://.../openapi.json"></label>
    </div>
    <div class="row" style="margin-top:8px">
      <label style="flex:1">Admin cookie (matrix) <input type="text" id="cookieAdmin" placeholder="admin session"></label>
      <label style="flex:1">HAR file path (seed) <input type="text" id="harFile" placeholder="C:\\captures\\traffic.har"></label>
      <label><input type="checkbox" id="useNuclei"> Run Nuclei</label>
      <label style="flex:1">ZAP API URL <input type="text" id="zapUrl" placeholder="http://127.0.0.1:8090"></label>
    </div>
    <div class="row" style="margin-top:8px">
      <label style="flex:1">Client name (reports) <input type="text" id="clientName" placeholder="Acme Ltd"></label>
    </div>
    <div class="row" style="margin-top:8px">
      <label><input type="checkbox" id="wafAdaptive" checked> WAF-adaptive mode (human pacing, evasion, quiet retry of blocked checks)</label>
      <label><input type="checkbox" id="bizlogicChk" checked> Business-logic attacks on the HAR workflow (step-skip / replay / price tampering)</label>
    </div>
  </details>
  <div class="row" style="margin-top:8px">
    <input type="text" id="newProject" placeholder="New project name" style="flex:none;min-width:180px">
    <input type="text" id="newClient" placeholder="Client (optional)" style="flex:none;min-width:160px">
    <button class="alt" onclick="addProject()">+ Project</button>
  </div>
  <div id="live" class="hidden" style="margin-top:12px">
    <div class="pbar"><div class="pfill" id="pfill"></div></div>
    <div class="pmeta"><b id="ppct">0%</b> <span id="plabel"></span></div>
    <div><b id="phase">…</b></div><div class="log" id="log"></div>
  </div>
</div>
</section>

<!-- ================= ATTACK SURFACE ================= -->
<section class="view" id="view-surface">
  <div class="stats" id="sfStats"></div>
  <div class="card" style="margin-top:16px">
    <div class="row"><input type="text" id="sfSearch" placeholder="Filter assets (host, org, tech)…" oninput="renderSfTable()">
    <select id="sfProvider" onchange="renderSfTable()"><option value="">All providers</option><option>AWS</option><option>Google Cloud</option><option>Azure</option><option>Cloudflare</option><option>DigitalOcean</option></select>
    <select id="sfSort" onchange="renderSfTable()"><option value="risk">Sort: highest risk</option><option value="host">Sort: hostname</option><option value="new">Sort: newest first</option></select></div>
    <div style="overflow:auto;margin-top:10px"><table><thead><tr><th>Host</th><th>IPs</th><th>Org / ASN</th><th>Country</th><th>Cloud / CDN</th><th>Ports</th><th>Tech</th><th>Env</th><th>Risk</th><th>First seen</th></tr></thead>
    <tbody id="sfTable"></tbody></table></div>
  </div>
  <div class="grid2">
    <div class="card"><h3 style="margin:4px 0 10px">DNS &amp; email security</h3><div id="sfDns" class="muted">Run an external-recon scan to populate.</div></div>
    <div class="card"><h3 style="margin:4px 0 10px">Certificates</h3><div id="sfCerts" class="muted">—</div></div>
  </div>
  <div class="grid2">
    <div class="card"><h3 style="margin:4px 0 10px">Cloud assets &amp; public emails</h3><div id="sfCloud" class="muted">—</div></div>
    <div class="card"><h3 style="margin:4px 0 10px">Exposed panels, APIs &amp; status pages</h3><div id="sfExposure" class="muted">—</div></div>
  </div>
</section>

<!-- ================= FINDINGS ================= -->
<section class="view" id="view-findings">
<div class="card hidden" id="resultsCard">
  <h3 style="margin:4px 0 12px">Scan results — <span id="resTarget"></span></h3>
  <div class="stats" id="stats"></div>
  <div style="margin:10px 0"><a id="dlHtml">HTML</a> · <a id="dlJson">JSON</a> · <a id="dlCsv">CSV</a> · <a id="dlPdf">PDF</a> · <a id="dlDocx">DOCX</a> · <a id="dlHar">HAR</a>
  &nbsp;|&nbsp; Compare with: <select id="diffSel" style="padding:5px"></select> <a onclick="doDiff()">diff</a>
  <span id="diffOut" class="muted"></span>
  &nbsp;|&nbsp; <label><input type="checkbox" id="groupToggle" onchange="renderFindings(window._curFindings||[], this.checked)"> Group by root cause</label></div>
  <div style="margin:10px 0"><button class="alt" onclick="retestAll()">⟳ Retest all findings (Verify-Fix)</button>
  <span id="retestOut" class="muted">Replays every finding's original attack against the live target and reports Fixed / Still vulnerable per finding.</span></div>
  <div id="retestPanel"></div>
  <div id="changes" class="hidden" style="background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.3);border-radius:8px;padding:10px;margin:10px 0"></div>
  <div id="findings"></div>
  <div id="suppBox" style="margin-top:14px"></div>
  <details style="margin-top:12px"><summary class="muted">Permission matrix (who can see what)</summary><div id="matrix" style="overflow:auto"></div></details>
  <details style="margin-top:8px"><summary class="muted">Screenshots (browser engine)</summary><div id="shots" class="muted"></div></details>
  <details style="margin-top:8px"><summary class="muted">Site map (crawl graph)</summary><div id="sitemap" class="log" style="max-height:260px"></div></details>
</div>
<div class="card" id="noResults"><h3 style="margin:4px 0">No scan selected</h3><div class="muted">Start a scan, or open one from History.</div></div>
</section>

<!-- ================= REPEATER ================= -->
<section class="view" id="view-repeater">
<div class="card">
  <h3 style="margin:4px 0 10px">HTTP Repeater</h3>
  <div class="row"><select id="rpMethod"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select>
  <input type="text" id="rpUrl" placeholder="http://target/path?x=1"></div>
  <textarea id="rpHeaders" rows="3" placeholder="Headers, one per line: Name: value"></textarea>
  <textarea id="rpBody" rows="3" placeholder="Request body (POST)"></textarea>
  <div class="row" style="margin-top:8px"><button class="alt" onclick="sendRepeat()">Send</button>
  <button class="alt" onclick="saveRepeat()">Save</button><span id="rpStatus" class="muted"></span></div>
  <pre id="rpResp" style="max-height:300px"></pre>
  <div id="rpHistory" class="muted"></div>
</div>
</section>

<!-- ================= 403 TESTER ================= -->
<section class="view" id="view-a403">
<div class="card">
  <div class="row" style="justify-content:space-between;align-items:flex-start">
    <div>
      <h3 style="margin:0">403 Access-Control Assessment</h3>
      <div class="muted" style="font-size:12.5px;margin-top:3px">Standalone assessment engine · never runs during scans · non-destructive checks only · a status change alone never counts as a bypass</div>
    </div>
    <span class="pill" id="a403ModState">Module enabled</span>
  </div>
  <div id="a403Disabled" class="hidden" style="background:rgba(244,83,74,.08);border:1px solid rgba(244,83,74,.35);border-radius:8px;padding:10px;margin:10px 0">This module is disabled. Enable it under Settings → Modules.</div>
  <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">How the assessment works</summary>
    <ul class="howto">
      <li><b>Mode A — Diagnostics</b> — each 403 is profiled against a nonexistent path; the engine identifies <b>who denied it</b> (F5 BIG-IP ASM, CDN/WAF, reverse proxy, application, or authentication layer), captures request IDs (including the F5 support ID for ASM log correlation), infers the likely rejection reason, then compares documented variant requests against the preserved original.</li>
      <li><b>Mode B — Validation</b> — you define the policy: test identities (anonymous + up to two owner test accounts), the access each identity <i>should</i> have, and a harmless test resource identified by a marker string. The engine checks enforcement consistency across equivalent spellings, identities and methods.</li>
      <li><b>VERIFIED means proven</b> — the harmless resource is served to an identity the policy denies, it reproduces on re-verification, and a nonexistent path does not serve the same content. A different status code alone is only ever <i>suspected</i>. HEAD can never verify (it has no body). Cookies and tokens are redacted from every record and report.</li>
    </ul>
  </details>

  <div class="secttl">Mode</div>
  <div class="row" style="gap:8px">
    <button type="button" class="modebtn on" id="a403ModeDiag" onclick="a403SetMode('diagnostics')">Mode A · 403 Diagnostics</button>
    <button type="button" class="modebtn" id="a403ModeVal" onclick="a403SetMode('validation')">Mode B · Access-Control Validation</button>
  </div>
  <div class="muted" id="a403ModeHint" style="font-size:12.5px;margin-top:6px">Diagnostics: find out who is denying the request and why, and whether documented variants are treated consistently.</div>

  <div class="secttl">Targets</div>
  <label>Target URLs <span class="muted">(one per line, max 20 · Mode A: URLs that return 403 · Mode B: the protected resources to validate · every request stays within the defined scope)</span></label>
  <textarea id="a403Urls" rows="4" placeholder="http://127.0.0.1:8080/vault&#10;http://127.0.0.1:8080/console" style="margin-top:5px"></textarea>

  <div class="secttl">Comparison options</div>
  <div class="fgrid">
    <div class="fld"><label>Test account A session cookie (optional)</label><input type="text" id="a403Cookie" placeholder="session=..."><div class="hint">Identity “role A” — anonymous vs signed-in comparison in both modes</div></div>
    <div class="fld"><label>Origin IP / host (optional)</label><input type="text" id="a403Origin" placeholder="203.0.113.10"><div class="hint">Enables edge vs origin comparison</div></div>
    <div class="fld"><label>Extra allowed hosts (optional)</label><input type="text" id="a403Allow" placeholder="staging.example.com"><div class="hint">Comma-separated additional scope</div></div>
    <div class="fld"><label>Known-public control URL (optional)</label><input type="text" id="a403Public" placeholder="https://target/"><div class="hint">Mode B sanity check — a resource that should answer everyone (defaults to the target root)</div></div>
    <div class="fld"><label>Alternate port (optional)</label><input type="number" id="a403AltPort" placeholder="e.g. 8080" min="1" max="65535"><div class="hint">Also test the same app on this port (origin group)</div></div>
  </div>
  <div class="fld" style="margin-top:10px"><label>F5 ASM log excerpt / policy notes (optional)</label><textarea id="a403F5Log" rows="2" placeholder="Paste F5 ASM event-log lines here — if a denial's support ID appears, the report confirms the block against the exact rule."></textarea><div class="hint">Used only for support-ID correlation; never sent anywhere.</div></div>
  <div class="secttl">Technique groups</div>
  <div class="row" style="margin-top:4px">
    <label class="tgl"><input type="checkbox" id="a403GrpPath" checked> A · Path &amp; URL normalization</label>
    <label class="tgl"><input type="checkbox" id="a403GrpOverride" checked> B · Override headers</label>
    <label class="tgl"><input type="checkbox" id="a403GrpHost" checked> C · Host &amp; proxy headers</label>
    <label class="tgl"><input type="checkbox" id="a403GrpIp" checked> D · Client-IP headers</label>
    <label class="tgl"><input type="checkbox" id="a403GrpMethods" checked> E · Methods &amp; verbs</label>
    <label class="tgl"><input type="checkbox" id="a403GrpProtocol" checked> F · Protocol &amp; connection</label>
    <label class="tgl"><input type="checkbox" id="a403GrpAuthctx" checked> G · Auth-context (session tests)</label>
    <label class="tgl"><input type="checkbox" id="a403GrpCache" checked> H · Cache deception</label>
    <label class="tgl"><input type="checkbox" id="a403GrpOrigin" checked> Origin / alternate port</label>
  </div>
  <div class="hint">Mode B runs the full verb set against your harmless resources. In Mode A, PUT/PATCH/DELETE stay behind the write-method opt-in below (diagnostics targets are real 403 pages).</div>

  <div id="a403ValPanel" class="hidden">
  <div class="secttl">Validation policy (Mode B) — define what SHOULD happen</div>
  <div class="fgrid">
    <div class="fld"><label>Test account B session cookie (optional)</label><input type="text" id="a403CookieB" placeholder="session=..."><div class="hint">Identity “role B” — e.g. a lower-privilege account that must stay locked out</div></div>
    <div class="fld"><label>Label for account A</label><input type="text" id="a403LabelA" placeholder="test account A"><div class="hint">Shown in the matrix and records</div></div>
    <div class="fld"><label>Label for account B</label><input type="text" id="a403LabelB" placeholder="test account B"><div class="hint">Shown in the matrix and records</div></div>
  </div>
  <div class="fgrid" style="margin-top:10px">
    <div class="fld"><label>Anonymous should be</label><select id="a403ExpAnon"><option value="deny" selected>Denied</option><option value="allow">Allowed</option></select></div>
    <div class="fld"><label>Account A should be</label><select id="a403ExpA"><option value="allow" selected>Allowed</option><option value="deny">Denied</option></select></div>
    <div class="fld"><label>Account B should be</label><select id="a403ExpB"><option value="deny" selected>Denied</option><option value="allow">Allowed</option></select></div>
  </div>
  <div class="fld" style="margin-top:10px"><label>Harmless test-resource marker</label><input type="text" id="a403Marker" placeholder="e.g. CANARY-TEST-RESOURCE-2026"><div class="hint">A unique string inside YOUR harmless test resource. A weakness is VERIFIED only when this exact content is served to an identity the policy denies — never real credentials or customer data.</div></div>
  <div class="row" style="margin-top:12px">
    <label class="tgl"><input type="checkbox" id="a403ChkWrite"> Write-method tests in Mode A too (PUT/PATCH/DELETE — off by default; Mode B always includes them against the harmless resource)</label>
  </div>
  <div class="fld" style="margin-top:10px"><label>Advanced per-resource policy (JSON, optional)</label><textarea id="a403Policy" rows="3" placeholder='{"https://target/harmless": {"marker": "CANARY-X", "expect": {"anon": "deny", "role_a": "allow", "role_b": "deny"}, "equivalents": ["https://target/harmless/"]}}'></textarea><div class="hint">Per-URL marker / expected access / equivalent URLs. Overrides the fields above for those URLs.</div></div>
  </div>

  <div class="secttl">Limits</div>
  <div class="fgrid">
    <div class="fld"><label>Concurrency</label><input type="number" id="a403Conc" value="3" min="1" max="8"><div class="hint">Parallel target workers (1–8)</div></div>
    <div class="fld"><label>Max requests</label><input type="number" id="a403MaxReq" value="1200" min="50" max="5000"><div class="hint">Hard request budget for the run</div></div>
    <div class="fld"><label>Timeout (seconds)</label><input type="number" id="a403Timeout" value="12" min="3" max="60"><div class="hint">Per-request timeout</div></div>
    <div class="fld"><label>Min interval (ms)</label><input type="number" id="a403Interval" value="100" min="0" max="5000"><div class="hint">Rate limit — minimum pause between requests to the same host</div></div>
  </div>

  <div class="authstrip">
    <input type="checkbox" id="a403Auth" onchange="a403Gate()">
    <div><b>Authorization</b><br><span style="font-size:13px">I confirm I am authorized to test these targets. The tester sends only non-destructive requests and never leaves the allowed scope.</span></div>
  </div>
  <div class="row" style="margin-top:14px">
    <button id="a403Start" onclick="startA403()" disabled>&#9654; Start Test</button>
    <button id="a403Stop" class="danger hidden" onclick="stopA403()">&#9632; Stop</button>
    <span style="flex:1"></span>
    <button class="alt" id="a403Json" onclick="exportA403('json')" disabled>Export JSON</button>
    <button class="alt" id="a403Html" onclick="exportA403('html')" disabled>Export HTML</button>
  </div>
  <div id="a403Msg" style="margin-top:8px;color:var(--crit);font-size:13px;min-height:16px"></div>
  <div id="a403Live" class="hidden" style="margin-top:6px">
    <div class="pbar"><div class="pfill" id="a403Fill"></div></div>
    <div class="pmeta"><b id="a403Pct">0%</b> <span id="a403Meta"></span></div>
    <div class="log" id="a403Log"></div>
  </div>
</div>
<div class="card hidden" id="a403Results">
  <div class="row" style="justify-content:space-between;align-items:flex-start">
    <h3 style="margin:0">Results</h3>
    <span class="muted" id="a403ResTarget" style="word-break:break-all;text-align:right"></span>
  </div>
  <div id="a403Stats" style="margin-top:12px"></div>
  <div class="secttl">Target profiles</div>
  <div id="a403Profiles"></div>
  <div id="a403Matrix"></div>
  <div class="secttl">Test results</div>
  <div class="row" style="margin:10px 0">
    <select id="a403FClass" onchange="renderA403()"><option value="">All classifications</option><option value="bypass_verified">BYPASS VERIFIED</option><option value="weakness_verified">Weakness VERIFIED</option><option value="bypass_candidate">Bypass candidate</option><option value="misconfig_suspected">Misconfiguration suspected</option><option value="waf_block">WAF block detected</option><option value="auth_required">Authentication required</option><option value="block_confirmed">Block confirmed</option><option value="inconclusive">Inconclusive</option><option value="confirmed">Confirmed (legacy)</option><option value="potential">Potential (legacy)</option><option value="denied">Denied (legacy)</option></select>
    <select id="a403FSev" onchange="renderA403()"><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>
    <select id="a403FType" onchange="renderA403()"><option value="">All types</option><option>auth-state</option><option>equivalent</option><option>path-normalization</option><option>url-override</option><option>host-header</option><option>ip-header</option><option>trusted-header</option><option>method</option><option>verb-override</option><option>protocol</option><option>auth-context</option><option>cache</option><option>session</option><option>origin</option><option>baseline</option></select>
    <input type="text" id="a403FQ" placeholder="Filter by URL or technique…" oninput="renderA403()" style="flex:1">
  </div>
  <div style="overflow:auto"><table><thead><tr><th>URL</th><th>Type</th><th>Technique</th><th>Original</th><th>Test</th><th>Classification</th><th>Severity</th><th>Confidence</th><th></th></tr></thead><tbody id="a403Table"></tbody></table></div>
  <div id="a403Detail" style="margin-top:14px"></div>
</div>
<div class="card">
  <h3 style="margin:4px 0 10px">Previous 403 Tester runs</h3>
  <table><thead><tr><th>Started</th><th>Target</th><th>Status</th><th></th></tr></thead><tbody id="a403History"><tr><td colspan="4" class="muted">—</td></tr></tbody></table>
</div>
</section>

<!-- ================= AUTOMATION ================= -->
<section class="view" id="view-automation">
<div class="grid2">
<div class="card">
  <h3 style="margin:4px 0 10px">Scheduled scans</h3>
  <div class="row"><input type="text" id="schTarget" placeholder="Target URL">
  <label>every <input type="number" id="schHours" value="24"> h</label>
  <button class="alt" onclick="addSchedule()">Add</button></div>
  <table><thead><tr><th>Target</th><th>Every</th><th>Last run</th><th></th></tr></thead><tbody id="schedules"></tbody></table>
</div>
<div class="card">
  <h3 style="margin:4px 0 10px">Custom rule builder</h3>
  <div class="row"><input type="text" id="ruleName" placeholder="Rule name" style="flex:1">
  <select id="ruleSev"><option>High</option><option>Critical</option><option>Medium</option><option>Low</option><option>Info</option></select></div>
  <div class="row" style="margin-top:8px"><input type="text" id="ruleUrl" placeholder="URL regex (optional)">
  <input type="text" id="ruleBody" placeholder="Body regex (optional)"></div>
  <div class="row" style="margin-top:8px"><input type="text" id="ruleHdr" placeholder="Header name (optional)">
  <input type="text" id="ruleHdrVal" placeholder="Header value regex">
  <input type="text" id="ruleDetail" placeholder="Detail shown in the finding" style="flex:1"></div>
  <div class="row" style="margin-top:8px"><button class="alt" onclick="saveRule()">Save rule</button>
  <span class="muted">Rules apply to every scan (stored in the rules folder).</span></div>
  <div id="ruleList" class="muted" style="margin-top:8px"></div>
</div>
</div>
</section>

<!-- ================= HISTORY ================= -->
<section class="view" id="view-history">
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center">
  <h3 style="margin:4px 0 10px">Scan history</h3>
  <button class="alt" onclick="clearHistory()">Clear old results</button></div>
  <table><thead><tr><th>Started</th><th>Target</th><th>Project</th><th>Status</th><th>Risk</th><th>Findings</th><th></th></tr></thead>
  <tbody id="history"></tbody></table>
</div>
</section>

<!-- ================= SETTINGS ================= -->
<section class="view" id="view-settings">
<div class="card">
  <h3 style="margin:4px 0 10px">Notifications</h3>
  <div class="row"><input type="text" id="webhook" placeholder="Webhook URL (Slack/Teams/generic) — fires on Critical + surface changes">
  <button class="alt" onclick="saveSettings()">Save</button></div>
  <h4>API access</h4>
  <div class="row"><input type="text" id="apiTokenSet" placeholder="Set API token for /api (optional)">
  <button class="alt" onclick="saveToken()">Set token</button></div>
  <h4>Report branding</h4>
  <div class="row"><input type="text" id="companyName" placeholder="Your company name (report cover)">
  <input type="text" id="logoPath" placeholder="Logo file path (optional)">
  <button class="alt" onclick="saveBranding()">Save</button></div>
  <h4>Modules</h4>
  <div class="row"><label style="font-size:13px;color:var(--txt)"><input type="checkbox" id="a403Enabled" checked> 403 Access-Control Assessment Engine (standalone module — never runs during scans)</label>
  <button class="alt" onclick="saveA403Enabled()">Save</button></div>
</div>
</section>

</main></div>
<script>
const _f=window.fetch;window.fetch=(u,o={})=>{o.headers={...(o.headers||{}),'X-Api-Key':localStorage.getItem('wscan_token')||''};return _f(u,o)};
document.getElementById('apiToken').value=localStorage.getItem('wscan_token')||'';
let cur=null,timer=null,ALL_ASSETS=[],LAST_EXT=null;
const SEVC={Critical:'crit',High:'high',Medium:'med',Low:'low',Info:'info'};
const TITLES={dashboard:'Dashboard',scanner:'Scanner',surface:'Attack Surface',findings:'Findings',repeater:'Repeater',a403:'403 Access-Control Assessment',automation:'Schedules & Rules',history:'History',settings:'Settings'};
const SUBS={a403:'Standalone diagnostic module — authorized targets only'};
function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}
function show(v){document.querySelectorAll('.view').forEach(s=>s.classList.remove('active'));
  document.getElementById('view-'+v).classList.add('active');
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===v));
  document.getElementById('viewTitle').textContent=TITLES[v]||v;
  document.getElementById('topSub').textContent=SUBS[v]||'Proof-based scanning with external reconnaissance';
  if(v==='surface') loadAssets();
  if(v==='a403') loadA403History();}
async function startScan(){
  const target=document.getElementById('target').value.trim(); if(!target) return;
  document.getElementById('scanBtn').disabled=true;
  const _vb0=document.getElementById('vaptBtn'); if(_vb0) _vb0.disabled=true;
  document.getElementById('stopBtn').classList.remove('hidden');
  const body={target,profile:document.getElementById('profile').value,
    project:document.getElementById('project').value,
    max_pages:+document.getElementById('maxPages').value,
    max_depth:+document.getElementById('maxDepth').value,
    threads:+document.getElementById('threads').value,
    cookie:document.getElementById('cookie').value.trim()||null,
    cookie_b:document.getElementById('cookieB').value.trim()||null,
    proxy:document.getElementById('proxy').value.trim()||null,
    idor_anon:document.getElementById('idorAnon').checked,
    auth_test:document.getElementById('authTest').checked,
    openapi:document.getElementById('openapi').value.trim()||null,
    cookie_admin:document.getElementById('cookieAdmin').value.trim()||null,
    har_file:document.getElementById('harFile').value.trim()||null,
    nuclei:document.getElementById('useNuclei').checked,
    zap_url:document.getElementById('zapUrl').value.trim()||null,
    waf_adaptive:document.getElementById('wafAdaptive').checked,
    bizlogic:document.getElementById('bizlogicChk').checked,
    client_name:document.getElementById('clientName').value.trim()||null};
  const au=document.getElementById('authUser').value.trim();
  if(au) body.auth={username:au,password:document.getElementById('authPass').value,
    login_url:document.getElementById('authUrl').value.trim()||undefined};
  const r=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json(); cur=j.id; window._lastSig='';
  document.getElementById('live').classList.remove('hidden');
  if(j.state==='duplicate') document.getElementById('phase').textContent='Already running or queued — a scan of this target with this profile exists, so no copy was started. Showing that scan.';
  if(j.state==='queued') document.getElementById('phase').textContent='Queued — the scan slots are busy; this scan starts automatically when one frees up.';
  timer=setInterval(poll,1500); poll();
}
function startVapt(){
  const t=document.getElementById('target').value.trim(); if(!t) return;
  document.getElementById('profile').value='full';
  window._vaptAutoPdf=true;
  startScan();
}
async function stopScan(){ if(cur) await fetch('/api/scans/'+cur+'/stop',{method:'POST'}); }
async function poll(){
  if(!cur) return;
  const r=await fetch('/api/scans/'+cur); const j=await r.json();
  document.getElementById('phase').textContent=j.phase||j.status;
  const pct=j.status==='done'?100:(j.progress||0);
  document.getElementById('pfill').style.width=pct+'%';
  document.getElementById('ppct').textContent=pct+'% scanned';
  document.getElementById('plabel').textContent=j.progress_label||'';
  document.getElementById('log').innerHTML=(j.log||[]).map(esc).join('<br>');
  const fs=j.result?j.result.findings:j.findings;
  if(fs&&fs.length){
    const sig=fs.length+'|'+(j.status||'');
    if(sig!==window._lastSig){window._lastSig=sig;
      renderResults(j.result?j.result.target:j.target, fs, j.result?j.result.counts:null, j.result);}
  }
  if(j.status!=='running'&&j.status!=='queued'){clearInterval(timer);document.getElementById('scanBtn').disabled=false;
    const _vb=document.getElementById('vaptBtn'); if(_vb) _vb.disabled=false;
    if(window._vaptAutoPdf&&j.status==='done'){window._vaptAutoPdf=false;
      document.getElementById('phase').textContent='Full VAPT done \u2014 PDF report downloading.';
      const a=document.createElement('a'); a.href='/api/scans/'+cur+'/pdf'; a.download=''; document.body.appendChild(a); a.click(); a.remove();}
    document.getElementById('stopBtn').classList.add('hidden');loadHistory();loadDiffOptions();loadAssets();}
}
function badgePills(f){
  return `${f.fp_suspect?`<span class="pill" style="background:rgba(234,179,8,.14);color:#eab308" title="${esc(f.fp_reason||'')}">possible FP</span>`:''}
   ${f.is_chain?`<span class="pill" style="background:rgba(167,139,250,.15);color:#a78bfa">⛓ attack chain</span>`:''}
   ${f.proof_verified?`<span class="pill" style="background:rgba(34,197,94,.14);color:#4ade80">✔ auto-proven</span>`:''}`;
}
function simpleRows(f, whereHtml){
  const rows=[];
  if(f.about||f.detail) rows.push(`<div class="jrow"><div class="jlab">What<span>the vulnerability</span></div><div class="jtxt">${esc(f.about||f.detail)}</div></div>`);
  if(whereHtml) rows.push(`<div class="jrow"><div class="jlab">Where</div><div class="jtxt">${whereHtml}</div></div>`);
  if(f.payload) rows.push(`<div class="jrow"><div class="jlab">Payload<span>the exact input used</span></div><div class="jpayload">${esc(f.payload)}</div></div>`);
  if(f.detail&&f.about) rows.push(`<div class="jrow"><div class="jlab">Why<span>it is vulnerable</span></div><div class="jtxt">${esc(f.detail)}</div></div>`);
  if(f.attacks&&f.attacks.length) rows.push(`<div class="jrow"><div class="jlab">Attacks<span>what can be done</span></div><ul class="atk">${f.attacks.map(a=>`<li>${esc(a)}</li>`).join('')}</ul></div>`);
  if(f.proof) rows.push(`<div class="jrow"><div class="jlab">Proof</div><div class="jproof">${esc(f.proof)}</div></div>`);
  if(f.proof_data) rows.push(`<div class="jrow"><div class="jlab">Proof<span>data extracted</span></div><div class="jproof">${esc(f.proof_data)}</div></div>`);
  if(f.screenshot) rows.push(`<div class="jrow"><div class="jlab">Evidence</div><div class="jtxt muted">${esc(f.screenshot)}</div></div>`);
  rows.push(`<div class="jrow"><div class="jlab">Fix</div><div class="jfix">${esc(f.remediation||'')}</div></div>`);
  return rows.join('');
}
function techDetails(f){
  const parts=[];
  if(f.poc_curl) parts.push(`<h4>PoC — curl</h4><pre>${esc(f.poc_curl)}</pre>`);
  if(f.poc_python) parts.push(`<h4>PoC — python</h4><pre>${esc(f.poc_python)}</pre>`);
  if(f.poc_html) parts.push(`<h4>PoC — auto-submit page</h4><pre>${esc(f.poc_html)}</pre>`);
  if(f.request) parts.push(`<h4>Request — the one that found it</h4><pre>${esc(f.request)}</pre>`);
  if(f.response_snippet) parts.push(`<h4>Response (excerpt)</h4><pre>${esc(f.response_snippet)}</pre>`);
  if(!parts.length) return '';
  return `<details class="tech"><summary>Technical details — request, response, proof-of-concept</summary>${parts.join('')}</details>`;
}
function renderFindings(findings, grouped){
  const openIds=window._openIds||new Set();
  if(grouped){
    const groups={};
    findings.forEach(f=>{(groups[f.title]=groups[f.title]||[]).push(f)});
    document.getElementById('findings').innerHTML=Object.entries(groups).map(([title,items])=>{
      const f=items[0];
      const anyPills={fp_suspect:items.some(x=>x.fp_suspect),fp_reason:(items.find(x=>x.fp_suspect)||{}).fp_reason,is_chain:items.some(x=>x.is_chain),proof_verified:items.some(x=>x.proof_verified)};
      const where=items.map(x=>`<div><span class="mono" style="font-family:'Cascadia Code',Consolas,monospace;font-size:12.5px">${esc(x.url)}</span>${x.param?' &middot; input: <code>'+esc(x.param)+'</code>':''}</div>`).join('');
      return `<details class="finding" style="border-left-color:var(--${SEVC[f.severity]==='crit'?'crit':SEVC[f.severity]==='med'?'med':SEVC[f.severity]})">
       <summary><span class="sev ${SEVC[f.severity]}">${f.severity}</span> <b>${esc(title)}</b>
        <span class="pill">${items.length} instance${items.length>1?'s':''}</span>
        <span class="conf">${esc(f.confidence)}${f.cwe?' · '+esc(f.cwe):''}</span>
        ${badgePills(anyPills)}</summary>
       <div class="body">${simpleRows(f, where)}
        <div class="muted" style="margin-top:8px">Untick "Group by root cause" for per-instance analyst controls and Verify Fix.</div>
       </div></details>`}).join('');
    return;
  }
  document.getElementById('findings').innerHTML=findings.map(f=>`
   <details class="finding" data-fid="${f.fp||f.id}" ${openIds.has(String(f.fp||f.id))?'open':''} style="border-left-color:var(--${SEVC[f.severity]==='crit'?'crit':SEVC[f.severity]==='med'?'med':SEVC[f.severity]})">
    <summary><span class="sev ${SEVC[f.severity]}">${f.severity}</span> <b>${esc(f.title)}</b>
     <span class="conf">${esc(f.confidence)}${f.cwe?' · '+esc(f.cwe):''}</span>
     ${f.status?`<span class="sev info">${esc(f.status)}</span>`:''}
     ${badgePills(f)}<br>
     <small style="color:var(--mut)">${esc(f.url)}</small>
     ${f.param?`<div style="margin-top:4px"><span class="sev info">Parameter</span> <code>${esc(f.param)}</code></div>`:''}</summary>
    <div class="body">
      ${simpleRows(f, `<span class="mono">${esc(f.url)}</span>${f.param?` &middot; input: <code>${esc(f.param)}</code>`:''}`)}
      ${techDetails(f)}
      <h4>Analyst</h4>
      <div class="row"><select id="st-${f.fp}" style="padding:6px">
        ${['open','confirmed','fp','fixed'].map(s=>`<option value="${s}" ${f.status===s?'selected':''}>${s==='fp'?'false positive':s}</option>`).join('')}
      </select>
      <input type="text" id="nt-${f.fp}" placeholder="Analyst note" value="${esc(f.notes||'')}" style="flex:1">
      <button class="alt" onclick="saveMeta('${f.fp}')">Save</button>
      <button class="alt" onclick="verifyFix('${f.fp}')">Verify Fix</button>
      <span id="vf-${f.fp}" class="muted"></span></div>
    </div></details>`).join('');
}
function renderResults(target, findings, counts, result){
  const sb=document.getElementById('suppBox');
  if(sb){const sup=(result&&result.suppressed_findings)||[];
    sb.innerHTML=sup.length?`<details class="finding" style="border-left-color:#eab308">
     <summary><span class="sev" style="background:rgba(234,179,8,.14);color:#eab308">Suppressed</span> <b>${sup.length} known false positive${sup.length>1?'s':''} hidden</b>
     <span class="conf">marked false-positive in an earlier scan of this target</span></summary>
     <div class="body">${sup.map(s=>`<div><small>${esc(s.severity)} · ${esc(s.title)} — ${esc(s.url)}</small></div>`).join('')}</div></details>`:'';}
  document.getElementById('resultsCard').classList.remove('hidden');
  document.getElementById('noResults').classList.add('hidden');
  document.getElementById('resTarget').textContent=target;
  counts=counts||findings.reduce((a,f)=>{a[f.severity]=(a[f.severity]||0)+1;return a},{});
  const order=['Critical','High','Medium','Low','Info'];
  const risk=result?result.risk_score:null;
  document.getElementById('stats').innerHTML=order.map(s=>
    `<div class="stat"><b>${counts[s]||0}</b>${s}</div>`).join('')
    +`<div class="stat"><b>${findings.length}</b>Total</div>`
    +(risk!==null&&risk!==undefined?`<div class="stat"><b style="color:${risk>=70?'var(--crit)':risk>=45?'var(--high)':risk>=25?'var(--med)':'var(--low)'}">${risk}</b>Risk /100</div>`:'');
  for(const [id,ext] of [['dlHtml','report.html'],['dlJson','report.json'],['dlCsv','report.csv'],['dlPdf','report.pdf'],['dlDocx','report.docx'],['dlHar','report.har']])
    document.getElementById(id).href='/api/scans/'+cur+'/'+ext;
  window._curFindings=findings;
  window._openIds=new Set([...document.querySelectorAll('#findings details[open]')].map(d=>d.dataset.fid));
  renderFindings(findings, (document.getElementById('groupToggle')||{}).checked);
  const ch=(result&&result.changes)||{};
  const chEl=document.getElementById('changes');
  if(ch.has_changes){chEl.classList.remove('hidden');
    chEl.innerHTML='<b>Attack-surface changes since previous scan:</b> '+
      [ (ch.new_serious_findings||[]).length?('New serious findings: '+ch.new_serious_findings.map(esc).join(', ')):'',
        (ch.new_assets||[]).length?('New assets: '+ch.new_assets.map(esc).join(', ')):'',
        (ch.new_subdomains||[]).length?('New subdomains: '+ch.new_subdomains.map(esc).join(', ')):'',
        (ch.new_ports||[]).length?('New ports: '+Object.values(ch.new_ports).flat().join(', ')):'',
        (ch.new_endpoints||[]).length?(ch.new_endpoints.length+' new endpoint(s)'):'',
        (ch.new_tech||[]).length?('New tech: '+ch.new_tech.map(esc).join(', ')):''
      ].filter(Boolean).join(' · ');
  } else chEl.classList.add('hidden');
  const mx=(result&&result.permission_matrix)||[];
  document.getElementById('matrix').innerHTML=mx.length?('<table><thead><tr><th>URL</th>'+
    Object.keys(mx[0].results).map(k=>'<th>'+esc(k)+'</th>').join('')+'</tr></thead><tbody>'+
    mx.map(r=>'<tr><td style="word-break:break-all">'+esc(r.url)+'</td>'+
      Object.values(r.results).map(v=>'<td>'+(v.status??'—')+' ('+v.length+' B)</td>').join('')+'</tr>').join('')+'</tbody></table>'):'<span class="muted">No matrix for this scan.</span>';
  const shots=(result&&result.screenshots)||[];
  document.getElementById('shots').innerHTML=shots.length?shots.map(s=>esc(s.url)+' → '+esc(s.file)).join('<br>'):'No screenshots captured (browser engine off or unavailable).';
  const sm=(result&&result.sitemap)||{};
  document.getElementById('sitemap').innerHTML=Object.entries(sm).map(([u,links])=>
    `<b>${esc(u)}</b> → ${links.map(esc).join(', ')}`).join('<br>');
  if(result&&result.extrecon){LAST_EXT=result.extrecon;renderExtrecon(result.extrecon);}
}
async function verifyFix(fp){
  const el=document.getElementById('vf-'+fp); el.textContent='replaying original request…';
  const r=await fetch('/api/findings/retest',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({scan_id:cur,fp})});
  const j=await r.json();
  el.textContent=j.verdict?('→ '+j.verdict+': '+j.detail):(j.error||'error');
}
async function saveMeta(fp){
  const status=document.getElementById('st-'+fp).value;
  const notes=document.getElementById('nt-'+fp).value;
  const t=document.getElementById('resTarget').textContent;
  await fetch('/api/findings/meta',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:t,fp,status,notes})});
  toast('Saved. False positives are auto-suppressed in future scans of this target.');
}
async function loadDiffOptions(){
  const r=await fetch('/api/scans'); const j=await r.json();
  document.getElementById('diffSel').innerHTML=j.scans.filter(s=>s.id!==cur&&s.status==='done')
    .map(s=>`<option value="${s.id}">${esc(s.started)} — ${esc(s.target)}</option>`).join('');
}
async function doDiff(){
  const other=document.getElementById('diffSel').value; if(!other||!cur) return;
  const r=await fetch(`/api/scans/${cur}/diff/${other}`); const j=await r.json();
  document.getElementById('diffOut').textContent=
    ` vs selected: ${j.new.length} NEW, ${j.fixed.length} FIXED, ${j.still_open.length} still open. New: `+
    j.new.slice(0,5).map(f=>f.title).join('; ');
}
async function loadHistory(){
  const r=await fetch('/api/scans'); const j=await r.json();
  document.getElementById('history').innerHTML=j.scans.map(s=>`<tr>
    <td>${esc(s.started||'')}</td><td>${esc(s.target)}</td><td>${esc(s.project||'')}</td><td>${esc(s.status)}</td>
    <td>${s.risk??''}</td><td>${s.total??''}</td><td><a onclick="viewScan('${s.id}')">view</a> · <a onclick="deleteScan('${s.id}')">delete</a>${(s.status==='interrupted'||s.status==='stopped')?` · <a onclick="resumeScan('${s.id}')">resume</a>`:''}</td></tr>`).join('');
  const done=j.scans.filter(s=>s.status==='done');
  const critScans=done.length;
  document.getElementById('dashStats').innerHTML=
    `<div class="stat"><b>${j.scans.length}</b>Total scans</div>
     <div class="stat"><b>${critScans}</b>Completed</div>
     <div class="stat"><b>${done[0]?done[0].risk??'—':'—'}</b>Latest risk</div>
     <div class="stat"><b>${done.reduce((a,s)=>a+(s.total||0),0)}</b>Findings (all scans)</div>`;
  const curScan=j.scans.find(s=>s.status==='running')||j.scans[0];
  document.getElementById('dashRecent').innerHTML=curScan?
    `<div style="padding:6px 0"><a onclick="viewScan('${curScan.id}')">${esc(curScan.target)}</a>
     <span class="muted">${esc(curScan.started||'')} · ${esc(curScan.status)} · risk ${curScan.risk??'—'}</span>
     <div class="muted" style="margin-top:4px">Previous scans are under History.</div></div>`
    :'<span class="muted">No scans yet.</span>';
  const byTarget={}; done.forEach(s=>{(byTarget[s.target]=byTarget[s.target]||[]).push(s)});
  const t=Object.keys(byTarget)[0];
  if(t&&byTarget[t].length>1){
    const arr=byTarget[t].slice().reverse();
    const max=Math.max(...arr.map(s=>s.risk||0),1);
    document.getElementById('trendNote').textContent='— '+t;
    document.getElementById('trend').innerHTML='<svg width="100%" height="60">'+arr.map((s,i)=>
      `<rect x="${i*36+4}" y="${58-(s.risk||0)/max*52}" width="26" height="${(s.risk||0)/max*52}" fill="${(s.risk||0)>=70?'#f4534a':(s.risk||0)>=45?'#f59e0b':'#eab308'}"><title>${esc(s.started)} risk ${s.risk}</title></rect>`).join('')+'</svg>';
  }
}
async function viewScan(id){
  cur=id; window._lastSig='';
  const r=await fetch('/api/scans/'+id); const j=await r.json();
  const fs=j.result?j.result.findings:j.findings;
  renderResults(j.result?j.result.target:j.target, fs||[], j.result?j.result.counts:null, j.result);
  loadDiffOptions(); show('findings');
}
async function deleteScan(id){
  if(!await uiConfirm('Delete scan','Delete this scan and its results? If it was the last scan of its domain, its assets are removed from Attack Surface too. This cannot be undone.','Delete')) return;
  const r=await fetch('/api/scans/'+id,{method:'DELETE'}); const j=await r.json();
  if(cur===id) cur=null;
  loadHistory();
  if(j.assets_cleared) toast(j.assets_cleared+' asset(s) removed from Attack Surface.');
}
async function resumeScan(id){
  const r=await fetch('/api/scans/'+id+'/resume',{method:'POST'}); const j=await r.json();
  if(j.error){toast(j.error,'err'); return;}
  toast('Resumed as a new scan ('+(j.state||'started')+').'+(j.note?' Note: '+j.note:''));
  cur=j.id; window._lastSig=''; show('scanner');
  document.getElementById('live').classList.remove('hidden');
  document.getElementById('scanBtn').disabled=true;
  document.getElementById('stopBtn').classList.remove('hidden');
  clearInterval(timer); timer=setInterval(poll,1500); poll();
}
let _retestTimer=null;
async function retestAll(){
  if(!cur){toast('Open a scan from History first.','err'); return;}
  const out=document.getElementById('retestOut');
  out.textContent='Retesting every finding against the live target…';
  document.getElementById('retestPanel').innerHTML='';
  const r=await fetch('/api/scans/'+cur+'/retest',{method:'POST'}); const j=await r.json();
  if(j.error){out.textContent=j.error; return;}
  clearInterval(_retestTimer);
  _retestTimer=setInterval(async()=>{
    const rr=await fetch('/api/retests/'+j.run_id); const rj=await rr.json();
    if(rj.status==='running'){out.textContent='Retest running — replaying the original attacks…'; return;}
    clearInterval(_retestTimer);
    if(!rj.result||!rj.result.verdicts){out.textContent='Retest failed.'; return;}
    const c=rj.result.counts||{};
    out.innerHTML='Retest finished: '+Object.entries(c).map(([k,v])=>'<b>'+v+'</b> '+esc(k)).join(' · ');
    document.getElementById('retestPanel').innerHTML=rj.result.verdicts.map(v=>
      '<div style="padding:5px 0;border-bottom:1px solid var(--line)"><span class="sev '+(v.verdict==='Fixed'?'info':v.verdict==='Still vulnerable'?'crit':'med')+'">'+esc(v.verdict)+'</span> <b>'+esc(v.title)+'</b> <span class="muted">'+esc(v.detail||'')+'</span><br><small>'+esc(v.url)+'</small></div>').join('');
  },2000);
}
async function clearHistory(){
  if(!await uiConfirm('Clear old results','Clear ALL old scan results? Stored scans, their findings and reports will be deleted, and the attack-surface asset inventory built from them goes too. This cannot be undone.','Clear all')) return;
  const r=await fetch('/api/scans',{method:'DELETE'}); const j=await r.json();
  cur=null; loadHistory();
  toast('Cleared '+(j.deleted??0)+' scan(s).'+(j.assets_cleared?' '+(j.assets_cleared)+' asset(s) removed from Attack Surface.':'')+(j.skipped_running?' '+j.skipped_running+' running scan(s) were kept.':''));
}
async function addProject(){
  const name=document.getElementById('newProject').value.trim(); if(!name) return;
  await fetch('/api/projects',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,client:document.getElementById('newClient').value.trim()})});
  loadProjects();
}
async function loadProjects(){
  const r=await fetch('/api/projects'); const j=await r.json();
  document.getElementById('project').innerHTML='<option value="">No project</option>'+
    j.projects.map(p=>`<option value="${esc(p.name)}">${esc(p.name)}${p.client?' ('+esc(p.client)+')':''}</option>`).join('');
}
/* ---------------- Attack Surface ---------------- */
async function loadAssets(){
  const r=await fetch('/api/assets'); const j=await r.json();
  ALL_ASSETS=j.assets||[];
  document.getElementById('sfBadge').textContent=ALL_ASSETS.length;
  const high=ALL_ASSETS.filter(a=>a.risk>=50).length;
  const news=ALL_ASSETS.filter(a=>a.is_new).length;
  const devs=ALL_ASSETS.filter(a=>a.env).length;
  document.getElementById('sfStats').innerHTML=
    `<div class="stat"><b>${ALL_ASSETS.length}</b>Assets tracked</div>
     <div class="stat"><b>${news}</b>New (latest scan)</div>
     <div class="stat"><b>${high}</b>High-risk assets</div>
     <div class="stat"><b>${devs}</b>Dev/staging exposed</div>
     <div class="stat"><b>${new Set(ALL_ASSETS.map(a=>a.domain)).size}</b>Root domains</div>`;
  document.getElementById('dashAssets').innerHTML=ALL_ASSETS.slice(0,5).map(a=>
    `<div style="padding:4px 0;border-bottom:1px solid var(--line)"><b>${esc(a.host)}</b>
     <span class="muted">risk ${a.risk} · ${esc((a.org||[])[0]||'')}</span></div>`).join('')||'<span class="muted">None yet.</span>';
  renderSfTable();
  if(LAST_EXT) renderExtrecon(LAST_EXT);
}
function renderSfTable(){
  const q=(document.getElementById('sfSearch').value||'').toLowerCase();
  const prov=document.getElementById('sfProvider').value;
  const sort=document.getElementById('sfSort').value;
  let rows=ALL_ASSETS.filter(a=>(!q||(a.host+' '+(a.org||[]).join(' ')+' '+(a.tech||[]).join(' ')).toLowerCase().includes(q))
    &&(!prov||a.cloud_provider===prov));
  rows.sort((x,y)=>sort==='risk'?y.risk-x.risk:sort==='host'?x.host.localeCompare(y.host):(y.first_seen||'').localeCompare(x.first_seen||''));
  document.getElementById('sfTable').innerHTML=rows.map(a=>`<tr>
    <td><b>${esc(a.host)}</b> ${a.is_new?'<span class="pill new">NEW</span>':''} ${a.takeover_candidate?'<span class="pill" style="background:rgba(244,83,74,.14);color:#f4534a">TAKEOVER?</span>':''} ${a.dangling?'<span class="pill" style="background:rgba(234,179,8,.14);color:#eab308">DANGLING</span>':''}</td>
    <td>${(a.ips||[]).map(esc).join('<br>')}</td>
    <td>${(a.org||[]).map(esc).join(', ')}<br><span class="muted">${(a.asn||[]).map(esc).join(', ')}</span></td>
    <td>${(a.country||[]).map(esc).join(', ')}</td>
    <td>${esc(a.cloud_provider||'')} ${a.cdn?'<span class="pill">CDN</span>':''}</td>
    <td>${(a.ports||[]).join(', ')}</td>
    <td>${(a.tech||[]).map(esc).join(', ')}</td>
    <td>${a.env?'<span class="pill" style="background:rgba(234,179,8,.14);color:#eab308">'+esc(a.env)+'</span>':''}</td>
    <td><div class="riskbar"><i style="width:${a.risk}%;background:${a.risk>=70?'#f4534a':a.risk>=45?'#f59e0b':a.risk>=25?'#eab308':'#22c55e'}"></i></div>${a.risk}</td>
    <td class="muted">${esc(a.first_seen||'')}</td></tr>`).join('')||'<tr><td colspan="10" class="muted">No assets yet — run a Full or External Recon scan on a domain.</td></tr>';
}
function renderExtrecon(ext){
  if(!ext||!ext.root_domain) return;
  const d=ext.dns||{};
  document.getElementById('sfDns').innerHTML=
    `<b>${esc(ext.root_domain)}</b> · wildcard DNS: ${ext.wildcard_dns?'yes':'no'} · DNSSEC: ${d.dnssec?'enabled':'<b style="color:#f4534a">not detected</b>'}<br>
     SPF: ${d.spf?esc(d.spf.slice(0,90)):'<b style="color:#f4534a">missing</b>'}<br>
     DMARC: ${d.dmarc?esc(d.dmarc.slice(0,90)):'<b style="color:#f4534a">missing</b>'}<br>
     DKIM selectors found: ${(d.dkim_selectors||[]).map(esc).join(', ')||'none'}<br>
     MX: ${(d.MX||[]).map(esc).join(', ')||'—'}<br>NS: ${(d.NS||[]).map(esc).join(', ')||'—'}`;
  const certs=(ext.certificates&&ext.certificates.certificates)||[];
  document.getElementById('sfCerts').innerHTML=certs.length?
    `<div class="muted">${ext.certificates.unique_serials} unique certificates; reused across hosts: ${Object.keys(ext.certificates.reused_across_hosts||{}).length}</div>`+
    certs.slice(0,8).map(c=>`<div style="padding:4px 0;border-bottom:1px solid var(--line)">${esc((c.sans||[])[0]||'')} <span class="muted">· ${esc(c.issuer||'')} · expires ${esc(c.not_after||'')} ${c.days_left!==undefined?'('+c.days_left+'d)':''}</span></div>`).join('')
    :'No certificates collected.';
  const emails=ext.emails||[];
  document.getElementById('sfCloud').innerHTML=
    ((ext.cloud||[]).map(c=>`<div><span class="pill">${esc(c.kind)}</span> ${esc(c.endpoint)} ${c.public_listing?'<b style="color:#f4534a">PUBLIC LISTING</b>':''}</div>`).join('')||'<div class="muted">No cloud endpoints referenced.</div>')+
    (emails.length?'<h4>Public emails</h4>'+emails.slice(0,10).map(e=>esc(e.email)).join('<br>')+((ext.email_patterns||[]).length?'<br><span class="muted">Pattern: '+ext.email_patterns.map(esc).join(', ')+'</span>':''):'');
  document.getElementById('sfExposure').innerHTML=(ext.exposure||[]).length?
    ext.exposure.map(x=>`<div><span class="pill">${esc(x.label)}</span> <a href="${esc(x.url)}" target="_blank">${esc(x.url)}</a> <span class="muted">HTTP ${x.status}</span></div>`).join('')
    :'Nothing exposed from the probe list.';
}
/* ---------------- Repeater ---------------- */
async function sendRepeat(){
  const headers={}; document.getElementById('rpHeaders').value.split('\n').forEach(l=>{
    const i=l.indexOf(':'); if(i>0) headers[l.slice(0,i).trim()]=l.slice(i+1).trim();});
  const r=await fetch('/api/repeat',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({method:document.getElementById('rpMethod').value,
      url:document.getElementById('rpUrl').value,headers,body:document.getElementById('rpBody').value})});
  const j=await r.json();
  document.getElementById('rpStatus').textContent='HTTP '+j.status+' · '+j.elapsed+'s';
  document.getElementById('rpResp').textContent=j.body||j.error||'';
  window._lastRepeat=j;
}
async function saveRepeat(){
  if(!window._lastRepeat) return;
  await fetch('/api/repeat/save',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(window._lastRepeat)}); loadRepeatHistory();
}
async function loadRepeatHistory(){
  const r=await fetch('/api/repeat/history'); const j=await r.json();
  document.getElementById('rpHistory').innerHTML=j.items.map(i=>`<div>${esc(i.created)} — ${esc(i.name)}</div>`).join('');
}
/* ---------------- Automation ---------------- */
async function addSchedule(){
  const target=document.getElementById('schTarget').value.trim(); if(!target) return;
  await fetch('/api/schedules',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target,interval_hours:+document.getElementById('schHours').value,opts:{profile:'full'}})});
  loadSchedules();
}
async function loadSchedules(){
  const r=await fetch('/api/schedules'); const j=await r.json();
  document.getElementById('schedules').innerHTML=j.schedules.map(s=>`<tr><td>${esc(s.target)}</td>
    <td>${s.interval_hours}h</td><td>${esc(s.last_run||'never')}</td>
    <td><a onclick="delSchedule('${s.id}')">delete</a></td></tr>`).join('');
}
async function delSchedule(id){ await fetch('/api/schedules/'+id,{method:'DELETE'}); loadSchedules(); }
async function saveRule(){
  const body={name:document.getElementById('ruleName').value.trim(),
    severity:document.getElementById('ruleSev').value,
    url:document.getElementById('ruleUrl').value.trim(),
    body:document.getElementById('ruleBody').value.trim(),
    header_name:document.getElementById('ruleHdr').value.trim(),
    header_value:document.getElementById('ruleHdrVal').value.trim(),
    detail:document.getElementById('ruleDetail').value.trim()};
  if(!body.name){toast('Give the rule a name','err');return;}
  await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  loadRules();
}
async function loadRules(){
  const r=await fetch('/api/rules'); const j=await r.json();
  document.getElementById('ruleList').innerHTML=j.rules.map(x=>
    `<div><span class="sev info">${esc(x.severity)}</span> ${esc(x.name)} <span class="muted">(${esc(x.file)})</span> <a onclick="delRule('${esc(x.file)}')">delete</a></div>`).join('')||'No rules yet.';
}
async function delRule(f){ await fetch('/api/rules/'+f,{method:'DELETE'}); loadRules(); }
/* ---------------- Settings ---------------- */
async function saveSettings(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({webhook_url:document.getElementById('webhook').value.trim()})});
  toast('Webhook saved.');
}
async function saveToken(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api_token:document.getElementById('apiTokenSet').value.trim()})});
  toast('API token set. Enter it in the sidebar box to keep using the UI.');
}
async function saveBranding(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({company_name:document.getElementById('companyName').value.trim(),
      logo_path:document.getElementById('logoPath').value.trim()})});
  toast('Branding saved — applies to reports of new scans.');
}
/* ---------------- 403 Access Control Tester ---------------- */
let A403_JOB=null,A403_TIMER=null,A403_RECORDS=[],A403_VIEW=[],A403_MODE='diagnostics';
function a403SetMode(m){
  A403_MODE=m;
  document.getElementById('a403ModeDiag').classList.toggle('on',m==='diagnostics');
  document.getElementById('a403ModeVal').classList.toggle('on',m==='validation');
  document.getElementById('a403ValPanel').classList.toggle('hidden',m!=='validation');
  document.getElementById('a403ModeHint').textContent=m==='validation'
    ? 'Validation: define the policy (identities, expected access, harmless-resource marker) — the engine verifies enforcement against it.'
    : 'Diagnostics: find out who is denying the request and why, and whether documented variants are treated consistently.';
}
function a403Gate(){document.getElementById('a403Start').disabled=!document.getElementById('a403Auth').checked}
async function startA403(){
  const msg=document.getElementById('a403Msg');
  if(!document.getElementById('a403Auth').checked){msg.textContent='Tick the authorization confirmation first.';return}
  const urls=document.getElementById('a403Urls').value.split('\n').map(s=>s.trim()).filter(Boolean);
  if(!urls.length){msg.textContent='Add at least one target URL.';return}
  let a403Policy={};
  const a403PolRaw=document.getElementById('a403Policy').value.trim();
  if(a403PolRaw){ try{ a403Policy=JSON.parse(a403PolRaw); }catch(e){ msg.textContent='Advanced policy JSON is invalid: '+e.message; return } }
  const body={authorized:true,urls,mode:A403_MODE,
    allow_hosts:document.getElementById('a403Allow').value.split(',').map(s=>s.trim()).filter(Boolean),
    cookie:document.getElementById('a403Cookie').value.trim(),
    origin:document.getElementById('a403Origin').value.trim(),
    concurrency:+document.getElementById('a403Conc').value||3,
    max_requests:+document.getElementById('a403MaxReq').value||1200,
    timeout:+document.getElementById('a403Timeout').value||12,
    min_interval_ms:+document.getElementById('a403Interval').value||0,
    public_control:document.getElementById('a403Public').value.trim(),
    alt_port:+document.getElementById('a403AltPort').value||null,
    f5_log:document.getElementById('a403F5Log').value,
    checks:{path:document.getElementById('a403GrpPath').checked,
      override:document.getElementById('a403GrpOverride').checked,
      host:document.getElementById('a403GrpHost').checked,
      ip:document.getElementById('a403GrpIp').checked,
      methods:document.getElementById('a403GrpMethods').checked,
      protocol:document.getElementById('a403GrpProtocol').checked,
      authctx:document.getElementById('a403GrpAuthctx').checked,
      cache:document.getElementById('a403GrpCache').checked,
      origin:document.getElementById('a403GrpOrigin').checked,
      write_methods:document.getElementById('a403ChkWrite').checked},
    validation:{role_b_cookie:document.getElementById('a403CookieB').value.trim(),
      role_a_label:document.getElementById('a403LabelA').value.trim(),
      role_b_label:document.getElementById('a403LabelB').value.trim(),
      marker:document.getElementById('a403Marker').value.trim(),
      expect:{anon:document.getElementById('a403ExpAnon').value,
        role_a:document.getElementById('a403ExpA').value,
        role_b:document.getElementById('a403ExpB').value},
      policy:a403Policy}};
  const r=await fetch('/api/a403/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!r.ok){msg.textContent=(j.details?j.error+': '+j.details.join('; '):j.error)||'Could not start.';return}
  A403_JOB=j.id; msg.textContent='';
  document.getElementById('a403Start').disabled=true;
  document.getElementById('a403Stop').classList.remove('hidden');
  document.getElementById('a403Live').classList.remove('hidden');
  document.getElementById('a403Json').disabled=true;
  document.getElementById('a403Html').disabled=true;
  clearInterval(A403_TIMER); A403_TIMER=setInterval(pollA403,1200); pollA403();
}
async function pollA403(){
  if(!A403_JOB) return;
  const r=await fetch('/api/a403/jobs/'+A403_JOB); if(!r.ok) return;
  const j=await r.json();
  const pct=j.total?Math.round(100*(j.done||0)/j.total):0;
  document.getElementById('a403Fill').style.width=pct+'%';
  document.getElementById('a403Pct').textContent=pct+'%';
  document.getElementById('a403Meta').textContent=(j.done||0)+'/'+(j.total||0)+' URLs · '+(j.requests||0)+' requests';
  const lg=document.getElementById('a403Log'); lg.innerHTML=(j.log||[]).map(esc).join('<br>'); lg.scrollTop=lg.scrollHeight;
  if(j.status!=='running'){
    clearInterval(A403_TIMER);
    a403Gate();
    document.getElementById('a403Stop').classList.add('hidden');
    document.getElementById('a403Json').disabled=false;
    document.getElementById('a403Html').disabled=false;
    if(j.result&&j.result.records) renderA403All(j.result);
    else if(j.result&&j.result.error) document.getElementById('a403Msg').textContent='Run failed: '+j.result.error;
    loadA403History();
  }
}
async function stopA403(){ if(A403_JOB) await fetch('/api/a403/jobs/'+A403_JOB+'/stop',{method:'POST'}); }
function exportA403(kind){ if(A403_JOB) window.open('/api/a403/jobs/'+A403_JOB+'/report.'+kind,'_blank'); }
function renderA403All(res){
  document.getElementById('a403Results').classList.remove('hidden');
  document.getElementById('a403ResTarget').textContent=(res.targets||[]).join(', ');
  const s=res.summary||{};
  const roll=res.rollup||{verified_bypass:0,verified_weakness:s.confirmed||0,candidates:0,suspected:s.potential||0,waf_blocked:0,auth_required:0,blocked:s.denied||0,inconclusive:s.inconclusive||0};
  document.getElementById('a403Stats').innerHTML=
    '<span class="sumchip" style="background:var(--crit)">BYPASS VERIFIED '+(roll.verified_bypass||0)+'</span>'+
    '<span class="sumchip" style="background:var(--crit)">Weakness VERIFIED '+(roll.verified_weakness||0)+'</span>'+
    '<span class="sumchip" style="background:#dc6803">Bypass candidates '+(roll.candidates||0)+'</span>'+
    '<span class="sumchip" style="background:var(--med)">Suspected '+(roll.suspected||0)+'</span>'+
    '<span class="sumchip" style="background:#7a4fd0">WAF-blocked '+(roll.waf_blocked||0)+'</span>'+
    '<span class="sumchip" style="background:var(--info)">Auth required '+(roll.auth_required||0)+'</span>'+
    '<span class="sumchip" style="background:#1f9d61">Blocked '+(roll.blocked||0)+'</span>'+
    '<span class="sumchip" style="background:#66788c">Inconclusive '+(roll.inconclusive||0)+'</span>'+
    '<span class="muted">'+(res.mode?'mode: '+esc(res.mode)+' · ':'')+(res.requests_used||0)+' requests'+(res.deduped_tests?' · '+res.deduped_tests+' duplicate tests skipped':'')+' · '+(res.started_at||'')+' → '+(res.finished_at||'')+(res.stopped?' · stopped by user':'')+'</span>';
  document.getElementById('a403Profiles').innerHTML=(res.profiles||[]).map(p=>
    '<div class="about"><b>'+esc(p.url)+'</b> — baseline HTTP '+esc(p.baseline_status??'—')+
    (p.attribution?' · denied by: <b>'+esc(p.attribution.vendor||p.attribution.layer)+'</b> ('+esc(p.attribution.layer)+', '+esc(p.attribution.confidence)+' confidence)':'')+
    (p.server?' · Server: '+esc(p.server):'')+
    (p.f5&&p.f5.support_id?' · <b>F5 support ID: '+esc(p.f5.support_id)+'</b>'+(p.f5.log_correlation&&p.f5.log_correlation.matched?' · <b>confirmed in supplied ASM log</b>':''):'')+
    (p.fingerprint?' · fingerprint: '+esc(p.fingerprint.sha256||'')+' ('+esc(p.fingerprint.size)+' B)':'')+
    (p.public_control?' · public control: HTTP '+esc(p.public_control.status):'')+
    (p.protected_baseline===false?' · <b>resource NOT protected at baseline</b>':'')+
    (p.custom_error_page?' · <b>custom/generic error page suspected</b>':'')+
    (p.auth_required?' · auth required':'')+
    ((p.likely_reasons&&p.likely_reasons.length)?'<br><i>Likely reason:</i> '+p.likely_reasons.map(esc).join('<br>'):'')+
    ((p.notes&&p.notes.length)?'<br>'+p.notes.map(esc).join('<br>'):'')+'</div>').join('');
  const mx=(res.profiles||[]).filter(p=>p.matrix&&p.matrix.length);
  document.getElementById('a403Matrix').innerHTML=mx.length?
    '<div class="secttl">Validation matrix — expected policy vs observed access</div>'+
    mx.map(p=>'<div class="about"><b>'+esc(p.url)+'</b><br>'+p.matrix.map(m=>
      esc(m.label)+': policy <b>'+esc(m.expected)+'</b> → observed <b>'+esc(m.access)+'</b> (HTTP '+esc(m.status)+', layer: '+esc(m.layer||'—')+') '+(m.match?'<span style="color:#1f9d61"><b>ok</b></span>':'<span style="color:var(--crit)"><b>MISMATCH</b></span>')).join('<br>')+'</div>').join('')
    :'';
  A403_RECORDS=res.records||[];
  document.getElementById('a403Detail').innerHTML='';
  renderA403();
}
function renderA403(){
  const fc=document.getElementById('a403FClass').value,
        fs=document.getElementById('a403FSev').value,
        ft=document.getElementById('a403FType').value,
        fq=document.getElementById('a403FQ').value.toLowerCase();
  A403_VIEW=A403_RECORDS.filter(r=>(!fc||r.classification===fc)&&(!fs||r.severity===fs)&&(!ft||r.type===ft)&&(!fq||(r.url+' '+r.technique).toLowerCase().includes(fq)));
  document.getElementById('a403Table').innerHTML=A403_VIEW.map((r,i)=>
    '<tr><td style="word-break:break-all">'+esc(r.url)+'</td><td>'+esc(r.group||'')+(r.group?'<br><small>':'')+esc(r.type)+(r.group?'</small>':'')+'</td><td>'+esc(r.technique)+'</td>'+
    '<td>'+esc(r.original.status)+' / '+esc(r.original.size)+' B</td>'+
    '<td>'+esc(r.test.status)+' / '+esc(r.test.size)+' B</td>'+
    '<td class="cls-'+esc(r.classification)+'">'+esc(r.class_label)+'</td>'+
    '<td><span class="sev '+(SEVC[r.severity]||'info')+'">'+esc(r.severity)+'</span></td>'+
    '<td>'+esc(r.confidence)+'</td>'+
    '<td><a onclick="viewA403('+i+')">compare</a></td></tr>').join('')||'<tr><td colspan="9" class="muted">No results match the filters.</td></tr>';
}
function hlReq(t){
  return esc(t||'').replace(/^([A-Z]+ \S+ HTTP\/[\d.]+)/,'<span class="hk">$1</span>')
    .replace(/\n([A-Za-z0-9-]+):/g,'\n<span class="hk">$1:</span>');
}
function hlResp(snap){
  const hdrs=Object.entries(snap.headers||{}).map(([k,v])=>'<span class="hk">'+esc(k)+':</span> '+esc(v)).join('\n');
  return '<span class="hk">HTTP '+esc(snap.status)+'</span> · '+esc(snap.size)+' bytes · '+esc(snap.content_type||'')+(hdrs?'\n'+hdrs:'');
}
function diffLines(body,otherBody,side){
  const mine=(body||'').split('\n').slice(0,400), other=new Set((otherBody||'').split('\n'));
  return mine.map(l=>{const mark=l.trim()&&!other.has(l);
    return '<span class="'+(mark?(side==='test'?'dl-add':'dl-del'):'')+'">'+esc(l)+'</span>'}).join('\n');
}
function viewA403(i){
  const r=A403_VIEW[i]; if(!r) return;
  document.getElementById('a403Detail').innerHTML=
   '<div class="card" style="margin:0"><h3 style="margin:4px 0 8px">'+esc(r.technique)+' — <span class="cls-'+esc(r.classification)+'">'+esc(r.class_label)+'</span></h3>'+
   '<div class="about">'+esc(r.about)+'</div>'+
   '<p style="margin:6px 0">'+(r.hypothesis?'<b>Hypothesis:</b> '+esc(r.hypothesis)+'<br>':'')+
   (r.expected?'<b>Expected:</b> '+esc(r.expected)+'<br>':'')+
   (r.identity?'<b>Identity:</b> '+esc(r.identity)+'<br>':'')+
   (r.group?'<b>Technique group:</b> '+esc(r.group)+'<br>':'')+
   (r.verify&&r.verify.observations?'<b>Verification:</b> reproduced on '+esc(r.verify.matches)+' of '+esc(r.verify.observations)+' observations · catch-all guard '+(r.verify.guard_ok===false?'FAILED':'passed')+' · fingerprint match: '+esc(r.fingerprint_match??'n/a')+'<br>':'')+
   (r.vendor?'<b>Responding layer:</b> '+esc(r.vendor)+' ('+esc(r.layer||'')+')<br>':'')+
   (r.f5&&r.f5.support_id?'<b>F5 support ID:</b> '+esc(r.f5.support_id)+' · <b>response time:</b> '+esc(r.f5.timestamp||'')+'<br>':'')+
   (r.request_ids&&Object.keys(r.request_ids).length?'<b>Request IDs:</b> '+esc(Object.entries(r.request_ids).map(([k,v])=>k+'='+v).join(', '))+'<br>':'')+
   '<b>Evidence:</b> '+esc(r.evidence)+'<br><b>Remediation:</b> '+esc(r.remediation)+
   '<br><span class="muted">Body similarity original vs test: '+esc(r.similarity??'—')+(r.comparison?' · status changed: '+(r.comparison.status_changed?'yes':'no')+' · size delta: '+(r.comparison.size_delta>=0?'+':'')+r.comparison.size_delta+' B · layer: '+(r.comparison.layer_original||'—')+' → '+(r.comparison.layer_test||'—'):'')+' · checked '+esc(r.checked_at)+'</span></p>'+
   '<div class="grid2"><div><h4>Original request</h4><pre>'+hlReq(r.original.request)+'</pre>'+
   '<h4>Original response</h4><pre>'+hlResp(r.original)+'</pre></div>'+
   '<div><h4>Test request</h4><pre>'+hlReq(r.test.request)+'</pre>'+
   '<h4>Test response</h4><pre>'+hlResp(r.test)+'</pre></div></div>'+
   '<div class="grid2"><div><h4>Original body (red = only here)</h4><pre>'+diffLines(r.original.body,r.test.body,'orig')+'</pre></div>'+
   '<div><h4>Test body (green = only here)</h4><pre>'+diffLines(r.test.body,r.original.body,'test')+'</pre></div></div></div>';
  document.getElementById('a403Detail').scrollIntoView({behavior:'smooth',block:'nearest'});
}
async function loadA403History(){
  try{
    const r=await fetch('/api/a403/runs'); if(!r.ok) return;
    const j=await r.json();
    document.getElementById('a403Enabled').checked=j.enabled!==false;
    document.getElementById('a403Disabled').classList.toggle('hidden',j.enabled!==false);
    const ms=document.getElementById('a403ModState'); if(ms){ms.textContent=j.enabled!==false?'Module enabled':'Module disabled'; ms.style.background=j.enabled!==false?'':'#b3261e'; ms.style.color=j.enabled!==false?'':'#fff';}
    document.getElementById('a403History').innerHTML=(j.runs||[]).map(x=>
      '<tr><td>'+esc(x.started)+'</td><td style="word-break:break-all">'+esc(x.target)+'</td><td><span class="pill">'+esc(x.status)+'</span></td><td><a onclick="openA403Run(\''+x.id+'\')">open</a></td></tr>').join('')||'<tr><td colspan="4" class="muted">No runs yet.</td></tr>';
  }catch(e){}
}
async function openA403Run(id){
  A403_JOB=id;
  const r=await fetch('/api/a403/jobs/'+id); if(!r.ok) return;
  const j=await r.json();
  document.getElementById('a403Json').disabled=false;
  document.getElementById('a403Html').disabled=false;
  if(j.result&&j.result.records) renderA403All(j.result);
}
async function saveA403Enabled(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({a403_enabled:document.getElementById('a403Enabled').checked?'1':'0'})});
  toast('Module setting saved.');
  loadA403History();
}
/* ---------------- In-app dialogs & toasts (no native pop-ups) ---------------- */
let _cfResolve=null;
function uiConfirm(title,msg,label){
  return new Promise(res=>{
    _cfResolve=res;
    document.getElementById('cfTitle').textContent=title;
    document.getElementById('cfMsg').textContent=msg;
    document.getElementById('cfOk').textContent=label||'Delete';
    document.getElementById('cfOverlay').classList.remove('hidden');
    document.getElementById('cfOk').focus();
  });
}
function _cfDone(v){
  document.getElementById('cfOverlay').classList.add('hidden');
  if(_cfResolve){const r=_cfResolve;_cfResolve=null;r(v);}
}
document.addEventListener('keydown',e=>{
  if(!_cfResolve) return;
  if(e.key==='Escape') _cfDone(false);
  else if(e.key==='Enter') _cfDone(true);
});
function toast(msg,kind){
  const box=document.getElementById('toasts');
  const t=document.createElement('div');
  t.className='toast'+(kind==='err'?' err':'');
  t.textContent=msg;
  t.title='Click to dismiss';
  t.onclick=()=>t.remove();
  box.appendChild(t);
  setTimeout(()=>{t.classList.add('out'); setTimeout(()=>t.remove(),320);},5000);
}
loadHistory(); loadProjects(); loadSchedules(); loadRepeatHistory(); loadRules(); loadAssets(); loadA403History();
</script>
<div id="cfOverlay" class="cf-overlay hidden" onclick="if(event.target===this)_cfDone(false)">
  <div class="cf-card" role="alertdialog" aria-modal="true">
    <div class="cf-title" id="cfTitle">Are you sure?</div>
    <div class="cf-msg" id="cfMsg"></div>
    <div class="cf-actions">
      <button class="alt" onclick="_cfDone(false)">Cancel</button>
      <button class="danger" id="cfOk" onclick="_cfDone(true)">Delete</button>
    </div>
  </div>
</div>
<div id="toasts"></div>
</body></html>"""


# --- Mobile app shell (Reconix 3.28) -------------------------------------
# Injected into the UI only when the request comes from the Android app
# (User-Agent contains "ReconixAndroid"). Desktop/laptop UI is untouched.
MOBILE_HEAD = r"""
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<style id="rxMobileCss">
html{-webkit-text-size-adjust:100%}
*{-webkit-tap-highlight-color:transparent;touch-action:manipulation}
body{display:block;font-size:15px}
aside{position:fixed;top:0;left:0;right:0;width:auto;height:52px;flex-direction:row;
 align-items:center;border-right:0;border-bottom:1px solid var(--line);z-index:60;padding:0 14px}
aside .logo{font-size:19px;padding:0}
aside .tagline,aside nav,aside .sidefoot{display:none}
.wrap{margin-top:52px;padding-bottom:92px}
main{max-width:none;padding:14px 12px 8px}
.topbar{flex-wrap:wrap;gap:2px;margin-bottom:10px}
.topbar h2{font-size:20px}
#topSub{font-size:12px;flex-basis:100%}
.card{border-radius:14px;padding:14px;margin-bottom:12px}
.row{flex-wrap:wrap;gap:9px}
input,select,textarea{font-size:16px!important;min-height:46px;padding:10px 12px;border-radius:10px}
input[type=checkbox]{min-height:0;width:20px;height:20px;vertical-align:-4px}
button{min-height:46px;padding:10px 16px;border-radius:10px;font-size:15px}
label{font-size:14px}
.stats{flex-wrap:wrap;gap:9px}
.stat{min-width:100px;flex:1}
.stat b{font-size:22px}
.grid2,.fgrid{grid-template-columns:1fr!important}
#view-scanner #target{flex:1 1 100%;font-size:16px;padding:13px}
#view-scanner #profile,#view-scanner #project{flex:1 1 44%}
#scanBtn,#vaptBtn{flex:1 1 100%;padding:15px;font-size:16.5px;font-weight:700}
#stopBtn{flex:1 1 100%}
.pbar{height:10px;border-radius:6px}
.pmeta{font-size:15px}
#phase{font-size:15px}
.log{max-height:170px;font-size:12px;line-height:1.65}
#rxRing{display:none;margin:6px auto 2px;width:168px;height:168px;position:relative}
#rxRing.on{display:block}
#rxRing svg{transform:rotate(-90deg)}
#rxRing .rc{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
#rxRing .rp{font-size:31px;font-weight:800;color:var(--navy)}
#resultsCard h3,.finding summary small,.finding .mono{overflow-wrap:anywhere;word-break:break-word}
#rxRing .rph{font-size:10.5px;letter-spacing:1.4px;line-height:1.45;color:var(--mut);text-transform:uppercase;max-width:130px;text-align:center;overflow-wrap:anywhere;word-break:break-word;display:-webkit-box;-webkit-line-clamp:5;-webkit-box-orient:vertical;overflow:hidden}
.finding{padding:15px}
.jrow{grid-template-columns:1fr;gap:4px;padding:11px 0}
.sev{font-size:11.5px;padding:4px 10px}
table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch;max-width:100%}
details>summary{padding:10px 0;font-size:14.5px}
h3{font-size:16.5px}
#rxTabs{position:fixed;left:0;right:0;bottom:0;z-index:70;display:flex;background:#0d0d0f;
 border-top:1px solid var(--line);padding:6px 2px calc(8px + env(safe-area-inset-bottom))}
#rxTabs button{flex:1;background:none;border:0;color:#6d6d75;font-size:10.5px;font-weight:600;
 min-height:52px;padding:4px 0;display:flex;flex-direction:column;align-items:center;gap:3px;border-radius:0}
#rxTabs button .ic{font-size:20px;line-height:1}
#rxTabs button.on{color:#fafafa}
#rxMoreSheet{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.62);display:none}
#rxMoreSheet.open{display:block}
#rxMoreSheet .sheet{position:absolute;left:0;right:0;bottom:0;background:#101012;
 border-top:1px solid var(--line);border-radius:18px 18px 0 0;padding:10px 14px calc(16px + env(safe-area-inset-bottom))}
#rxMoreSheet .sheet button{display:flex;width:100%;align-items:center;gap:12px;background:none;border:0;
 border-bottom:1px solid var(--line);color:var(--txt);font-size:16px;padding:15px 4px;text-align:left;border-radius:0}
#rxMoreSheet .sheet button:last-child{border-bottom:0}
</style>
"""

MOBILE_BODY = r"""
<div id="rxMoreSheet" onclick="if(event.target===this)rxMore(false)">
  <div class="sheet">
    <button onclick="rxGo('surface')">&#9673;&nbsp; Attack Surface</button>
    <button onclick="rxGo('repeater')">&#8635;&nbsp; Repeater</button>
    <button onclick="rxGo('a403')">&#9940;&nbsp; 403 Tester</button>
    <button onclick="rxGo('automation')">&#128337;&nbsp; Schedules &amp; Rules</button>
    <button onclick="rxGo('settings')">&#9881;&nbsp; Settings</button>
  </div>
</div>
<nav id="rxTabs">
  <button data-rx="dashboard" class="on" onclick="rxGo('dashboard')"><span class="ic">&#8962;</span>Home</button>
  <button data-rx="scanner" onclick="rxGo('scanner')"><span class="ic">&#8982;</span>Scan</button>
  <button data-rx="findings" onclick="rxGo('findings')"><span class="ic">&#9888;</span>Findings</button>
  <button data-rx="history" onclick="rxGo('history')"><span class="ic">&#128340;</span>History</button>
  <button data-rx="more" onclick="rxMore(true)"><span class="ic">&#9776;</span>More</button>
</nav>
<script>
(function(){
  var MAIN={dashboard:1,scanner:1,findings:1,history:1};
  window.rxMore=function(open){document.getElementById('rxMoreSheet').classList.toggle('open',!!open);};
  window.rxGo=function(v){rxMore(false);show(v);rxSync(v);window.scrollTo(0,0);
    if(window._lastRx!==v){try{history.pushState({rx:v},'', '#'+v);}catch(e){}window._lastRx=v;}};
  window.addEventListener('popstate',function(e){
    var v=(e.state&&e.state.rx)||''; if(!v){show('dashboard');rxSync('dashboard');window._lastRx='dashboard';return;}
    show(v);rxSync(v);window._lastRx=v;});
  function rxSync(v){
    document.querySelectorAll('#rxTabs button').forEach(function(b){
      b.classList.toggle('on', b.dataset.rx===v || (b.dataset.rx==='more' && !MAIN[v]));
    });
  }
  var _show=window.show;
  window.show=function(v){_show(v);rxSync(v);};
  // Progress ring for the scanner (Concept B)
  var live=document.getElementById('live');
  if(live){
    var wrap=document.createElement('div'); wrap.id='rxRing';
    wrap.innerHTML='<svg width="168" height="168"><circle cx="84" cy="84" r="74" fill="none" stroke="#1c1c1f" stroke-width="11"/>'
      +'<circle id="rxArc" cx="84" cy="84" r="74" fill="none" stroke="#a3e635" stroke-width="11" stroke-linecap="round" stroke-dasharray="465" stroke-dashoffset="465"/></svg>'
      +'<div class="rc"><div class="rp" id="rxPct">0%</div><div class="rph" id="rxPhase">starting</div></div>';
    live.insertBefore(wrap, live.firstChild);
    var C=465;
    setInterval(function(){
      var on=!live.classList.contains('hidden');
      wrap.classList.toggle('on', on);
      if(!on) return;
      var pct=parseInt((document.getElementById('ppct')||{}).textContent||'0',10)||0;
      document.getElementById('rxPct').textContent=pct+'%';
      document.getElementById('rxArc').style.strokeDashoffset=C-(C*pct/100);
      var ph=(document.getElementById('phase')||{}).textContent||'';
      if(ph.indexOf('Target ')===0){var hm=ph.match(/Target https?:\/\/([^\/\s]+)/);ph=hm?hm[1]:'Starting scan';}
      document.getElementById('rxPhase').textContent=ph;
    },600);
  }
})();
</script>
"""



def _scan_view(scan_id):
    with LIVE_LOCK:
        st = LIVE.get(scan_id)
        if st:
            out = dict(st)
            out["findings"] = list(st.get("findings") or [])
            out["log"] = list(st.get("log") or [])
            out.pop("stop_event", None)
            out.pop("scan_key", None)
            return out
    conn = db()
    row = conn.execute(
        "SELECT target, started, status, result, project FROM scans WHERE id=?",
        (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = json.loads(row[3]) if row[3] else None
    return {"id": scan_id, "target": row[0], "started": row[1],
            "status": row[2], "result": result,
            "findings": result["findings"] if result else [],
            "project": row[4]}


def attach_meta(view):
    """Merge analyst status/notes into findings."""
    if not view:
        return view
    result = view.get("result")
    findings = result["findings"] if result else view.get("findings") or []
    if not findings:
        return view
    conn = db()
    rows = conn.execute("SELECT fp, status, notes FROM finding_meta "
                        "WHERE target=?", (view["target"],)).fetchall()
    conn.close()
    meta = {fp: (s, n) for fp, s, n in rows}
    for f in findings:
        fp = f.get("fp") or fingerprint_of(f)
        f["fp"] = fp
        if "attacks" not in f:
            f["attacks"] = attacks_for(f)
        if fp in meta:
            f["status"], f["notes"] = meta[fp]
    return view


def run_a403_thread(job_id, urls, opts):
    """Background runner for the standalone 403 Access Control Tester."""
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    stop_event = threading.Event()
    with A403_LOCK:
        A403[job_id] = {"id": job_id, "status": "running",
                        "started": started, "targets": urls, "done": 0,
                        "total": len(urls), "requests": 0, "log": [],
                        "stop_event": stop_event, "result": None}

    def progress(**kw):
        with A403_LOCK:
            st = A403.get(job_id)
            if not st:
                return
            for k in ("done", "total", "requests"):
                if k in kw:
                    st[k] = kw[k]
            if kw.get("log"):
                st["log"].append(kw["log"])

    try:
        result = _a403.analyze(urls, opts, stop=stop_event,
                               progress=progress)
        status = "stopped" if stop_event.is_set() else "done"
    except Exception as exc:  # module errors must not kill the server
        result = {"error": f"{type(exc).__name__}: {exc}"}
        status = "error"
    finished = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = db()
        conn.execute("INSERT OR REPLACE INTO a403_runs VALUES (?,?,?,?,?,?)",
                     (job_id, urls[0] if urls else "", started, finished,
                      status, json.dumps(result)))
        conn.commit()
        conn.close()
    except Exception:
        pass
    with A403_LOCK:
        st = A403.get(job_id)
        if st:
            st["status"] = status
            st["result"] = result
            st["finished"] = finished


def _a403_view(job_id):
    with A403_LOCK:
        st = A403.get(job_id)
    if st:
        return {k: v for k, v in st.items() if k != "stop_event"}
    conn = db()
    row = conn.execute(
        "SELECT id, target, started, finished, status, result FROM "
        "a403_runs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "targets": [row[1]], "started": row[2],
            "finished": row[3], "status": row[4],
            "result": json.loads(row[5]) if row[5] else None, "log": []}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        token = get_setting("api_token")
        if not token:
            return True
        return self.headers.get("X-Api-Key") == token

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 10_000_000:
            return {}  # absurd for this API — refuse to allocate it
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    # ------------------------------------------------------------ GET
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            html = UI.replace("%%MARK%%", MARK_URI).replace(
                "%%LOCKUP%%", LOCKUP_URI)
            # Loopback token delivery: the page's own fetch wrapper
            # reads localStorage 'wscan_token' on every request, so the
            # browser always sends the current server token without the
            # user ever typing one. Injected into the HTML head only —
            # no endpoint hands the token out.
            _tok = ensure_api_token()
            _script = ("<script>try{localStorage.setItem('wscan_token',%s)}"
                       "catch(e){}</script>" % json.dumps(_tok))
            html = html.replace('<meta charset="utf-8">',
                                '<meta charset="utf-8">' + _script, 1)
            if "ReconixAndroid" in (self.headers.get("User-Agent") or ""):
                html = html.replace('<meta charset="utf-8">',
                                    '<meta charset="utf-8">' + MOBILE_HEAD, 1)
                html = html.replace("</body>", MOBILE_BODY + "</body>", 1)
            data = html.encode()
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if not self._authed():
            return self._json({"error": "API token required"}, 401)
        if path == "/api/rules":
            rules = []
            if os.path.isdir(RULES_DIR):
                import glob as _glob
                for fp_ in sorted(_glob.glob(os.path.join(RULES_DIR, "*.json"))):
                    try:
                        with open(fp_, encoding="utf-8") as fh:
                            data = json.load(fh)
                        for rule in data if isinstance(data, list) else [data]:
                            rules.append({"file": os.path.basename(fp_),
                                          "name": rule.get("name", ""),
                                          "severity": rule.get("severity", "")})
                    except Exception:
                        pass
            return self._json({"rules": rules})
        if path == "/api/assets":
            conn = db()
            rows = conn.execute(
                "SELECT domain, host, data FROM assets").fetchall()
            conn.close()
            assets = []
            for domain, host, data in rows:
                try:
                    a = json.loads(data)
                    a["domain"] = domain
                    assets.append(a)
                except Exception:
                    pass
            assets.sort(key=lambda a: -a.get("risk", 0))
            return self._json({"assets": assets})
        if path == "/api/projects":
            conn = db()
            rows = conn.execute("SELECT name, client FROM projects").fetchall()
            conn.close()
            return self._json({"projects": [{"name": n, "client": c}
                                            for n, c in rows]})
        if path == "/api/schedules":
            conn = db()
            rows = conn.execute(
                "SELECT id, target, interval_hours, last_run FROM schedules "
                "WHERE enabled=1").fetchall()
            conn.close()
            return self._json({"schedules": [
                {"id": i, "target": t, "interval_hours": h, "last_run": lr}
                for i, t, h, lr in rows]})
        if path == "/api/repeat/history":
            conn = db()
            rows = conn.execute(
                "SELECT id, created, name FROM repeater_log ORDER BY created "
                "DESC LIMIT 30").fetchall()
            conn.close()
            return self._json({"items": [
                {"id": i, "created": c, "name": n} for i, c, n in rows]})
        if path == "/api/scans":
            conn = db()
            rows = conn.execute(
                "SELECT id, target, started, status, result, project FROM "
                "scans ORDER BY started DESC LIMIT 50").fetchall()
            conn.close()
            scans = []
            for sid, target, started, status, result, project in rows:
                total, risk = None, None
                if result:
                    try:
                        rj = json.loads(result)
                        total = len(rj.get("findings", []))
                        risk = rj.get("risk_score")
                    except Exception:
                        pass
                scans.append({"id": sid, "target": target, "started": started,
                              "status": status, "total": total, "risk": risk,
                              "project": project or ""})
            with LIVE_LOCK:
                for sid, st in LIVE.items():
                    if st["status"] == "running" and not any(
                            s["id"] == sid for s in scans):
                        scans.insert(0, {"id": sid, "target": st["target"],
                                         "started": st["started"],
                                         "status": "running", "total":
                                         len(st["findings"]), "risk": None,
                                         "project": st.get("project", "")})
            return self._json({"scans": scans})
        if path.startswith("/api/retests/"):
            run_id = path.split("/")[3]
            conn = db()
            row = conn.execute(
                "SELECT scan_id, target, started, status, result FROM "
                "retest_runs WHERE id=?", (run_id,)).fetchone()
            conn.close()
            if not row:
                return self._json({"error": "not found"}, 404)
            return self._json({
                "id": run_id, "scan_id": row[0], "target": row[1],
                "started": row[2], "status": row[3],
                "result": json.loads(row[4]) if row[4] else None})
        if path.startswith("/api/scans/"):
            parts = path.split("/")
            scan_id = parts[3]
            if len(parts) == 5 and parts[4] == "retests":
                conn = db()
                rows = conn.execute(
                    "SELECT id, started, status, result FROM retest_runs "
                    "WHERE scan_id=? ORDER BY started DESC LIMIT 10",
                    (scan_id,)).fetchall()
                conn.close()
                out = []
                for rid, rstarted, rstatus, rresult in rows:
                    counts = {}
                    if rresult:
                        try:
                            counts = json.loads(rresult).get("counts", {})
                        except Exception:
                            pass
                    out.append({"id": rid, "started": rstarted,
                                "status": rstatus, "counts": counts})
                return self._json({"retests": out})
            if len(parts) == 6 and parts[4] == "diff":
                a, b = _scan_view(scan_id), _scan_view(parts[5])
                if not a or not b or not a.get("result") or not b.get("result"):
                    return self._json({"error": "both scans need results"}, 404)
                d = diff_scans(b["result"], a["result"])
                return self._json({k: [{"title": f["title"],
                                         "severity": f["severity"],
                                         "url": f["url"]} for f in v]
                                   for k, v in d.items()})
            if len(parts) == 5 and parts[4].startswith("report."):
                conn = db()
                row = conn.execute("SELECT result FROM scans WHERE id=?",
                                   (scan_id,)).fetchone()
                conn.close()
                if not row or not row[0]:
                    return self._json({"error": "not found"}, 404)
                result = json.loads(row[0])
                kind = parts[4].split(".", 1)[1]
                if kind == "json":
                    return self._json(result)
                result = attach_meta({"target": result.get("target", ""),
                                      "result": result})["result"]
                if kind == "csv":
                    data = to_csv(result["findings"]).encode()
                    ctype, ext = "text/csv", "csv"
                elif kind == "docx":
                    data = to_docx(result)
                    ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    ext = "docx"
                elif kind == "har":
                    data = (result.get("har") or "{}").encode()
                    ctype, ext = "application/json", "har"
                elif kind == "pdf":
                    data = to_pdf(result)
                    ctype, ext = "application/pdf", "pdf"
                else:
                    import tempfile as _tf
                    fd, tmp = _tf.mkstemp(suffix=".html")
                    os.close(fd)
                    try:
                        write_html(result, tmp)
                        with open(tmp, "rb") as fh:
                            data = fh.read()
                    finally:
                        os.unlink(tmp)
                    ctype, ext = "text/html", "html"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition",
                                 f"attachment; filename=webscan-{scan_id[:8]}.{ext}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            view = attach_meta(_scan_view(scan_id))
            if not view:
                return self._json({"error": "not found"}, 404)
            return self._json(view)
        if path == "/api/a403/runs":
            if _a403 is None:
                return self._json(
                    {"error": "403 Tester module unavailable"}, 503)
            conn = db()
            rows = conn.execute(
                "SELECT id, target, started, status FROM a403_runs "
                "ORDER BY started DESC LIMIT 20").fetchall()
            conn.close()
            runs = [{"id": i, "target": t, "started": s, "status": st}
                    for i, t, s, st in rows]
            with A403_LOCK:
                for jid, st in A403.items():
                    if st["status"] == "running" and not any(
                            r["id"] == jid for r in runs):
                        runs.insert(0, {
                            "id": jid,
                            "target": st["targets"][0] if st["targets"]
                            else "",
                            "started": st["started"], "status": "running"})
            return self._json({
                "runs": runs,
                "enabled": get_setting("a403_enabled", "1") != "0"})
        if path.startswith("/api/a403/jobs/"):
            if _a403 is None:
                return self._json(
                    {"error": "403 Tester module unavailable"}, 503)
            parts = path.split("/")
            job_id = parts[4] if len(parts) > 4 else ""
            view = _a403_view(job_id)
            if not view:
                return self._json({"error": "not found"}, 404)
            if len(parts) == 6 and parts[5] in ("report.json",
                                                "report.html"):
                result = view.get("result")
                if not result:
                    return self._json({"error": "run not finished"}, 409)
                if parts[5] == "report.json":
                    data = json.dumps(result, indent=1).encode()
                    ctype, ext = "application/json", "json"
                else:
                    data = _a403.to_html(result).encode()
                    ctype, ext = "text/html", "html"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=reconix-403tester-"
                    f"{job_id[:8]}.{ext}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return self._json(view)
        return self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------ POST
    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/") and not self._authed():
            return self._json({"error": "API token required"}, 403)
        if path == "/api/projects":
            body = self._body()
            conn = db()
            conn.execute("INSERT OR REPLACE INTO projects VALUES (?,?,?)",
                         (uuid.uuid4().hex[:8], body.get("name", ""),
                          body.get("client", "")))
            conn.commit()
            conn.close()
            return self._json({"ok": True})
        if path == "/api/rules":
            body = self._body()
            import re as _re
            name = (body.get("name") or "custom rule").strip()
            slug = _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "rule"
            match = {}
            if body.get("url"):
                match["url"] = body["url"]
            if body.get("body"):
                match["body"] = body["body"]
            if body.get("header_name"):
                match["header"] = {body["header_name"]: body.get("header_value", ".*")}
            if body.get("status"):
                match["status"] = int(body["status"])
            rule = {"name": name, "severity": body.get("severity", "Medium"),
                    "detail": body.get("detail", "Custom rule matched."),
                    "match": match}
            os.makedirs(RULES_DIR, exist_ok=True)
            with open(os.path.join(RULES_DIR, f"ui-{slug}.json"), "w",
                      encoding="utf-8") as fh:
                json.dump([rule], fh, indent=1)
            return self._json({"ok": True, "file": f"ui-{slug}.json"})
        if path == "/api/findings/retest":
            body = self._body()
            view = _scan_view(body.get("scan_id", ""))
            if not view or not view.get("result"):
                return self._json({"error": "scan not found"}, 404)
            finding = next((f for f in view["result"]["findings"]
                            if (f.get("fp") or fingerprint_of(f))
                            == body.get("fp")), None)
            if not finding:
                return self._json({"error": "finding not found"}, 404)
            verdict = retest_finding(Client(), finding)
            if verdict["verdict"] == "Fixed":
                conn = db()
                conn.execute(
                    "INSERT OR REPLACE INTO finding_meta VALUES (?,?,?,?)",
                    (view["target"], body.get("fp"), "fixed",
                     "Verify-Fix: " + verdict["detail"]))
                conn.commit()
                conn.close()
            return self._json(verdict)
        if path == "/api/settings":
            body = self._body()
            for k in ("webhook_url", "api_token", "company_name",
                      "logo_path", "a403_enabled"):
                if k in body:
                    # A blank api_token would silently reopen the API
                    # (empty token means "no auth" in _authed), so a
                    # blank value is ignored and the current token kept.
                    if k == "api_token" and not str(body[k]).strip():
                        continue
                    set_setting(k, body[k])
            return self._json({"ok": True})
        if path == "/api/a403/run":
            if _a403 is None:
                return self._json(
                    {"error": "403 Tester module unavailable"}, 503)
            if get_setting("a403_enabled", "1") == "0":
                return self._json(
                    {"error": "403 Tester module is disabled in "
                              "Settings"}, 403)
            body = self._body()
            if body.get("authorized") is not True:
                return self._json(
                    {"error": "authorization confirmation required"}, 400)
            raw_urls = body.get("urls") or []
            if isinstance(raw_urls, str):
                raw_urls = [u for u in raw_urls.splitlines() if u.strip()]
            urls, errors = [], []
            for u in list(raw_urls)[:_a403.MAX_URLS]:
                clean, err = _a403.validate_url(u)
                if err:
                    errors.append(f"{u}: {err}")
                elif clean not in urls:
                    urls.append(clean)
            if errors:
                return self._json({"error": "invalid target URL(s)",
                                   "details": errors}, 400)
            if not urls:
                return self._json(
                    {"error": "at least one target URL required"}, 400)
            opts = {
                "mode": body.get("mode") or "diagnostics",
                "cookie": body.get("cookie") or "",
                "origin": body.get("origin") or "",
                "allow_hosts": body.get("allow_hosts") or [],
                "concurrency": body.get("concurrency") or 3,
                "timeout": body.get("timeout") or 12,
                "max_requests": body.get("max_requests") or 1200,
                "min_interval_ms": body.get("min_interval_ms"),
                "public_control": body.get("public_control") or "",
                "alt_port": body.get("alt_port"),
                "f5_log": body.get("f5_log") or "",
                "checks": body.get("checks") or {},
                "validation": body.get("validation") or {},
            }
            job_id = uuid.uuid4().hex[:12]
            threading.Thread(target=run_a403_thread,
                             args=(job_id, urls, opts),
                             daemon=True).start()
            return self._json({"id": job_id})
        if path.startswith("/api/a403/jobs/") and \
                path.endswith("/stop"):
            job_id = path.split("/")[4]
            with A403_LOCK:
                st = A403.get(job_id)
            if st and st.get("status") == "running" \
                    and st.get("stop_event"):
                st["stop_event"].set()
                return self._json({"ok": True})
            return self._json({"error": "not running"}, 404)
        if path == "/api/findings/meta":
            body = self._body()
            conn = db()
            conn.execute("INSERT OR REPLACE INTO finding_meta VALUES (?,?,?,?)",
                         (body.get("target", ""), body.get("fp", ""),
                          body.get("status", "open"), body.get("notes", "")))
            conn.commit()
            conn.close()
            return self._json({"ok": True})
        if path == "/api/schedules":
            body = self._body()
            conn = db()
            conn.execute("INSERT INTO schedules VALUES (?,?,?,?,?,1)",
                         (uuid.uuid4().hex[:12],
                          ensure_url_scheme(body.get("target", "")),
                          float(body.get("interval_hours", 24)),
                          json.dumps(body.get("opts", {})), None))
            conn.commit()
            conn.close()
            return self._json({"ok": True})
        if path == "/api/repeat":
            body = self._body()
            client = Client()
            url = ensure_url_scheme(body.get("url", ""))
            if not url:
                return self._json({"status": 0, "elapsed": 0, "body": "",
                                   "error": "URL required",
                                   "request": "", "name": ""}, 400)
            headers = body.get("headers") or {}
            raw = (body.get("body") or "").encode() or None
            try:
                r = client.fetch(url, method=body.get("method", "GET"),
                                 headers=headers, raw_body=raw)
            except Exception as e:
                return self._json({
                    "status": 0, "elapsed": 0, "body": "",
                    "error": f"Request failed: {e}", "request": "",
                    "name": f"{body.get('method','GET')} {url}"})
            if r.status is None:
                return self._json({
                    "status": 0, "elapsed": round(r.elapsed, 2),
                    "body": "",
                    "error": "No response — host unreachable, DNS "
                             "failed, or the connection was refused "
                             "or timed out.",
                    "request": r.request_text,
                    "name": f"{body.get('method','GET')} {url}"})
            return self._json({
                "status": r.status, "elapsed": round(r.elapsed, 2),
                "body": (r.body or "")[:60000],
                "request": r.request_text,
                "name": f"{body.get('method','GET')} {url}"})
        if path == "/api/repeat/save":
            body = self._body()
            conn = db()
            conn.execute("INSERT INTO repeater_log VALUES (?,?,?,?,?)",
                         (uuid.uuid4().hex[:12],
                          time.strftime("%Y-%m-%d %H:%M:%S"),
                          body.get("name", ""), body.get("request", ""),
                          (body.get("body") or "")[:20000]))
            conn.commit()
            conn.close()
            return self._json({"ok": True})
        if path == "/api/scans":
            body = self._body()
            target = (body.get("target") or "").strip()
            if not target:
                return self._json({"error": "target required"}, 400)
            # scheme is resolved in launch_scan (https probed first)
            opts = {k: body.get(k) for k in
                    ("max_pages", "max_depth", "threads", "cookie", "profile",
                     "proxy", "cookie_b", "idor_anon", "auth_test", "openapi",
                     "cookie_admin", "nuclei", "nuclei_file", "zap_url",
                     "har_file", "har_text", "client_name")
                    if body.get(k) not in (None, "", False)}
            if "waf_adaptive" in body:
                opts["waf_adaptive"] = bool(body["waf_adaptive"])
            if "bizlogic" in body:
                opts["bizlogic"] = bool(body["bizlogic"])
            if body.get("auth"):
                a = body["auth"]
                opts["auth"] = {"username": a.get("username", ""),
                                "password": a.get("password", ""),
                                "login_url": a.get("login_url") or
                                target.rstrip("/") + "/login"}
            scan_id, state = launch_scan(target, opts,
                                         body.get("project", ""))
            return self._json({"id": scan_id, "state": state})
        if path.startswith("/api/scans/") and path.endswith("/retest"):
            scan_id = path.split("/")[3]
            conn = db()
            row = conn.execute("SELECT target FROM scans WHERE id=? "
                               "AND result IS NOT NULL",
                               (scan_id,)).fetchone()
            conn.close()
            if not row:
                return self._json({"error": "scan has no results"}, 404)
            run_id = uuid.uuid4().hex[:12]
            _save_retest(run_id, scan_id, row[0],
                         time.strftime("%Y-%m-%d %H:%M:%S"), "running",
                         None)
            threading.Thread(target=run_retest_thread,
                             args=(run_id, scan_id), daemon=True).start()
            return self._json({"run_id": run_id})
        if path.startswith("/api/scans/") and path.endswith("/resume"):
            scan_id = path.split("/")[3]
            conn = db()
            row = conn.execute(
                "SELECT target, status, opts, project FROM scans "
                "WHERE id=?", (scan_id,)).fetchone()
            conn.close()
            if not row:
                return self._json({"error": "not found"}, 404)
            target, status, opts_json, project = row
            if status not in ("interrupted", "stopped", "error"):
                return self._json(
                    {"error": f"a {status} scan cannot be resumed"}, 400)
            try:
                opts = json.loads(opts_json) if opts_json else {}
            except Exception:
                opts = {}
            note = ""
            opts = {k: v for k, v in opts.items() if v != "__stored__"}
            if isinstance(opts.get("auth"), dict) and \
                    opts["auth"].get("password") == "__stored__":
                opts.pop("auth", None)
                note = ("login credentials are not stored, so the "
                        "resumed scan runs unauthenticated")
            conn = db()
            prev = conn.execute(
                "SELECT result FROM scans WHERE target=? AND "
                "status='done' ORDER BY started DESC LIMIT 1",
                (target,)).fetchone()
            conn.close()
            if prev and prev[0]:
                try:
                    smap = json.loads(prev[0]).get("sitemap") or {}
                    if smap:
                        opts["seed_urls"] = list(smap.keys())[:60]
                except Exception:
                    pass
            new_id, state = launch_scan(target, opts, project or "")
            return self._json({"id": new_id, "state": state,
                               "resumed_from": scan_id, "note": note})
        if path.startswith("/api/scans/") and path.endswith("/stop"):
            scan_id = path.split("/")[3]
            with QUEUE_LOCK:
                for i, job in enumerate(SCAN_QUEUE):
                    if job["scan_id"] == scan_id:
                        SCAN_QUEUE.pop(i)
                        with LIVE_LOCK:
                            st = LIVE.pop(scan_id, None)
                        save_scan(scan_id, job["target"],
                                  (st or {}).get("started", ""),
                                  "stopped", project=job["project"])
                        return self._json({"ok": True,
                                           "note": "removed from queue"})
            with LIVE_LOCK:
                st = LIVE.get(scan_id)
            if st and st.get("stop_event"):
                st["stop_event"].set()
                return self._json({"ok": True, "note": "stops at next phase"})
            return self._json({"error": "not running"}, 404)
        return self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/") and not self._authed():
            return self._json({"error": "API token required"}, 403)
        if path.startswith("/api/rules/"):
            fname = os.path.basename(path.split("/")[3])
            fpath = os.path.join(RULES_DIR, fname)
            if os.path.isfile(fpath):
                os.unlink(fpath)
            return self._json({"ok": True})
        if path.startswith("/api/schedules/"):
            conn = db()
            conn.execute("UPDATE schedules SET enabled=0 WHERE id=?",
                         (path.split("/")[3],))
            conn.commit()
            conn.close()
            return self._json({"ok": True})
        if path == "/api/scans":
            # Clear old results: every stored scan except ones still
            # running (their rows are rewritten as the scan progresses).
            with LIVE_LOCK:
                running = {sid for sid, st in LIVE.items()
                           if st.get("status") == "running"}
            conn = db()
            rows = conn.execute("SELECT id, target FROM scans").fetchall()
            doomed = [(i, t) for i, t in rows if i not in running]
            conn.executemany("DELETE FROM scans WHERE id=?",
                             [(i,) for i, _t in doomed])
            assets_cleared = _asset_cleanup(conn, [t for _i, t in doomed])
            conn.commit()
            conn.close()
            return self._json({"ok": True, "deleted": len(doomed),
                               "assets_cleared": assets_cleared,
                               "skipped_running": len(rows) - len(doomed)})
        if path.startswith("/api/scans/"):
            sid = path.split("/")[3]
            with LIVE_LOCK:
                st = LIVE.get(sid)
            if st and st.get("status") == "running":
                return self._json({"error": "scan is running"}, 409)
            conn = db()
            row = conn.execute("SELECT target FROM scans WHERE id=?",
                               (sid,)).fetchone()
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
            assets_cleared = _asset_cleanup(conn, [row[0]] if row else [])
            conn.commit()
            conn.close()
            return self._json({"ok": True, "assets_cleared": assets_cleared})
        return self._json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8777)
    args = ap.parse_args()
    db().close()
    # crash/restart recovery: nothing is legitimately running at
    # process start, so any scan still marked running/queued was cut
    # off mid-flight — mark it interrupted so it can be resumed.
    _c = db()
    _c.execute("UPDATE scans SET status='interrupted' WHERE status IN "
               "('running','queued')")
    _c.commit()
    _c.close()
    # First run: mint the loopback API token so the API is never
    # open by default (see ensure_api_token).
    ensure_api_token()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Reconix 3.28 UI -> http://127.0.0.1:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
