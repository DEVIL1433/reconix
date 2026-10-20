"""External scanner bridges: Nuclei (binary / JSONL import) and OWASP ZAP
(API). Results are normalised into WebScan findings and deduplicated
against what WebScan already found (same URL + same vuln class)."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request

SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info", "informational": "Info",
           "3": "High", "2": "Medium", "1": "Low", "0": "Info"}
CLASS_WORDS = [
    ("sql injection", ("sql injection", "sqli")),
    ("cross-site scripting", ("xss", "cross-site scripting")),
    ("remote code execution", ("rce", "remote code", "command")),
    ("ssrf", ("ssrf", "server-side request forgery")),
    ("lfi", ("lfi", "file inclusion", "path traversal", "directory traversal")),
    ("xxe", ("xxe", "xml external")),
    ("open redirect", ("open redirect",)),
    ("csrf", ("csrf", "cross-site request forgery")),
]


def _class_of(title):
    low = title.lower()
    for canon, words in CLASS_WORDS:
        if any(w in low for w in words):
            return canon
    return ""


def _add_external(ctx, sev, title, url, detail, param="", source=""):
    F = ctx.findings
    cls = _class_of(title)
    if cls:
        for existing in list(F.items):
            if existing["url"] == url and _class_of(existing["title"]) == cls:
                existing["detail"] += f" (Also detected by {source}.)"
                return None
    return F.add(sev, f"{source}: {title}", url, detail,
                 param=param, confidence=f"External tool ({source})",
                 dedupe_key=(source, title, url, param))


def import_nuclei_jsonl(ctx, path_or_text):
    count = 0
    text = path_or_text
    if os.path.isfile(path_or_text):
        with open(path_or_text, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        info = item.get("info") or {}
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "Info")
        title = info.get("name") or item.get("template-id") or "Nuclei match"
        url = item.get("matched-at") or item.get("host") or ctx.base
        detail = (info.get("description") or
                  f"Nuclei template {item.get('template-id')} matched.")
        if item.get("extracted-results"):
            detail += " Extracted: " + ", ".join(
                str(x) for x in item["extracted-results"])[:200]
        f = _add_external(ctx, sev, title, url, detail,
                          param=item.get("template-id", ""), source="Nuclei")
        if f:
            f["proof"] = f"Nuclei template {item.get('template-id')} matched at {url}"
            count += 1
    return count


def run_nuclei(ctx, target):
    binary = shutil.which("nuclei")
    if not binary:
        ctx.emit("Nuclei: binary not found on PATH — skipped "
                 "(install nuclei or import a JSONL file instead)")
        return 0
    _fd, tmp = tempfile.mkstemp(suffix=".jsonl")
    os.close(_fd)
    try:
        subprocess.run([binary, "-u", target, "-jsonl", "-o", tmp, "-silent",
                        "-nc", "-timeout", "8", "-retries", "1"],
                       capture_output=True, timeout=1500)
        if os.path.isfile(tmp):
            return import_nuclei_jsonl(ctx, tmp)
    except Exception as e:
        ctx.emit(f"Nuclei run failed: {e}")
    finally:
        if os.path.isfile(tmp):
            os.unlink(tmp)
    return 0


def zap_alerts(ctx, target, api_url="http://127.0.0.1:8090", apikey=""):
    """Pull alerts from a running ZAP daemon's API."""
    api_url = api_url.rstrip("/")
    qs = urllib.parse.urlencode({"baseurl": target, "apikey": apikey})
    url = f"{api_url}/JSON/alert/view/alerts/?{qs}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode(errors="replace"))
    except Exception as e:
        ctx.emit(f"ZAP: could not reach API at {api_url} ({e}) — skipped")
        return 0
    count = 0
    for alert in data.get("alerts", []):
        sev = SEV_MAP.get(str(alert.get("riskcode", "0")), "Info")
        f = _add_external(
            ctx, sev, alert.get("alert") or "ZAP alert",
            alert.get("url") or target,
            (alert.get("description") or "")[:500] + " " +
            ("Solution: " + alert.get("solution", "") if alert.get("solution") else ""),
            param=alert.get("param", ""), source="ZAP")
        if f:
            f["proof"] = (alert.get("evidence") or "")[:200]
            if alert.get("cweid") and str(alert["cweid"]).isdigit():
                f["cwe"] = f"CWE-{alert['cweid']}"
            count += 1
    return count
