"""HAR (HTTP Archive) import/export.

Import: seed a scan from traffic captured in Burp/browser devtools —
GET entries become pages/parameter surfaces, urlencoded POST entries
become forms, so the active checks run without a fresh crawl.
Export: build a HAR from the pages and finding requests a scan produced.
"""
import base64
import json
import urllib.parse


def parse_har(text):
    """Returns {pages:[url], forms:[(page_url, form)], entries:n}."""
    out = {"pages": [], "forms": [], "entries": 0}
    try:
        data = json.loads(text)
    except Exception:
        return out
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        url = req.get("url")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        out["entries"] += 1
        if method == "GET":
            if url not in out["pages"]:
                out["pages"].append(url)
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            post = req.get("postData") or {}
            params = post.get("params") or []
            if not params and post.get("text"):
                try:
                    params = [{"name": k, "value": v} for k, v in
                              urllib.parse.parse_qsl(post["text"])]
                except Exception:
                    params = []
            if params:
                form = {"action": url, "method": method,
                        "inputs": [{"name": p.get("name", ""),
                                    "type": "text",
                                    "value": p.get("value", "")}
                                   for p in params if p.get("name")]}
                out["forms"].append((url, form))
            elif url not in out["pages"]:
                out["pages"].append(url)
    return out


def parse_har_steps(text):
    """Ordered workflow steps WITH recorded responses (for business-
    logic testing): [{method, url, params, body_text, content_type,
    status, resp_body}]."""
    steps = []
    try:
        data = json.loads(text)
    except Exception:
        return steps
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        url = req.get("url")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        post = req.get("postData") or {}
        params = {}
        for p in post.get("params") or []:
            if p.get("name"):
                params[p["name"]] = p.get("value", "")
        body_text = post.get("text") or ""
        if not params and body_text and \
                "application/x-www-form-urlencoded" in (post.get("mimeType") or ""):
            try:
                params = dict(urllib.parse.parse_qsl(body_text))
            except Exception:
                params = {}
        resp = entry.get("response") or {}
        content = resp.get("content") or {}
        rbody = content.get("text") or ""
        if content.get("encoding") == "base64" and rbody:
            try:
                rbody = base64.b64decode(rbody).decode("utf-8", "replace")
            except Exception:
                rbody = ""
        steps.append({"method": method, "url": url, "params": params,
                      "body_text": body_text,
                      "content_type": post.get("mimeType") or "",
                      "status": resp.get("status") or 0,
                      "resp_body": rbody})
    return steps


def build_har(pages, findings):
    """pages: [(url, Resp)] — findings contribute their stored requests."""
    entries = []
    for url, r in pages:
        entries.append(_entry(r.request_text, r.status, url,
                              r.body or "", r.elapsed))
    seen = {e["request"]["url"] for e in entries}
    for f in findings:
        if f.get("request") and f["url"] not in seen:
            entries.append(_entry(f["request"], 0, f["url"],
                                  f.get("response_snippet", ""), 0))
    return json.dumps({"log": {"version": "1.2",
                               "creator": {"name": "Reconix 3.20",
                                           "version": "3.1"},
                               "entries": entries}}, indent=1)


def _entry(request_text, status, url, body, elapsed):
    lines = (request_text or "").split("\r\n")
    if not lines or " " not in lines[0]:
        lines = (request_text or "").split("\n")
    first = lines[0] if lines else "GET / HTTP/1.1"
    parts = first.split(" ")
    method = parts[0] if parts else "GET"
    headers, body_text, in_body = [], "", False
    for ln in lines[1:]:
        if in_body:
            body_text += ln
        elif ln == "":
            in_body = True
        elif ":" in ln:
            k, v = ln.split(":", 1)
            headers.append({"name": k.strip(), "value": v.strip()})
    return {
        "startedDateTime": "2026-01-01T00:00:00.000Z",
        "time": round((elapsed or 0) * 1000),
        "request": {"method": method, "url": url, "headers": headers,
                    "postData": {"mimeType": "", "text": body_text}
                    if body_text else {}},
        "response": {"status": status or 0,
                     "content": {"size": len(body or ""),
                                 "text": (body or "")[:20000]}},
    }
