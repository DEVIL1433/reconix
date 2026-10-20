"""Verify-Fix retesting: replay a finding's original attack request and
decide whether the vulnerability is still there."""
import re
import urllib.parse

from .checks import _sql_error_in


def _parse_request(request_text):
    if not request_text:
        return None
    lines = request_text.replace("\r\n", "\n").split("\n")
    first = lines[0].split(" ")
    if len(first) < 2:
        return None
    method, path = first[0], first[1]
    headers, body, in_body = {}, [], False
    for ln in lines[1:]:
        if in_body:
            body.append(ln)
        elif ln == "":
            in_body = True
        elif ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip().lower() not in ("host", "content-length"):
                headers[k.strip()] = v.strip()
    return method, path, headers, "\n".join(body)


def retest_finding(client, finding):
    """Returns {verdict: Fixed|Still vulnerable|Changed, detail}."""
    parsed = _parse_request(finding.get("request") or "")
    if not parsed:
        return {"verdict": "Not retestable",
                "detail": "Finding has no stored request to replay."}
    method, path, headers, body = parsed
    parts = urllib.parse.urlsplit(finding["url"])
    url = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, "", "", "")) + path
    r = client.fetch(url, method=method, headers=headers,
                     raw_body=body.encode() if body else None)
    if r.status is None:
        return {"verdict": "Changed", "detail": "Target did not respond."}
    if r.status in (404, 410):
        return {"verdict": "Fixed",
                "detail": f"Endpoint now returns {r.status}."}
    title = finding["title"]
    proof = finding.get("proof") or ""
    body_text = r.body or ""
    still, why = False, ""
    if "SQL Injection" in title:
        err = _sql_error_in(body_text)
        still, why = bool(err), f"database error still returned ({err})"
    elif "Cross-Site Scripting" in title and "payload" in proof:
        payload = proof.split("payload reflected unescaped:")[-1].strip()
        if not payload or payload == proof:
            payload = proof.split(":")[-1].strip()
        still = bool(payload) and payload in body_text
        why = "payload still reflected unescaped" if still else ""
    elif "Sensitive File" in title or ".env" in title:
        from .calibrate import similarity as _sim2
        snippet = finding.get("response_snippet") or ""
        still = (r.status == 200 and len(body_text) > 20
                 and (not snippet or _sim2(body_text, snippet) > 0.5))
        why = "sensitive file still served (content matches original)" \
            if still else ""
    elif "Directory Listing" in title:
        still = "Index of" in body_text
        why = "listing still enabled" if still else ""
    else:
        snippet = (finding.get("response_snippet") or "")[:80].strip()
        distinctive = max((ln.strip() for ln in snippet.splitlines()
                           if len(ln.strip()) > 25), default="")
        if distinctive:
            still = distinctive in body_text
            why = "original evidence still present in response" if still else ""
    if still:
        return {"verdict": "Still vulnerable",
                "detail": f"Replayed the original request (HTTP {r.status}): {why}."}
    if r.status in (400, 401, 403):
        return {"verdict": "Fixed",
                "detail": f"Request is now rejected with HTTP {r.status}."}
    return {"verdict": "Changed",
            "detail": f"Original proof no longer reproduces (HTTP {r.status}), "
                      "but the endpoint still responds — manual review advised."}
