"""Ticketing: send proven scan findings to Jira Cloud and GitHub Issues.

Stdlib only (urllib). Credentials are USER-SUPPLIED settings only —
passed in by the caller at send time, never hardcoded, never stored in
scan history or reports, and never included in returned results or in
any log/error string this module produces. Error text is sanitised:
every secret value from the settings dict is replaced with
``[REDACTED]`` before it can reach a result.

No live calls happen unless the caller supplies real settings and real
findings; tests inject ``http_post`` (see below) instead of the network.

Settings shapes
---------------
Jira (dict)::

    {
      "base_url": "https://your-domain.atlassian.net",  # required
      "email": "you@example.com",                        # required
      "api_token": "<Jira API token>",                   # required
      "project_key": "SEC",                              # required
      "issue_type": "Bug",        # optional str, or see issue_type_map
      "issue_type_map": {"Critical": "Bug", "High": "Bug",
                         "Medium": "Task", "Low": "Task",
                         "Info": "Task"},  # optional, wins over issue_type
      "labels": ["reconix"],       # optional extra labels
      "priority_map": {...},       # optional, overrides defaults below
    }

GitHub (dict)::

    {
      "repo": "owner/repo",         # required, "owner/name" form
      "token": "<PAT or fine-grained token>",  # required
      "labels": ["security"],      # optional extra labels
      "api_base_url": "https://api.github.com",  # optional override
    }

Send functions
--------------
``send_to_jira(findings, settings, single_summary=False, http_post=None)``
``send_to_github(findings, settings, single_summary=False, http_post=None)``

* ``findings`` — list of finding dicts (as in a scan result), already
  selected by the caller (the UI's selected-findings list).
* ``single_summary`` — False (default): one issue per finding.
  True: one summary issue listing every finding.
* ``http_post`` — optional test hook / transport override:
  ``http_post(url, headers, payload_bytes) -> (status_code, body_bytes)``
  where ``body_bytes`` may also be a dict (already-decoded JSON).
  When None, ``urllib`` performs a real HTTPS POST.
* Return value — ALWAYS a list of per-finding (or single-summary)
  result dicts, one entry per attempted issue::

      {"finding_title": str, "severity": str, "url": str,
       "success": bool, "issue_key": str | None,   # Jira
       "issue_url": str | None,                     # both
       "issue_number": int | None,                  # GitHub
       "error": str | None}

  One failed issue never aborts the rest: failures are captured per
  entry and the loop continues. Returned dicts contain no credential
  material — verified by the test suite's credential-leak check.

Priority / label mapping
------------------------
Jira priority from severity (defaults, overridable via
``priority_map``): Critical→Highest, High→High, Medium→Medium,
Low→Low, Info→Lowest.
GitHub labels per issue: ``["security", <severity-lowercase>]`` plus
any settings ``labels`` (deduped, order preserved).
"""
import base64
import json
import urllib.error
import urllib.request

JIRA_PRIORITY = {"Critical": "Highest", "High": "High", "Medium": "Medium",
                 "Low": "Low", "Info": "Lowest"}
JIRA_ISSUE_TYPE = {"Critical": "Bug", "High": "Bug", "Medium": "Task",
                   "Low": "Task", "Info": "Task"}


# ---------------------------------------------------------------- helpers

def _secrets_of(settings):
    secrets = []
    for key in ("api_token", "token", "password", "email"):
        val = settings.get(key)
        if val:
            secrets.append(str(val))
    return secrets


def _sanitize(text, secrets):
    out = "" if text is None else str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "[REDACTED]")
    return out


def _require(settings, *keys):
    missing = [k for k in keys if not settings.get(k)]
    if missing:
        raise ValueError("Missing ticketing setting(s): %s"
                         % ", ".join(missing))


def jira_priority_for(severity, settings=None):
    mapping = dict(JIRA_PRIORITY)
    if settings and settings.get("priority_map"):
        mapping.update(settings["priority_map"])
    return mapping.get(severity, "Medium")


def jira_issue_type_for(severity, settings=None):
    if settings:
        mapping = settings.get("issue_type_map")
        if isinstance(mapping, dict) and mapping.get(severity):
            return mapping[severity]
        if isinstance(settings.get("issue_type"), str) \
                and settings["issue_type"]:
            return settings["issue_type"]
    return JIRA_ISSUE_TYPE.get(severity, "Task")


def github_labels_for(finding, settings=None):
    labels = ["security"]
    sev = (finding.get("severity") or "").lower()
    if sev:
        labels.append(sev)
    if settings:
        for label in settings.get("labels") or []:
            if label not in labels:
                labels.append(label)
    return labels


def jira_labels_for(finding, settings=None):
    labels = ["reconix"]
    sev = (finding.get("severity") or "").lower()
    if sev and sev not in labels:
        labels.append(sev)
    if settings:
        for label in settings.get("labels") or []:
            if label not in labels:
                labels.append(label)
    return labels


def finding_body(finding, target=""):
    """Plain-text body shared by Jira (as ADF paragraphs) and GitHub."""
    lines = []
    if target:
        lines.append("Target: %s" % target)
    lines.append("Severity: %s" % finding.get("severity", ""))
    if finding.get("cwe"):
        lines.append("CWE: %s" % finding["cwe"])
    lines.append("URL: %s" % finding.get("url", ""))
    if finding.get("param"):
        lines.append("Parameter: %s" % finding["param"])
    if finding.get("confidence"):
        lines.append("Confidence: %s" % finding["confidence"])
    lines.append("")
    lines.append("Detail: %s" % finding.get("detail", ""))
    if finding.get("proof"):
        lines.append("Evidence: %s" % finding["proof"])
    if finding.get("payload"):
        lines.append("Payload: %s" % finding["payload"])
    lines.append("Remediation: %s" % finding.get("remediation", ""))
    if finding.get("poc_curl"):
        lines.append("PoC (curl): %s" % finding["poc_curl"])
    lines.append("")
    lines.append("Reported by Reconix from a proven scan finding.")
    return "\n".join(lines)


def _jira_adf(text):
    paragraphs = []
    for para in str(text).split("\n"):
        paragraphs.append({"type": "paragraph", "content": [
            {"type": "text", "text": para}]})
    return {"type": "doc", "version": 1, "content": paragraphs}


def _real_post(url, headers, payload_bytes):
    req = urllib.request.Request(url, data=payload_bytes, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # network failure: surfaced per-issue, not raised
        raise RuntimeError("Request failed: %s" % e)


def _post(url, headers, payload, http_post):
    data = json.dumps(payload).encode("utf-8")
    if http_post is not None:
        status, body = http_post(url, headers, data)
    else:
        status, body = _real_post(url, headers, data)
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", errors="replace")
    if isinstance(body, str):
        try:
            body = json.loads(body) if body.strip() else {}
        except Exception:
            body = {"raw": body}
    return status, (body if isinstance(body, dict) else {"raw": body})


# ------------------------------------------------------------------- Jira

def send_to_jira(findings, settings, single_summary=False, http_post=None,
                 target=""):
    """Create Jira Cloud issue(s) for findings. See module docstring."""
    _require(settings, "base_url", "email", "api_token", "project_key")
    secrets = _secrets_of(settings)
    base = settings["base_url"].rstrip("/")
    token = base64.b64encode(
        ("%s:%s" % (settings["email"], settings["api_token"])
         ).encode()).decode()
    headers = {"Content-Type": "application/json",
               "Accept": "application/json",
               "Authorization": "Basic %s" % token}
    url = "%s/rest/api/3/issue" % base

    if single_summary:
        titles = "\n".join(
            "- [%s] %s (%s)" % (f.get("severity", ""),
                                f.get("title", ""), f.get("url", ""))
            for f in findings)
        body_text = ("Reconix scan findings%s\n\n%s\n\n"
                     "Full per-finding detail is in the scan report."
                     % ((" for " + target) if target else "", titles))
        payload = {"fields": {
            "project": {"key": settings["project_key"]},
            "summary": "Reconix scan: %d finding(s)%s"
                       % (len(findings), (" on " + target) if target else ""),
            "description": _jira_adf(body_text),
            "issuetype": {"name": "Task"},
            "labels": ["reconix"] + list(settings.get("labels") or []),
        }}
        items = [({"title": payload["fields"]["summary"],
                   "severity": "", "url": target}, payload)]
    else:
        items = []
        for f in findings:
            payload = {"fields": {
                "project": {"key": settings["project_key"]},
                "summary": "[%s] %s" % (f.get("severity", ""),
                                         f.get("title", "")),
                "description": _jira_adf(finding_body(f, target)),
                "issuetype": {"name": jira_issue_type_for(
                    f.get("severity", ""), settings)},
                "priority": {"name": jira_priority_for(
                    f.get("severity", ""), settings)},
                "labels": jira_labels_for(f, settings),
            }}
            items.append((f, payload))

    results = []
    for finding, payload in items:
        try:
            status, body = _post(url, headers, payload, http_post)
        except Exception as e:
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": False, "issue_key": None,
                            "issue_url": None, "issue_number": None,
                            "error": _sanitize(str(e), secrets)[:500]})
            continue
        if status in (200, 201) and body.get("key"):
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": True, "issue_key": body["key"],
                            "issue_url": body.get("self"),
                            "issue_number": None, "error": None})
        else:
            msg = body.get("errorMessages") or body.get("errors") \
                or body.get("message") or "HTTP %s" % status
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": False, "issue_key": None,
                            "issue_url": None, "issue_number": None,
                            "error": _sanitize(str(msg), secrets)[:500]})
    return results


# ----------------------------------------------------------------- GitHub

def send_to_github(findings, settings, single_summary=False, http_post=None,
                   target=""):
    """Create GitHub issue(s) for findings. See module docstring."""
    _require(settings, "repo", "token")
    repo = settings["repo"].strip("/")
    if repo.count("/") != 1 or not all(repo.split("/")):
        raise ValueError("GitHub setting 'repo' must be 'owner/name'")
    secrets = _secrets_of(settings)
    api_base = (settings.get("api_base_url")
                or "https://api.github.com").rstrip("/")
    headers = {"Content-Type": "application/json",
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "Authorization": "token %s" % settings["token"]}
    url = "%s/repos/%s/issues" % (api_base, repo)

    if single_summary:
        body_text = "Reconix scan findings%s\n\n" % (
            (" for " + target) if target else "")
        body_text += "\n".join(
            "- [%s] %s (%s)" % (f.get("severity", ""),
                                f.get("title", ""), f.get("url", ""))
            for f in findings)
        body_text += "\n\nFull per-finding detail is in the scan report."
        items = [({"title": "Reconix scan: %d finding(s)" % len(findings),
                   "severity": "", "url": target},
                  {"title": "Reconix scan: %d finding(s)%s"
                   % (len(findings), (" on " + target) if target else ""),
                   "body": body_text,
                   "labels": ["security", "reconix"]
                   + list(settings.get("labels") or [])})]
    else:
        items = []
        for f in findings:
            items.append((f, {
                "title": "[%s] %s" % (f.get("severity", ""),
                                       f.get("title", "")),
                "body": finding_body(f, target),
                "labels": github_labels_for(f, settings),
            }))

    results = []
    for finding, payload in items:
        try:
            status, body = _post(url, headers, payload, http_post)
        except Exception as e:
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": False, "issue_key": None,
                            "issue_url": None, "issue_number": None,
                            "error": _sanitize(str(e), secrets)[:500]})
            continue
        if status in (200, 201) and body.get("number") is not None:
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": True, "issue_key": None,
                            "issue_url": body.get("html_url"),
                            "issue_number": body.get("number"),
                            "error": None})
        else:
            msg = body.get("message") or body.get("errors") \
                or "HTTP %s" % status
            results.append({"finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "url": finding.get("url", target),
                            "success": False, "issue_key": None,
                            "issue_url": None, "issue_number": None,
                            "error": _sanitize(str(msg), secrets)[:500]})
    return results


# Aliases used by the (separate) UI integration step.
send_findings_to_jira = send_to_jira
send_findings_to_github = send_to_github
