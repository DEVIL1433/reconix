"""Custom detection rules (JSON) + custom payload files — the plugin layer.

A rule file is JSON: a list of
  {"name": "...", "severity": "High", "detail": "...",
   "match": {"url": "regex", "body": "regex",
             "header": {"Server": "regex"}, "status": 200}}
All present match keys must match. Rules run against every crawled response.
"""
import glob
import json
import os
import re


def load_rules(rules_dir):
    rules = []
    if not rules_dir or not os.path.isdir(rules_dir):
        return rules
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                rules.extend(data)
        except Exception:
            continue
    return rules


def apply_rules(ctx, pages, rules):
    F = ctx.findings
    for rule in rules:
        if not (rule.get("match") or {}):
            continue  # a rule with no match criteria would fire everywhere
        try:
            match = rule.get("match") or {}
            url_re = re.compile(match["url"]) if match.get("url") else None
            body_re = re.compile(match["body"]) if match.get("body") else None
            hdrs = {k.lower(): re.compile(v)
                    for k, v in (match.get("header") or {}).items()}
            status = match.get("status")
        except re.error:
            continue
        for url, r in pages:
            if url_re and not url_re.search(url):
                continue
            if status and r.status != status:
                continue
            if body_re and not body_re.search(r.body or ""):
                continue
            if any(not rx.search(r.header(k)) for k, rx in hdrs.items()):
                continue
            F.add(rule.get("severity", "Medium"),
                  f"Custom Rule: {rule.get('name', 'unnamed')}", url,
                  rule.get("detail", "Custom detection rule matched."),
                  proof=(body_re.search(r.body).group(0)[:140]
                         if body_re and body_re.search(r.body or "") else ""),
                  confidence="Rule match", resp=r,
                  dedupe_key=("rule", rule.get("name"), url))


def load_payloads(path):
    out = []
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            out = [ln.rstrip("\n") for ln in fh if ln.strip()]
    return out
