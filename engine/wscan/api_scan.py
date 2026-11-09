"""API security: OpenAPI/Swagger import, endpoint fuzzing, JSON injection
(SQL + NoSQL operators), excessive-data and auth checks on API endpoints."""
import json
import urllib.parse

import re

from .checks import _sim, _sql_error_in
from .passive import excessive_data_scan


def load_openapi(ctx, spec_url):
    """Fetch + parse an OpenAPI/Swagger JSON spec. Returns endpoint list:
    [{method, url, params:[names], json_fields:[names]}]."""
    r = ctx.client.fetch(spec_url)
    endpoints = []
    try:
        spec = json.loads(r.body)
    except Exception:
        return endpoints
    base_parts = urllib.parse.urlsplit(spec_url)
    servers = spec.get("servers") or []
    api_base = ""
    if servers and servers[0].get("url"):
        u = servers[0]["url"]
        api_base = u if u.startswith("http") else \
            f"{base_parts.scheme}://{base_parts.netloc}" + \
            (u if u.startswith("/") else "/" + u)
    if not api_base:
        api_base = f"{base_parts.scheme}://{base_parts.netloc}"
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in (ops or {}).items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            url = api_base.rstrip("/") + "/" + path.lstrip("/")
            url = re.sub(r"\{[^}]+\}", "1", url)  # {id} -> 1 (fuzzable)
            params, fields = [], []
            param_schemas, field_schemas = {}, {}
            for p in (op.get("parameters") or []):
                params.append(p.get("name", ""))
                if p.get("name"):
                    param_schemas[p["name"]] = p.get("schema") or {}
            rb = (op.get("requestBody") or {}).get("content", {})
            for _ct, media in rb.items():
                schema = media.get("schema") or {}
                props = schema.get("properties") or {}
                fields += list(props.keys())
                field_schemas.update(props)
            endpoints.append({"method": method.upper(), "url": url,
                              "params": [p for p in params if p],
                              "param_schemas": param_schemas,
                              "json_fields": fields,
                              "field_schemas": field_schemas})
    return endpoints


def discover_openapi(ctx, base):
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    for path in ("/openapi.json", "/swagger.json", "/api-docs",
                 "/swagger/v1/swagger.json", "/v2/api-docs", "/api/openapi.json"):
        r = ctx.client.fetch(root + path)
        if r.status == 200 and ('"paths"' in (r.body or "")
                                or '"swagger"' in (r.body or "")
                                or '"openapi"' in (r.body or "")):
            ctx.findings.add("Info", "API Specification Exposed", root + path,
                             "A full OpenAPI/Swagger document is public — a "
                             "complete map of the API for an attacker.",
                             proof=(r.body or "")[:140], resp=r, cwe="CWE-200")
            return root + path
    return ""


def _schema_value(schema, depth=0):
    """A VALID value for an OpenAPI schema — strict APIs reject junk
    types before the vulnerable code ever runs, so probes must arrive
    in the right shape."""
    if not isinstance(schema, dict):
        return "wscan"
    if schema.get("enum"):
        return schema["enum"][0]
    fmt = schema.get("format", "")
    if fmt == "email":
        return "reconix.tester@example.com"
    if fmt == "date":
        return "2000-01-15"
    if fmt in ("date-time",):
        return "2000-01-15T00:00:00Z"
    if fmt in ("uri", "url"):
        return "https://example.com"
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000001"
    t = schema.get("type", "string")
    if t == "integer":
        return 1
    if t == "number":
        return 1.5
    if t == "boolean":
        return True
    if t == "array" and depth < 2:
        return [_schema_value(schema.get("items") or {}, depth + 1)]
    if t == "object" and depth < 2:
        return {k: _schema_value(v, depth + 1)
                for k, v in (schema.get("properties") or {}).items()}
    return "wscan"


_MISSING = object()


def _json_field_value(body, field):
    """Value of `field` in a JSON object (or any item of a JSON list),
    or _MISSING when the body is not JSON or lacks the field."""
    try:
        data = json.loads(body or "")
    except Exception:
        return _MISSING
    if isinstance(data, dict):
        return data.get(field, _MISSING)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and field in item:
                return item[field]
    return _MISSING


# Fields an attacker would try to smuggle into a write body. Each is
# paired with a unique canary value and the severity if it sticks.
# "role"/"is_admin" = privilege escalation (High); "price" = business-logic
# tampering (Medium). Only fields NOT in the endpoint's declared schema
# are tried — a declared field is not mass assignment.
_MASS_ASSIGN_CANDIDATES = [
    ("role", "rxcanary-4d2a-admin", "High"),
    ("is_admin", True, "High"),
    ("price", 0.07, "Medium"),
]


def fuzz_endpoints(ctx, endpoints):
    F, client = ctx.findings, ctx.client
    tested_pages = []
    for ep in endpoints[:40]:
        url, method = ep["url"], ep["method"]
        # seed query params with values so injection checks have a surface
        if ep["params"]:
            ps = ep.get("param_schemas") or {}
            q = urllib.parse.urlencode(
                {p: ("1" if (ps.get(p) or {}).get("type")
                     in ("integer", "number") else "wscan")
                 for p in ep["params"]})
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{q}"
        else:
            full = url
        r = client.fetch(full, method=method)
        if r.status:
            tested_pages.append((full, r))
        # JSON body injection on write methods
        if method in ("POST", "PUT", "PATCH") and ep["json_fields"]:
            fs = ep.get("field_schemas") or {}
            body = {f: _schema_value(fs.get(f) or {})
                    for f in ep["json_fields"]}
            # SQLi in JSON field
            for f_name in ep["json_fields"][:4]:
                probe = dict(body)
                probe[f_name] = "wscan'"
                rr = client.fetch(url, method=method,
                                  raw_body=json.dumps(probe).encode(),
                                  content_type="application/json")
                err = _sql_error_in(rr.body)
                if rr.status and err:
                    F.add("High", "SQL Injection (JSON API field)", url,
                          f"JSON field '{f_name}' on {method} {url} triggers "
                          f"a database error.",
                          proof=f"DB error: {err}", param=f_name, resp=rr,
                          cwe="CWE-89")
                    break
            # NoSQL operator injection
            for f_name in ep["json_fields"][:4]:
                probe = dict(body)
                probe[f_name] = {"$ne": "wscan-no-match-7391"}
                rr = client.fetch(url, method=method,
                                  raw_body=json.dumps(probe).encode(),
                                  content_type="application/json")
                base_r = client.fetch(url, method=method,
                                      raw_body=json.dumps(body).encode(),
                                      content_type="application/json")
                sim = _sim(ctx, base_r.body, rr.body)
                if rr.status == 200 and base_r.status == 200 and sim < 0.75:
                    F.add("High", "NoSQL Injection (JSON operator)", url,
                          f"JSON field '{f_name}' evaluates Mongo operators: "
                          f"the $ne probe response diverges from the baseline "
                          f"(similarity {sim:.2f}) — the operator changed the "
                          f"result set.",
                          proof=f"$ne probe similarity to baseline: {sim:.2f} "
                                f"({len(base_r.body)} -> {len(rr.body)} bytes)",
                          param=f_name, resp=rr, cwe="CWE-943")
                    break
            # Mass assignment (BOPLA): add an undeclared field, then prove
            # it was STORED by reading the resource back. A write response
            # that merely echoes the request is NOT proof (echo endpoints
            # would flag on every field), so only a GET that returns the
            # canary afterwards counts. If the endpoint has no readable
            # GET, nothing is reported — strict, no false positives.
            for field, canary, sev in _MASS_ASSIGN_CANDIDATES:
                if field in ep["json_fields"]:
                    continue
                if _json_field_value(
                        client.fetch(url).body, field) == canary:
                    continue  # canary already there: cannot prove storage
                probe = dict(body)
                probe[field] = canary
                rr = client.fetch(url, method=method,
                                  raw_body=json.dumps(probe).encode(),
                                  content_type="application/json")
                if not (rr.status and 200 <= rr.status < 300):
                    continue
                after = client.fetch(url)
                if _json_field_value(after.body, field) == canary:
                    F.add(sev, "Mass Assignment (stored undeclared field)",
                          url,
                          f"{method} {url} stores the undeclared field "
                          f"'{field}': a read-back after the write returns "
                          f"the injected value, so an attacker can set "
                          f"fields the API never declared.",
                          proof=f"GET after write returns {field}="
                                f"{canary!r}", param=field, resp=after,
                          cwe="CWE-915")
                    break
    # excessive data exposure over the API responses we collected
    excessive_data_scan(ctx, tested_pages)
    return tested_pages
