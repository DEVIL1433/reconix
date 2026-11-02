"""GraphQL testing (Reconix proof-only pack).

Extends — never duplicates — the existing checks: checks.graphql_check
only probes introspection on fixed paths, and checks3.graphql_deep_check
only probes batching/aliases/suggestions. This module adds:

  * discovery from crawled pages/JS + common paths (not fixed paths only)
  * introspection exposure PROVEN by a real introspection answer
  * broken access control PROVEN as anonymous / second-user access to
    sensitive fields (engine session model: primary vs anon vs client_b)
  * batching abuse PROVEN by a batch that actually executes N operations
  * depth/complexity PROVEN by a bounded (depth 8) nested query that
    actually resolves to that depth — never a DoS attempt

Every finding carries the exact query + response evidence. A dead,
unreachable, or auth-gated endpoint is never a finding. Stdlib only.

Integration entry point: graphql_scan(ctx, base, pages=None, ...).
Pure helpers (no ctx) are provided so tests can drive them directly.
"""
import json
import re
import urllib.parse

COMMON_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
                "/api/v1/graphql", "/graphql/v1", "/api/graphiql",
                "/gql", "/api/gql")

INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}"
    "types{name kind fields{name type{name kind ofType{name kind "
    "ofType{name}}}}}}}"
)

# Fields whose unauthenticated disclosure is itself the proof. A field
# returning data is only flagged when its subtree carries one of these
# sensitive keys with a non-empty value — public fields never qualify.
SENSITIVE_KEYS = ("email", "secret", "password", "token", "ssn",
                  "card", "balance", "phone", "address", "private")

DEFAULT_PROTECTED = (
    {"query": "{ me { id email } }", "label": "me"},
    {"query": "{ users { id email } }", "label": "users"},
    {"query": "{ adminPanel { secret } }", "label": "adminPanel"},
)

# Bounded, safe depth for the complexity probe. One small query, eight
# nesting levels — enough to prove "no depth limit", far from a DoS.
DEPTH_LEVELS = 8
BATCH_SIZE = 10


# ------------------------------------------------------------------ helpers

def _post(client, url, payload):
    """POST a GraphQL payload (dict or list). Returns (resp, parsed)."""
    resp = client.fetch(url, method="POST",
                        raw_body=json.dumps(payload).encode(),
                        content_type="application/json")
    try:
        parsed = json.loads(resp.body or "")
    except Exception:
        parsed = None
    return resp, parsed


def _unwrap_type(t):
    """Follow NON_NULL/LIST wrappers to the named base type."""
    while isinstance(t, dict) and t.get("name") is None and t.get("ofType"):
        t = t["ofType"]
    return (t or {}).get("name") if isinstance(t, dict) else None


def _find_sensitive(node, depth=0):
    """First (key, value) sensitive pair in a JSON subtree, else None."""
    if depth > 12 or node is None:
        return None
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower() in SENSITIVE_KEYS and v not in (None, "", [], {}):
                return (k, v)
            hit = _find_sensitive(v, depth + 1)
            if hit:
                return hit
    elif isinstance(node, list):
        for item in node[:5]:
            hit = _find_sensitive(item, depth + 1)
            if hit:
                return hit
    return None


def _data_of(parsed, label):
    """parsed['data'][label] or None, tolerating errors alongside data."""
    if not isinstance(parsed, dict):
        return None
    data = parsed.get("data")
    if isinstance(data, dict):
        return data.get(label)
    return None


def _nested_depth(node, field, depth=0):
    """How many consecutive `field` levels resolve inside node."""
    if isinstance(node, list):
        if not node:
            return depth
        return _nested_depth(node[0], field, depth)
    if isinstance(node, dict):
        nxt = node.get(field)
        if nxt is None:
            return depth
        return _nested_depth(nxt, field, depth + 1)
    return depth


def discover_candidates(base, pages=None, extra_urls=None):
    """Candidate GraphQL URLs: common paths + any /graphql-like URL
    found in crawled page/JS bodies + caller-supplied URLs. No requests
    are made here — probing happens in discover_graphql()."""
    parts = urllib.parse.urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"
    out, seen = [], set()

    def _add(u):
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    for p in COMMON_PATHS:
        _add(root + p)
    for _u, r in (pages or []):
        for m in re.finditer(r"""["'`]([^"'`]*graphql[^"'`\s]*)["'`]""",
                             r.body or "", re.I):
            _add(urllib.parse.urljoin(_u, m.group(1)))
    for u in (extra_urls or []):
        _add(u)
    return out


def discover_graphql(ctx, base, pages=None, extra_urls=None):
    """Probe candidates with a minimal { __typename } query. Returns
    only endpoints that ANSWER as GraphQL (200 + data.__typename) —
    mere existence of a URL is never reported as an endpoint."""
    endpoints = []
    for url in discover_candidates(base, pages, extra_urls):
        if ctx.stop.is_set():
            break
        try:
            _resp, parsed = _post(ctx.client, url, {"query": "{ __typename }"})
        except Exception:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict) \
                and parsed["data"].get("__typename"):
            endpoints.append(url)
    return endpoints


def _introspection(ctx, url, client=None):
    """Run the full introspection query. Returns (resp, types_list)."""
    client = client or ctx.client
    _resp, parsed = _post(client, url, {"query": INTROSPECTION_QUERY})
    types = []
    if isinstance(parsed, dict):
        schema = (parsed.get("data") or {}).get("__schema") or {}
        types = schema.get("types") or []
    return _resp, types


# ------------------------------------------------------------------- checks

def introspection_check(ctx, endpoints):
    """PROOF: the introspection query returns real schema data (a
    non-empty types list with named types). Disabled introspection
    (errors / empty schema) is not a finding."""
    found = []
    for url in endpoints:
        if ctx.stop.is_set():
            break
        resp, types = _introspection(ctx, url)
        names = [t.get("name") for t in types if t.get("name")]
        if resp.status == 200 and len(names) >= 2:
            f = ctx.findings.add(
                "Medium", "GraphQL Introspection Enabled", url,
                "The full schema is exposed: an introspection query "
                "returned real type definitions, giving an attacker a "
                "complete map of the API.",
                proof=f"query: {INTROSPECTION_QUERY[:120]}... | "
                      f"types returned ({len(names)}): "
                      f"{', '.join(names[:12])}",
                payload=INTROSPECTION_QUERY, resp=resp, cwe="CWE-200")
            if f:
                found.append(url)
    return found


def broken_access_control_check(ctx, endpoints, protected_queries=None,
                                cross_user_queries=None):
    """PROOF, two sessions:
    * anonymous: a fresh client (no cookies at all) runs each protected
      query; a finding needs sensitive data actually returned.
    * cross-user: ctx.client_b (second user, where the engine provides
      one) runs each cross_user_queries entry; a finding needs data
      actually returned for another user's object.
    Auth errors, nulls, and empty objects are never findings."""
    from .client import Client
    protected_queries = protected_queries if protected_queries is not None \
        else list(DEFAULT_PROTECTED)
    anon = ctx.client_anon or Client()
    # A truly anonymous client must carry no session: rebuild if the
    # engine's anon client somehow holds cookies.
    if anon.cookies():
        anon = Client()
    found = []
    for url in endpoints:
        for probe in protected_queries:
            if ctx.stop.is_set():
                break
            query, label = probe["query"], probe.get("label", "field")
            try:
                resp, parsed = _post(anon, url, {"query": query})
            except Exception:
                continue
            value = _data_of(parsed, label)
            hit = _find_sensitive(value) if value is not None else None
            if value is not None and hit:
                sev = "High" if label in ("users", "adminPanel") else "Medium"
                f = ctx.findings.add(
                    sev, "GraphQL Broken Access Control (unauthenticated)",
                    url,
                    f"Anonymous users can read the '{label}' field, which "
                    f"should require authentication: the query returned "
                    f"real data without any session.",
                    proof=f"query: {query} | anonymous response data: "
                          f"{json.dumps(value)[:300]}",
                    param=label, payload=query, resp=resp, cwe="CWE-862")
                if f:
                    found.append(url)
        if ctx.client_b and cross_user_queries:
            for probe in cross_user_queries:
                if ctx.stop.is_set():
                    break
                query = probe["query"] if isinstance(probe, dict) \
                    else probe
                label = probe.get("label", "field") \
                    if isinstance(probe, dict) else "field"
                try:
                    resp, parsed = _post(ctx.client_b, url, {"query": query})
                except Exception:
                    continue
                value = _data_of(parsed, label)
                hit = _find_sensitive(value) if value is not None else None
                if value is not None and (hit or value not in ([], {})):
                    f = ctx.findings.add(
                        "High", "GraphQL Broken Access Control (cross-user)",
                        url,
                        "A lower-privileged session read data belonging to "
                        "another user: the query returned real data for an "
                        "object this session should not access.",
                        proof=f"query: {query} | second-user response "
                              f"data: {json.dumps(value)[:300]}",
                        param=label, payload=query, resp=resp, cwe="CWE-862")
                    if f:
                        found.append(url)
    return found


def batching_check(ctx, endpoints):
    """PROOF: one request carrying BATCH_SIZE queries comes back as a
    JSON array of BATCH_SIZE results — the batch really executed."""
    found = []
    batch = [{"query": "{ __typename }"} for _ in range(BATCH_SIZE)]
    for url in endpoints:
        if ctx.stop.is_set():
            break
        try:
            resp, parsed = _post(ctx.client, url, batch)
        except Exception:
            continue
        if isinstance(parsed, list) and len(parsed) >= BATCH_SIZE and \
                all(isinstance(r, dict) and r.get("data") for r in parsed):
            f = ctx.findings.add(
                "Medium", "GraphQL Query Batching Enabled", url,
                f"The endpoint answers {BATCH_SIZE} queries batched in "
                "one request. Batching multiplies brute-force attacks "
                "(OTP, passwords, coupons) by the batch size per request.",
                proof=f"batch of {BATCH_SIZE} -> array of {len(parsed)} "
                      f"results, each with data",
                payload=json.dumps(batch), resp=resp, cwe="CWE-770")
            if f:
                found.append(url)
    return found


def _depth_query_for(types):
    """Build a bounded nested query from introspection types.

    Prefers a self-referential field (e.g. User.friends -> [User]) on a
    type reachable from a Query field. Returns (query, root_field,
    nested_field) or None."""
    by_name = {t.get("name"): t for t in types if t.get("name")}
    query_type = by_name.get("Query") or {}
    for field in query_type.get("fields") or []:
        root, root_type = field.get("name"), _unwrap_type(field.get("type"))
        target = by_name.get(root_type) or {}
        for f in target.get("fields") or []:
            if _unwrap_type(f.get("type")) == root_type:
                nested = f["name"]
                leaf = "id"
                leaf_names = {x.get("name") for x in
                              target.get("fields") or []}
                if "id" not in leaf_names:
                    leaf = "__typename"
                inner = leaf
                for _ in range(DEPTH_LEVELS):
                    inner = f"{nested} {{ {inner} }}"
                return (f"{{ {root} {{ {inner} }} }}", root, nested)
    return None


def depth_check(ctx, endpoints):
    """PROOF: a bounded depth-8 nested query actually resolves to that
    depth in the response. A depth-limit error, or a truncated result,
    is not a finding — it proves the limit works."""
    found = []
    for url in endpoints:
        if ctx.stop.is_set():
            break
        _resp, types = _introspection(ctx, url)
        built = _depth_query_for(types)
        if not built:
            continue
        query, root, nested = built
        try:
            resp, parsed = _post(ctx.client, url, {"query": query})
        except Exception:
            continue
        value = _data_of(parsed, root)
        depth = _nested_depth(value, nested)
        if resp.status == 200 and depth >= DEPTH_LEVELS:
            f = ctx.findings.add(
                "Medium", "GraphQL Query Depth / Complexity Unbounded", url,
                f"A query nested {DEPTH_LEVELS} levels deep was fully "
                "resolved — no depth limit stopped it. Deep or aliased "
                "queries let one request force disproportionate work.",
                proof=f"query: {query[:300]} | resolved nesting depth: "
                      f"{depth}",
                payload=query, resp=resp, cwe="CWE-770")
            if f:
                found.append(url)
    return found


def suggestions_check(ctx, endpoints):
    """Bonus, same proof discipline: a typo'd field whose error message
    suggests the real field name leaks schema without introspection."""
    found = []
    for url in endpoints:
        if ctx.stop.is_set():
            break
        try:
            resp, parsed = _post(ctx.client, url, {"query": "{ __typ }"})
        except Exception:
            continue
        body = resp.body or ""
        if "did you mean" in body.lower():
            f = ctx.findings.add(
                "Medium", "GraphQL Field Suggestions Enabled", url,
                "Error messages suggest correct field names ('Did you "
                "mean...'), leaking the schema even where introspection "
                "is disabled.",
                proof=body[:200], payload="{ __typ }", resp=resp,
                cwe="CWE-209")
            if f:
                found.append(url)
    return found


# ------------------------------------------------------------- entry point

def graphql_scan(ctx, base, pages=None, protected_queries=None,
                 cross_user_queries=None):
    """Discover endpoints, then run every GraphQL check. Returns a
    summary dict; findings go through ctx.findings as usual."""
    endpoints = discover_graphql(ctx, base, pages)
    before = len(ctx.findings.items)
    introspection_check(ctx, endpoints)
    broken_access_control_check(ctx, endpoints,
                                protected_queries=protected_queries,
                                cross_user_queries=cross_user_queries)
    batching_check(ctx, endpoints)
    depth_check(ctx, endpoints)
    suggestions_check(ctx, endpoints)
    return {"endpoints": endpoints,
            "findings_added": len(ctx.findings.items) - before}
