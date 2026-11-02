"""Local AI assistance (3.32) — the model SUGGESTS, the engine PROVES.

Design rule (non-negotiable): AI output never creates a finding on its
own. Payload ideas are tested through the existing checks and their
proof guards; logic ideas become engine test attempts that still require
proof; ranking changes display order only and never adds or drops a
finding; report text is written from proven findings only and never
invents new ones.

Local only, always: the model is the laptop's own Ollama instance
(127.0.0.1:11434, llama3.2:3b — the same model the Jarvis offline
brain uses). No cloud APIs, no API keys, no scan data ever leaves the
machine — this matters for client engagements. No new installs.

Opt-in and fail-safe: AI is OFF by default (scan option "ai"). When
off, this module is never called and the engine behaves exactly as
before. When on, every call is bounded (small token caps, short
timeouts, a per-scan call budget) and any failure — unreachable
Ollama, timeout, bad output — degrades silently: the feature returns
nothing and the scan continues unchanged. One failure trips a circuit
breaker so a dead or hanging model cannot stall a scan with repeated
calls. There are no retries in loops.

Phone safety: the Android app syncs wscan/*.py, so this file ships on
phones too — but AI stays off unless explicitly enabled, and on a
phone Ollama is unreachable, so a call fails fast (connection
refused) and the breaker trips. A phone scan is never slowed or
crashed by AI.
"""

import difflib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

MODEL = os.environ.get("RECONIX_AI_MODEL", "llama3.2:3b")
BASE_URL = os.environ.get("RECONIX_AI_URL", "http://127.0.0.1:11434").rstrip("/")
MAX_CALLS = 6          # LLM calls per scan, total across all features
TIMEOUT = 10           # seconds per call — a hanging model must not stall
MAX_TOKENS = 300       # output tokens per call
MAX_IDEAS = 6          # ideas/payloads kept per call
MAX_CONTEXT = 600      # prompt context characters per call


def ai_enabled(opts):
    """AI is opt-in: only an explicit scan option enables it."""
    return bool((opts or {}).get("ai"))


class AIBudget:
    """Per-scan call budget + circuit breaker. One failure kills AI
    for the rest of the scan so a dead model costs one call, not six."""

    def __init__(self, max_calls=MAX_CALLS):
        self.max_calls = max_calls
        self.calls = 0
        self.dead = False

    def spend(self):
        if self.dead or self.calls >= self.max_calls:
            return False
        self.calls += 1
        return True

    def fail(self):
        self.dead = True


def _post(prompt, num_predict):
    """One Ollama /api/generate call. Module-level so tests can stub
    it; production code never calls it directly (use generate())."""
    data = json.dumps({
        "model": MODEL, "prompt": prompt, "stream": False,
        "options": {"num_predict": num_predict, "temperature": 0.2},
    }).encode()
    req = urllib.request.Request(
        BASE_URL + "/api/generate", data=data,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", errors="replace")).get(
            "response", "")


def generate(prompt, num_predict=MAX_TOKENS, budget=None):
    """Ask the local model; return text or None. Never raises, never
    retries, never waits past TIMEOUT."""
    if budget is None or not budget.spend():
        return None
    try:
        text = _post(prompt, num_predict)
    except Exception:
        budget.fail()
        return None
    if not text:
        return None
    return text[:4000]


# ------------------------------------------------------------------ parsing

def _json_array(text):
    """Extract a JSON array from model output (tolerates prose around
    it). Returns [] on anything unparseable."""
    if not text:
        return []
    try:
        start, end = text.index("["), text.rindex("]") + 1
        val = json.loads(text[start:end])
        return val if isinstance(val, list) else []
    except Exception:
        return []


def _clean_payload(p):
    """One payload string, or None if it is unusable as a probe."""
    if not isinstance(p, str):
        return None
    p = p.strip()
    # Strip a matched surrounding quote pair only; a lone leading quote
    # is part of the payload (e.g. the breakout in "'><svg...").
    if len(p) >= 2 and p[0] == p[-1] and p[0] in "`\"'":
        p = p[1:-1].strip()
    p = re.sub(r"^(?:[-*•]\s+|\d+[.)]\s*)", "", p)
    if not p or len(p) > 300 or "\n" in p or "\r" in p:
        return None
    return p


# ------------------------------------------------------- 1. payload ideas

def payload_ideas(kind, context_url, budget):
    """Fresh payload suggestions for one URL context (kind "xss" or
    "sqli"). Suggestions only — the caller tests each one through the
    existing check machinery and its proof guards."""
    if budget is None:
        return []
    ctx = (context_url or "")[:MAX_CONTEXT]
    prompt = (
        "You are helping an authorized web security scanner. Suggest up "
        f"to {MAX_IDEAS} fresh {kind.upper()} test payloads for this "
        f"target URL (parameters are the interesting part): {ctx} "
        "Return ONLY a JSON array of payload strings, no explanation, "
        "no markdown. Payloads must be short, single-line test strings."
    )
    text = generate(prompt, 200, budget)
    out, seen = [], set()
    for raw in _json_array(text):
        p = _clean_payload(raw)
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    if not out and text:
        # Fallback: one payload per line, for models that ignore JSON.
        for line in text.splitlines():
            p = _clean_payload(line)
            if p and p not in seen:
                seen.add(p)
                out.append(p)
    return out[:MAX_IDEAS]


def payload_ideas_for(ctx, kind, url):
    """Cached per (kind, URL) so one URL costs at most one LLM call
    no matter how many parameters or forms it has."""
    budget = getattr(ctx, "ai_budget", None)
    if budget is None:
        return []
    cache = getattr(ctx, "ai_payload_cache", None)
    if cache is None:
        cache = ctx.ai_payload_cache = {}
    key = (kind, url)
    if key not in cache:
        cache[key] = payload_ideas(kind, url, budget)
    return list(cache[key])


# ------------------------------------------- 2. business-logic test ideas

_LOGIC_TYPES = ("anon_access", "id_tamper", "role_access")


def logic_ideas(surface, budget):
    """Propose multi-step / role / state-abuse test ideas for a site
    surface summary. Returns validated idea dicts; the caller attempts
    each one and only reports it if the attempt proves something."""
    if budget is None:
        return []
    prompt = (
        "You are helping an authorized web security scanner. Read this "
        "site surface (URLs, parameters, forms) and propose up to "
        f"{MAX_IDEAS} business-logic abuse tests: access-control, "
        "role, ID-tampering, or state-flow tests. Return ONLY a JSON "
        "array of objects with keys type, target, method, note. type "
        "must be one of: anon_access (a page that may not need login), "
        "id_tamper (a URL with a numeric id to vary), role_access (a "
        "page a lower-privilege user should not reach). target must be "
        "a full URL from the surface below. Surface:\n"
        + (surface or "")[:2000]
    )
    out = []
    for raw in _json_array(generate(prompt, 300, budget)):
        if not isinstance(raw, dict):
            continue
        typ, target = raw.get("type", ""), raw.get("target", "")
        if typ not in _LOGIC_TYPES or not isinstance(target, str) \
                or not target.strip():
            continue
        out.append({"type": typ, "target": target.strip()[:500],
                    "method": str(raw.get("method", "GET"))[:20],
                    "note": str(raw.get("note", ""))[:300]})
    return out[:MAX_IDEAS]


def _sim(a, b):
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()


def _looks_like_login(body):
    low = (body or "").lower()
    return ("password" in low and ("log in" in low or "sign in" in low
                                   or "login" in low))


def logic_check(ctx, pages, forms):
    """Attempt AI-proposed logic tests. Returns (attempted, proven).
    A test only becomes a finding when the attempt itself proves the
    flaw (same content reachable without the right session). Anything
    else is discarded silently — unproven ideas are never reported."""
    budget = getattr(ctx, "ai_budget", None)
    if budget is None:
        return 0, 0
    base_host = urllib.parse.urlsplit(ctx.base).netloc
    lines = []
    for u, _r in (pages or [])[:20]:
        params = urllib.parse.parse_qsl(
            urllib.parse.urlsplit(u).query, keep_blank_values=True)
        lines.append(u + (f" params={','.join(k for k, _ in params)}"
                          if params else ""))
    for page_url, form in (forms or [])[:10]:
        names = ",".join(i.get("name", "") for i in form.get("inputs", []))
        lines.append(f"form {page_url} -> {form.get('action', '')} [{names}]")
    ideas = logic_ideas("\n".join(lines), budget)
    if not ideas:
        return 0, 0
    from .client import Client  # deferred: avoids an import cycle

    attempted = proven = 0
    for idea in ideas:
        target = idea["target"]
        parts = urllib.parse.urlsplit(target)
        if parts.netloc != base_host or parts.scheme not in ("http", "https"):
            continue  # never test off-target hosts, whatever the model says
        try:
            if idea["type"] == "anon_access":
                attempted += 1
                base = ctx.client.fetch(target)
                if base.status != 200 or _looks_like_login(base.body):
                    continue
                anon = Client().fetch(target)
                if anon.status == 200 and not _looks_like_login(anon.body) \
                        and _sim(base.body, anon.body) > 0.85:
                    ctx.findings.add(
                        "Medium", "Access Control (AI-proposed test)", target,
                        "A page reached with the scan's session returns the "
                        "same content with no session at all, so it may not "
                        "require login. (Test proposed by the local AI "
                        "model; the identical anonymous response is the "
                        "proof.)",
                        proof=f"Anonymous GET returned HTTP 200, "
                              f"{len(anon.body or '')} bytes, "
                              f"{_sim(base.body, anon.body):.0%} similar to "
                              "the authenticated baseline",
                        resp=anon, cwe="CWE-862")
                    proven += 1
            elif idea["type"] in ("id_tamper", "role_access"):
                second = ctx.client_b if idea["type"] == "role_access" \
                    else (ctx.client_b or ctx.client_anon)
                if second is None:
                    continue  # no second session: cannot prove, discard
                pairs = urllib.parse.parse_qsl(parts.query,
                                               keep_blank_values=True)
                num = [(k, v) for k, v in pairs if v.isdigit()]
                if not num:
                    continue
                attempted += 1
                name, val = num[0]
                for new_val in (str(int(val) + 1), "1"):
                    if new_val == val:
                        continue
                    variant = urllib.parse.urlunsplit(parts._replace(
                        query=urllib.parse.urlencode(
                            [(k, new_val if k == name else v)
                             for k, v in pairs])))
                    base = ctx.client.fetch(target)
                    other = second.fetch(variant)
                    if base.status == 200 and other.status == 200 \
                            and not _looks_like_login(other.body) \
                            and _sim(base.body, other.body) > 0.85:
                        ctx.findings.add(
                            "Medium",
                            "Insecure Direct Object Reference (AI-proposed "
                            "test)", variant,
                            f"Changing parameter '{name}' to '{new_val}' "
                            "returns content matching the original record "
                            "under a different session, so object access "
                            "may not be checked. (Test proposed by the "
                            "local AI model; the matching second-session "
                            "response is the proof.)",
                            proof=f"Second-session GET returned HTTP 200, "
                                  f"{_sim(base.body, other.body):.0%} "
                                  "similar to the original record",
                            param=name, resp=other, cwe="CWE-639")
                        proven += 1
                        break
        except Exception:
            continue  # one bad idea never breaks the scan
    return attempted, proven


# ------------------------------------------------------- 3. ranking

def rank_items(items, budget):
    """Reorder proven findings by model-judged risk. Returns the SAME
    list object unless the model returns a valid full permutation —
    display order only, never adds or drops a finding."""
    if budget is None or len(items) < 2:
        return items
    lines = []
    for i, f in enumerate(items[:40]):
        lines.append(f"{i}. [{f['severity']}] {f['title']} — "
                     f"{f['url']}"[:120])
    prompt = (
        "You are helping an authorized web security scanner rank its "
        "already-proven findings by real risk (most dangerous first). "
        "Return ONLY a JSON array of the numbers below, each number "
        "exactly once, most dangerous first. Findings:\n"
        + "\n".join(lines)
    )
    order = []
    for raw in _json_array(generate(prompt, 200, budget)):
        if isinstance(raw, int) and 0 <= raw < len(items):
            order.append(raw)
    if sorted(order) != list(range(len(items))) or len(order) != len(items):
        return items
    return [items[i] for i in order]


# ------------------------------------------------------- 4. narrative

def report_narrative(target, items, budget):
    """Plain-language briefing written ONLY from proven findings.
    Returns "" when the model is unavailable or says nothing."""
    if budget is None or not items:
        return ""
    top = sorted(items, key=lambda f: ({"Critical": 0, "High": 1,
                                        "Medium": 2, "Low": 3,
                                        "Info": 4}.get(f["severity"], 9)))[:12]
    lines = [f"- [{f['severity']}] {f['title']} ({f.get('cwe', '')}) "
             f"{f['url']}"[:160] for f in top]
    prompt = (
        f"Write a short plain-language security briefing for {target}, "
        "based ONLY on these already-proven findings. Do not invent, "
        "guess, or add any finding not listed. Sections: What was "
        "found; What matters most; What to fix first. Under 250 "
        "words, plain language, no jargon:\n" + "\n".join(lines)
    )
    return (generate(prompt, 300, budget) or "").strip()


# ======================================================= 5+6. AI phase 2
# Two capabilities on top of the 3.32 layer, under the SAME rules:
# local model only, off by default (a None budget degrades silently),
# capped calls through generate()/AIBudget, breaker on failure, and —
# non-negotiable as ever — AI output never creates or changes a
# finding. In fix re-test the AI only SUMMARIZES the fix and the
# mapping to the re-test comes from the finding itself; the verdict
# comes from the engine's proof machinery (wscan/retest.py), never
# from model text. In fix snippets the AI writes ADVISORY text only,
# rendered as "suggested fix" — it never alters scan results.

def _json_object(text):
    """Extract a JSON object from model output (tolerates prose around
    it). Returns {} on anything unparseable."""
    if not text:
        return {}
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        val = json.loads(text[start:end])
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}


# kind -> (language hint, fix guidance). Matched on CWE first, then on
# the finding title; the language is a hint from the evidence, not a
# claim about the target's stack — the snippet stays advisory either
# way.
_FIX_CONTEXTS = [
    (("89",), ("sql injection",), "SQL / application code",
     "parameterized queries / prepared statements with bound "
     "parameters — never string-concatenated SQL"),
    (("79",), ("cross-site scripting", "xss"), "HTML / JavaScript",
     "context-aware output encoding of untrusted data, never raw "
     "interpolation into HTML or script"),
    (("78", "88"), ("command injection", "os command"), "shell / backend",
     "avoid the shell entirely (argument arrays) or a strict "
     "allowlist — never concatenate user input into a command"),
    (("918",), ("server-side request forgery", "ssrf"), "backend HTTP",
     "allowlist of permitted hosts/schemes and block private / "
     "link-local destinations, with redirects disabled or validated"),
    (("22", "23", "35", "73"), ("path traversal", "local file inclusion",
                                "file inclusion", "directory traversal"),
     "backend file handling",
     "canonicalize the path and confine it under an allowlisted base "
     "directory — never open a user-supplied path directly"),
    (("94", "95", "96"), ("template injection", "code injection"),
     "templates / backend",
     "never render user input as template code; use data-only "
     "templates with autoescaping"),
    (("611",), ("xml external entity", "xxe"), "XML parser config",
     "disable DTDs / external entities in the XML parser"),
    (("352",), ("cross-site request forgery", "csrf"), "web forms",
     "per-session anti-CSRF tokens validated on state-changing "
     "requests, plus SameSite cookies"),
    (("601",), ("open redirect",), "URL handling",
     "allowlist of redirect destinations — never redirect to a "
     "user-supplied absolute URL"),
    (("502",), ("deserialization", "insecure deserialization"),
     "serialization code",
     "never deserialize untrusted data with native deserializers; "
     "use signed, schema-validated formats instead"),
    (("434",), ("unrestricted file upload", "file upload"),
     "upload handling",
     "allowlist extensions and content types, store outside the web "
     "root, never execute uploaded files"),
]


def _detect_fix_context(finding):
    """(kind, language, guidance) for a proven finding — pure
    evidence matching, no model call, so the snippet prompt always
    names the right fix class even when the model is vague."""
    finding = finding or {}
    cwe = str(finding.get("cwe") or "")
    cwe_num = re.sub(r"(?i)^cwe-?", "", cwe).strip()
    title = (finding.get("title") or "").lower()
    for cwes, titles, language, guidance in _FIX_CONTEXTS:
        if cwe_num and cwe_num in cwes:
            return {"kind": titles[0], "language": language,
                    "guidance": guidance}
        if any(t in title for t in titles):
            return {"kind": titles[0], "language": language,
                    "guidance": guidance}
    return {"kind": "general hardening", "language": "application code",
            "guidance": "validate and encode all untrusted input at the "
                        "trust boundary for this flaw class"}


# ------------------------------------------------------- 5a. fix summary

def summarize_fix(finding, fix_description, budget):
    """AI summary of a user-supplied fix (2–3 sentences) plus the
    re-test mapping, which is derived from the FINDING, not the model:
    same check, same target/parameter. Returns None when the model is
    unavailable (silent degradation) — the caller still runs the
    engine re-test without a summary."""
    if budget is None:
        return None
    finding = finding or {}
    prompt = (
        "Summarize this fix in 2-3 sentences for an authorized "
        "security tester. Do NOT judge whether the fix works — the "
        "engine re-tests the proof separately. Fix description:\n"
        + (fix_description or "")[:1000]
        + "\nFinding it addresses: "
        + f"{finding.get('title', '')} at {finding.get('url', '')}"
        + (f" (parameter: {finding.get('param', '')})"
           if finding.get("param") else "")
        + "\nSummary only, plain language, no verdict words like "
        "'fixed' or 'secure'."
    )
    text = generate(prompt, 250, budget)
    if not text:
        return None
    return {"summary": text.strip()[:2000],
            "retest_target": {"url": finding.get("url", ""),
                              "param": finding.get("param", ""),
                              "title": finding.get("title", "")}}


# ------------------------------------------------------- 5b. fix re-test

_VERDICT_MAP = {"Fixed": "fixed", "Still vulnerable": "still vulnerable",
                "Changed": "changed", "Not retestable": "not retestable"}


def retest_with_fix(finding, fix_description, budget, client=None,
                    retest_fn=None):
    """AI reads the fix; the ENGINE re-tests the exact proof.

    Returns {"verdict", "engine_verdict", "detail", "fix_summary",
    "ai_available"}. "verdict" is normalized from the engine's verdict
    ("fixed" / "still vulnerable" / "changed" / "not retestable") and
    is NEVER derived from the AI summary — a model that claims "fully
    fixed" cannot overrule a proof that still reproduces, and vice
    versa. When the model is absent, fix_summary is "" and
    ai_available is False, but the engine verdict is still returned:
    that is the silent degradation for this capability (no exception,
    no AI claim, proof still judged). retest_fn(client, finding) may
    be injected (tests do); the default is wscan.retest.retest_finding
    (deferred import: retest imports checks, which imports this
    module)."""
    summary = summarize_fix(finding, fix_description, budget)
    ai_text = summary["summary"] if summary else ""
    if retest_fn is None:
        try:
            from .retest import retest_finding as retest_fn
        except Exception:
            retest_fn = None
    if retest_fn is None or client is None:
        return {"verdict": "not retestable", "engine_verdict": None,
                "detail": "No scan client or re-test function available, "
                          "so the original proof could not be replayed.",
                "fix_summary": ai_text, "ai_available": bool(ai_text)}
    try:
        raw = retest_fn(client, finding or {})
    except Exception as e:
        return {"verdict": "not retestable", "engine_verdict": None,
                "detail": f"Engine re-test could not run: {e}",
                "fix_summary": ai_text, "ai_available": bool(ai_text)}
    engine_verdict = (raw or {}).get("verdict", "Not retestable")
    return {"verdict": _VERDICT_MAP.get(engine_verdict,
                                        str(engine_verdict).lower()),
            "engine_verdict": engine_verdict,
            "detail": (raw or {}).get("detail", ""),
            "fix_summary": ai_text, "ai_available": bool(ai_text)}


# ------------------------------------------------------- 6. fix snippets

def fix_snippet(finding, budget):
    """Concrete fix code snippet for a proven finding, written by the
    local model. Returns None when the model is unavailable (silent
    degradation). The result is ADVISORY TEXT ONLY: {"kind",
    "language", "guidance", "snippet", "explanation", "advisory":
    True, "note"} — it never mutates the finding and never feeds back
    into scan results. Render it with format_suggested_fix()."""
    if budget is None:
        return None
    finding = finding or {}
    ctx = _detect_fix_context(finding)
    evidence = (f"{finding.get('title', '')} at "
                f"{finding.get('url', '')}"
                + (f" (parameter: {finding.get('param', '')})"
                   if finding.get("param") else "")
                + (f" — evidence: {finding.get('proof', '')}"
                   if finding.get("proof") else ""))[:800]
    prompt = (
        "Write a concrete fix code snippet for this already-proven "
        "web vulnerability, in " + ctx["language"] + ". Fix approach: "
        + ctx["guidance"] + ". Finding: " + evidence + " Return ONLY "
        'a JSON object {"snippet": "<code>", "explanation": "<one or '
        'two sentences>"}. The snippet must be complete, minimal, and '
        "directly address the finding above — no placeholders for the "
        "vulnerable operation itself."
    )
    text = generate(prompt, 300, budget)
    if not text:
        return None
    parsed = _json_object(text)
    snippet = parsed.get("snippet") if isinstance(parsed, dict) else None
    explanation = parsed.get("explanation") if isinstance(parsed, dict) \
        else None
    if not isinstance(snippet, str) or not snippet.strip():
        # Fallback: the model ignored JSON — treat its text as the
        # snippet itself rather than dropping a usable fix.
        snippet, explanation = text.strip()[:2000], ""
    if not isinstance(explanation, str):
        explanation = ""
    return {"kind": ctx["kind"], "language": ctx["language"],
            "guidance": ctx["guidance"],
            "snippet": snippet.strip()[:2000],
            "explanation": explanation.strip()[:800],
            "advisory": True,
            "note": "Suggested fix — advisory only; it does not change "
                    "scan results or findings."}


def format_suggested_fix(snippet_dict):
    """Plain-text rendering for the report / findings view (the UI
    escapes it like any other finding text). Always leads with the
    advisory label so a suggested fix can never be mistaken for an
    engine verdict or an applied change. Never mutates its input."""
    if not snippet_dict:
        return ""
    parts = ["Suggested fix (advisory only — does not change scan "
             "results):"]
    if snippet_dict.get("explanation"):
        parts.append(snippet_dict["explanation"])
    lang = snippet_dict.get("language") or "code"
    parts.append(f"```{lang}\n{snippet_dict.get('snippet', '')}\n```")
    return "\n".join(parts)


# Alias: suggest_fix is the same advisory-snippet capability.
suggest_fix = fix_snippet
