"""Secrets hidden in JavaScript bundles and source maps (proof-only,
masked display).

Relationship to ``wscan/passive.py`` — read this before wiring it in:

* passive.py's ``secrets_scan`` already fetches each JS file (first 14)
  and its ``.map`` file, reports source-map *exposure*, extracts API
  endpoints from bundles and map ``sourcesContent``, and regex-scans
  every blob for 8 patterns — but it prints the raw match into the
  finding proof (``m.group(0)[:80]``), which for a 40-character key IS
  the whole secret, and it gives no line number or masked form.
* This module EXTENDS that coverage instead of duplicating it:
    - 18+ additional secret families passive.py has no pattern for
      (GitHub/GitLab/npm/PyPI tokens, Stripe live keys, OpenAI,
      Anthropic, SendGrid, Mailgun, Telegram bot tokens, Discord
      tokens, AWS secret access keys in context, generic
      high-entropy assignments).
    - Line-level location: file URL + line number + surrounding
      context, for bundles, inline page scripts, AND source-map
      ``sourcesContent`` (each original source reported under the
      map URL + source filename, so a secret that only exists in
      original source is still located).
    - Masked display everywhere: findings carry first-4 / last-4
      characters only (first-2 / last-2 for short values). The raw
      value never reaches a finding — the check deliberately passes
      ``resp=None`` to ``Findings.add`` so the framework cannot stash
      the full response body in ``response_snippet`` either, and
      :func:`find_secrets_in_text` returns masked records only.
    - Plausibility gating: a match must pass format + length +
      entropy / placeholder checks (see :func:`is_plausible_secret`),
      so random strings, example values, test fixtures and
      ``"your-api-key-here"`` placeholders are not reported.
    - ``sourceMappingURL`` comments are followed, not just the
      ``.js.map`` convention passive.py uses.

For families that overlap passive.py (AWS access key ID, Slack token,
Google API key, private key), the dedupe key is deliberately
identical to passive.py's ``("secret", name, url)`` so that running
both in one scan reports the secret once, with whichever module ran
first winning. New families use ``("jssecret", kind, url, line)``.

A match is reported on its own — that IS the proof for a secret
finding (the secret text, in a publicly served file, at a stated
line). There is no second "is it live?" probe: validating a leaked
key by using it would be an authenticated action against someone
else's account, which this engine never does.
"""

import json
import math
import re
import urllib.parse
from html.parser import HTMLParser

# ---------------------------------------------------------------- masking / entropy

def mask_secret(value):
    """Masked form only: first/last few chars, never the middle.

    Values of 8 chars or fewer show first-2 / last-2; longer values
    first-4 / last-4. Callers must never put the raw value in a
    finding, log line or returned record — use this."""
    v = value or ""
    if len(v) <= 8:
        return v[:2] + "…" + v[-2:] if len(v) > 4 else "…" * len(v)
    return v[:4] + "…" + v[-4:]


def shannon_entropy(value):
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_PLACEHOLDERS = ("example", "placeholder", "dummy", "sample", "changeme",
                 "your-", "your_", "todo", "fake", "testtest", "xxxx",
                 "12345678", "password123", "abcdef0123")


def is_plausible_secret(value, require_entropy=True):
    """Format/entropy/placeholder gate for a candidate secret value."""
    v = (value or "").strip()
    if len(v) < 16:
        return False
    low = v.lower()
    if any(p in low for p in _PLACEHOLDERS):
        return False
    if v.startswith(("http://", "https://", "/", "./", "../")):
        return False
    # Degenerate values: one character, or a short repeating unit.
    if len(set(v)) < 4:
        return False
    if re.fullmatch(r"(.)\1+", v):
        return False
    if require_entropy and shannon_entropy(v) < 3.5:
        return False
    return True


# ---------------------------------------------------------------- patterns
# (regex, kind, severity). Named groups are not used: the first
# capturing group, when present, is the secret value; otherwise the
# whole match is. Kind names for the four passive.py overlaps match
# passive.py exactly so dedupe keys line up (see module docstring).
PATTERNS = (
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "High"),
    (r"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}", "Google API key", "Medium"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack token", "High"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private key", "Critical"),
    (r"ghp_[A-Za-z0-9]{36,}", "GitHub personal access token", "High"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained token", "High"),
    (r"gho_[A-Za-z0-9]{36,}", "GitHub OAuth token", "High"),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab personal access token", "High"),
    (r"npm_[A-Za-z0-9]{36}", "npm access token", "High"),
    (r"pypi-[A-Za-z0-9_\-]{20,}", "PyPI API token", "High"),
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe live secret key", "High"),
    (r"rk_live_[A-Za-z0-9]{16,}", "Stripe restricted live key", "High"),
    (r"sk-proj-[A-Za-z0-9_\-]{20,}", "OpenAI API key", "High"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key", "High"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "SendGrid API key", "High"),
    (r"key-[0-9a-z]{32}", "Mailgun API key", "High"),
    (r"(?<![0-9])[0-9]{9,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])",
     "Telegram bot token", "High"),
    (r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}",
     "Discord bot token", "High"),
    # AWS secret access key: 40 base64 chars are common in random
    # strings, so this ONLY fires next to an AWS-secret variable name.
    (r"(?i)(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*"
     r"[\"']([A-Za-z0-9/+=]{40})[\"']", "AWS secret access key", "High"),
    # Generic assignment: a credential-named variable holding a long
    # quoted value. The entropy gate in find_secrets_in_text does the
    # real filtering; short / low-entropy / placeholder values die there.
    (r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"
     r"auth[_-]?token|private[_-]?token|client[_-]?secret)\s*[:=]\s*"
     r"[\"']([^\"'\s]{20,120})[\"']", "Hardcoded credential in JS", "Medium"),
)

# Kinds whose dedupe key must match passive.py exactly.
_PASSIVE_KINDS = {"AWS access key ID", "Google API key", "Slack token",
                  "Private key"}

_COMPILED = [(re.compile(p), kind, sev) for p, kind, sev in PATTERNS]

_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _line_no(text, pos):
    return text.count("\n", 0, pos) + 1


def _context_line(text, pos):
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:200]


def find_secrets_in_text(text, url):
    """Scan one text blob. Returns masked records only, each::

        {kind, severity, masked, url, line, context}
        ``context`` is the source line with the secret replaced by its
        masked form, so no record ever contains a live secret.
    """
    records = []
    seen = set()
    for rx, kind, sev in _COMPILED:
        for m in rx.finditer(text or ""):
            value = m.group(1) if m.lastindex else m.group(0)
            if kind == "Private key":
                plausible = True  # a BEGIN PRIVATE KEY header is proof
            elif kind in ("AWS secret access key",
                          "Hardcoded credential in JS"):
                plausible = is_plausible_secret(value)
            else:
                # Prefixed tokens: format + charset + length are the
                # gate; still reject placeholders embedded in them.
                plausible = len(value) >= 16 and not any(
                    p in value.lower() for p in _PLACEHOLDERS)
            if not plausible:
                continue
            masked = mask_secret(value)
            line = _line_no(text, m.start())
            key = (kind, masked, line)
            if key in seen:
                continue
            seen.add(key)
            context = _context_line(text, m.start()).replace(value, masked)
            records.append({"kind": kind, "severity": sev,
                            "masked": masked, "url": url, "line": line,
                            "context": context})
    return records


def _scan_source_map(ctx, js_url, map_url, out_records):
    """Scan a source map's sourcesContent; locations are
    ``<map_url>#<source_file>`` so the original file is identified
    even though the secret is only visible via the map."""
    r = ctx.client.fetch(map_url)
    if r.status != 200 or not r.body:
        return
    try:
        smap = json.loads(r.body)
    except Exception:
        return
    sources = smap.get("sources") or []
    contents = smap.get("sourcesContent") or []
    for src, content in zip(sources, contents):
        if not content:
            continue
        loc = f"{map_url}#{src}"
        for rec in find_secrets_in_text(content, loc):
            out_records.append(rec)


class _InlineScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blobs = []
        self._in_script = False
        self._buf = []

    def handle_starttag(self, tag, attrs):
        if tag == "script" and not dict(attrs).get("src"):
            self._in_script = True
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            self.blobs.append("".join(self._buf))

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def js_secrets_check(ctx, pages, js_urls):
    """Scan crawled pages' inline scripts, JS bundles and their source
    maps. Emits masked findings (resp=None — see module docstring)
    and returns the masked records found."""
    records = []
    for page_url, resp in pages or []:
        body = getattr(resp, "body", "") or ""
        if not body:
            continue
        parser = _InlineScriptParser()
        try:
            parser.feed(body)
        except Exception:
            pass
        for blob in parser.blobs:
            records.extend(find_secrets_in_text(blob, page_url))
    for js in js_urls or []:
        r = ctx.client.fetch(js)
        if r.status != 200 or not r.body:
            continue
        records.extend(find_secrets_in_text(r.body, js))
        # source map via explicit comment, else the .map convention
        m = _SOURCE_MAP_RE.search(r.body)
        map_url = None
        if m:
            map_url = urllib.parse.urljoin(js, m.group(1).strip())
        else:
            map_url = js + ".map"
        _scan_source_map(ctx, js, map_url, records)
    added = []
    for rec in records:
        if rec["kind"] in _PASSIVE_KINDS:
            dedupe = ("secret", rec["kind"], rec["url"])
        else:
            dedupe = ("jssecret", rec["kind"], rec["url"], rec["line"])
        f = ctx.findings.add(
            rec["severity"], f"Secret Exposed in JavaScript: {rec['kind']}",
            rec["url"],
            f"A {rec['kind']} was found in publicly served JavaScript at "
            f"line {rec['line']}. The value below is MASKED (first/last "
            f"characters only) — rotate the credential if it is real, "
            f"remove it from the bundle/source map, and never ship "
            f"secrets in client-side code.",
            proof=f"{rec['masked']}  (line {rec['line']}: {rec['context'][:200]})",
            param=rec["masked"], resp=None, cwe="CWE-798",
            dedupe_key=dedupe)
        if f is not None:
            added.append(f)
    return added
