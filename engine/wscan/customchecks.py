"""Custom check builder — user-defined checks, no code writing.

A user defines a check from structured data (a dict, or JSON of the
same shape). The runner executes it through the engine's proof
discipline — control request + proof request + comparison — and
unproven means NO finding, exactly like the built-in checks. A check
that errors at runtime is skipped with a note, never a scan failure,
and a malformed definition fails validation with a clear error
instead of crashing anything.

Definition format (dict / JSON)
-------------------------------
::

    {
      "name": "Reflected marker in search",      # required, unique
      "description": "Optional free text.",
      "target": {                                 # required
        "kind": "url_param",                     # "url_param"|"form_field"
        "param": "q",                            # url_param: query param
        # ... or "field": "search" for form_field
        "url_contains": "/search",               # optional substring filter
        "method": "GET",                         # optional, default GET
                                                  # (form_field: POST)
        "payload_mode": "replace"                # "replace"|"append"
      },
      "payloads": ["<MARKER123>"],               # required, 1..20
      "proof_rule": {                            # required, one of:
        # reflection: marker (default "{payload}") appears in the proof
        #   response and not in the control response.
        "type": "reflection", "marker": "{payload}",
        # error_string: an error string appears in proof, not control.
        # "type": "error_string", "strings": ["SQL syntax", ...]
        # status: proof status is expected, control status is not.
        # "type": "status", "expected": 500
        # differential: proof/control bodies differ in length by at
        #   least min_length_diff (default 100); "contains" optionally
        #   must also appear in proof and not in control.
        # "type": "differential", "min_length_diff": 100
      },
      "severity": "Medium",                      # optional, default Medium
      "cwe": "CWE-79",                           # optional
      "title": "Custom check finding title",     # optional, default name
      "enabled": true                            # optional, default true
    }

* ``payload_mode``: ``replace`` sends the payload as the whole value
  (XSS-style, the default); ``append`` sends original-value + payload
  (SQLi-style). The control request always sends the original value
  (url_param) or an empty value (form_field), so the comparison is
  against what the page does without the payload.
* ``marker`` / ``contains`` may embed ``{payload}``; it is replaced
  with the payload being tested. A marker with no placeholder is a
  literal string.
* Unknown keys are validation errors, not ignored typos: a misspelled
  key (e.g. ``"payload"`` for ``"payloads"``) must fail loudly.

Storage
-------
Definitions live in a dedicated scans.db table, ``workflow_custom_checks``
(name TEXT PRIMARY KEY, definition TEXT (JSON), created_at TEXT,
updated_at TEXT). The table was chosen over a sidecar JSON file so
definitions travel with the scan history they belong to (same backup,
same install, no extra file to deploy or lose); :func:`export_definitions`
/ :func:`definition_to_json` still make definitions portable as JSON.
The table is created if missing; nothing else in scans.db is touched.

Public API
----------
* ``CustomCheckError`` (a ValueError), ``validate_definition(d)``,
  ``check_definition(d)`` (error list, no raise),
  ``definition_to_json(d)``, ``definition_from_json(text)``
* ``run_custom_check(definition, client, url, form_data=None)``
* ``run_custom_checks(definitions, client, urls, form_data=None)``
* ``ensure_schema(db)``, ``create_custom_check(db, d, overwrite=False)``,
  ``list_custom_checks(db, enabled_only=False)``,
  ``get_custom_check(db, name)``, ``delete_custom_check(db, name)``
"""

import json
import os
import re
import sqlite3
import urllib.parse
from datetime import datetime, timezone

try:
    from .core import params_of, with_param
except ImportError:  # pragma: no cover - direct-module import fallback
    try:
        from wscan.core import params_of, with_param
    except ImportError:
        params_of = None
        with_param = None

__all__ = [
    "CustomCheckError", "validate_definition", "check_definition",
    "definition_to_json", "definition_from_json",
    "run_custom_check", "run_custom_checks",
    "ensure_schema", "create_custom_check", "list_custom_checks",
    "get_custom_check", "delete_custom_check", "TABLE",
]

TABLE = "workflow_custom_checks"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
_PROOF_TYPES = ("reflection", "error_string", "status", "differential")
_DEF_KEYS = {"name", "description", "target", "payloads", "proof_rule",
             "severity", "cwe", "title", "enabled"}
_TARGET_KEYS = {"kind", "param", "field", "url_contains", "method",
                "payload_mode"}
_RULE_KEYS = {
    "reflection": {"type", "marker", "must_not_appear_in_control"},
    "error_string": {"type", "strings", "string"},
    "status": {"type", "expected"},
    "differential": {"type", "min_length_diff", "contains"},
}


class CustomCheckError(ValueError):
    """A custom-check definition (or stored row) is malformed."""


# ---------------------------------------------------------------- validation

def check_definition(defn):
    """Return a list of validation error strings (empty = valid)."""
    errors = []

    def _err(msg):
        errors.append(msg)

    if not isinstance(defn, dict):
        return ["definition must be an object/dict, got %s"
                % type(defn).__name__]
    for key in sorted(set(defn) - _DEF_KEYS):
        _err("unknown field %r (allowed: %s)"
             % (key, ", ".join(sorted(_DEF_KEYS))))
    name = defn.get("name")
    if not isinstance(name, str) or not name.strip():
        _err("name is required and must be a non-empty string")
    elif len(name.strip()) > 120:
        _err("name must be at most 120 characters")
    if "description" in defn and not isinstance(defn["description"], str):
        _err("description must be a string")
    target = defn.get("target")
    if not isinstance(target, dict):
        _err("target is required and must be an object")
    else:
        for key in sorted(set(target) - _TARGET_KEYS):
            _err("target: unknown field %r (allowed: %s)"
                 % (key, ", ".join(sorted(_TARGET_KEYS))))
        kind = target.get("kind")
        if kind not in ("url_param", "form_field"):
            _err('target.kind must be "url_param" or "form_field"')
        elif kind == "url_param":
            if not isinstance(target.get("param"), str) \
                    or not target["param"].strip():
                _err('target.param is required for kind "url_param"')
        else:
            if not isinstance(target.get("field"), str) \
                    or not target["field"].strip():
                _err('target.field is required for kind "form_field"')
        if "url_contains" in target \
                and not isinstance(target["url_contains"], str):
            _err("target.url_contains must be a string")
        if "method" in target and target["method"] not in (
                "GET", "POST", "get", "post"):
            _err('target.method must be "GET" or "POST"')
        if "payload_mode" in target \
                and target["payload_mode"] not in ("replace", "append"):
            _err('target.payload_mode must be "replace" or "append"')
    payloads = defn.get("payloads")
    if not isinstance(payloads, list) or not payloads:
        _err("payloads is required and must be a non-empty list")
    elif len(payloads) > 20:
        _err("payloads must contain at most 20 entries")
    else:
        for i, payload in enumerate(payloads):
            if not isinstance(payload, str) or not payload:
                _err("payloads[%d] must be a non-empty string" % i)
            elif len(payload) > 2000:
                _err("payloads[%d] must be at most 2000 characters" % i)
    rule = defn.get("proof_rule")
    if not isinstance(rule, dict):
        _err("proof_rule is required and must be an object")
    else:
        rtype = rule.get("type")
        if rtype not in _PROOF_TYPES:
            _err("proof_rule.type must be one of: %s"
                 % ", ".join(_PROOF_TYPES))
        else:
            for key in sorted(set(rule) - _RULE_KEYS[rtype]):
                _err("proof_rule: unknown field %r for type %r"
                     % (key, rtype))
            if rtype == "reflection":
                if "marker" in rule and (
                        not isinstance(rule["marker"], str)
                        or not rule["marker"]):
                    _err("proof_rule.marker must be a non-empty string")
                if "must_not_appear_in_control" in rule and not isinstance(
                        rule["must_not_appear_in_control"], bool):
                    _err("proof_rule.must_not_appear_in_control must be "
                         "true/false")
            elif rtype == "error_string":
                has_list = "strings" in rule
                has_one = "string" in rule
                if has_list and has_one:
                    _err("proof_rule: use strings or string, not both")
                elif has_list:
                    if not isinstance(rule["strings"], list) \
                            or not rule["strings"] \
                            or any(not isinstance(s, str) or not s
                                   for s in rule["strings"]):
                        _err("proof_rule.strings must be a non-empty "
                             "list of non-empty strings")
                elif has_one:
                    if not isinstance(rule["string"], str) \
                            or not rule["string"]:
                        _err("proof_rule.string must be a non-empty string")
                else:
                    _err("proof_rule: error_string needs strings or string")
            elif rtype == "status":
                expected = rule.get("expected")
                values = expected if isinstance(expected, list) else [expected]
                if not values or any(not isinstance(v, int)
                                     or isinstance(v, bool)
                                     or not 100 <= v <= 599
                                     for v in values):
                    _err("proof_rule.expected must be an HTTP status "
                         "(100-599) or a non-empty list of them")
            elif rtype == "differential":
                if "min_length_diff" in rule and (
                        not isinstance(rule["min_length_diff"], int)
                        or isinstance(rule["min_length_diff"], bool)
                        or rule["min_length_diff"] < 1):
                    _err("proof_rule.min_length_diff must be an integer >= 1")
                if "contains" in rule and (
                        not isinstance(rule["contains"], str)
                        or not rule["contains"]):
                    _err("proof_rule.contains must be a non-empty string")
    if "severity" in defn and defn["severity"] not in SEVERITIES:
        _err("severity must be one of: %s" % ", ".join(SEVERITIES))
    if "cwe" in defn and defn["cwe"]:
        # "" means "no CWE" (the normalised form of an absent cwe), so
        # a normalised definition must re-validate cleanly.
        if not isinstance(defn["cwe"], str) \
                or not re.match(r"^CWE-\d+$", defn["cwe"].strip()):
            _err('cwe must look like "CWE-79"')
    if "title" in defn and (not isinstance(defn["title"], str)
                            or not defn["title"].strip()):
        _err("title must be a non-empty string when present")
    if "enabled" in defn and not isinstance(defn["enabled"], bool):
        _err("enabled must be true/false")
    return errors


def validate_definition(defn):
    """Validate and return a normalised copy, or raise CustomCheckError.

    The error message lists every problem found, so a malformed
    definition fails with a clear explanation instead of a crash.
    """
    errors = check_definition(defn)
    if errors:
        raise CustomCheckError(
            "invalid custom check definition (%s): %s"
            % (defn.get("name") if isinstance(defn, dict) else "?",
               "; ".join(errors)))
    target = dict(defn["target"])
    kind = target["kind"]
    target.setdefault("method", "POST" if kind == "form_field" else "GET")
    target["method"] = str(target["method"]).upper()
    target.setdefault("payload_mode", "replace")
    if kind == "url_param":
        target["param"] = target["param"].strip()
    else:
        target["field"] = target["field"].strip()
    rule = dict(defn["proof_rule"])
    if rule["type"] == "reflection":
        rule.setdefault("marker", "{payload}")
        rule.setdefault("must_not_appear_in_control", True)
    elif rule["type"] == "error_string":
        if "string" in rule:
            rule["strings"] = [rule.pop("string")]
    elif rule["type"] == "status":
        expected = rule["expected"]
        rule["expected"] = expected if isinstance(expected, list) \
            else [expected]
    elif rule["type"] == "differential":
        rule.setdefault("min_length_diff", 100)
    out = {
        "name": defn["name"].strip(),
        "description": defn.get("description", ""),
        "target": target,
        "payloads": list(defn["payloads"]),
        "proof_rule": rule,
        "severity": defn.get("severity", "Medium"),
        "cwe": defn.get("cwe", ""),
        "title": (defn.get("title") or defn["name"]).strip()
        if isinstance(defn.get("title"), str) and defn.get("title")
        else defn["name"].strip(),
        "enabled": defn.get("enabled", True),
    }
    return out


def definition_to_json(defn):
    """Serialise a (validated) definition to a JSON string."""
    return json.dumps(validate_definition(defn), indent=2,
                      sort_keys=True)


def definition_from_json(text):
    """Parse JSON text into a validated definition (clear errors)."""
    try:
        raw = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise CustomCheckError(
            "custom check JSON is not valid JSON: %s" % (exc,))
    return validate_definition(raw)


# ---------------------------------------------------------------- runner

def _with_param(url, name, value):
    if with_param is not None:
        return with_param(url, name, value)
    parts = urllib.parse.urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in
             urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    return urllib.parse.urlunsplit(
        parts._replace(query=urllib.parse.urlencode(pairs)))


def _params_of(url):
    if params_of is not None:
        return params_of(url)
    return urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                  keep_blank_values=True)


def _body(resp):
    return (getattr(resp, "body", "") or "") if resp is not None else ""


def _status(resp):
    return getattr(resp, "status", None) if resp is not None else None


def _evaluate_rule(rule, control, proof, payload):
    """Apply one proof rule. Returns (proven, explanation)."""
    c_body, p_body = _body(control), _body(proof)
    c_status, p_status = _status(control), _status(proof)
    rtype = rule["type"]
    if rtype == "reflection":
        marker = rule["marker"].replace("{payload}", payload)
        if not marker:
            return False, "reflection marker resolved to empty"
        if marker not in p_body:
            return False, "marker %r not reflected in proof response" \
                % marker
        if rule["must_not_appear_in_control"] and marker in c_body:
            return False, ("marker %r already present in the control "
                           "response — not proof of reflection" % marker)
        return True, "marker %r reflected in proof response, absent " \
            "from control response" % marker
    if rtype == "error_string":
        for needle in rule["strings"]:
            if needle in p_body and needle not in c_body:
                return True, "error string %r in proof response, " \
                    "absent from control response" % needle
        if any(s in c_body for s in rule["strings"]):
            return False, ("error string(s) already present in the "
                           "control response — baseline noise, not proof")
        return False, "no error string found in proof response"
    if rtype == "status":
        if p_status is None:
            return False, "proof request produced no HTTP status"
        if p_status not in rule["expected"]:
            return False, "proof status %s not in expected %s" \
                % (p_status, rule["expected"])
        if c_status in rule["expected"]:
            return False, ("control status %s is also in expected %s — "
                           "status change is not payload-caused"
                           % (c_status, rule["expected"]))
        return True, "proof status %s (expected), control status %s" \
            % (p_status, c_status)
    if rtype == "differential":
        diff = abs(len(p_body) - len(c_body))
        if diff < rule["min_length_diff"]:
            return False, ("response length difference %d below "
                           "threshold %d" % (diff, rule["min_length_diff"]))
        contains = rule.get("contains")
        if contains:
            needle = contains.replace("{payload}", payload)
            if needle not in p_body:
                return False, "differential marker %r not in proof " \
                    "response" % needle
            if needle in c_body:
                return False, ("differential marker %r already in "
                               "control response" % needle)
        return True, ("response length differs by %d (>= %d)"
                      % (diff, rule["min_length_diff"]))
    return False, "unknown proof rule type %r" % (rtype,)


def run_custom_check(definition, client, url, form_data=None):
    """Run one custom check against one URL. Never raises for a bad
    definition or a failed request — those become a skipped result.

    Returns {"name", "proven", "finding", "skipped", "error", "notes",
    "attempts"}. ``finding`` is an engine-shaped dict (severity, title,
    url, param, detail, proof, cwe, payload, confidence, custom_check)
    or None when unproven/skipped; ``Findings.add``-compatible, so the
    integration step can feed it straight into a scan's findings.
    """
    name = definition.get("name") if isinstance(definition, dict) else "?"
    base = {"name": name, "proven": False, "finding": None,
            "skipped": False, "error": None, "notes": [], "attempts": []}
    try:
        defn = validate_definition(definition)
    except CustomCheckError as exc:
        base.update(skipped=True, error=str(exc),
                    notes=["skipped: %s" % (exc,)])
        return base
    base["name"] = defn["name"]
    if client is None:
        base.update(skipped=True, error="no HTTP client supplied",
                    notes=["skipped: no HTTP client supplied"])
        return base
    if not url:
        base.update(skipped=True, error="no URL supplied",
                    notes=["skipped: no URL supplied"])
        return base
    target = defn["target"]
    if target.get("url_contains") and target["url_contains"] not in url:
        base.update(skipped=True,
                    notes=["skipped: URL does not contain %r"
                           % target["url_contains"]])
        return base
    kind = target["kind"]
    method = target["method"]
    mode = target["payload_mode"]
    try:
        if kind == "url_param":
            param = target["param"]
            values = dict(_params_of(url))
            if param not in values:
                base.update(skipped=True, notes=[
                    "skipped: parameter %r not present in URL" % param])
                return base
            original = values[param]

            def _request(value):
                return client.fetch(_with_param(url, param, value),
                                    method=method)
            param_name = param
        else:
            field = target["field"]
            base_data = dict(form_data or {})
            original = base_data.get(field, "")

            def _request(value):
                data = dict(base_data)
                data[field] = value
                return client.fetch(url, method=method, data=data)
            param_name = field
    except Exception as exc:  # request construction failed: skip, no crash
        base.update(skipped=True, error=str(exc),
                    notes=["skipped: request setup failed: %s" % (exc,)])
        return base
    try:
        control = _request(original)
    except Exception as exc:
        base.update(skipped=True, error=str(exc), notes=[
            "skipped: control request failed: %s" % (exc,)])
        return base
    if _status(control) is None:
        base.update(skipped=True, error="control request produced no status",
                    notes=["skipped: control request produced no status — "
                           "proof comparison needs a control response"])
        return base
    for payload in defn["payloads"]:
        value = original + payload if mode == "append" else payload
        try:
            proof = _request(value)
        except Exception as exc:
            note = "payload %r: proof request failed: %s" % (payload, exc)
            base["notes"].append(note)
            base["attempts"].append({"payload": payload, "status": None,
                                     "proven": False, "note": note})
            continue
        proven, explanation = _evaluate_rule(defn["proof_rule"], control,
                                             proof, payload)
        base["attempts"].append({"payload": payload,
                                 "status": _status(proof),
                                 "proven": proven, "note": explanation})
        if proven:
            base["proven"] = True
            base["finding"] = {
                "severity": defn["severity"],
                "title": defn["title"],
                "url": url, "param": param_name,
                "detail": ("Custom check %r proved on parameter %r: %s"
                           % (defn["name"], param_name, explanation)),
                "proof": ("Custom check %r | control status %s, proof "
                          "status %s | payload %r | %s"
                          % (defn["name"], _status(control),
                             _status(proof), payload, explanation)),
                "cwe": defn["cwe"], "payload": payload,
                "confidence": "Confirmed",
                "custom_check": defn["name"],
            }
            base["notes"].append("proven with payload %r: %s"
                                 % (payload, explanation))
            break
        base["notes"].append("payload %r unproven: %s"
                             % (payload, explanation))
    if not base["proven"] and not base["attempts"]:
        base["skipped"] = True
        base["notes"].append("skipped: no payload attempt completed")
    return base


def run_custom_checks(definitions, client, urls, form_data=None):
    """Run many custom checks over many URLs. Never raises per-check.

    Disabled definitions are skipped with a note. Returns
    {"findings": [...proven finding dicts...], "results": [...per-run
    results...], "notes": [...flat note strings...]}.
    """
    findings, results, notes = [], [], []
    for raw in definitions or []:
        if isinstance(raw, dict) and raw.get("enabled") is False:
            results.append({"name": raw.get("name", "?"), "proven": False,
                            "finding": None, "skipped": True,
                            "error": None,
                            "notes": ["skipped: check disabled"],
                            "attempts": []})
            continue
        for url in urls or []:
            result = run_custom_check(raw, client, url,
                                      form_data=form_data)
            results.append(result)
            notes.extend("%s: %s" % (result["name"], n)
                         for n in result["notes"])
            if result["finding"] is not None:
                findings.append(result["finding"])
    return {"findings": findings, "results": results, "notes": notes}


# ---------------------------------------------------------------- storage

def _default_db_path():
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "scans.db")


def _open(db):
    if db is None:
        return sqlite3.connect(_default_db_path()), True
    if isinstance(db, sqlite3.Connection):
        return db, False
    return sqlite3.connect(os.fspath(db)), True


def _close(conn, owned):
    if owned:
        conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_schema(db=None):
    """Create the definitions table if missing."""
    conn, owned = _open(db)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS %s ("
            "name TEXT PRIMARY KEY, definition TEXT NOT NULL, "
            "created_at TEXT, updated_at TEXT)" % TABLE)
        conn.commit()
    finally:
        _close(conn, owned)


def create_custom_check(db, definition, overwrite=False):
    """Validate and store a definition. Returns the normalised dict.

    Raises CustomCheckError on a malformed definition or on a duplicate
    name (unless overwrite=True, which updates in place).
    """
    defn = validate_definition(definition)
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        row = conn.execute("SELECT created_at FROM %s WHERE name=?"
                           % TABLE, (defn["name"],)).fetchone()
        if row and not overwrite:
            raise CustomCheckError(
                "a custom check named %r already exists (pass "
                "overwrite=True to replace it)" % defn["name"])
        created = row[0] if row else _now()
        conn.execute(
            "INSERT OR REPLACE INTO %s VALUES (?,?,?,?)" % TABLE,
            (defn["name"], json.dumps(defn, sort_keys=True),
             created, _now()))
        conn.commit()
    finally:
        _close(conn, owned)
    return defn


def get_custom_check(db, name):
    """Stored definition by name, or None when absent.

    A stored row that no longer validates raises CustomCheckError
    (corrupt data must not silently become a different check); use
    list_custom_checks, which skips such rows, for bulk runs.
    """
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        row = conn.execute("SELECT definition FROM %s WHERE name=?"
                           % TABLE, (name,)).fetchone()
    finally:
        _close(conn, owned)
    if not row:
        return None
    try:
        raw = json.loads(row[0])
    except (ValueError, TypeError) as exc:
        raise CustomCheckError(
            "stored custom check %r is not valid JSON: %s" % (name, exc))
    return validate_definition(raw)


def list_custom_checks(db, enabled_only=False):
    """All stored definitions, sorted by name.

    Rows that fail validation are skipped (a single corrupt row must
    not break a scan that runs the rest); they are not silently fixed.
    """
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        rows = conn.execute(
            "SELECT definition FROM %s ORDER BY name" % TABLE).fetchall()
    finally:
        _close(conn, owned)
    out = []
    for (text,) in rows:
        try:
            defn = validate_definition(json.loads(text))
        except (CustomCheckError, ValueError, TypeError):
            continue
        if enabled_only and not defn["enabled"]:
            continue
        out.append(defn)
    return out


def delete_custom_check(db, name):
    """Delete a stored definition. Returns True when one was removed."""
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        cur = conn.execute("DELETE FROM %s WHERE name=?" % TABLE, (name,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        _close(conn, owned)


def export_definitions(db):
    """All stored definitions as plain dicts (for JSON export)."""
    return list_custom_checks(db)
