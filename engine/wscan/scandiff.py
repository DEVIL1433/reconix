"""Scan diff — compare two scans of the same target (workflow feature).

Proof-only discipline: this module organises findings, it never creates
them. It reads scan results (dicts in the engine's format, or rows from
``scans.db``) and classifies every finding as NEW, CHANGED, FIXED or
UNCHANGED. It never issues HTTP requests and never touches the network.

Finding identity (stable across scans — do NOT rely on row ids)
---------------------------------------------------------------
``finding_identity(finding, target=None)`` is a SHA-1 hexdigest
(truncated to 16 chars, the same length as ``wscan.core.fingerprint_of``)
over::

    normalised-target | check-title | location

* ``normalised-target`` — see :func:`normalize_target`. Scheme is
  normalised away (the engine itself rebases http -> https), the host is
  lower-cased, default ports are dropped, a trailing slash is stripped.
* ``check-title`` — the finding's ``title`` (falling back to its
  ``check`` field), stripped. The title is the check's canonical name in
  the engine (e.g. ``"SQL Injection (error-based)"``).
* ``location`` — the finding URL reduced to scheme://host/path plus,
  for a parameterised finding, ``?`` + the parameter *name* only.
  Query *values* are deliberately excluded: a rescan whose seed value
  for ``?q=`` differs must still match the earlier finding, otherwise
  every rescan would report the same flaw as NEW + FIXED. For a finding
  with no parameter, the sorted query *keys* (not values) are kept, so
  two pages that differ only by which parameters exist stay distinct.

This identity is intentionally NOT ``core.fingerprint_of`` (which hashes
title|full-url|param, values included). The legacy fingerprint is still
surfaced in every diff detail as ``fp`` (computed the same way when the
finding does not already carry one) so the UI can join diff rows to
``finding_meta`` / history views, but classification uses the identity
above.

Classification
--------------
* NEW       — identity present in the new scan only.
* FIXED     — identity present in the old scan only.
* UNCHANGED — identity in both, same severity AND same evidence.
* CHANGED   — identity in both, but severity differs and/or the
  evidence differs. Evidence here means the finding's ``proof`` text
  (the engine's proof string); ``detail`` wording alone does not count,
  so a reworded engine message cannot fake a change.

Same-target guard
-----------------
``diff_scans`` compares the two scans' targets with
:func:`normalize_target`. If both targets are present and their
normalised forms differ, the result carries ``warning`` and — in the
default strict mode — empty classifications and zero counts, instead of
silently comparing two different sites. Pass ``strict_target=False`` to
compare anyway; the warning stays attached. If either target is missing,
the comparison proceeds but carries a warning that the target could not
be verified (never a silent comparison either).

Public API
----------
* ``finding_identity(finding, target=None)``
* ``finding_identity_parts(finding, target=None)``
* ``normalize_target(target)``, ``targets_match(a, b)``
* ``diff_scans(old_result, new_result, strict_target=True)``
* ``diff_scans_by_id(old_id, new_id, loader)``
* ``load_scan_from_db(db_path_or_conn, scan_id)``
* ``summarize_diff(diff)``, ``diff_to_report_section(diff)``
"""

import hashlib
import json
import sqlite3
import urllib.parse

__all__ = [
    "finding_identity", "finding_identity_parts", "normalize_target",
    "targets_match", "diff_scans", "diff_scans_by_id",
    "load_scan_from_db", "summarize_diff", "diff_to_report_section",
    "classify_pair",
]


# ---------------------------------------------------------------- identity

def normalize_target(target):
    """Normalise a scan target for comparison and identity purposes.

    Returns "" for a missing/blank target. Otherwise: scheme is dropped
    (http/https treated alike — the engine rebases http -> https),
    host lower-cased, default ports (:80/:443) dropped, trailing slash
    stripped, fragment/query dropped. The path is kept: two different
    paths are two different targets.
    """
    if not target:
        return ""
    text = str(target).strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and port not in (80, 443):
        host = "%s:%d" % (host, port)
    path = parts.path.rstrip("/") or "/"
    return host + path


def _location_of(finding):
    """URL reduced to host/path + parameter name (see module docstring)."""
    url = str(finding.get("url") or "")
    if not url:
        return ""
    parts = urllib.parse.urlsplit(url)
    host = (parts.netloc or "").lower()
    base = "%s://%s%s" % (parts.scheme.lower() or "https", host,
                          parts.path or "/")
    param = str(finding.get("param") or "").strip()
    if param:
        return base + "?" + param
    keys = sorted({k for k, _v in urllib.parse.parse_qsl(
        parts.query, keep_blank_values=True)})
    if keys:
        return base + "?" + ",".join(keys)
    return base


def finding_identity_parts(finding, target=None):
    """Return the (target, check, location) triple behind an identity."""
    finding = finding or {}
    scan_target = target if target is not None else finding.get("target")
    norm_target = normalize_target(scan_target)
    if not norm_target:
        # Fall back to the finding URL's host so a bare finding dict
        # (no scan target at all) still gets a stable identity.
        url = str(finding.get("url") or "")
        if url:
            parts = urllib.parse.urlsplit(
                url if "://" in url else "https://" + url)
            norm_target = (parts.hostname or "").lower()
    check = str(finding.get("title") or finding.get("check") or "").strip()
    return {"target": norm_target, "check": check,
            "location": _location_of(finding)}


def finding_identity(finding, target=None):
    """Stable identity of a finding across scans (16 hex chars)."""
    parts = finding_identity_parts(finding, target)
    raw = "%s|%s|%s" % (parts["target"], parts["check"], parts["location"])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _legacy_fp(finding):
    """The engine's fingerprint (title|full-url|param), for joining."""
    if finding.get("fp"):
        return finding["fp"]
    try:
        from .core import fingerprint_of
    except Exception:
        try:
            from wscan.core import fingerprint_of
        except Exception:
            raw = "%s|%s|%s" % (finding.get("title", ""),
                                finding.get("url", ""),
                                finding.get("param", ""))
            return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return fingerprint_of(finding)


def targets_match(a, b):
    """True when two targets normalise to the same target.

    Returns None when either target is missing (unverifiable, not a
    match and not a mismatch — callers must surface that as a warning).
    """
    na, nb = normalize_target(a), normalize_target(b)
    if not na or not nb:
        return None
    return na == nb


# ---------------------------------------------------------------- inputs

def _findings_of(result):
    """Accept a scan-result dict, a bare findings list, or None."""
    if result is None:
        return [], ""
    if isinstance(result, (list, tuple)):
        return list(result), ""
    if isinstance(result, dict):
        findings = result.get("findings")
        if findings is None:
            findings = result.get("items") or []
        return list(findings), result.get("target") or ""
    return [], ""


def _by_identity(findings, target):
    """First occurrence wins per identity (engine output is deduped,
    but synthetic / imported data may repeat an identity)."""
    out = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        ident = finding_identity(finding, target)
        if ident not in out:
            out[ident] = finding
    return out


def classify_pair(old, new):
    """Classify one matched pair: 'unchanged' or 'changed'.

    Returns (classification, changes) where changes maps field names to
    [old_value, new_value] for every field that differs. Severity and
    proof (evidence) are the compared fields.
    """
    changes = {}
    if (old or {}).get("severity") != (new or {}).get("severity"):
        changes["severity"] = [old.get("severity"), new.get("severity")]
    if (old or {}).get("proof", "") != (new or {}).get("proof", ""):
        changes["evidence"] = [old.get("proof", ""), new.get("proof", "")]
    if changes:
        return "changed", changes
    return "unchanged", changes


def _detail(ident, classification, old, new, changes=None):
    finding = new if new is not None else old
    return {
        "identity": ident,
        "classification": classification,
        "title": (finding or {}).get("title", ""),
        "url": (finding or {}).get("url", ""),
        "param": (finding or {}).get("param", ""),
        "cwe": (finding or {}).get("cwe", "") or
               (new or old or {}).get("cwe", ""),
        "severity_old": (old or {}).get("severity"),
        "severity_new": (new or {}).get("severity"),
        "fp": _legacy_fp(finding) if finding else "",
        "changes": changes or {},
        "old": old,
        "new": new,
    }


# ---------------------------------------------------------------- diff

def diff_scans(old_result, new_result, strict_target=True):
    """Compare two scan results. Returns a render-ready dict::

        {
          "old_target": ..., "new_target": ...,
          "targets_match": True/False/None,
          "warning": str | None,
          "summary": {"new": n, "changed": n, "fixed": n, "unchanged": n,
                      "total_old": n, "total_new": n},
          "new": [detail, ...], "changed": [...],
          "fixed": [...], "unchanged": [...],
        }

    ``old_result`` / ``new_result`` may each be a scan-result dict
    (with ``target`` and ``findings``), a bare findings list, or None.
    In strict mode (default) a target mismatch yields empty
    classifications; with ``strict_target=False`` the comparison runs
    anyway and the warning stays attached.
    """
    old_findings, old_target = _findings_of(old_result)
    new_findings, new_target = _findings_of(new_result)
    match = targets_match(old_target, new_target)
    warning = None
    if match is False:
        warning = ("Targets differ (%r vs %r) — scans of different "
                   "targets were not compared." % (old_target, new_target))
    elif match is None:
        warning = ("Target could not be verified (old=%r, new=%r) — "
                   "comparison proceeds unverified." % (old_target,
                                                        new_target))
    result = {
        "old_target": old_target, "new_target": new_target,
        "targets_match": match, "warning": warning,
        "summary": {"new": 0, "changed": 0, "fixed": 0, "unchanged": 0,
                    "total_old": 0, "total_new": 0},
        "new": [], "changed": [], "fixed": [], "unchanged": [],
    }
    if match is False and strict_target:
        return result
    old_by_id = _by_identity(old_findings, old_target)
    new_by_id = _by_identity(new_findings, new_target)
    result["summary"]["total_old"] = len(old_by_id)
    result["summary"]["total_new"] = len(new_by_id)
    for ident, new_f in new_by_id.items():
        if ident not in old_by_id:
            result["new"].append(_detail(ident, "new", None, new_f))
        else:
            cls, changes = classify_pair(old_by_id[ident], new_f)
            result[cls].append(_detail(ident, cls, old_by_id[ident],
                                       new_f, changes))
    for ident, old_f in old_by_id.items():
        if ident not in new_by_id:
            result["fixed"].append(_detail(ident, "fixed", old_f, None))
    for key in ("new", "changed", "fixed", "unchanged"):
        result["summary"][key] = len(result[key])
    return result


def summarize_diff(diff):
    """Return just the summary dict of a diff (counts per class)."""
    return dict(diff.get("summary", {}))


def diff_to_report_section(diff):
    """Shape a diff for the report layer (no rendering here).

    Returns {"heading", "summary", "warning", "sections"} where each
    section entry carries identity/title/url/param/severity
    old+new and the changes map — everything a report template needs
    without re-deriving the diff.
    """
    def _row(detail):
        return {
            "identity": detail["identity"], "title": detail["title"],
            "url": detail["url"], "param": detail["param"],
            "cwe": detail["cwe"], "severity_old": detail["severity_old"],
            "severity_new": detail["severity_new"],
            "changes": detail["changes"],
        }

    return {
        "heading": "Scan comparison",
        "warning": diff.get("warning"),
        "summary": summarize_diff(diff),
        "sections": {key: [_row(d) for d in diff.get(key, [])]
                     for key in ("new", "changed", "fixed", "unchanged")},
    }


# ---------------------------------------------------------------- id loader

def _open_db(db):
    """Accept a sqlite3 connection (returned as-is) or a path."""
    if isinstance(db, sqlite3.Connection):
        return db, False
    return sqlite3.connect(db), True


def load_scan_from_db(db, scan_id):
    """Load one stored scan from a ``scans.db``-shaped database.

    Reads the ``scans`` table (``id, target, result`` — the shape
    ``app.py`` writes) read-only in effect: no rows are modified, and a
    caller-supplied connection is never closed by this function.
    Returns {"id", "target", "findings", ...result} or None when the
    id is unknown or its stored result is not JSON.
    """
    conn, owned = _open_db(db)
    try:
        row = conn.execute(
            "SELECT target, result FROM scans WHERE id=?",
            (scan_id,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        if owned:
            conn.close()
    if not row or not row[1]:
        return None
    try:
        result = json.loads(row[1])
    except (ValueError, TypeError):
        return None
    if not isinstance(result, dict):
        return None
    out = dict(result)
    out.setdefault("target", row[0])
    out.setdefault("findings", [])
    out["id"] = scan_id
    return out


def diff_scans_by_id(old_id, new_id, loader):
    """Diff two scans fetched through ``loader``.

    ``loader(scan_id)`` may return a scan-result dict (with ``target``
    and ``findings``), a ``(target, result)`` tuple, or None. Unknown
    ids raise ValueError with a clear message instead of comparing
    against an empty scan. Pass ``load_scan_from_db`` partially applied
    (e.g. ``lambda sid: load_scan_from_db(path, sid)``) to diff stored
    scans by their history ids.
    """
    def _resolve(scan_id):
        loaded = loader(scan_id)
        if loaded is None:
            raise ValueError("no scan found with id %r" % (scan_id,))
        if isinstance(loaded, tuple) and len(loaded) == 2:
            target, result = loaded
            if isinstance(result, dict):
                out = dict(result)
                out.setdefault("target", target)
                return out
            return {"target": target, "findings": list(result or [])}
        return loaded

    return diff_scans(_resolve(old_id), _resolve(new_id))
