"""Mark false positives with a reason (workflow feature).

An analyst marks a finding as a false positive WITH a reason note.
Marked findings stay EXCLUDED from future reports of that target, with
the reason attached, and can be UNMARKED (restoring them). Excluded
findings are never silently deleted: :func:`apply_exclusions` returns
them in a separate, countable ``excluded`` list carrying the full
exclusion record, so the report layer can render an
"excluded as false positive (reason)" section.

Storage (dedicated table in scans.db, created if missing)
---------------------------------------------------------
Table ``workflow_false_positives`` — deliberately separate from the
existing ``finding_meta`` table (which drives the engine's pre-scan
suppression via status='fp'). This module does not read or write
``finding_meta``; the integration step may bridge the two, but this
module's contract stands on its own and cannot disturb live scans::

    CREATE TABLE IF NOT EXISTS workflow_false_positives (
        target      TEXT NOT NULL,   -- normalised target (see below)
        identity    TEXT NOT NULL,   -- scandiff.finding_identity
        title       TEXT,            -- snapshot at mark time
        url         TEXT,            -- snapshot at mark time
        param       TEXT,            -- snapshot at mark time
        reason      TEXT NOT NULL,   -- analyst's reason, plain text
        marked_by   TEXT,            -- who, plain text ("" if unknown)
        marked_at   TEXT,            -- UTC ISO-8601, plain text
        status      TEXT,            -- 'active' | 'removed'
        unmarked_by TEXT,            -- who unmarked, plain text
        unmarked_at TEXT,            -- UTC ISO-8601, plain text
        PRIMARY KEY (target, identity)
    )

* Keyed by (normalised target, finding identity): exclusions apply
  PER-TARGET, never globally — the same flaw on another target is
  unaffected.
* Targets are normalised with ``scandiff.normalize_target`` on write
  and on read, so ``https://example.com/`` and ``https://example.com``
  refer to the same exclusion.
* Unmarking is a soft delete (status -> 'removed' with who/when kept),
  not a row delete: the audit trail survives, and re-marking the same
  finding revives the row with the new reason. ``list_false_positives``
  returns active marks by default; ``include_removed=True`` shows the
  audit trail.
* All who/when fields are plain text; no user accounts are assumed —
  ``marked_by`` is whatever label the caller passes (analyst name,
  "analyst", or "").

Public API (``db`` accepts a sqlite3 connection, a path string, a
pathlib Path, or None for the scans.db next to this package's app)::

* ``ensure_schema(db)``
* ``mark_false_positive(db, target, finding, reason, marked_by="")``
* ``unmark_false_positive(db, target, finding, unmarked_by="")``
* ``list_false_positives(db, target, include_removed=False)``
* ``get_exclusion(db, target, finding)`` / ``is_false_positive(...)``
* ``apply_exclusions(db, target, findings)``
* ``apply_exclusions_to_result(db, result)``
"""

import os
import sqlite3
from datetime import datetime, timezone

try:
    from .scandiff import finding_identity, normalize_target
except ImportError:  # pragma: no cover - direct-module import fallback
    from scandiff import finding_identity, normalize_target

__all__ = [
    "ensure_schema", "mark_false_positive", "unmark_false_positive",
    "list_false_positives", "get_exclusion", "is_false_positive",
    "apply_exclusions", "apply_exclusions_to_result",
    "TABLE", "MAX_REASON_LEN",
]

TABLE = "workflow_false_positives"
MAX_REASON_LEN = 2000


def _default_db_path():
    # wscan/ sits next to app.py, which owns scans.db.
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "scans.db")


def _open(db):
    """Return (conn, owned). A caller-supplied connection is not closed."""
    if db is None:
        return sqlite3.connect(_default_db_path()), True
    if isinstance(db, sqlite3.Connection):
        return db, False
    return sqlite3.connect(os.fspath(db)), True


def _close(conn, owned):
    if owned:
        conn.close()


def ensure_schema(db=None):
    """Create the table if missing. Safe to call on every operation."""
    conn, owned = _open(db)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS %s ("
            "target TEXT NOT NULL, identity TEXT NOT NULL, "
            "title TEXT, url TEXT, param TEXT, reason TEXT NOT NULL, "
            "marked_by TEXT, marked_at TEXT, status TEXT, "
            "unmarked_by TEXT, unmarked_at TEXT, "
            "PRIMARY KEY (target, identity))" % TABLE)
        conn.commit()
    finally:
        _close(conn, owned)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _identity_of(finding):
    if isinstance(finding, str):
        return finding
    if isinstance(finding, dict):
        return finding_identity(finding)
    raise ValueError("finding must be a finding dict or an identity string")


def _snapshot(finding):
    if isinstance(finding, dict):
        return (finding.get("title", ""), finding.get("url", ""),
                finding.get("param", ""))
    return ("", "", "")


def mark_false_positive(db, target, finding, reason, marked_by=""):
    """Mark a finding as a false positive for one target.

    ``finding`` is a finding dict (identity derived from it) or an
    identity string. ``reason`` must be non-blank — a reasonless mark is
    a ValueError, never a silent row. Returns the stored record dict.
    Re-marking updates the reason/who/when and revives a removed mark.
    """
    if not target or not str(target).strip():
        raise ValueError("mark_false_positive: target is required")
    if reason is None or not str(reason).strip():
        raise ValueError(
            "mark_false_positive: a reason is required — refusing to "
            "mark a finding as a false positive without one")
    reason = str(reason).strip()[:MAX_REASON_LEN]
    norm_target = normalize_target(target)
    ident = _identity_of(finding)
    title, url, param = _snapshot(finding)
    record = {
        "target": norm_target, "identity": ident, "title": title,
        "url": url, "param": param, "reason": reason,
        "marked_by": str(marked_by or ""), "marked_at": _now(),
        "status": "active", "unmarked_by": "", "unmarked_at": "",
    }
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO %s VALUES (?,?,?,?,?,?,?,?,?,?,?)"
            % TABLE,
            (record["target"], record["identity"], record["title"],
             record["url"], record["param"], record["reason"],
             record["marked_by"], record["marked_at"], record["status"],
             record["unmarked_by"], record["unmarked_at"]))
        conn.commit()
    finally:
        _close(conn, owned)
    return record


def unmark_false_positive(db, target, finding, unmarked_by=""):
    """Unmark a finding, restoring it to future reports.

    Soft delete: the row stays with status='removed' and the unmark
    who/when recorded. Returns True when an active mark was removed,
    False when there was no active mark (nothing to restore).
    """
    if not target or not str(target).strip():
        raise ValueError("unmark_false_positive: target is required")
    norm_target = normalize_target(target)
    ident = _identity_of(finding)
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        cur = conn.execute(
            "UPDATE %s SET status='removed', unmarked_by=?, "
            "unmarked_at=? WHERE target=? AND identity=? "
            "AND status='active'" % TABLE,
            (str(unmarked_by or ""), _now(), norm_target, ident))
        conn.commit()
        return cur.rowcount > 0
    finally:
        _close(conn, owned)


def list_false_positives(db, target, include_removed=False):
    """All false-positive marks for one target (active by default)."""
    if not target or not str(target).strip():
        raise ValueError("list_false_positives: target is required")
    norm_target = normalize_target(target)
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        sql = ("SELECT target, identity, title, url, param, reason, "
               "marked_by, marked_at, status, unmarked_by, unmarked_at "
               "FROM %s WHERE target=?" % TABLE)
        if not include_removed:
            sql += " AND status='active'"
        sql += " ORDER BY marked_at, identity"
        rows = conn.execute(sql, (norm_target,)).fetchall()
    finally:
        _close(conn, owned)
    keys = ("target", "identity", "title", "url", "param", "reason",
            "marked_by", "marked_at", "status", "unmarked_by",
            "unmarked_at")
    return [dict(zip(keys, row)) for row in rows]


def get_exclusion(db, target, finding):
    """Active exclusion record for one finding, or None."""
    if not target or not str(target).strip():
        return None
    norm_target = normalize_target(target)
    ident = _identity_of(finding)
    ensure_schema(db)
    conn, owned = _open(db)
    try:
        row = conn.execute(
            "SELECT target, identity, title, url, param, reason, "
            "marked_by, marked_at, status, unmarked_by, unmarked_at "
            "FROM %s WHERE target=? AND identity=? AND status='active'"
            % TABLE, (norm_target, ident)).fetchone()
    finally:
        _close(conn, owned)
    if not row:
        return None
    keys = ("target", "identity", "title", "url", "param", "reason",
            "marked_by", "marked_at", "status", "unmarked_by",
            "unmarked_at")
    return dict(zip(keys, row))


def is_false_positive(db, target, finding):
    """True when this finding is actively excluded for this target."""
    return get_exclusion(db, target, finding) is not None


def apply_exclusions(db, target, findings):
    """Split a scan's findings into kept vs excluded (auditable).

    Returns {"findings": [...kept...],
             "excluded": [{finding fields..., "exclusion_reason",
                           "exclusion_marked_by", "exclusion_marked_at",
                           "exclusion_identity"}],
             "counts": {"total": n, "kept": n, "excluded": n}}.
    Excluded findings are NOT deleted: the report layer renders the
    ``excluded`` list as its "excluded as false positive (reason)"
    section, and ``counts`` keeps the totals honest.
    """
    findings = list(findings or [])
    if not target or not str(target).strip():
        # No target, no per-target exclusions can apply — nothing is
        # silently dropped; everything is kept.
        return {"findings": findings, "excluded": [],
                "counts": {"total": len(findings), "kept": len(findings),
                           "excluded": 0}}
    active = {r["identity"]: r
              for r in list_false_positives(db, target)}
    kept, excluded = [], []
    for finding in findings:
        if not isinstance(finding, dict):
            kept.append(finding)
            continue
        record = active.get(finding_identity(finding))
        if record is None:
            kept.append(finding)
        else:
            entry = dict(finding)
            entry["exclusion_reason"] = record["reason"]
            entry["exclusion_marked_by"] = record["marked_by"]
            entry["exclusion_marked_at"] = record["marked_at"]
            entry["exclusion_identity"] = record["identity"]
            entry["excluded_as_false_positive"] = True
            excluded.append(entry)
    return {"findings": kept, "excluded": excluded,
            "counts": {"total": len(findings), "kept": len(kept),
                       "excluded": len(excluded)}}


def apply_exclusions_to_result(db, result):
    """Apply exclusions to a whole scan-result dict (copy, not mutate).

    Returns a copy of ``result`` whose ``findings`` are the kept ones,
    plus ``excluded_false_positives`` (the auditable excluded list)
    and ``exclusion_counts``. The original result dict is untouched.
    """
    if not isinstance(result, dict):
        raise ValueError("apply_exclusions_to_result: result must be a dict")
    target = result.get("target") or ""
    split = apply_exclusions(db, target, result.get("findings") or [])
    out = dict(result)
    out["findings"] = split["findings"]
    out["excluded_false_positives"] = split["excluded"]
    out["exclusion_counts"] = split["counts"]
    return out
