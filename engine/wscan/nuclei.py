"""Nuclei templates inside Reconix — honesty-compliant runner.

Runs Nuclei's ready-made known-bug checks from inside a scan and parses
its JSONL output into structured results.

SEPARATION CONTRACT (read before integrating):
  * Matches returned here are NEVER engine findings. They are dicts with
    ``source == "nuclei"`` and ``is_engine_finding == False`` and must be
    rendered as a separate "Nuclei template matches" section in the
    report. They must NOT be passed to ``Findings.add`` and must NOT
    feed ``risk_score`` / ``counts`` / ``groups``.
  * This is deliberately separate from ``wscan/integrations.py``.
    That older module (``run_nuclei`` / ``import_nuclei_jsonl``) merges
    Nuclei output INTO the findings store, which silently mixes
    template matches with engine-proven findings. Do NOT call both
    modules for the same scan — use this module for new integrations
    and leave ``integrations.py`` untouched for its existing callers.
  * A Nuclei match is template evidence ("template X matched at URL,
    matcher Y, extracted Z"), not a Reconix proof. The report layer
    must label it as Nuclei-sourced; the ``evidence`` field below is
    worded that way on purpose.

DEGRADATION CONTRACT:
  * Nuclei binary absent  -> result with ``available == False`` and a
    "Nuclei not installed" note. Never a scan failure, never a hang.
  * Runner timeout / OSError / empty output -> a note, zero matches,
    never an exception out of ``run_nuclei_scan``.
  * Templates are NEVER auto-updated during a scan. Updating is a
    separate, user-initiated step: see ``update_templates_command``
    / ``run_template_update`` (the user runs ``nuclei
    -update-templates`` themselves).

SAFETY:
  * The target URL is passed as one argv element; subprocess is never
    invoked with ``shell=True``. Targets must be http(s) URLs.
  * The subprocess run is bounded by ``timeout`` (default 300 s).

Stdlib only. No live Nuclei install is needed to import or test this
module: pass ``which`` / ``runner`` test seams (or mock subprocess).
"""

import json
import shutil
import subprocess
import urllib.parse

# Nuclei severity words -> Reconix finding severities (used for display
# sorting inside the Nuclei section only — never for engine counts).
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "unknown": "Info",
    "none": "Info",
}

NOT_INSTALLED_NOTE = (
    "Nuclei not installed — Nuclei template checks skipped. "
    "Install Nuclei (https://github.com/projectdiscovery/nuclei) and "
    "re-run the scan to include template matches."
)

DEFAULT_TIMEOUT = 300  # seconds, bounding the whole Nuclei subprocess run
UPDATE_TIMEOUT = 600  # seconds, for the separate template-update step


# ------------------------------------------------------------------ binary

def find_nuclei_binary(binary=None, which=None):
    """Return the Nuclei binary path, or None if it is not available.

    ``binary``: explicit path to use (must exist to count as found).
    ``which``: test seam, defaults to ``shutil.which``.
    """
    if binary:
        import os
        return binary if os.path.isfile(binary) else None
    finder = which or shutil.which
    try:
        return finder("nuclei")
    except Exception:
        return None


# ------------------------------------------------------------------ command

def _clean_severities(severities):
    out = []
    for s in severities or []:
        s = str(s).strip().lower()
        if s in SEVERITY_MAP and s not in ("unknown", "none"):
            if s not in out:
                out.append(s)
    return out


def build_nuclei_command(target, binary, template_paths=None,
                         templates_dir=None, severities=None, tags=None):
    """Build the Nuclei argv list (no shell, target is one element).

    ``template_paths``: explicit template files and/or directories,
    each passed as its own ``-t`` argument. ``templates_dir``: a
    single templates root, also passed via ``-t``. ``severities``:
    Nuclei severity filter (e.g. ["critical", "high"]); unknown words
    are dropped. ``tags``: Nuclei tag filter, comma-joined.
    """
    cmd = [binary, "-u", target, "-jsonl", "-silent", "-nc"]
    for path in template_paths or []:
        if path:
            cmd += ["-t", str(path)]
    if templates_dir:
        cmd += ["-t", str(templates_dir)]
    sev = _clean_severities(severities)
    if sev:
        cmd += ["-severity", ",".join(sev)]
    clean_tags = [str(t).strip() for t in (tags or []) if str(t).strip()]
    if clean_tags:
        cmd += ["-tags", ",".join(clean_tags)]
    return cmd


def validate_target(target):
    """True only for http(s) URLs with a host — anything else is refused."""
    if not target or not isinstance(target, str):
        return False
    parts = urllib.parse.urlsplit(target.strip())
    return parts.scheme in ("http", "https") and bool(parts.netloc)


# ------------------------------------------------------------------ parsing

def _normalise_match(item):
    """One Nuclei JSONL object -> a structured, Nuclei-labelled dict.

    Returns None for objects that carry no usable template identity.
    """
    if not isinstance(item, dict):
        return None
    info = item.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    template_id = (item.get("template-id") or item.get("templateID")
                   or info.get("template-id") or "")
    if not template_id:
        return None
    matched_at = (item.get("matched-at") or item.get("matchedAt")
                  or item.get("host") or "")
    name = info.get("name") or template_id
    severity = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(),
                                "Info")
    matcher = item.get("matcher-name") or item.get("matcherName") or ""
    extracted = item.get("extracted-results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    extracted = [str(x) for x in extracted][:10]
    references = info.get("reference") or []
    if isinstance(references, str):
        references = [references]
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    cwe = info.get("classification", {}).get("cwe-id") or []
    if isinstance(cwe, str):
        cwe = [cwe]
    evidence = f"Nuclei template {template_id} matched at {matched_at}"
    if matcher:
        evidence += f" (matcher: {matcher})"
    if extracted:
        evidence += " Extracted: " + ", ".join(extracted)[:200]
    return {
        "source": "nuclei",
        "source_label": "Nuclei template match",
        "is_engine_finding": False,
        "template_id": template_id,
        "name": name,
        "severity": severity,
        "matched_at": matched_at,
        "url": matched_at,
        "host": item.get("host") or "",
        "matcher_name": matcher,
        "extracted_results": extracted,
        "description": info.get("description") or
                       f"Nuclei template {template_id} matched.",
        "references": [str(r) for r in references][:10],
        "tags": [str(t) for t in tags][:20],
        "cwe_ids": [str(c) for c in cwe][:10],
        # "evidence" is Nuclei's matcher output, worded as such — it is
        # NOT a Reconix proof and must not be stored in a finding's
        # "proof" field.
        "evidence": evidence,
    }


def parse_nuclei_jsonl(text):
    """Parse Nuclei ``-jsonl`` output into structured match dicts.

    Accepts str or bytes. Blank lines, non-JSON lines and objects with
    no template id are skipped (never fatal). Matches are deduplicated
    on (template_id, matched_at, matcher_name).
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    matches, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        m = _normalise_match(item)
        if m is None:
            continue
        key = (m["template_id"], m["matched_at"], m["matcher_name"])
        if key in seen:
            continue
        seen.add(key)
        matches.append(m)
    return matches


# ------------------------------------------------------------------ running

def run_nuclei_scan(target, template_paths=None, templates_dir=None,
                    severities=None, tags=None, timeout=DEFAULT_TIMEOUT,
                    binary=None, runner=None, which=None, emit=None):
    """Run Nuclei for ``target`` and return a self-describing result.

    Never raises for a missing binary, a timeout, a runner error or
    bad output — it returns ``{"available": bool, "note": str|None,
    "matches": [...], "command": [...]}`` instead. ``runner`` is the
    subprocess seam: ``runner(cmd, capture_output=True, text=True,
    timeout=...)`` returning an object with ``.stdout`` / ``.returncode``
    (defaults to ``subprocess.run``). ``emit`` (optional) receives
    note strings for the scan log.
    """
    resolved = find_nuclei_binary(binary=binary, which=which)
    if not resolved:
        note = NOT_INSTALLED_NOTE
        if emit:
            emit(note)
        return {"available": False, "note": note, "matches": [],
                "command": []}
    if not validate_target(target):
        note = (f"Nuclei skipped: invalid target URL {target!r} "
                "(expected an http(s) URL).")
        if emit:
            emit(note)
        return {"available": True, "note": note, "matches": [],
                "command": []}
    cmd = build_nuclei_command(target, resolved,
                               template_paths=template_paths,
                               templates_dir=templates_dir,
                               severities=severities, tags=tags)
    run = runner or subprocess.run
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = getattr(proc, "stdout", "") or ""
    except subprocess.TimeoutExpired:
        note = (f"Nuclei run timed out after {timeout}s — template "
                "checks skipped (no partial results kept).")
        if emit:
            emit(note)
        return {"available": True, "note": note, "matches": [],
                "command": cmd}
    except Exception as e:
        note = f"Nuclei run failed ({e}) — template checks skipped."
        if emit:
            emit(note)
        return {"available": True, "note": note, "matches": [],
                "command": cmd}
    matches = parse_nuclei_jsonl(stdout)
    note = None
    if getattr(proc, "returncode", 0) not in (0, None) and not matches:
        note = (f"Nuclei exited with code {proc.returncode} and produced "
                "no template matches.")
    if emit and note:
        emit(note)
    return {"available": True, "note": note, "matches": matches,
            "command": cmd}


# ------------------------------------------------------- template updating
# NEVER called by run_nuclei_scan. The user runs this themselves when
# they want fresh templates; the integration must surface the command
# (e.g. in scan settings / the Nuclei section note), not execute it
# silently during a scan.

def update_templates_command(binary=None, which=None):
    """The documented update invocation, or None if Nuclei is absent."""
    resolved = find_nuclei_binary(binary=binary, which=which)
    if not resolved:
        return None
    return [resolved, "-update-templates"]


def run_template_update(binary=None, timeout=UPDATE_TIMEOUT,
                        runner=None, which=None):
    """Run ``nuclei -update-templates`` on explicit user request.

    Returns ``(ok, note)``. Never called automatically by scans.
    """
    cmd = update_templates_command(binary=binary, which=which)
    if cmd is None:
        return False, NOT_INSTALLED_NOTE
    run = runner or subprocess.run
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"Nuclei template update timed out after {timeout}s."
    except Exception as e:
        return False, f"Nuclei template update failed: {e}"
    if getattr(proc, "returncode", 0) == 0:
        return True, "Nuclei templates updated."
    return False, (f"Nuclei template update exited with code "
                   f"{proc.returncode}.")


# ------------------------------------------------------- report rendering
# The report layer renders this section SEPARATELY from findings:
# never merge ``matches`` into the findings list, counts or risk score.

def nuclei_section(result):
    """Result dict -> report-section dict for the separate Nuclei block."""
    result = result or {}
    return {
        "title": "Nuclei template matches",
        "available": bool(result.get("available")),
        "note": result.get("note"),
        "count": len(result.get("matches") or []),
        "matches": list(result.get("matches") or []),
    }


def format_nuclei_section(result):
    """Plain-text lines for the separate Nuclei section of a report."""
    sec = nuclei_section(result)
    lines = [f"Nuclei template matches ({sec['count']})"]
    if not sec["available"] or sec["note"]:
        lines.append(sec["note"] or "Nuclei template checks were skipped.")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    for m in sorted(sec["matches"],
                    key=lambda x: (order.get(x["severity"], 9),
                                   x["template_id"])):
        lines.append(f"  [{m['severity']}] {m['name']} "
                     f"(template {m['template_id']}) -> {m['matched_at']}")
        lines.append(f"    Evidence (Nuclei-sourced): {m['evidence']}")
    return lines
