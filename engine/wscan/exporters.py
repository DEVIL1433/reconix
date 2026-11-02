"""Report exporters: Excel (.xlsx) and JSON dumps of a scan result.

Both exporters render ONLY what the scan result already contains: proven
findings from ``result["findings"]`` plus, where the result structure
provides them, clearly-labelled advisory/external-tool sections. They
never invent findings, severities, or evidence.

JSON schema (``to_json`` output, top level)
--------------------------------------------
::

    {
      "schema": "reconix-scan-export",
      "schema_version": 1,
      "exported_format": "json",
      "metadata": {
        "target": str, "profile": str, "finished_at": str,
        "started_at": str | null, "duration_s": number | null,
        "risk_score": int, "risk_grade": str,
        "engine": "Reconix"   // only if the result carries no other label
      },
      "counts": {"Critical": int, "High": int, "Medium": int,
                 "Low": int, "Info": int, "total": int},
      "findings": [ <finding dict, verbatim — every field the scan
                     recorded: severity, confidence, title, cwe, url,
                     param, detail, about, payload, proof, remediation,
                     status_code, poc_curl, poc_python, id, fp, ...> ],
      "advisory_findings": [ <subset of findings whose title starts with
        "Nuclei:" / "ZAP:" or whose confidence names an external tool.
        Clearly labelled advisory/external-tool results, NOT proven
        Reconix findings. Empty list when there are none.> ],
      "groups": [ ... ] | null,        // root-cause groups, if present
      "coverage": { ... } | null,      // crawl/test coverage, if present
      "permission_matrix": [ ... ] | null,
      "ai_narrative": str | null,      // local-model narrative, if present
      "suppressed_findings": [ ... ]   // known-FP suppressions, if present
    }

Deliberately NOT included: the HAR blob (``result["har"]``) and raw
screenshot bytes — both are served by the existing HTML/HAR exports and
would bloat a machine-readable dump. Everything else the scan recorded
about a finding is copied verbatim, so a consumer can round-trip
``findings`` back to the finding dicts the engine produced.

Excel workbook (``to_xlsx``)
-----------------------------
Stdlib only: a real .xlsx is a zip of XML parts, built here with
``zipfile`` + ``xml`` escaping (no openpyxl, no new dependency).
Sheets:

* ``Summary`` — target, finished/profile, risk score + grade, total
  findings, and one row per severity with its count.
* ``Findings`` — one row per finding: Title, Severity, CWE, URL,
  Parameter, Evidence, Remediation, Confidence, Detail. ``Evidence``
  is the finding's ``proof`` field verbatim (empty when the scan
  recorded no proof — never synthesised).

Both functions accept the same ``result`` dict the PDF/DOCX writers
take (see ``wscan.report3`` / ``wscan.report_docx``).
"""
import io
import json
import time
import zipfile
from xml.sax.saxutils import escape as _xml_escape

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

SCHEMA = "reconix-scan-export"
SCHEMA_VERSION = 1


def counts_by_severity(result):
    """Severity counts for a result, preferring its stored counts."""
    counts = dict(result.get("counts") or {})
    findings = result.get("findings") or []
    if not counts and findings:
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f.get("severity", "Info")] = \
                counts.get(f.get("severity", "Info"), 0) + 1
    out = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
    for k, v in counts.items():
        if k not in out:
            out[k] = int(v or 0)
    out["total"] = sum(out[s] for s in SEVERITIES) \
        if set(counts) <= set(SEVERITIES) else len(findings)
    # When stored counts carry extra keys, total is the finding count.
    if set(counts) - set(SEVERITIES):
        out["total"] = len(findings)
    return out


def _is_advisory(finding):
    title = (finding.get("title") or "")
    conf = (finding.get("confidence") or "")
    return title.startswith(("Nuclei:", "ZAP:")) or \
        "External tool" in conf


def to_json_dict(result):
    """Full machine-readable dump of a scan result as a plain dict."""
    counts = counts_by_severity(result)
    findings = result.get("findings") or []
    meta = result.get("report_meta") or {}
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "exported_format": "json",
        "metadata": {
            "target": result.get("target", ""),
            "profile": result.get("profile", ""),
            "finished_at": result.get("finished_at", ""),
            "started_at": result.get("started_at"),
            "duration_s": result.get("duration_s"),
            "risk_score": result.get("risk_score", 0),
            "risk_grade": result.get("risk_grade", ""),
            "client": meta.get("client", ""),
            "company": meta.get("company", ""),
        },
        "counts": counts,
        "findings": [dict(f) for f in findings],
        "advisory_findings": [dict(f) for f in findings if _is_advisory(f)],
        "groups": result.get("groups"),
        "coverage": result.get("coverage"),
        "permission_matrix": result.get("permission_matrix"),
        "ai_narrative": result.get("ai_narrative"),
        "suppressed_findings": result.get("suppressed_findings") or [],
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def to_json(result, indent=2):
    """Serialise ``to_json_dict(result)`` to a JSON string."""
    return json.dumps(to_json_dict(result), indent=indent,
                      ensure_ascii=False, default=str)


# Aliases used by the (separate) UI integration step.
to_json_export = to_json
export_json = to_json


# ------------------------------------------------------------------ XLSX
# Minimal valid OOXML workbook: shared strings + two sheets + styles.
# Column widths are set so the workbook is readable when opened, not
# just parseable.

def _x(s):
    return _xml_escape("" if s is None else str(s))


class _SharedStrings:
    def __init__(self):
        self.items = []
        self.index = {}

    def add(self, value):
        value = "" if value is None else str(value)
        if value not in self.index:
            self.index[value] = len(self.items)
            self.items.append(value)
        return self.index[value]

    def xml(self):
        parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                 '<sst xmlns="http://schemas.openxmlformats.org/'
                 'spreadsheetml/2006/main" count="%d" uniqueCount="%d">'
                 % (len(self.items), len(self.items))]
        for item in self.items:
            parts.append("<si><t xml:space=\"preserve\">%s</t></si>"
                         % _x(item))
        parts.append("</sst>")
        return "".join(parts)


def _sheet_xml(rows, ss, header=True, widths=None):
    """rows: list of list-of-str. Header row (if any) is bold (style 1)."""
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<worksheet xmlns="http://schemas.openxmlformats.org/'
           'spreadsheetml/2006/main"><sheetViews><sheetView '
           'workbookViewId="0"/></sheetViews><sheetFormatPr '
           'defaultRowHeight="15"/>']
    if widths:
        out.append("<cols>")
        for i, w in enumerate(widths, 1):
            out.append('<col min="%d" max="%d" width="%.1f" '
                       'customWidth="1"/>' % (i, i, w))
        out.append("</cols>")
    out.append("<sheetData>")
    for r_i, row in enumerate(rows):
        out.append('<row r="%d">' % (r_i + 1))
        for c_i, val in enumerate(row):
            col = chr(ord("A") + c_i) if c_i < 26 else "A" + chr(
                ord("A") + c_i - 26)
            style = ' s="1"' if (header and r_i == 0) else ""
            out.append('<c r="%s%d" t="s"%s><v>%d</v></c>'
                       % (col, r_i + 1, style, ss.add(val)))
        out.append("</row>")
    out.append("</sheetData></worksheet>")
    return "".join(out)


def to_xlsx(result):
    """Build a real .xlsx workbook (bytes) from a scan result."""
    counts = counts_by_severity(result)
    findings = result.get("findings") or []
    risk = result.get("risk_score", 0)
    grade = result.get("risk_grade", "")

    summary_rows = [
        ["Reconix Vulnerability Report", ""],
        ["Target", result.get("target", "")],
        ["Profile", result.get("profile", "")],
        ["Finished", result.get("finished_at", "")],
        ["Risk score", "%s/100 (%s)" % (risk, grade)],
        ["Total findings", str(counts["total"])],
        ["", ""],
        ["Severity", "Count"],
    ]
    for sev in SEVERITIES:
        summary_rows.append([sev, str(counts[sev])])

    header = ["Title", "Severity", "CWE", "URL", "Parameter",
              "Evidence", "Remediation", "Confidence", "Detail"]
    finding_rows = [header]
    for f in findings:
        finding_rows.append([
            f.get("title", ""), f.get("severity", ""), f.get("cwe", ""),
            f.get("url", ""), f.get("param", ""),
            f.get("proof", ""),  # Evidence = recorded proof, verbatim
            f.get("remediation", ""), f.get("confidence", ""),
            f.get("detail", ""),
        ])

    ss = _SharedStrings()
    summary_xml = _sheet_xml(summary_rows, ss, header=False,
                             widths=[22, 60])
    findings_xml = _sheet_xml(finding_rows, ss, header=True,
                              widths=[42, 11, 12, 50, 16, 50, 50, 16, 50])
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/'
              'spreadsheetml/2006/main"><fonts><font><sz val="11"/>'
              '<name val="Calibri"/></font><font><b/><sz val="11"/>'
              '<name val="Calibri"/></font></fonts><fills>'
              '<fill><patternFill patternType="none"/></fill></fills>'
              '<borders><border/></borders><cellStyleXfs count="1">'
              '<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
              '</cellStyleXfs><cellXfs count="2">'
              '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" '
              'xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" '
              'borderId="0" xfId="0" applyFont="1"/></cellXfs>'
              '</styleSheet>')
    content_types = ('<?xml version="1.0" encoding="UTF-8" '
                     'standalone="yes"?>\n<Types xmlns="http://schemas.'
                     'openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/'
                     'vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/xl/workbook.xml" ContentType='
                     '"application/vnd.openxmlformats-officedocument.'
                     'spreadsheetml.sheet.main+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet1.xml" '
                     'ContentType="application/vnd.openxmlformats-'
                     'officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet2.xml" '
                     'ContentType="application/vnd.openxmlformats-'
                     'officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/sharedStrings.xml" '
                     'ContentType="application/vnd.openxmlformats-'
                     'officedocument.spreadsheetml.sharedStrings+xml"/>'
                     '<Override PartName="/xl/styles.xml" ContentType='
                     '"application/vnd.openxmlformats-officedocument.'
                     'spreadsheetml.styles+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/'
            'package/2006/relationships"><Relationship Id="rId1" Type='
            '"http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
               '<Relationships xmlns="http://schemas.openxmlformats.org/'
               'package/2006/relationships">'
               '<Relationship Id="rId1" Type="http://schemas.'
               'openxmlformats.org/officeDocument/2006/relationships/'
               'worksheet" Target="worksheets/sheet1.xml"/>'
               '<Relationship Id="rId2" Type="http://schemas.'
               'openxmlformats.org/officeDocument/2006/relationships/'
               'worksheet" Target="worksheets/sheet2.xml"/>'
               '<Relationship Id="rId3" Type="http://schemas.'
               'openxmlformats.org/officeDocument/2006/relationships/'
               'sharedStrings" Target="sharedStrings.xml"/>'
               '<Relationship Id="rId4" Type="http://schemas.'
               'openxmlformats.org/officeDocument/2006/relationships/'
               'styles" Target="styles.xml"/></Relationships>')
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<workbook xmlns="http://schemas.openxmlformats.org/'
                'spreadsheetml/2006/main" xmlns:r="http://schemas.'
                'openxmlformats.org/officeDocument/2006/relationships">'
                '<sheets><sheet name="Summary" sheetId="1" r:id="rId1"/>'
                '<sheet name="Findings" sheetId="2" r:id="rId2"/>'
                '</sheets></workbook>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/worksheets/sheet1.xml", summary_xml)
        z.writestr("xl/worksheets/sheet2.xml", findings_xml)
        z.writestr("xl/sharedStrings.xml", ss.xml())
        z.writestr("xl/styles.xml", styles)
    return buf.getvalue()


export_xlsx = to_xlsx
