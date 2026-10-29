import re
"""Dependency-free DOCX report writer (zip + WordprocessingML)."""
import io
import zipfile

from .report3 import executive_summary


def _x(s):
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(s))
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _p(text, style=None, bold=False):
    props = ""
    if style:
        props = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>'
    runs = ""
    for i, line in enumerate(str(text).split("\n")):
        if i:
            runs += "<w:r><w:br/></w:r>"
        runs += (f'<w:r>{"<w:rPr><w:b/></w:rPr>" if bold else ""}'
                 f'<w:t xml:space="preserve">{_x(line)}</w:t></w:r>')
    return f"<w:p>{props}{runs}</w:p>"


def _table(rows, widths=None):
    out = ['<w:tbl><w:tblPr><w:tblBorders>'
           '<w:top w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/>'
           '<w:bottom w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/>'
           '<w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/>'
           '</w:tblBorders></w:tblPr>']
    for r_i, row in enumerate(rows):
        out.append("<w:tr>")
        for cell in row:
            out.append('<w:tc><w:tcPr><w:tcW w:w="2400" w:type="dxa"/></w:tcPr>'
                       + _p(cell, bold=(r_i == 0)) + "</w:tc>")
        out.append("</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def to_docx(result):
    meta = result.get("report_meta") or {}
    body = []
    if meta.get("company"):
        body.append(_p(meta["company"], "Title"))
    body.append(_p("Web Application Security Assessment", "Heading1"))
    if meta.get("client"):
        body.append(_p(f"Prepared for: {meta['client']}", bold=True))
    body.append(_p(f"Target: {result.get('target')}"))
    body.append(_p(f"Date: {result.get('finished_at', '')}  ·  "
                   f"Profile: {result.get('profile', '')}  ·  "
                   f"Risk score: {result.get('risk_score', 0)}/100 "
                   f"({result.get('risk_grade', '')})"))
    body.append(_p("CONFIDENTIAL — prepared exclusively for the client named "
                   "above.", bold=True))
    body.append(_p("Executive summary", "Heading1"))
    for line in executive_summary(result).split("\n"):
        body.append(_p(line))
    body.append(_p("Methodology", "Heading1"))
    body.append(_p("Automated assessment with Reconix: reconnaissance "
                   "(DNS, ports, TLS, technology fingerprinting), crawling, "
                   "passive analysis, active proof-based vulnerability "
                   "checks (injection, XSS, SSRF, XXE, access control, API), "
                   "out-of-band verification, and browser-based confirmation "
                   "where available. Findings marked 'Needs manual "
                   "confirmation' require analyst validation."))
    body.append(_p("Findings summary", "Heading1"))
    rows = [["Severity", "Title", "Parameter", "Confidence"]]
    for f in result.get("findings", []):
        rows.append([f["severity"], f["title"], f.get("param") or "-",
                     f["confidence"]])
    body.append(_table(rows))
    body.append(_p("Detailed findings", "Heading1"))
    for f in result.get("findings", []):
        body.append(_p(f"[{f['severity']}] {f['title']}", "Heading2"))
        body.append(_p(f"URL: {f['url']}"))
        if f.get("param"):
            body.append(_p(f"Parameter: {f['param']}"))
        if f.get("cwe"):
            body.append(_p(f"CWE: {f['cwe']}"))
        if f.get("about"):
            body.append(_p(f"What is it? {f['about']}"))
        body.append(_p(f["detail"]))
        if f.get("proof"):
            body.append(_p(f"Proof: {f['proof']}"))
        if f.get("payload"):
            body.append(_p(f"Payload: {f['payload']}"))
        body.append(_p(f"Remediation: {f['remediation']}"))
        if f.get("poc_curl"):
            body.append(_p(f"PoC (curl): {f['poc_curl']}"))
    body.append(_p("Remediation tracker", "Heading1"))
    rows = [["#", "Finding", "Severity", "Status", "Owner", "Target date"]]
    for i, f in enumerate(result.get("findings", []), 1):
        rows.append([str(i), f["title"], f["severity"],
                     f.get("status", "open"), "", ""])
    body.append(_table(rows))
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main"><w:body>' + "".join(body) +
                '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1134" w:bottom="1134" w:left="1134" '
                'w:right="1134"/></w:sectPr></w:body></w:document>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<w:styles xmlns:w="http://schemas.openxmlformats.org/'
              'wordprocessingml/2006/main">'
              '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>'
              '<w:rPr><w:b/><w:sz w:val="52"/><w:color w:val="1A3A6B"/></w:rPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>'
              '<w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="1A3A6B"/></w:rPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>'
              '<w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style></w:styles>')
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                     '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", styles)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
    return buf.getvalue()
