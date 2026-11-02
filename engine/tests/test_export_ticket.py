"""Report-format + ticketing exports: DOCX, XLSX, JSON, Jira, GitHub.

No live external calls: Jira/GitHub transports are fully mocked via the
``http_post`` hook. Stdlib only.
Run:  python3 -m unittest discover -s tests -v -k export
"""
import io
import json
import os
import sys
import unittest
import zipfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import ticketing  # noqa: E402
from wscan.exporters import (  # noqa: E402
    counts_by_severity, to_json, to_json_dict, to_xlsx)
from wscan.report_docx import to_docx  # noqa: E402


def _finding(sev, title, cwe, url, param, proof, conf="Confirmed"):
    return {"id": 1, "severity": sev, "confidence": conf, "title": title,
            "cwe": cwe, "url": url, "param": param,
            "detail": "Detail for " + title, "about": "About " + title,
            "payload": "payload-" + title[:4], "proof": proof,
            "remediation": "Fix " + title, "poc_curl": "curl " + url}


def _result():
    findings = [
        _finding("Critical", "SQL Injection", "CWE-89",
                 "https://example.test/search?q=x", "q",
                 "error-based proof: database error returned"),
        _finding("Medium", "Cross-Site Scripting", "CWE-79",
                 "https://example.test/comment", "comment",
                 "payload reflected unencoded"),
        _finding("Info", "Missing Security Header", "CWE-693",
                 "https://example.test/", "", ""),
        # Advisory / external-tool finding: must be clearly labelled,
        # never presented as a proven Reconix finding.
        _finding("High", "Nuclei: Exposed Panel", "CWE-200",
                 "https://example.test/admin", "template-id",
                 "Nuclei template exposed-panel matched",
                 conf="External tool (Nuclei)"),
    ]
    return {"target": "https://example.test", "profile": "full",
            "finished_at": "2026-11-02 17:00:00",
            "risk_score": 49, "risk_grade": "High risk",
            "counts": {"Critical": 1, "High": 1, "Medium": 1, "Low": 0,
                       "Info": 1},
            "findings": findings,
            "ai_narrative": "Local narrative from proven findings only.",
            "permission_matrix": [{"url": "https://example.test/admin",
                                   "results": {"anon": {"status": 200,
                                                        "length": 123}}}]}


def _docx_text(testcase, data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        testcase.assertIn("word/document.xml", z.namelist())
        return z.read("word/document.xml").decode()


def _xlsx_parts(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        return names, {n: z.read(n) for n in names}


def _sheet_values(parts):
    """Resolve a sheet's shared-string cells to plain text rows."""
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    ss_root = ET.fromstring(parts["xl/sharedStrings.xml"])
    strings = ["".join(t.text or "" for t in si.iter(
        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"))
        for si in ss_root.findall("m:si", ns)]
    out = {}
    for name in ("xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"):
        root = ET.fromstring(parts[name])
        rows = []
        for row in root.iter("{http://schemas.openxmlformats.org/"
                             "spreadsheetml/2006/main}row"):
            vals = []
            for c in row:
                v = c.find("m:v", ns)
                vals.append(strings[int(v.text)] if v is not None
                            and v.text is not None else "")
            rows.append(vals)
        out[name] = rows
    return out


class TestDocx(unittest.TestCase):
    def test_docx_contains_expected_content(self):
        text = _docx_text(self, to_docx(_result()))
        for needle in ("Web Application Security Assessment",
                       "https://example.test", "SQL Injection", "CWE-89",
                       "error-based proof: database error returned",
                       "Fix SQL Injection", "Summary counts",
                       "Local narrative from proven findings only.",
                       "Permission matrix"):
            self.assertIn(needle, text)

    def test_docx_empty_findings_still_valid(self):
        res = _result()
        res["findings"] = []
        res["counts"] = {}
        text = _docx_text(self, to_docx(res))
        self.assertIn("https://example.test", text)


class TestXlsx(unittest.TestCase):
    def test_xlsx_unzips_parses_sheets_rows(self):
        names, parts = _xlsx_parts(to_xlsx(_result()))
        for part in ("[Content_Types].xml", "xl/workbook.xml",
                     "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml",
                     "xl/sharedStrings.xml", "xl/styles.xml"):
            self.assertIn(part, names)
        # Every part must be well-formed XML.
        for part in parts:
            if part.endswith(".xml"):
                ET.fromstring(parts[part])
        workbook = parts["xl/workbook.xml"].decode()
        self.assertIn('name="Summary"', workbook)
        self.assertIn('name="Findings"', workbook)
        sheets = _sheet_values(parts)
        summary = sheets["xl/worksheets/sheet1.xml"]
        self.assertIn(["Target", "https://example.test"], summary)
        self.assertIn(["Critical", "1"], summary)
        self.assertIn(["Total findings", "4"], summary)
        findings = sheets["xl/worksheets/sheet2.xml"]
        self.assertEqual(findings[0],
                         ["Title", "Severity", "CWE", "URL", "Parameter",
                          "Evidence", "Remediation", "Confidence",
                          "Detail"])
        self.assertEqual(len(findings), 5)  # header + 4 findings
        self.assertEqual(findings[1][0], "SQL Injection")
        self.assertEqual(findings[1][2], "CWE-89")
        self.assertEqual(findings[1][5],
                         "error-based proof: database error returned")
        self.assertEqual(findings[1][6], "Fix SQL Injection")

    def test_xlsx_empty_findings(self):
        res = _result()
        res["findings"] = []
        res["counts"] = {}
        _, parts = _xlsx_parts(to_xlsx(res))
        sheets = _sheet_values(parts)
        self.assertEqual(len(sheets["xl/worksheets/sheet2.xml"]), 1)


class TestJson(unittest.TestCase):
    def test_json_round_trips(self):
        text = to_json(_result())
        data = json.loads(text)
        self.assertEqual(data["schema"], "reconix-scan-export")
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["metadata"]["target"], "https://example.test")
        self.assertEqual(data["counts"]["Critical"], 1)
        self.assertEqual(data["counts"]["total"], 4)
        self.assertEqual(len(data["findings"]), 4)
        # Findings are verbatim: every original field survives.
        orig = _result()["findings"][0]
        for key, val in orig.items():
            self.assertEqual(data["findings"][0][key], val)
        # Advisory section is a clearly-labelled subset, not invented.
        self.assertEqual(len(data["advisory_findings"]), 1)
        self.assertTrue(data["advisory_findings"][0]["title"]
                        .startswith("Nuclei:"))
        self.assertEqual(data["ai_narrative"],
                         "Local narrative from proven findings only.")

    def test_counts_fallback_from_findings(self):
        res = _result()
        res["counts"] = {}
        self.assertEqual(counts_by_severity(res)["Critical"], 1)
        self.assertEqual(to_json_dict(res)["counts"]["total"], 4)


class TestJira(unittest.TestCase):
    SETTINGS = {"base_url": "https://example.atlassian.net",
                "email": "dev@example.test", "api_token": "SECRET-JIRA-TOKEN",
                "project_key": "SEC", "labels": ["pentest"]}

    def test_per_issue_partial_failure(self):
        calls = []

        def fake_post(url, headers, payload):
            calls.append((url, json.loads(payload)))
            idx = len(calls)
            if idx == 2:
                return 400, json.dumps(
                    {"errorMessages": ["bad project"]}).encode()
            return 201, json.dumps(
                {"key": "SEC-%d" % idx, "self": "https://x/SEC-%d" % idx}
            ).encode()

        results = ticketing.send_to_jira(
            _result()["findings"][:3], self.SETTINGS, http_post=fake_post)
        self.assertEqual(len(results), 3)
        self.assertEqual([r["success"] for r in results],
                         [True, False, True])
        self.assertEqual(results[0]["issue_key"], "SEC-1")
        self.assertIn("bad project", results[1]["error"])
        self.assertIsNone(results[1]["issue_key"])
        # One failure did not abort the rest.
        self.assertEqual(results[2]["issue_key"], "SEC-3")
        # Payload checks: priority + issue-type mapping, labels.
        self.assertEqual(calls[0][1]["fields"]["priority"]["name"], "Highest")
        self.assertEqual(calls[0][1]["fields"]["issuetype"]["name"], "Bug")
        self.assertIn("critical", calls[0][1]["fields"]["labels"])
        self.assertIn("pentest", calls[0][1]["fields"]["labels"])
        self.assertTrue(calls[0][0].endswith("/rest/api/3/issue"))
        # Credential-leak check: token nowhere in returned results.
        self.assertNotIn("SECRET-JIRA-TOKEN", json.dumps(results))
        self.assertNotIn("SECRET-JIRA-TOKEN",
                         json.dumps([r["error"] for r in results]))

    def test_jira_summary_issue(self):
        calls = []

        def fake_post(url, headers, payload):
            calls.append(json.loads(payload))
            return 201, json.dumps({"key": "SEC-99",
                                    "self": "https://x/SEC-99"}).encode()

        results = ticketing.send_to_jira(
            _result()["findings"][:2], self.SETTINGS, single_summary=True,
            http_post=fake_post, target="https://example.test")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["success"])
        self.assertEqual(results[0]["issue_key"], "SEC-99")

    def test_jira_missing_settings(self):
        with self.assertRaises(ValueError):
            ticketing.send_to_jira([], {"base_url": "https://x"})
        with self.assertRaises(ValueError):
            ticketing.send_to_jira([], {})

    def test_jira_sanitizes_token_in_error(self):
        def fake_post(url, headers, payload):
            return 400, json.dumps(
                {"errorMessages": ["leak SECRET-JIRA-TOKEN here"]}
            ).encode()

        results = ticketing.send_to_jira(
            _result()["findings"][:1], self.SETTINGS, http_post=fake_post)
        self.assertFalse(results[0]["success"])
        self.assertNotIn("SECRET-JIRA-TOKEN", results[0]["error"])
        self.assertIn("[REDACTED]", results[0]["error"])


class TestGithub(unittest.TestCase):
    SETTINGS = {"repo": "owner/repo", "token": "SECRET-GH-TOKEN",
                "labels": ["pentest"]}

    def test_per_issue_partial_failure(self):
        calls = []

        def fake_post(url, headers, payload):
            calls.append((url, headers, json.loads(payload)))
            if len(calls) == 2:
                return 422, json.dumps(
                    {"message": "Validation Failed"}).encode()
            n = len(calls)
            return 201, json.dumps(
                {"number": n, "html_url": "https://github.com/owner/repo/"
                                          "issues/%d" % n}).encode()

        results = ticketing.send_to_github(
            _result()["findings"][:3], self.SETTINGS, http_post=fake_post)
        self.assertEqual([r["success"] for r in results],
                         [True, False, True])
        self.assertEqual(results[0]["issue_number"], 1)
        self.assertIn("Validation Failed", results[1]["error"])
        self.assertEqual(results[2]["issue_number"], 3)
        self.assertTrue(calls[0][0].endswith("/repos/owner/repo/issues"))
        self.assertIn("security", calls[0][2]["labels"])
        self.assertIn("critical", calls[0][2]["labels"])
        self.assertIn("pentest", calls[0][2]["labels"])
        self.assertNotIn("SECRET-GH-TOKEN", json.dumps(results))

    def test_github_summary_issue(self):
        calls = []

        def fake_post(url, headers, payload):
            calls.append(json.loads(payload))
            return 201, json.dumps(
                {"number": 7,
                 "html_url": "https://github.com/owner/repo/issues/7"}
            ).encode()

        results = ticketing.send_to_github(
            _result()["findings"][:2], self.SETTINGS, single_summary=True,
            http_post=fake_post, target="https://example.test")
        self.assertEqual(len(calls), 1)
        self.assertTrue(results[0]["success"])
        self.assertEqual(results[0]["issue_number"], 7)

    def test_github_bad_repo_and_missing_token(self):
        with self.assertRaises(ValueError):
            ticketing.send_to_github([], {"repo": "not-a-repo",
                                          "token": "x"})
        with self.assertRaises(ValueError):
            ticketing.send_to_github([], {"repo": "owner/repo"})

    def test_integrations_reexports(self):
        from wscan import integrations  # noqa: E402
        self.assertIs(integrations.send_to_jira, ticketing.send_to_jira)
        self.assertIs(integrations.send_to_github, ticketing.send_to_github)


if __name__ == "__main__":
    unittest.main()
