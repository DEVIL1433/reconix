"""Integration tests for the Reconix 4.0 wiring (engine + reports + app).

No live model, live Nuclei, network feeds, or real Jira/GitHub: the
engine test patches the CVE/Nuclei/cloud runners (their own module
tests cover their behaviour), the ticket tests point at a localhost
stub, and every other target is a localhost stub server.
Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
import app as app_mod  # noqa: E402
from wscan import ai as ai_mod  # noqa: E402
from wscan import customchecks as cc_mod  # noqa: E402
from wscan import engine as engine_mod  # noqa: E402
from wscan import falsepositives as fp_mod  # noqa: E402
from wscan import report3  # noqa: E402
from wscan.core import Findings, remediation_for  # noqa: E402
from wscan.engine import run_scan  # noqa: E402
from wscan.exporters import to_json, to_xlsx  # noqa: E402

_FAKE_TOKEN = ("sk_live_aB" + "3dEf6hIj9k" + "Lm2nOp5qRs" + "8t")  # fixture only, not real


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="text/html"):
    data = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


class _Stub(BaseHTTPRequestHandler):
    """WordPress-flavoured stub: generator + plugin asset + JS secret
    + a parameterized echo page for the custom check."""

    def do_GET(self):
        if self.path == "/":
            _send(self, 200,
                  '<html><head><meta name="generator" content="WordPress '
                  '5.8.1"></head><body>'
                  '<script src="/wp-content/plugins/akismet/akismet.js">'
                  '</script><script src="/app.js"></script>'
                  '<a href="/search?q=hello">search</a></body></html>')
        elif self.path == "/app.js":
            _send(self, 200, f'const KEY = "{_FAKE_TOKEN}";\n',
                  "application/javascript")
        elif self.path.startswith("/search"):
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            _send(self, 200, f"<html><body>echo: {q}</body></html>")
        else:
            _send(self, 404, "not found")

    def log_message(self, *a):
        pass


def _finding(sev, title, url, param=""):
    return {"severity": sev, "confidence": "Confirmed", "title": title,
            "cwe": "", "url": url, "param": param, "detail": "d",
            "proof": "p", "remediation": "r", "payload": ""}


def _result(findings):
    return {"target": "http://example.test", "profile": "full",
            "pages": 3, "forms": 0, "findings": findings,
            "counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0,
                       "Info": 0},
            "recon": {}, "sitemap": {}, "extrecon": {},
            "permission_matrix": [], "browser": {}, "screenshots": [],
            "report_meta": {}, "risk_score": 15, "risk_grade": "Low risk",
            "groups": [], "coverage": {}, "ai": {"enabled": False},
            "ai_narrative": "", "suppressed_findings": [],
            "duration_s": 1.0, "stopped": False,
            "finished_at": "2026-11-02 00:00:00",
            "cms": {"cms": "wordpress", "confidence": "high",
                    "advisories": [{"kind": "advisory",
                                    "title": "CMS Version Disclosed: "
                                             "wordpress 5.8.1",
                                    "detail": "Version disclosure only."}]},
            "nuclei": {"available": True, "note": None, "matches": [
                {"severity": "High", "name": "WP readme",
                 "template_id": "http/exposed-panels/wordpress",
                 "matched_at": "http://example.test/readme.html",
                 "evidence": "readme found"}],
                "command": []},
            "cve_advisories": {"advisories": [
                {"cve_id": "CVE-2021-44228", "severity": "Critical",
                 "cvss_score": 10.0, "description": "Log4Shell",
                 "references": ["https://example.test/x"],
                 "tech": "Apache", "detected_version": "2.4.49"}],
                "by_tech": {}, "notes": []}}


class TestEngineWiring(unittest.TestCase):
    def test_engine_wiring_stub(self):
        srv, base = _serve(_Stub)
        tmp = tempfile.mkdtemp()
        cc_db = os.path.join(tmp, "cc.db")
        cc_mod.create_custom_check(cc_db, {
            "name": "reflected marker",
            "target": {"kind": "url_param", "param": "q"},
            "payloads": ["reconixmarker123"],
            "proof_rule": {"type": "reflection"},
            "severity": "Medium", "title": "Custom Reflected Marker"})
        orig_cve = engine_mod.cve_mod.lookup_cves_for_fingerprint
        orig_nuc = engine_mod.nuclei_mod.run_nuclei_scan
        orig_cloud = engine_mod.cloud_mod.cloud_check
        orig_legacy = engine_mod.integrations.run_nuclei
        cloud_calls = []
        try:
            engine_mod.cve_mod.lookup_cves_for_fingerprint = lambda fp, **kw: {
                "advisories": [{"cve_id": "CVE-2021-44228",
                                "severity": "Critical", "cvss_score": 10.0,
                                "description": "Log4Shell", "references": [],
                                "tech": "Apache",
                                "detected_version": "2.4.49"}],
                "by_tech": {}, "notes": []}
            engine_mod.nuclei_mod.run_nuclei_scan = lambda *a, **kw: {
                "available": True, "note": None, "matches": [
                    {"severity": "High", "name": "stub match",
                     "template_id": "stub/template",
                     "matched_at": base, "evidence": "stub evidence"}],
                "command": []}
            engine_mod.cloud_mod.cloud_check = lambda ctx, **kw: \
                cloud_calls.append(True) or []
            def _legacy_fail(ctx, target):
                raise AssertionError("legacy integrations.run_nuclei "
                                     "must never run in a 4.0 scan")
            engine_mod.integrations.run_nuclei = _legacy_fail
            res = run_scan(base, {
                "checks": ["recon", "passive", "cms", "takeover",
                           "graphql", "websocket", "cloud"],
                "max_pages": 10, "threads": 2,
                "custom_checks_db": cc_db,
                "nuclei": True, "nuclei_templates": ["stub.yaml"]})
        finally:
            engine_mod.cve_mod.lookup_cves_for_fingerprint = orig_cve
            engine_mod.nuclei_mod.run_nuclei_scan = orig_nuc
            engine_mod.cloud_mod.cloud_check = orig_cloud
            engine_mod.integrations.run_nuclei = orig_legacy
            srv.shutdown()
        # New result keys present.
        self.assertIn("cms", res)
        self.assertIn("nuclei", res)
        self.assertIn("cve_advisories", res)
        self.assertTrue(cloud_calls, "cloud phase did not run")
        # CMS advisory present, and advisory-only (not a finding).
        adv = res["cms"].get("advisories") or []
        self.assertTrue(any("5.8.1" in a.get("title", "") for a in adv))
        self.assertFalse(any("CMS Version" in f["title"]
                             for f in res["findings"]))
        # Nuclei + CVE advisories never in counts / risk / findings.
        self.assertEqual(len(res["nuclei"]["matches"]), 1)
        self.assertFalse(any("stub match" in f["title"]
                             for f in res["findings"]))
        self.assertFalse(any("CVE-2021-44228" in f["title"]
                             for f in res["findings"]))
        self.assertEqual(sum(res["counts"].values()),
                         len(res["findings"]))
        score, _grade = report3.risk_score(res["findings"])
        self.assertEqual(score, res["risk_score"])
        # Custom check: proven finding fed into the engine findings.
        self.assertTrue(any(f["title"] == "Custom Reflected Marker"
                            for f in res["findings"]),
                        [f["title"] for f in res["findings"]])
        # JS secret: reported once, masked, no curl PoC, no raw value.
        secrets = [f for f in res["findings"]
                   if "Secret Exposed" in f["title"]]
        self.assertTrue(secrets, "JS secret finding missing")
        for f in secrets:
            self.assertEqual(f.get("poc_curl", ""), "")
            self.assertEqual(f.get("response_snippet", ""), "")
            self.assertNotIn(_FAKE_TOKEN, f.get("proof", ""))
            self.assertNotIn(_FAKE_TOKEN, f.get("response_snippet", ""))
        # AI phase-2 stat keys exist.
        self.assertIn("fix_retest", res["ai"])
        self.assertIn("fix_snippets", res["ai"])

    def test_remediation_mappings(self):
        self.assertIn("dangling DNS record",
                      remediation_for("Subdomain Takeover (proven, "
                                      "unclaimed service)"))
        self.assertIn("Rotate the credential",
                      remediation_for("Secret Exposed in JavaScript: "
                                      "Stripe live secret key"))

    def test_resp_none_findings_have_no_poc(self):
        f = Findings()
        item = f.add("High", "WebSocket Missing Authentication",
                     "ws://example.test/ws", "d", proof="p",
                     payload="probe", resp=None, cwe="CWE-306")
        self.assertEqual(item["poc_curl"], "")
        self.assertEqual(item["request"], "")
        self.assertEqual(item["response_snippet"], "")


class TestReportSections(unittest.TestCase):
    def test_pdf_and_exporters_separate_advisories(self):
        res = _result([_finding("High", "SQL Injection",
                                "http://example.test/?q=1", "q")])
        pdf = report3.to_pdf(res)
        for heading in (b"CMS advisories", b"Nuclei template matches",
                        b"CVE advisories"):
            self.assertIn(heading, pdf)
        # Excluded section appears once exclusions are applied.
        tmp = tempfile.mktemp(suffix=".db")
        try:
            fp_mod.mark_false_positive(tmp, res["target"], res["findings"][0],
                                       "test reason", marked_by="tester")
            split = fp_mod.apply_exclusions_to_result(tmp, res)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self.assertEqual(len(res["findings"]), 1,
                         "input result must be untouched")
        self.assertEqual(len(split["findings"]), 0)
        self.assertEqual(len(split["excluded_false_positives"]), 1)
        pdf2 = report3.to_pdf(split)
        self.assertIn(b"Excluded as false positive", pdf2)
        self.assertIn(b"test reason", pdf2)
        # Exporters never promote advisories into findings.
        exp = json.loads(to_json(split))
        self.assertEqual(len(exp["findings"]), 0)
        xlsx = to_xlsx(split)
        self.assertTrue(xlsx.startswith(b"PK"))


class TestAppEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db = app_mod.DB
        fd, cls._tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        app_mod.DB = cls._tmp
        cls.token = app_mod.ensure_api_token()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app_mod.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        # Local ticket stub: Jira + GitHub issue creation endpoints.
        class _Ticket(BaseHTTPRequestHandler):
            def do_POST(self):
                ln = int(self.headers.get("Content-Length", 0))
                self.rfile.read(ln)
                if "jira" in self.path:
                    body, code = b'{"key": "TEST-1", "self": "x"}', 201
                else:
                    body, code = (b'{"number": 7, "html_url": '
                                  b'"https://example.test/7"}', 201)
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        cls.tsrv, cls.tbase = _serve(_Ticket)
        # Seed one done scan.
        res = _result([_finding("High", "SQL Injection",
                                "http://example.test/?q=1", "q")])
        conn = sqlite3.connect(cls._tmp)
        conn.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                     ("scan00000001", res["target"], "2026-11-02 00:00:00",
                      res["finished_at"], "done", json.dumps(res), "",
                      "{}"))
        conn.commit()
        conn.close()
        cls.scan_id = "scan00000001"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tsrv.shutdown()
        cls.tsrv.server_close()
        app_mod.DB = cls._orig_db
        os.unlink(cls._tmp)

    def _req(self, path, method="GET", body=None):
        req = urllib.request.Request(
            self.base + path, method=method,
            data=(json.dumps(body).encode() if body is not None else None))
        if body is not None:
            req.add_header("Content-Type", "application/json")
        req.add_header("X-Api-Key", self.token)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_export_endpoints(self):
        code, body = self._req(f"/api/scans/{self.scan_id}/report.xlsx")
        self.assertEqual(code, 200)
        self.assertTrue(body.startswith(b"PK"))
        code, body = self._req(
            f"/api/scans/{self.scan_id}/report.export.json")
        self.assertEqual(code, 200)
        exp = json.loads(body)
        self.assertEqual(exp["schema"], "reconix-scan-export")
        # Distinct from the raw report.json dump (no raw result keys).
        self.assertNotIn("cms", exp)
        code, raw = self._req(f"/api/scans/{self.scan_id}/report.json")
        self.assertEqual(code, 200)
        self.assertIn("cms", json.loads(raw))

    def test_custom_checks_endpoints(self):
        code, body = self._req("/api/custom-checks", "POST", {
            "name": "api reflected marker",
            "target": {"kind": "url_param", "param": "q"},
            "payloads": ["apitestmarker"],
            "proof_rule": {"type": "reflection"},
            "severity": "Medium", "title": "API Reflected Marker"})
        self.assertEqual(code, 200, body)
        code, body = self._req("/api/custom-checks")
        self.assertIn("api reflected marker", body.decode())
        # Verbatim validation error for a malformed definition.
        code, body = self._req("/api/custom-checks", "POST",
                               {"name": "bad one"})
        self.assertEqual(code, 400)
        self.assertIn("target is required", body.decode())
        code, body = self._req(
            "/api/custom-checks/api%20reflected%20marker", "DELETE")
        self.assertEqual(code, 200)

    def test_false_positive_exclusion_in_view_and_pdf(self):
        code, body = self._req("/api/findings/false-positive", "POST", {
            "target": "http://example.test",
            "finding": {"title": "SQL Injection",
                         "url": "http://example.test/?q=1", "param": "q"},
            "reason": "endpoint test reason", "marked_by": "tester"})
        self.assertEqual(code, 200, body)
        code, body = self._req(f"/api/scans/{self.scan_id}")
        view = json.loads(body)
        self.assertEqual(view["result"]["findings"], [])
        self.assertEqual(
            len(view["result"]["excluded_false_positives"]), 1)
        self.assertEqual(
            view["result"]["excluded_false_positives"][0]
            ["exclusion_reason"], "endpoint test reason")
        code, body = self._req(f"/api/scans/{self.scan_id}/report.pdf")
        self.assertEqual(code, 200)
        self.assertIn(b"Excluded as false positive", body)
        # Unmark restores.
        code, body = self._req("/api/findings/false-positive/unmark",
                               "POST", {
            "target": "http://example.test",
            "finding": {"title": "SQL Injection",
                         "url": "http://example.test/?q=1", "param": "q"},
            "unmarked_by": "tester"})
        self.assertEqual(code, 200, body)
        code, body = self._req("/api/false-positives?target="
                               "http://example.test&include_removed=1")
        items = json.loads(body)["items"]
        self.assertTrue(any(i["status"] == "removed" for i in items))

    def test_ticket_endpoints_verbatim(self):
        # Re-seed findings (previous test unmarked, but findings are
        # back; selection is by index 0).
        for kind, settings in (
                ("jira", {"base_url": self.tbase + "/jira",
                          "email": "a@example.test", "api_token": "t",
                          "project_key": "TEST"}),
                ("github", {"owner": "o", "name": "r", "token": "t",
                           "api_base_url": self.tbase})):
            code, body = self._req(
                f"/api/scans/{self.scan_id}/ticket/{kind}", "POST", {
                    "finding_ids_or_indices": [0], "single_summary": False,
                    "settings": settings})
            self.assertEqual(code, 200, body)
            results = json.loads(body)["results"]
            self.assertTrue(results[0]["success"], results)
        # Settings must never be stored in scan history.
        conn = sqlite3.connect(self._tmp)
        row = conn.execute("SELECT result FROM scans WHERE id=?",
                           (self.scan_id,)).fetchone()
        conn.close()
        self.assertNotIn('"api_token"', row[0])

    def test_diff_endpoint_four_classes(self):
        res2 = _result([])
        conn = sqlite3.connect(self._tmp)
        conn.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                     ("scan00000002", res2["target"],
                      "2026-11-02 01:00:00", res2["finished_at"], "done",
                      json.dumps(res2), "", "{}"))
        conn.commit()
        conn.close()
        code, body = self._req(
            f"/api/scans/{self.scan_id}/diff/scan00000002")
        self.assertEqual(code, 200, body)
        d = json.loads(body)
        for key in ("new", "changed", "fixed", "unchanged", "sections"):
            self.assertIn(key, d)
        self.assertEqual(len(d["new"]), 1)

    def test_nuclei_update_command_endpoint(self):
        code, body = self._req("/api/nuclei/update-command")
        self.assertEqual(code, 200)
        j = json.loads(body)
        self.assertTrue(j.get("command") is None or
                        isinstance(j["command"], list))

    def test_suggested_fix_degrades_without_model(self):
        from wscan.core import fingerprint_of
        fp = fingerprint_of({"title": "SQL Injection",
                             "url": "http://example.test/?q=1", "param": "q"})
        orig_post = ai_mod._post
        ai_mod._post = lambda *a, **kw: (_ for _ in ()).throw(
            ConnectionError("no model"))
        try:
            code, body = self._req("/api/findings/suggested-fix", "POST",
                                   {"scan_id": self.scan_id, "fp": fp})
        finally:
            ai_mod._post = orig_post
        self.assertEqual(code, 200, body)
        j = json.loads(body)
        self.assertFalse(j["available"])
        self.assertTrue(j["advisory"])

    def test_ui_contains_new_controls(self):
        text = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "app.py"), encoding="utf-8").read()
        for needle in ("recordedSession", "nucleiTemplates",
                       "report.xlsx", "report.export.json", "tickchk",
                       "Send selected to Jira", "Send selected to GitHub",
                       "Custom checks (builder)", "Record new login",
                       "Suggested fix", "Re-test this fix",
                       "CMS advisories", "Nuclei template matches",
                       "CVE advisories"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
