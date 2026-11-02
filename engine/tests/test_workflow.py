"""Workflow features: scan diff, false positives, custom checks.

Self-contained unittest. No external network: scan-diff and
false-positive tests use synthetic findings and temporary SQLite files;
custom-check runner tests use a stub HTTP server on 127.0.0.1 (an
ephemeral port) plus stub clients. Never touches the real scans.db.

Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import customchecks, falsepositives, scandiff  # noqa: E402
from wscan.client import Client  # noqa: E402

TARGET = "https://example.com"


def _finding(title, url, param="", severity="High", proof="", cwe=""):
    return {"title": title, "url": url, "param": param,
            "severity": severity, "proof": proof, "cwe": cwe}


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def _send(handler, code, body):
    data = body.encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body_for(self, params):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/search":
            return 200, "<html>you searched: %s</html>" % params.get("q", "")
        if path == "/plain":
            return 200, "<html>static page, nothing reflected</html>"
        if path == "/err":
            if "boom" in params.get("x", ""):
                return 200, "<html>SQL syntax error near boom</html>"
            return 200, "<html>all fine</html>"
        if path == "/errbase":
            return 200, "<html>SQL syntax error always here</html>"
        if path == "/status":
            if params.get("x", "") == "trigger500":
                return 500, "<html>server error</html>"
            return 200, "<html>ok</html>"
        if path == "/statusalways":
            return 500, "<html>always broken</html>"
        if path == "/diff":
            if "LONG" in params.get("x", ""):
                return 200, "A" * 500
            return 200, "ok"
        if path == "/form":
            return 200, "<html>field says: %s</html>" % params.get(
                "search", "")
        return 404, "<html>not found</html>"

    def do_GET(self):
        params = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(self.path).query, keep_blank_values=True))
        code, body = self._body_for(params)
        _send(self, code, body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        params = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
        code, body = self._body_for(params)
        _send(self, code, body)


def _defn(**over):
    base = {
        "name": "Reflected marker",
        "target": {"kind": "url_param", "param": "q"},
        "payloads": ["MARKER123"],
        "proof_rule": {"type": "reflection"},
    }
    base.update(over)
    return base


class DiffTests(unittest.TestCase):
    def test_new_fixed_unchanged(self):
        old = {"target": TARGET, "findings": [
            _finding("SQL Injection", TARGET + "/a?id=1", "id",
                     proof="err"),
            _finding("XSS", TARGET + "/b?q=x", "q", proof="ref"),
        ]}
        new = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=x", "q", proof="ref"),
            _finding("SSRF", TARGET + "/c?u=y", "u", proof="meta"),
        ]}
        diff = scandiff.diff_scans(old, new)
        self.assertIsNone(diff["warning"])
        self.assertEqual(diff["summary"],
                         {"new": 1, "changed": 0, "fixed": 1,
                          "unchanged": 1, "total_old": 2, "total_new": 2})
        self.assertEqual(diff["new"][0]["title"], "SSRF")
        self.assertEqual(diff["fixed"][0]["title"], "SQL Injection")
        self.assertEqual(diff["unchanged"][0]["title"], "XSS")

    def test_changed_severity(self):
        old = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=x", "q", "Medium", "ref")]}
        new = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=x", "q", "High", "ref")]}
        diff = scandiff.diff_scans(old, new)
        self.assertEqual(diff["summary"]["changed"], 1)
        self.assertEqual(diff["changed"][0]["changes"]["severity"],
                         ["Medium", "High"])

    def test_changed_evidence(self):
        old = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=x", "q", "High", "ref-v1")]}
        new = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=x", "q", "High", "ref-v2")]}
        diff = scandiff.diff_scans(old, new)
        self.assertEqual(diff["summary"]["changed"], 1)
        self.assertIn("evidence", diff["changed"][0]["changes"])

    def test_different_target_guard_strict(self):
        old = {"target": TARGET, "findings": [_finding("XSS", TARGET + "/b", "")]}
        new = {"target": "https://other.com", "findings": [
            _finding("XSS", "https://other.com/b", "")]}
        diff = scandiff.diff_scans(old, new)
        self.assertIsNotNone(diff["warning"])
        self.assertFalse(diff["targets_match"])
        self.assertEqual(diff["summary"]["new"], 0)
        self.assertEqual(diff["new"], [])

    def test_different_target_non_strict_still_warns(self):
        old = {"target": TARGET, "findings": []}
        new = {"target": "https://other.com", "findings": [
            _finding("XSS", "https://other.com/b", "")]}
        diff = scandiff.diff_scans(old, new, strict_target=False)
        self.assertIsNotNone(diff["warning"])
        self.assertEqual(diff["summary"]["new"], 1)

    def test_same_target_spelling_variants_match(self):
        self.assertTrue(scandiff.targets_match(
            "https://example.com/", "http://example.com"))
        self.assertTrue(scandiff.targets_match(
            TARGET, TARGET + "/"))
        self.assertFalse(scandiff.targets_match(
            TARGET + "/app", TARGET + "/other"))

    def test_missing_target_warns_but_compares(self):
        diff = scandiff.diff_scans(
            {"findings": [_finding("XSS", TARGET + "/b?q=x", "q")]},
            {"findings": [_finding("XSS", TARGET + "/b?q=x", "q")]})
        self.assertIsNotNone(diff["warning"])
        self.assertEqual(diff["summary"]["unchanged"], 1)

    def test_identity_stable_across_query_values(self):
        old = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=hello", "q", proof="ref")]}
        new = {"target": TARGET, "findings": [
            _finding("XSS", TARGET + "/b?q=world", "q", proof="ref")]}
        diff = scandiff.diff_scans(old, new)
        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertEqual(scandiff.finding_identity(old["findings"][0]),
                         scandiff.finding_identity(new["findings"][0]))

    def test_diff_by_id_via_loader_and_unknown_id(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        try:
            conn = sqlite3.connect(tmp.name)
            conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, "
                         "target TEXT, result TEXT)")
            conn.execute("INSERT INTO scans VALUES (?,?,?)",
                         ("old1", TARGET, json.dumps(
                             {"target": TARGET, "findings": [
                                 _finding("XSS", TARGET + "/b?q=x", "q")]})))
            conn.execute("INSERT INTO scans VALUES (?,?,?)",
                         ("new1", TARGET, json.dumps(
                             {"target": TARGET, "findings": []})))
            conn.commit()
            conn.close()
            loader = lambda sid: scandiff.load_scan_from_db(tmp.name, sid)
            diff = scandiff.diff_scans_by_id("old1", "new1", loader)
            self.assertEqual(diff["summary"]["fixed"], 1)
            with self.assertRaises(ValueError):
                scandiff.diff_scans_by_id("old1", "nope", loader)
        finally:
            os.unlink(tmp.name)

    def test_report_section_shape(self):
        diff = scandiff.diff_scans(
            {"target": TARGET, "findings": []},
            {"target": TARGET, "findings": [
                _finding("XSS", TARGET + "/b?q=x", "q")]})
        section = scandiff.diff_to_report_section(diff)
        self.assertEqual(section["summary"]["new"], 1)
        self.assertEqual(section["sections"]["new"][0]["title"], "XSS")


class FalsePositiveTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.db = tmp.name
        self.finding = _finding("XSS", TARGET + "/b?q=x", "q")

    def tearDown(self):
        os.unlink(self.db)

    def test_mark_and_list(self):
        rec = falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "intended reflection",
            marked_by="analyst")
        self.assertEqual(rec["status"], "active")
        self.assertEqual(rec["reason"], "intended reflection")
        listed = falsepositives.list_false_positives(self.db, TARGET)
        self.assertEqual(len(listed), 1)
        self.assertTrue(falsepositives.is_false_positive(
            self.db, TARGET, self.finding))

    def test_empty_reason_rejected(self):
        for bad in ("", "   ", None):
            with self.subTest(reason=bad):
                with self.assertRaises(ValueError):
                    falsepositives.mark_false_positive(
                        self.db, TARGET, self.finding, bad)

    def test_apply_exclusions_auditable(self):
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "by design")
        other = _finding("SQL Injection", TARGET + "/a?id=1", "id")
        split = falsepositives.apply_exclusions(
            self.db, TARGET, [self.finding, other])
        self.assertEqual(split["counts"],
                         {"total": 2, "kept": 1, "excluded": 1})
        self.assertEqual(split["findings"], [other])
        self.assertEqual(split["excluded"][0]["exclusion_reason"],
                         "by design")
        self.assertTrue(split["excluded"][0]["excluded_as_false_positive"])

    def test_per_target_isolation(self):
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "by design")
        split = falsepositives.apply_exclusions(
            self.db, "https://other.com", [self.finding])
        self.assertEqual(split["counts"]["excluded"], 0)

    def test_unmark_restores_and_audit_kept(self):
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "by design")
        self.assertTrue(falsepositives.unmark_false_positive(
            self.db, TARGET, self.finding, unmarked_by="analyst2"))
        self.assertFalse(falsepositives.unmark_false_positive(
            self.db, TARGET, self.finding))
        self.assertFalse(falsepositives.is_false_positive(
            self.db, TARGET, self.finding))
        split = falsepositives.apply_exclusions(
            self.db, TARGET, [self.finding])
        self.assertEqual(split["counts"]["kept"], 1)
        audit = falsepositives.list_false_positives(
            self.db, TARGET, include_removed=True)
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["status"], "removed")

    def test_remark_updates_reason(self):
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "first reason")
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "better reason")
        listed = falsepositives.list_false_positives(self.db, TARGET)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["reason"], "better reason")

    def test_target_normalisation(self):
        falsepositives.mark_false_positive(
            self.db, TARGET + "/", self.finding, "by design")
        self.assertTrue(falsepositives.is_false_positive(
            self.db, TARGET, self.finding))

    def test_apply_to_result_does_not_mutate(self):
        falsepositives.mark_false_positive(
            self.db, TARGET, self.finding, "by design")
        result = {"target": TARGET, "findings": [self.finding]}
        out = falsepositives.apply_exclusions_to_result(self.db, result)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["exclusion_counts"]["excluded"], 1)
        self.assertEqual(len(out["excluded_false_positives"]), 1)


class CustomCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve(_StubHandler)
        cls.client = Client()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_validation_defaults(self):
        defn = customchecks.validate_definition(_defn())
        self.assertEqual(defn["severity"], "Medium")
        self.assertEqual(defn["title"], "Reflected marker")
        self.assertEqual(defn["proof_rule"]["marker"], "{payload}")
        self.assertEqual(defn["target"]["method"], "GET")
        self.assertTrue(defn["enabled"])

    def test_validation_rejects_malformed(self):
        bad_cases = [
            _defn(name=""),
            _defn(payloads=[]),
            _defn(payloads=[""]),
            _defn(proof_rule={"type": "magic"}),
            _defn(severity="Extreme"),
            _defn(payload="oops"),  # unknown key / typo for payloads
            _defn(target={"kind": "url_param"}),
            _defn(cwe="79"),
            _defn(proof_rule={"type": "status"}),
            _defn(proof_rule={"type": "error_string"}),
            "not-a-dict",
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(customchecks.CustomCheckError):
                    customchecks.validate_definition(bad)
        self.assertEqual(customchecks.check_definition(_defn()), [])

    def test_json_roundtrip_and_bad_json(self):
        text = customchecks.definition_to_json(_defn())
        self.assertEqual(customchecks.definition_from_json(text)["name"],
                         "Reflected marker")
        with self.assertRaises(customchecks.CustomCheckError):
            customchecks.definition_from_json("{not json")

    def test_reflection_proven(self):
        res = customchecks.run_custom_check(
            _defn(), self.client, self.base + "/search?q=hello")
        self.assertTrue(res["proven"])
        self.assertIsNotNone(res["finding"])
        self.assertEqual(res["finding"]["param"], "q")
        self.assertEqual(res["finding"]["severity"], "Medium")

    def test_reflection_unproven_static_page(self):
        res = customchecks.run_custom_check(
            _defn(), self.client, self.base + "/plain?q=hello")
        self.assertFalse(res["proven"])
        self.assertIsNone(res["finding"])

    def test_reflection_append_mode(self):
        defn = _defn(target={"kind": "url_param", "param": "q",
                             "payload_mode": "append"})
        res = customchecks.run_custom_check(
            defn, self.client, self.base + "/search?q=hello")
        self.assertTrue(res["proven"])

    def test_error_string_proven_and_baseline_rejected(self):
        defn = _defn(name="Err", target={"kind": "url_param",
                                         "param": "x"},
                     payloads=["boom"],
                     proof_rule={"type": "error_string",
                                 "strings": ["SQL syntax"]})
        proven = customchecks.run_custom_check(
            defn, self.client, self.base + "/err?x=ok")
        self.assertTrue(proven["proven"])
        baseline = customchecks.run_custom_check(
            defn, self.client, self.base + "/errbase?x=ok")
        self.assertFalse(baseline["proven"])
        self.assertIsNone(baseline["finding"])

    def test_status_proven_and_control_also_expected_rejected(self):
        defn = _defn(name="Stat", target={"kind": "url_param",
                                          "param": "x"},
                     payloads=["trigger500"],
                     proof_rule={"type": "status", "expected": 500})
        proven = customchecks.run_custom_check(
            defn, self.client, self.base + "/status?x=ok")
        self.assertTrue(proven["proven"])
        always = customchecks.run_custom_check(
            defn, self.client, self.base + "/statusalways?x=ok")
        self.assertFalse(always["proven"])

    def test_differential_proven_and_unproven(self):
        defn = _defn(name="Diff", target={"kind": "url_param",
                                          "param": "x"},
                     payloads=["LONG"],
                     proof_rule={"type": "differential",
                                 "min_length_diff": 100})
        proven = customchecks.run_custom_check(
            defn, self.client, self.base + "/diff?x=ok")
        self.assertTrue(proven["proven"])
        unproven = customchecks.run_custom_check(
            _defn(name="Diff2", target={"kind": "url_param", "param": "x"},
                  payloads=["short"],
                  proof_rule={"type": "differential",
                              "min_length_diff": 100}),
            self.client, self.base + "/diff?x=ok")
        self.assertFalse(unproven["proven"])

    def test_form_field_proven(self):
        defn = _defn(name="FormMarker",
                     target={"kind": "form_field", "field": "search"},
                     payloads=["MARKER123"],
                     proof_rule={"type": "reflection"})
        res = customchecks.run_custom_check(
            defn, self.client, self.base + "/form")
        self.assertTrue(res["proven"])
        self.assertEqual(res["finding"]["param"], "search")

    def test_missing_param_skipped_not_crash(self):
        res = customchecks.run_custom_check(
            _defn(), self.client, self.base + "/search?other=1")
        self.assertTrue(res["skipped"])
        self.assertIsNone(res["finding"])

    def test_runtime_error_client_skipped(self):
        class BoomClient:
            def fetch(self, *a, **kw):
                raise RuntimeError("connection died")

        res = customchecks.run_custom_check(
            _defn(), BoomClient(), self.base + "/search?q=hello")
        self.assertTrue(res["skipped"])
        self.assertIsNone(res["finding"])

    def test_malformed_definition_via_runner_skipped(self):
        res = customchecks.run_custom_check(
            _defn(payloads=[]), self.client,
            self.base + "/search?q=hello")
        self.assertTrue(res["skipped"])
        self.assertIsNotNone(res["error"])
        self.assertIsNone(res["finding"])

    def test_run_all_collects_proven_only(self):
        out = customchecks.run_custom_checks(
            [_defn(), _defn(name="Nope",
                            target={"kind": "url_param", "param": "q"},
                            payloads=["ZZZ"],
                            proof_rule={"type": "reflection"})],
            self.client, [self.base + "/search?q=hello"])
        # Both payloads reflect on the stub, so both prove; the point
        # is the aggregate shape, findings == proven results.
        self.assertEqual(len(out["findings"]), 2)
        self.assertEqual(len(out["results"]), 2)

    def test_storage_create_list_delete(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        try:
            stored = customchecks.create_custom_check(tmp.name, _defn())
            self.assertEqual(stored["name"], "Reflected marker")
            with self.assertRaises(customchecks.CustomCheckError):
                customchecks.create_custom_check(tmp.name, _defn())
            customchecks.create_custom_check(
                tmp.name, _defn(description="updated"), overwrite=True)
            self.assertEqual(
                customchecks.get_custom_check(tmp.name,
                                              "Reflected marker")["description"],
                "updated")
            customchecks.create_custom_check(
                tmp.name, _defn(name="Disabled", enabled=False))
            self.assertEqual(len(customchecks.list_custom_checks(tmp.name)),
                             2)
            self.assertEqual(len(customchecks.list_custom_checks(
                tmp.name, enabled_only=True)), 1)
            self.assertTrue(customchecks.delete_custom_check(
                tmp.name, "Disabled"))
            self.assertFalse(customchecks.delete_custom_check(
                tmp.name, "Disabled"))
            self.assertIsNone(customchecks.get_custom_check(
                tmp.name, "Disabled"))
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
