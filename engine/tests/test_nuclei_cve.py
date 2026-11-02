"""Tests for wscan/nuclei.py (Nuclei template matches, kept separate
from engine findings) and wscan/cve.py (CVE advisories, never findings).

Self-contained: no live Nuclei install, no network, no external tools.
Subprocess and HTTP are mocked via the modules' injection seams.
Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import nuclei, cve  # noqa: E402
from wscan.core import Findings  # noqa: E402


class _Proc:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _jsonl_line(template_id, severity, matched_at, name=None,
                matcher=None, extracted=None):
    item = {
        "template-id": template_id,
        "info": {"name": name or template_id, "severity": severity,
                 "description": f"{template_id} description",
                 "reference": ["https://example.com/ref"],
                 "tags": ["test"]},
        "matched-at": matched_at,
        "host": matched_at,
    }
    if matcher:
        item["matcher-name"] = matcher
    if extracted:
        item["extracted-results"] = extracted
    return json.dumps(item)


_SAMPLE_JSONL = "\n".join([
    _jsonl_line("http/exposed-panels/test", "critical",
                "http://127.0.0.1:9/admin", name="Exposed Panel",
                matcher="word", extracted=["admin"]),
    _jsonl_line("ssl/expired", "medium", "https://127.0.0.1:9/",
                name="Expired Cert"),
    "this is not json",
    "",
    _jsonl_line("http/exposed-panels/test", "critical",
                "http://127.0.0.1:9/admin", name="Exposed Panel",
                matcher="word", extracted=["admin"]),  # exact duplicate
    json.dumps({"info": {"severity": "high"}}),  # no template id -> skip
])

_NVD_PAYLOAD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en",
                              "value": "Path traversal in Apache."}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8,
                              "baseSeverity": "CRITICAL"}}]},
            "references": [{"url": "https://example.com/cve-1"}],
            "published": "2021-10-05T00:00:00.000"}},
        {"cve": {
            "id": "CVE-2021-42013",
            "descriptions": [{"lang": "en",
                              "value": "Incomplete fix."}],
            "metrics": {"cvssMetricV30": [
                {"cvssData": {"baseScore": 5.3,
                              "baseSeverity": "MEDIUM"}}]},
            "references": [{"url": "https://example.com/cve-2"}],
            "published": "2021-10-07T00:00:00.000"}},
    ]
}


# ---------------------------------------------------------------- nuclei

class NucleiAbsentTest(unittest.TestCase):
    def test_absent_binary_is_a_note_not_a_failure(self):
        calls = []

        def runner(cmd, **kw):
            calls.append(cmd)
            return _Proc()

        result = nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/", runner=runner,
            which=lambda name: None)
        self.assertFalse(result["available"])
        self.assertEqual(result["matches"], [])
        self.assertIn("not installed", result["note"].lower())
        self.assertEqual(calls, [])  # nothing was ever executed

    def test_explicit_missing_binary_path(self):
        result = nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/", binary="/nonexistent/nuclei",
            runner=lambda cmd, **kw: _Proc())
        self.assertFalse(result["available"])
        self.assertIn("not installed", result["note"].lower())

    def test_invalid_target_never_runs(self):
        calls = []
        # sys.executable stands in as an existing file for the binary
        # path check; the runner is never reached for bad targets.
        for bad in ("ftp://example.com/", "", "not-a-url"):
            result = nuclei.run_nuclei_scan(
                bad, binary=sys.executable,
                runner=lambda cmd, **kw: calls.append(cmd) or _Proc())
            self.assertEqual(result["matches"], [])
            self.assertIn("invalid target", result["note"].lower())
        self.assertEqual(calls, [])


class NucleiPresentTest(unittest.TestCase):
    def test_mocked_run_parses_and_labels_matches(self):
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"] = cmd
            return _Proc(stdout=_SAMPLE_JSONL, returncode=0)

        result = nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/", runner=runner,
            which=lambda name: "/usr/bin/nuclei")
        self.assertTrue(result["available"])
        self.assertIsNone(result["note"])
        # 2 unique matches: malformed/blank/duplicate/no-id lines skipped
        self.assertEqual(len(result["matches"]), 2)
        first = result["matches"][0]
        self.assertEqual(first["source"], "nuclei")
        self.assertFalse(first["is_engine_finding"])
        self.assertEqual(first["template_id"], "http/exposed-panels/test")
        self.assertEqual(first["severity"], "Critical")
        self.assertEqual(first["matched_at"], "http://127.0.0.1:9/admin")
        self.assertEqual(first["matcher_name"], "word")
        self.assertEqual(first["extracted_results"], ["admin"])
        self.assertIn("http/exposed-panels/test", first["evidence"])
        self.assertIn("admin", first["evidence"])
        # command: argv list, target as its own element, no shell string
        self.assertIsInstance(seen["cmd"], list)
        self.assertIn("http://127.0.0.1:9/", seen["cmd"])
        self.assertNotIn("-update-templates", seen["cmd"])

    def test_template_paths_severity_and_tags_in_command(self):
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"] = cmd
            return _Proc(stdout="", returncode=0)

        nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/",
            template_paths=["/tmp/tpl1.yaml", "/tmp/tpl2.yaml"],
            templates_dir="/tmp/templates",
            severities=["critical", "high", "bogus-severity"],
            tags=["panel", "exposure"],
            runner=runner, which=lambda name: "/usr/bin/nuclei")
        cmd = seen["cmd"]
        self.assertIn("-t", cmd)
        self.assertEqual(cmd.count("/tmp/tpl1.yaml"), 1)
        self.assertIn("/tmp/templates", cmd)
        sev_idx = cmd.index("-severity")
        self.assertEqual(cmd[sev_idx + 1], "critical,high")  # bogus dropped
        tags_idx = cmd.index("-tags")
        self.assertEqual(cmd[tags_idx + 1], "panel,exposure")

    def test_timeout_is_graceful(self):
        def runner(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, timeout=kw.get("timeout"))

        result = nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/", timeout=5, runner=runner,
            which=lambda name: "/usr/bin/nuclei")
        self.assertEqual(result["matches"], [])
        self.assertIn("timed out", result["note"].lower())

    def test_runner_error_is_graceful(self):
        def runner(cmd, **kw):
            raise OSError("exec failed")

        result = nuclei.run_nuclei_scan(
            "http://127.0.0.1:9/", runner=runner,
            which=lambda name: "/usr/bin/nuclei")
        self.assertEqual(result["matches"], [])
        self.assertIn("failed", result["note"].lower())

    def test_update_command_is_separate_from_scans(self):
        # sys.executable stands in as an existing file for the binary
        # path check ("/usr/bin/nuclei" does not exist on this VM).
        self.assertEqual(
            nuclei.update_templates_command(binary=sys.executable),
            [sys.executable, "-update-templates"])
        self.assertIsNone(
            nuclei.update_templates_command(binary="/nonexistent/nuclei"))
        ok, note = nuclei.run_template_update(
            binary=sys.executable,
            runner=lambda cmd, **kw: _Proc(stdout="", returncode=0))
        self.assertTrue(ok)

    def test_section_helper_keeps_matches_separate(self):
        result = {"available": True, "note": None,
                  "matches": nuclei.parse_nuclei_jsonl(_SAMPLE_JSONL),
                  "command": []}
        sec = nuclei.nuclei_section(result)
        self.assertEqual(sec["title"], "Nuclei template matches")
        self.assertEqual(sec["count"], 2)
        self.assertTrue(all(m["source"] == "nuclei"
                            for m in sec["matches"]))
        lines = nuclei.format_nuclei_section(result)
        self.assertTrue(any("Nuclei template matches" in ln for ln in lines))
        # and nothing here ever touched the engine findings store
        self.assertEqual(Findings().items, [])


# ---------------------------------------------------------------- CVE

class CveParseTest(unittest.TestCase):
    def test_tech_string_forms(self):
        self.assertEqual(cve.parse_tech_string("Apache/2.4.49"),
                         ("Apache", "2.4.49"))
        self.assertEqual(cve.parse_tech_string("nginx/1.18.0"),
                         ("nginx", "1.18.0"))
        self.assertEqual(cve.parse_tech_string("OpenSSL/1.0.1f"),
                         ("OpenSSL", "1.0.1f"))
        self.assertEqual(cve.parse_tech_string("WordPress 5.8.1"),
                         ("WordPress", "5.8.1"))
        self.assertEqual(cve.parse_tech_string("Cloudflare"),
                         ("Cloudflare", None))
        self.assertEqual((None, None), cve.parse_tech_string("  "))

    def test_cpe_mapping_and_url(self):
        self.assertEqual(cve.tech_to_cpe("Apache"), ("apache", "http_server"))
        self.assertEqual(cve.tech_to_cpe("Microsoft-IIS"),
                         ("microsoft", "internet_information_services"))
        self.assertEqual(cve.tech_to_cpe("jQuery"), ("jquery", "jquery"))
        self.assertIsNone(cve.tech_to_cpe("SomeUnknownThing"))
        url = cve.build_nvd_url("apache", "http_server", "2.4.49")
        self.assertIn("cpeName=", url)
        self.assertIn("2.4.49", url)
        self.assertIn("apache", url)

    def test_parse_nvd_payload(self):
        advs = cve.parse_nvd_response(_NVD_PAYLOAD)
        self.assertEqual(len(advs), 2)
        first, second = advs
        self.assertEqual(first["cve_id"], "CVE-2021-41773")
        self.assertEqual(first["cvss_score"], 9.8)
        self.assertEqual(first["severity"], "Critical")
        self.assertIn("Path traversal", first["description"])
        self.assertEqual(first["references"], ["https://example.com/cve-1"])
        self.assertEqual(second["severity"], "Medium")
        self.assertEqual(second["cvss_score"], 5.3)
        for adv in advs:
            self.assertEqual(adv["kind"], "cve_advisory")
            self.assertFalse(adv["is_finding"])
            self.assertEqual(adv["source"], "NVD API 2.0")
        self.assertEqual(cve.parse_nvd_response("not json"), [])
        self.assertEqual(cve.parse_nvd_response({}), [])


class CveLookupTest(unittest.TestCase):
    def _tmp_cache(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)  # lookup must work with a missing cache file
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_mocked_feed_parsed_as_advisories(self):
        def fetcher(url, headers, timeout):
            self.assertIn("services.nvd.nist.gov", url)
            self.assertIn("cpeName=", url)
            return _NVD_PAYLOAD

        result = cve.lookup_cves_for_tech(
            "Apache", "2.4.49", cache_path=self._tmp_cache(),
            fetcher=fetcher)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["advisories"]), 2)
        self.assertFalse(result["from_cache"])
        self.assertTrue(all(not a["is_finding"]
                            for a in result["advisories"]))

    def test_feed_down_is_a_note_not_a_failure(self):
        def fetcher(url, headers, timeout):
            raise urllib.error.URLError("network unreachable")

        result = cve.lookup_cves_for_tech(
            "Apache", "2.4.49", cache_path=self._tmp_cache(),
            fetcher=fetcher)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["advisories"], [])
        self.assertIn("No CVE data available", result["note"])

    def test_empty_feed_is_no_data_not_invented(self):
        result = cve.lookup_cves_for_tech(
            "nginx", "1.99.0", cache_path=self._tmp_cache(),
            fetcher=lambda url, headers, timeout: {"vulnerabilities": []})
        self.assertEqual(result["status"], "no_data")
        self.assertEqual(result["advisories"], [])

    def test_no_version_and_no_mapping(self):
        no_ver = cve.lookup_cves_for_tech(
            "Cloudflare", None, cache_path=self._tmp_cache(),
            fetcher=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(no_ver["status"], "no_version")
        no_map = cve.lookup_cves_for_tech(
            "SomeUnknownThing", "1.0", cache_path=self._tmp_cache(),
            fetcher=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(no_map["status"], "no_mapping")
        self.assertEqual(no_map["advisories"], [])

    def test_cache_serves_offline_repeat_and_stale_is_not_served(self):
        path = self._tmp_cache()
        good = lambda url, headers, timeout: _NVD_PAYLOAD  # noqa: E731
        first = cve.lookup_cves_for_tech("Apache", "2.4.49",
                                         cache_path=path, fetcher=good)
        self.assertEqual(first["status"], "ok")

        def down(url, headers, timeout):
            raise urllib.error.URLError("offline")

        second = cve.lookup_cves_for_tech("Apache", "2.4.49",
                                          cache_path=path, fetcher=down)
        self.assertEqual(second["status"], "cached")
        self.assertTrue(second["from_cache"])
        self.assertEqual(second["advisories"], first["advisories"])

        # age the entry past the TTL: the stale answer must NOT be served
        cache = cve.load_cache(path)
        key = "apache:http_server@2.4.49"
        cache[key]["fetched_at"] = time.time() - cve.CACHE_TTL_SECONDS - 10
        cve.save_cache(path, cache)
        third = cve.lookup_cves_for_tech("Apache", "2.4.49",
                                         cache_path=path, fetcher=down)
        self.assertEqual(third["status"], "unavailable")
        self.assertEqual(third["advisories"], [])


class CveFingerprintTest(unittest.TestCase):
    def test_fingerprint_lookup_annotates_and_never_creates_findings(self):
        seen_urls = []

        def fetcher(url, headers, timeout):
            seen_urls.append(url)
            return _NVD_PAYLOAD

        fingerprint = {
            "tech": ["Apache/2.4.49", "nginx/1.18.0", "Cloudflare"],
            "versions": {"jQuery": "1.12.4"},
            "generator": "",
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = os.path.join(tmp, "cve_cache.json")
            result = cve.lookup_cves_for_fingerprint(
                fingerprint, cache_path=cache, fetcher=fetcher)
        # Apache + nginx + jQuery queried once each; bare Cloudflare skipped
        self.assertEqual(len(seen_urls), 3)
        joined = " ".join(seen_urls)
        self.assertIn("http_server", joined)
        self.assertIn("nginx", joined)
        self.assertIn("jquery", joined)
        self.assertEqual(len(result["advisories"]), 6)  # 2 per product
        self.assertTrue(all(a["kind"] == "cve_advisory"
                            and not a["is_finding"]
                            for a in result["advisories"]))
        self.assertTrue(all("detected_version" in a
                            for a in result["advisories"]))
        sec = cve.cve_section(result)
        self.assertIn("informational only", sec["title"])
        self.assertEqual(sec["count"], 6)
        lines = cve.format_cve_section(result)
        self.assertTrue(any("informational only" in ln for ln in lines))
        # separation: the findings store was never involved
        self.assertEqual(Findings().items, [])

    def test_fingerprint_with_no_versions_is_quiet(self):
        result = cve.lookup_cves_for_fingerprint(
            {"tech": ["Cloudflare"], "versions": {}, "generator": ""},
            cache_path=os.path.join(tempfile.gettempdir(),
                                    "no-such-cve-cache.json"),
            fetcher=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(result["advisories"], [])


if __name__ == "__main__":
    unittest.main()
