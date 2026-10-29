"""Tests for the 403 Access-Control Assessment Engine (3.14).

Layers:
  * pure unit tests — attribution, F5 diagnostics + log correlation,
    fingerprints, the verdict-gating truth table, the technique
    catalog (groups, required forms, dedupe), rate limiting;
  * raw-channel tests (HTTP/1.0, absolute-form, empty method);
  * integration tests against the local mock application with KNOWN
    access-control rules (tests/mock_acl_app.py), incl. its planted
    host-header, cache-deception, flaky, weak-session and
    never-protected cases; plus the safety rails.

Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import threading
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mock_acl_app as mock                       # noqa: E402
from wscan import access403                       # noqa: E402
from wscan.client import Resp                     # noqa: E402

MARKER = mock.MARKER


def R(status, body="", headers=None, url="http://t/x"):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return Resp(status, h, list((headers or {}).items()), body, url,
                0.1, "GET /x HTTP/1.1")


F5_BODY = ("<html><body><h1>The requested URL was rejected. Please "
           "consult with your administrator.</h1><p>Your support ID "
           "is: 1234567890123456789</p></body></html>")


# ======================================================================
# Pure unit tests
# ======================================================================
class AttributionTests(unittest.TestCase):
    def test_f5_attributed_with_support_id(self):
        r = R(403, F5_BODY, {"Server": "BigIP",
                             "Date": "Fri, 16 Oct 2026 10:00:00 GMT"})
        a = access403.attribute_source(r)
        self.assertEqual(a["layer"], "waf")
        self.assertEqual(a["vendor"], "F5 BIG-IP ASM")
        d = access403.f5_diagnostics(r)
        self.assertEqual(d["support_id"], "1234567890123456789")
        self.assertEqual(d["timestamp"], "Fri, 16 Oct 2026 10:00:00 GMT")
        self.assertIn("f5-support-id", access403.extract_request_ids(r))

    def test_f5_absent_for_plain_403(self):
        r = R(403, "<html><body>403 Forbidden</body></html>",
              {"Server": "nginx"})
        self.assertIsNone(access403.f5_diagnostics(r))
        self.assertEqual(access403.attribute_source(r)["layer"],
                         "application")

    def test_cloudflare_attributed(self):
        r = R(403, "Attention Required!", {"cf-ray": "8abc-IAD"})
        a = access403.attribute_source(r)
        self.assertEqual((a["layer"], a["vendor"]), ("cdn", "Cloudflare"))

    def test_auth_layer(self):
        r = R(401, "auth", {"WWW-Authenticate": 'Basic realm="x"'})
        self.assertEqual(access403.attribute_source(r)["layer"],
                         "authentication")
        self.assertTrue(access403.auth_signal(r))

    def test_f5_log_correlation(self):
        f5 = {"support_id": "1234567890123456789"}
        hit = access403.correlate_f5_log(
            f5, "ts=1 id=1234567890123456789 blocked, attack signature "
                "'SQLi' in policy /Common/app")
        self.assertTrue(hit["matched"])
        self.assertIn("signature", hit["rule_hint"])
        miss = access403.correlate_f5_log(f5, "unrelated log lines")
        self.assertFalse(miss["matched"])
        self.assertIsNone(access403.correlate_f5_log(f5, ""))


class FingerprintTests(unittest.TestCase):
    def test_fields(self):
        fp = access403.fingerprint(
            R(200, "<title>Canary</title>" + "x" * 50 + MARKER), MARKER)
        self.assertEqual(fp["title"], "Canary")
        self.assertTrue(fp["marker_present"])
        self.assertEqual(len(fp["sha256"]), 16)

    def test_exact_and_soft_match(self):
        body = "<title>Canary</title>" + "a" * 200
        fp = access403.fingerprint(R(200, body, {"Content-Type":
                                                 "text/html"}))
        self.assertTrue(access403.fingerprint_match(
            fp, R(200, body, {"Content-Type": "text/html"})))
        soft = "<title>Canary</title>" + "a" * 190 + " (v2)"
        self.assertTrue(access403.fingerprint_match(
            fp, R(200, soft, {"Content-Type": "text/html"})))
        other = "<title>Other</title>" + "a" * 200
        self.assertFalse(access403.fingerprint_match(
            fp, R(200, other, {"Content-Type": "text/html"})))

    def test_marker_match(self):
        fp = access403.fingerprint(R(200, "anything " + MARKER), MARKER)
        self.assertTrue(access403.fingerprint_match(
            fp, R(200, "different body, still " + MARKER), MARKER))
        self.assertFalse(access403.fingerprint_match(
            fp, R(200, "no marker here"), MARKER))


class ClassifierTests(unittest.TestCase):
    C = staticmethod(access403.classify_outcome)
    FULL = dict(resp=None, base_status=403, proof=True, marker=True,
                guard_ok=True, verify_fetches=3, verify_matches=3,
                fingerprint_match=True, policy_expected="deny")

    def _full(self, **over):
        kw = dict(self.FULL)
        kw["resp"] = R(200, "real resource content")
        kw.update(over)
        return kw

    def test_no_response_inconclusive(self):
        self.assertEqual(self.C(resp=None, base_status=403)[0],
                         "inconclusive")

    def test_bypass_verified_needs_full_chain(self):
        out = self.C(**self._full())
        self.assertEqual(out[0], "bypass_verified")
        self.assertEqual(out[2], "CONFIRMED")

    def test_identity_kind_verifies_as_weakness(self):
        self.assertEqual(self.C(**self._full(kind="identity"))[0],
                         "weakness_verified")

    def test_partial_reproduction_is_candidate(self):
        self.assertEqual(self.C(**self._full(verify_matches=2))[0],
                         "bypass_candidate")

    def test_guard_failure_is_candidate(self):
        self.assertEqual(self.C(**self._full(guard_ok=False))[0],
                         "bypass_candidate")

    def test_unreproduced_is_only_suspected(self):
        self.assertEqual(self.C(**self._full(verify_matches=1))[0],
                         "misconfig_suspected")

    def test_fingerprint_mismatch_is_suspected(self):
        self.assertEqual(
            self.C(**self._full(fingerprint_match=False))[0],
            "misconfig_suspected")

    def test_marker_absent_is_suspected(self):
        self.assertEqual(self.C(**self._full(marker=False))[0],
                         "misconfig_suspected")

    def test_status_change_alone_is_never_verified(self):
        out = self.C(resp=R(200, "some other page"), base_status=403,
                     proof=False, proof_why="not the protected content")
        self.assertEqual(out[0], "misconfig_suspected")
        self.assertEqual(out[2], "SPECULATIVE")

    def test_head_can_never_verify(self):
        self.assertEqual(self.C(**self._full(method="HEAD"))[0],
                         "misconfig_suspected")

    def test_head_success_vs_get_denial_is_suspected(self):
        out = self.C(resp=R(200, ""), base_status=403, method="HEAD")
        self.assertEqual(out[0], "misconfig_suspected")
        self.assertIn("no body", out[3])

    def test_never_protected_caps_techniques(self):
        self.assertEqual(self.C(**self._full(never_protected=True))[0],
                         "misconfig_suspected")

    def test_never_protected_caps_auth_context(self):
        self.assertEqual(
            self.C(**self._full(never_protected=True, kind="identity",
                                test_type="auth-context"))[0],
            "misconfig_suspected")

    def test_never_protected_front_door_still_weakness(self):
        # the plain request itself violating policy is not a bypass
        # claim, so it still verifies as a weakness
        self.assertEqual(
            self.C(**self._full(never_protected=True, kind="identity",
                                test_type="auth-state"))[0],
            "weakness_verified")

    def test_soft404_spelling_is_block_confirmed(self):
        self.assertEqual(
            self.C(resp=R(200, "not here"), base_status=403,
                   proof=False,
                   proof_why="the site's soft-404 page")[0],
            "block_confirmed")

    def test_same_403_is_block_confirmed(self):
        self.assertEqual(
            self.C(resp=R(403, "plain application denial"),
                   base_status=403)[0], "block_confirmed")

    def test_f5_variant_is_waf_block(self):
        self.assertEqual(
            self.C(resp=R(403, F5_BODY, {"Server": "BigIP"}),
                   base_status=403)[0], "waf_block")

    def test_401_variant_is_auth_required(self):
        self.assertEqual(
            self.C(resp=R(401, "", {"WWW-Authenticate": "Basic"}),
                   base_status=403)[0], "auth_required")

    def test_404_variant_is_block_confirmed(self):
        self.assertEqual(self.C(resp=R(404, "nope"), base_status=403)[0],
                         "block_confirmed")

    def test_500_is_inconclusive(self):
        self.assertEqual(self.C(resp=R(500, "boom"), base_status=403)[0],
                         "inconclusive")


class CatalogTests(unittest.TestCase):
    def _catalog(self, checks=None, cookie="session=rolea"):
        t = access403.Tester(["http://127.0.0.1/canary"],
                             {"mode": "validation", "checks": checks
                              or {}})
        u = "http://127.0.0.1/canary"
        parts = urllib.parse.urlsplit(u)
        return t._catalog(u, parts, "http://127.0.0.1", "/canary",
                          "http://127.0.0.1/reconix-nonexistent-7391",
                          "anon", cookie=cookie)

    def test_required_forms_present(self):
        techs = self._catalog()
        urls = [t["url"] for t in techs]
        paths = [urllib.parse.urlsplit(u).path for u in urls]
        self.assertTrue(any(p.startswith("//") for p in paths))
        self.assertTrue(any(";jsessionid=" in p for p in paths))
        self.assertTrue(any("%c0%ae" in p for p in paths))
        self.assertTrue(any(p.endswith(".html") for p in paths))
        self.assertTrue(any("%25" in p for p in paths))  # double-enc
        hdrs = [h for t in techs for h in (t.get("headers") or {})]
        self.assertIn("X-Forwarded-Prefix", hdrs)
        self.assertIn("X-Original-Path", hdrs)
        self.assertIn("X-Forwarded-Host", hdrs)
        self.assertIn("X-Originating-IP", hdrs)
        methods = [t.get("method") for t in techs]
        for verb in ("POST", "HEAD", "PUT", "PATCH", "DELETE",
                     "OPTIONS", "TRACE", "get", "RECONIX", ""):
            self.assertIn(verb, methods)
        raw = [t for t in techs if t.get("raw")]
        self.assertTrue(any(t["raw"].get("version") == "1.0"
                            for t in raw))
        self.assertTrue(any(t["raw"].get("absolute_form")
                            for t in raw))
        groups = {t["group"] for t in techs}
        for g in ("path", "override", "host", "ip", "methods",
                  "protocol", "authctx", "cache"):
            self.assertIn(g, groups)
        self.assertTrue(all(t["hypothesis"] for t in techs))

    def test_query_string_append_present(self):
        techs = self._catalog()
        q = [x for x in techs
             if "query-string append" in x["label"]]
        self.assertEqual(len(q), 1)
        self.assertTrue(q[0]["url"].endswith("/canary?wscan=1"))
        self.assertEqual(q[0]["group"], "path")
        self.assertTrue(q[0]["hypothesis"])
        guard = q[0]["guard"]
        self.assertTrue(guard["url"].endswith(
            "/reconix-nonexistent-7391?wscan=1"))

    def test_group_toggles(self):
        techs = self._catalog(checks={"ip": False, "host": False,
                                      "protocol": False})
        groups = {t["group"] for t in techs}
        self.assertNotIn("ip", groups)
        self.assertNotIn("host", groups)
        self.assertNotIn("protocol", groups)
        self.assertIn("path", groups)

    def test_legacy_check_aliases(self):
        techs = self._catalog(checks={"trusted_headers": False})
        self.assertNotIn("ip", {t["group"] for t in techs})

    def test_dedupe_plan(self):
        t = access403.Tester(["http://127.0.0.1/x"], {})
        tech = {"url": "http://127.0.0.1/x", "method": "GET",
                "headers": {"A": "1"}, "data": None, "identity": "anon"}
        out = t._dedupe_plan([tech, dict(tech), dict(tech, method="POST")])
        self.assertEqual(len(out), 2)
        self.assertEqual(t.deduped, 1)

    def test_rate_limit_enforced(self):
        srv, base = mock.serve(mock.MockAclHandler)
        try:
            t = access403.Tester([base + "/internal"],
                                 {"min_interval_ms": 300})
            c = t._client()
            t0 = time.time()
            t._fetch(c, base + "/internal")
            t._fetch(c, base + "/internal")
            self.assertGreaterEqual(time.time() - t0, 0.25)
        finally:
            srv.shutdown()


class RawChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = mock.serve(mock.MockAclHandler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_http10(self):
        r = access403.raw_fetch(self.base + "/internal",
                                version="1.0")
        self.assertEqual(r.status, 403)

    def test_absolute_form(self):
        r = access403.raw_fetch(self.base + "/internal",
                                absolute_form=True)
        self.assertIsNotNone(r.status)

    def test_empty_method(self):
        # servers commonly just drop malformed requests — a Resp
        # must come back either way, and never a 2xx
        r = access403.raw_fetch(self.base + "/internal", method="")
        self.assertIsNotNone(r)
        self.assertNotIn(r.status, (200, 201, 206))


# ======================================================================
# Integration tests against the mock application
# ======================================================================
class IntegrationBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv_main, cls.main = mock.serve(mock.MockAclHandler)
        cls.srv_custom, cls.custom = mock.serve(mock.Custom403Handler)
        cls.srv_origin, cls.origin = mock.serve(mock.OriginHandler)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv_main, cls.srv_custom, cls.srv_origin):
            s.shutdown()

    def run_diag(self, urls, **opts):
        opts.setdefault("concurrency", 1)
        opts.setdefault("max_requests", 1500)
        opts.setdefault("min_interval_ms", 0)
        return access403.analyze(urls, opts)

    def run_val(self, urls, **val):
        kw = {}
        for key in ("checks", "alt_port", "public_control", "f5_log",
                    "origin"):
            if key in val:
                kw[key] = val.pop(key)
        val.setdefault("role_a_cookie", "session=rolea")
        val.setdefault("role_b_cookie", "session=roleb")
        val.setdefault("marker", MARKER)
        kw.update({"mode": "validation", "validation": val})
        return self.run_diag(urls, **kw)

    def by_url(self, run, url):
        return [r for r in run["records"] if r["url"] == url]

    def classes(self, run, url):
        return {r["classification"] for r in self.by_url(run, url)}

    def verified(self, run, url):
        return [r for r in self.by_url(run, url)
                if r["classification"] in ("bypass_verified",
                                          "weakness_verified")]


class DiagnosticsIntegration(IntegrationBase):
    def test_vault_verified_via_trusted_header(self):
        url = self.main + "/vault"
        run = self.run_diag([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"]
        self.assertTrue(any("X-Forwarded-For" in r["technique"]
                            for r in ver))
        self.assertTrue(any(r["severity"] == "High" for r in ver))
        self.assertTrue(all(r["hypothesis"] for r in ver))
        self.assertTrue(all(
            r["verify"]["observations"] == 3 for r in ver))

    def test_console_verified_via_trailing_slash(self):
        url = self.main + "/console"
        run = self.run_diag([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"]
        self.assertTrue(any("trailing slash" in r["technique"]
                            for r in ver))

    def test_querycanary_verified_via_query_string(self):
        url = self.main + "/querycanary"
        run = self.run_diag([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"]
        self.assertTrue(any("query-string append" in r["technique"]
                            for r in ver))
        self.assertTrue(all(
            r["verify"]["observations"] == 3 for r in ver))

    def test_internal_hard_403_no_verified(self):
        url = self.main + "/internal"
        run = self.run_diag([url])
        self.assertEqual(self.verified(run, url), [])
        self.assertIn("block_confirmed", self.classes(run, url))

    def test_catchall_becomes_candidate_never_verified(self):
        url = self.main + "/fake"
        run = self.run_diag([url])
        self.assertEqual(self.verified(run, url), [])
        cand = [r for r in self.by_url(run, url)
                if r["classification"] == "bypass_candidate"]
        self.assertTrue(cand, "catch-all content must be a candidate")
        self.assertTrue(any("catch-all" in r["evidence"] for r in cand))

    def test_custom_error_page_detected(self):
        url = self.custom + "/anything"
        run = self.run_diag([url])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertTrue(prof["custom_error_page"])
        self.assertEqual(self.verified(run, url), [])

    def test_session_profile(self):
        url = self.main + "/member"
        run = self.run_diag([url], cookie="session=letmein")
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertEqual(prof.get("session_status"), 200)
        self.assertTrue(prof.get("session_can_access"))
        self.assertEqual(self.verified(run, url), [])

    def test_origin_inconsistency_verified(self):
        url = self.main + "/edgeonly"
        origin = self.origin.split("://", 1)[1]
        run = self.run_diag([url], origin=origin)
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"
               and r["type"] == "origin"]
        self.assertTrue(ver, "edge 403 + origin content must verify")

    def test_f5_diagnostics_end_to_end(self):
        url = self.main + "/f5"
        run = self.run_diag([url])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertEqual(prof["attribution"]["vendor"], "F5 BIG-IP ASM")
        self.assertEqual(prof["f5"]["support_id"], mock.F5_SUPPORT_ID)
        self.assertIn("waf_block", self.classes(run, url))
        self.assertEqual(run["rollup"]["waf_blocked"],
                         len([r for r in run["records"]
                              if r["classification"] == "waf_block"]))

    def test_f5_log_correlation_end_to_end(self):
        url = self.main + "/f5"
        log = ("Oct 16 event: support id " + mock.F5_SUPPORT_ID +
               " blocked by attack signature 'Illegal URL' policy main")
        run = self.run_diag([url], f5_log=log)
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        corr = prof["f5"]["log_correlation"]
        self.assertTrue(corr["matched"])
        self.assertIn("signature", corr["rule_hint"])

    def test_authvault_profile(self):
        url = self.main + "/authvault"
        run = self.run_diag([url])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertTrue(prof["auth_required"])
        self.assertEqual(prof["attribution"]["layer"], "authentication")

    def test_write_verbs_opt_in_for_diagnostics(self):
        url = self.main + "/internal"
        run = self.run_diag([url])
        methods = {r["technique"] for r in self.by_url(run, url)
                   if r["type"] == "method"}
        self.assertFalse(any(t.startswith("PUT") for t in methods))
        run2 = self.run_diag([url], checks={"write_methods": True})
        methods2 = {r["technique"] for r in self.by_url(run2, url)
                    if r["type"] == "method"}
        self.assertTrue(any(t.startswith("PUT") for t in methods2))


class ValidationIntegration(IntegrationBase):
    def test_canary_matrix_all_match(self):
        url = self.main + "/canary"
        run = self.run_val([url])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        matrix = {m["identity"]: m for m in prof["matrix"]}
        self.assertTrue(matrix["anon"]["match"])
        self.assertEqual(matrix["anon"]["access"], "denied")
        self.assertTrue(matrix["role_a"]["match"])
        self.assertEqual(matrix["role_a"]["access"], "granted")
        self.assertTrue(matrix["role_b"]["match"])
        self.assertTrue(prof["protected_baseline"])
        self.assertTrue(prof["fingerprint"]["marker_present"])
        self.assertEqual(prof["public_control"]["status"], 200)

    def test_canary_trailing_slash_flaw_verified(self):
        url = self.main + "/canary"
        run = self.run_val([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"]
        self.assertTrue(any("trailing slash" in r["technique"]
                            for r in ver))
        self.assertTrue(any(r["identity"] == "anon" for r in ver))

    def test_xff_flaw_verified_by_content_not_status(self):
        url = self.main + "/xff-canary"
        run = self.run_val([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"
               and r["type"] == "ip-header"]
        self.assertTrue(ver, "XFF serving the canary must verify")

    def test_host_header_flaw_verified(self):
        url = self.main + "/hostcanary"
        run = self.run_val([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"
               and r["group"] == "host"]
        self.assertTrue(any("X-Forwarded-Host" in r["technique"]
                            for r in ver))

    def test_cache_deception_verified(self):
        url = self.main + "/cachecanary"
        run = self.run_val([url])
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "bypass_verified"
               and r["group"] == "cache"]
        self.assertTrue(any("reconix-cache.css" in r["technique"]
                            for r in ver))

    def test_flaky_is_candidate_never_verified(self):
        url = self.main + "/flaky"
        run = self.run_val([url])
        self.assertNotIn("bypass_verified", self.classes(run, url))
        self.assertIn("bypass_candidate", self.classes(run, url))

    def test_never_protected_caps_techniques(self):
        url = self.main + "/neverprotected"
        run = self.run_val([url])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertFalse(prof["protected_baseline"])
        # the front-door policy violation verifies as a weakness...
        self.assertIn("weakness_verified", self.classes(run, url))
        # ...but nothing may be called a bypass of an unprotected page
        self.assertNotIn("bypass_verified", self.classes(run, url))

    def test_weakauth_degraded_cookie_verified(self):
        url = self.main + "/weakauth"
        run = self.run_val([url],
                           role_a_cookie="session=rolea-valid",
                           role_b_cookie="session=plainuser")
        ver = [r for r in self.by_url(run, url)
               if r["classification"] == "weakness_verified"
               and r["type"] == "auth-context"]
        self.assertTrue(ver, "truncated/stale session tokens must "
                             "be caught as a verified weakness")
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        matrix = {m["identity"]: m for m in prof["matrix"]}
        self.assertTrue(matrix["role_a"]["match"])
        self.assertTrue(matrix["role_b"]["match"])

    def test_head_inconsistency_suspected_never_verified(self):
        url = self.main + "/head-canary"
        run = self.run_val([url])
        self.assertEqual(self.verified(run, url), [])
        sus = [r for r in self.by_url(run, url)
               if r["classification"] == "misconfig_suspected"
               and "HEAD" in r["technique"]]
        self.assertTrue(sus, "HEAD 200 vs GET 403 must be suspected")

    def test_policy_mismatch_when_role_wrongly_denied(self):
        url = self.main + "/canary"
        run = self.run_val(
            [url], policy={url: {"expect": {"role_b": "allow"}}})
        sus = [r for r in self.by_url(run, url)
               if r["classification"] == "misconfig_suspected"
               and r["type"] == "auth-state"]
        self.assertTrue(sus)

    def test_equivalent_supplied_and_bogus(self):
        url = self.main + "/canary"
        run = self.run_val([url], policy={url: {
            "equivalents": [url + "/", self.main + "/"]}})
        ver = [r for r in self.by_url(run, url)
               if r["type"] == "equivalent"
               and r["classification"] == "bypass_verified"]
        inc = [r for r in self.by_url(run, url)
               if r["type"] == "equivalent"
               and r["classification"] == "inconclusive"]
        self.assertTrue(ver, "the real equivalent must verify")
        self.assertTrue(inc, "the bogus equivalent must be "
                             "inconclusive (sameness unproven)")

    def test_internal_validation_clean(self):
        url = self.main + "/internal"
        run = self.run_val([url], expect={"role_a": "deny"})
        self.assertEqual(self.verified(run, url), [])
        prof = [p for p in run["profiles"] if p["url"] == url][0]
        self.assertTrue(all(m["match"] for m in prof["matrix"]))
        run2 = self.run_val([url])
        prof2 = [p for p in run2["profiles"] if p["url"] == url][0]
        matrix2 = {m["identity"]: m for m in prof2["matrix"]}
        self.assertFalse(matrix2["role_a"]["match"])

    def test_protocol_group_runs(self):
        url = self.main + "/canary"
        run = self.run_val([url])
        proto = [r for r in self.by_url(run, url)
                 if r["group"] == "protocol"]
        self.assertTrue(proto, "protocol techniques must be recorded")
        self.assertFalse(any(r["classification"] == "bypass_verified"
                             for r in proto))

    def test_alt_port_recorded(self):
        url = self.main + "/internal"
        port = urllib.parse.urlsplit(self.main).port
        run = self.run_val([url], alt_port=port)
        alt = [r for r in self.by_url(run, url)
               if "alternate port" in r["technique"]]
        self.assertTrue(alt)

    def test_validation_html_report(self):
        url = self.main + "/canary"
        run = self.run_val([url], role_a_cookie="session=topsecretvalue")
        page = access403.to_html(run)
        self.assertIn("BYPASS_VERIFIED", page)
        self.assertIn("Validation matrix", page)
        self.assertNotIn("topsecretvalue", page)

    def test_f5_html_report(self):
        run = self.run_diag([self.main + "/f5"])
        page = access403.to_html(run)
        self.assertIn("F5 WAF diagnostics", page)
        self.assertIn(mock.F5_SUPPORT_ID, page)


class SafetyRails(IntegrationBase):
    def test_scope_enforced(self):
        t = access403.Tester([self.main + "/vault"], {"concurrency": 1})
        t.analyze_url(self.custom + "/vault")   # different origin
        self.assertFalse(any(r["url"].startswith(self.custom)
                             for r in t.records))

    def test_stop_event_cancels(self):
        stop = threading.Event()
        stop.set()
        run = access403.analyze([self.main + "/vault"], {}, stop=stop)
        self.assertTrue(run["stopped"])
        self.assertEqual(run["records"], [])

    def test_budget_cap_respected(self):
        run = self.run_diag([self.main + "/vault"], max_requests=50)
        self.assertLessEqual(run["requests_used"], 50)

    def test_validate_url(self):
        self.assertEqual(access403.validate_url("example.com/x")[0],
                         "http://example.com/x")
        self.assertIsNotNone(access403.validate_url("ftp://x/y")[1])
        self.assertIsNotNone(access403.validate_url("")[1])

    def test_redaction(self):
        out = access403.redact_text("session=abc123&token=zzz999 ok")
        self.assertNotIn("abc123", out)
        self.assertNotIn("zzz999", out)
        resp = Resp(200, {"set-cookie": "session=zzz"},
                    [("Set-Cookie", "session=zzz"),
                     ("Content-Type", "text/html")],
                    "body token=abc123456 end", "http://x/", 0.1,
                    "GET / HTTP/1.1\r\nCookie: session=zzz\r\n")
        snap = access403._snapshot(resp)
        self.assertEqual(snap["headers"].get("Set-Cookie"), "***")
        self.assertNotIn("abc123456", snap["body"])
        self.assertNotIn("zzz", snap["request"])
        self.assertEqual(snap["elapsed_ms"], 100)

    def test_html_report_redacted_and_complete(self):
        run = self.run_diag([self.main + "/vault"],
                            cookie="session=topsecretvalue")
        page = access403.to_html(run)
        self.assertIn("403 Access-Control Assessment", page)
        self.assertIn("BYPASS_VERIFIED", page)
        self.assertNotIn("topsecretvalue", page)


if __name__ == "__main__":
    unittest.main()
