"""Tests for the three new VM-only modules: wscan/takeover.py,
wscan/jssecrets.py and wscan/cloud.py.

No live external scans: takeover/cloud proofs run through injected
fetcher/resolver seams or a localhost stub server, exactly like the
existing tests. Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import threading
import types
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import cloud as cloud_mod  # noqa: E402
from wscan import jssecrets as js_mod  # noqa: E402
from wscan import takeover as tk_mod  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings  # noqa: E402
from wscan.engine import Ctx  # noqa: E402


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


def _ctx(base, opts=None):
    F = Findings()
    return Ctx(Client(), F, None, base, opts or {}, lambda m: None), F


_GHP = ("ghp_aB3dEf" + "6hIj9kLm2n" + "Op5qRs8tUv" + "1wXy4zA7bC")
_GHP_MAP = ("ghp_Zz9yXx" + "8wWw7vVv6u" + "Uu5tTt4sSs" + "3rRr2qQq1p")
_STRIPE = ("sk_live_aB" + "3dEf6hIj9k" + "Lm2nOp5qRs" + "8t")
_AWS_SECRET = ("aB3dEf6hIj" + "9kLm2nOp5q" + "Rs8tUv1wXy" + "4zA7bC9dE2")
_GENERIC = ("aB9xQ2mZ8k" + "L4vN7pR3tY" + "6wS1dF0hJ5" + "g")


# =============================================================== takeover

class TestTakeover(unittest.TestCase):
    def _run(self, subs, cnames, pages):
        ctx, F = _ctx("http://example.com/")
        resolver = lambda h: cnames.get(h)  # noqa: E731
        calls = []

        def fetcher(url):
            host = urllib.parse.urlsplit(url).hostname
            calls.append(host)
            return pages.get(host, (404, "not found"))

        tk_mod.takeover_check(ctx, subdomains=subs, resolver=resolver,
                              fetcher=fetcher)
        return F, calls

    def test_proven_github_pages(self):
        F, _ = self._run(
            ["blog.example.com"],
            {"blog.example.com": "blog.github.io"},
            {"blog.example.com": (404,
             "404: There isn't a GitHub Pages site here.")})
        self.assertEqual(len(F.items), 1)
        f = F.items[0]
        self.assertEqual(f["severity"], "High")
        self.assertIn("Subdomain Takeover", f["title"])
        self.assertIn("blog.github.io", f["proof"])
        self.assertIn("GitHub Pages", f["proof"])

    def test_fingerprint_without_proof_is_not_reported(self):
        # CNAME matches Netlify, but the live page is a real site.
        F, _ = self._run(
            ["docs.example.com"],
            {"docs.example.com": "docs.netlify.app"},
            {"docs.example.com": (200, "<html>Welcome to our docs</html>")})
        self.assertEqual(len(F.items), 0)

    def test_transient_signature_is_not_proof(self):
        seen = {"n": 0}

        def fetcher(url):
            seen["n"] += 1
            if seen["n"] == 1:
                return 200, "No such app"
            return 200, "<html>real app home</html>"

        ctx, F = _ctx("http://example.com/")
        tk_mod.takeover_check(
            ctx, subdomains=["old.example.com"],
            resolver=lambda h: "old.herokuapp.com", fetcher=fetcher)
        self.assertEqual(len(F.items), 0)

    def test_unrelated_cname_never_fetched(self):
        F, calls = self._run(
            ["api.example.com"],
            {"api.example.com": "api.othercdn.example.net"},
            {})
        self.assertEqual(len(F.items), 0)
        self.assertNotIn("api.example.com", calls)

    def test_match_fingerprint_trailing_dot(self):
        fp = tk_mod.match_fingerprint("x.github.io.")
        self.assertIsNotNone(fp)
        self.assertEqual(fp["service"], "GitHub Pages")
        self.assertIsNone(tk_mod.match_fingerprint("x.evilgithub.io"))

    def test_collect_subdomains_from_recon_and_pages(self):
        pages = [("http://app.example.com/",
                  types.SimpleNamespace(body="see shop.example.com and "
                                             "cdn.other.com"))]
        subs = tk_mod.collect_subdomains(
            "http://example.com/",
            pages=pages,
            recon_subdomains=["api.example.com", "app.example.com"])
        self.assertIn("api.example.com", subs)
        self.assertIn("app.example.com", subs)
        self.assertIn("shop.example.com", subs)
        self.assertNotIn("cdn.other.com", subs)


# =============================================================== js secrets

class TestJsSecretsUnit(unittest.TestCase):
    def test_mask_and_entropy(self):
        self.assertEqual(js_mod.mask_secret("abcdefghij"), "abcd…ghij")
        self.assertEqual(js_mod.mask_secret("12345678"), "12…78")
        self.assertGreater(js_mod.shannon_entropy(_GENERIC), 3.5)
        self.assertEqual(js_mod.shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0)

    def test_specific_tokens_masked(self):
        recs = js_mod.find_secrets_in_text(
            f'const t = "{_GHP}";\nconst s = "{_STRIPE}";',
            "http://x/app.js")
        kinds = {r["kind"] for r in recs}
        self.assertIn("GitHub personal access token", kinds)
        self.assertIn("Stripe live secret key", kinds)
        blob = json.dumps(recs, ensure_ascii=False)
        self.assertNotIn(_GHP, blob)
        self.assertNotIn(_STRIPE, blob)
        self.assertTrue(all(r["masked"] in blob for r in recs))

    def test_generic_assignment_gate(self):
        good = js_mod.find_secrets_in_text(
            f'api_key = "{_GENERIC}"', "http://x/a.js")
        self.assertEqual(len(good), 1)
        self.assertEqual(good[0]["kind"], "Hardcoded credential in JS")
        # Placeholder, low-entropy and short values must not fire.
        for bad_val in ("testtesttesttesttesttest",
                        "aaaaaaaaaaaaaaaaaaaaaaaa",
                        "your-api-key-here-12345", "short"):
            recs = js_mod.find_secrets_in_text(
                f'api_key = "{bad_val}"', "http://x/a.js")
            self.assertEqual(recs, [], bad_val)

    def test_aws_secret_needs_context(self):
        recs = js_mod.find_secrets_in_text(
            f'aws_secret = "{_AWS_SECRET}"', "http://x/a.js")
        self.assertTrue(any(r["kind"] == "AWS secret access key"
                            for r in recs))
        # The same 40-char string with no AWS context must not fire
        # as an AWS secret (it may not fire at all).
        recs2 = js_mod.find_secrets_in_text(
            f'const blob = "{_AWS_SECRET}"', "http://x/a.js")
        self.assertFalse(any(r["kind"] == "AWS secret access key"
                             for r in recs2))

    def test_private_key_header(self):
        recs = js_mod.find_secrets_in_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA",
            "http://x/k.js")
        self.assertTrue(any(r["kind"] == "Private key" and
                            r["severity"] == "Critical" for r in recs))


class TestJsSecretsCheck(unittest.TestCase):
    def _handler(self, app_js, app_map=None):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/static/app.js":
                    _send(self, 200, app_js, "application/javascript")
                elif self.path == "/static/app.js.map" and app_map:
                    _send(self, 200, app_map, "application/json")
                elif self.path == "/":
                    _send(self, 200,
                          '<html><head><script src="/static/app.js">'
                          "</script></head><body>ok</body></html>")
                else:
                    _send(self, 404, "nope")

            def log_message(self, *a):
                pass

        return H

    def test_bundle_secrets_masked_in_findings(self):
        app_js = (f'const t = "{_GHP}";\nconst s = "{_STRIPE}";\n'
                  'console.log("hello");\n')
        _srv, base = _serve(self._handler(app_js))
        ctx, F = _ctx(base + "/")
        r = ctx.client.fetch(base + "/")
        js_mod.js_secrets_check(ctx, [(base + "/", r)],
                                [base + "/static/app.js"])
        self.assertEqual(len(F.items), 2)
        dump = json.dumps(F.items)
        self.assertNotIn(_GHP, dump)
        self.assertNotIn(_STRIPE, dump)
        self.assertTrue(all("…" in f["proof"] for f in F.items))
        self.assertTrue(all(f["param"] and "…" in f["param"]
                            for f in F.items))

    def test_source_map_sources_content_located(self):
        app_js = "//# sourceMappingURL=app.js.map\nconsole.log(1);\n"
        smap = json.dumps({"version": 3, "sources": ["src/original.js"],
                           "sourcesContent":
                               [f'const t = "{_GHP_MAP}";'],
                           "mappings": "AAAA"})
        _srv, base = _serve(self._handler(app_js, smap))
        ctx, F = _ctx(base + "/")
        js_mod.js_secrets_check(ctx, [], [base + "/static/app.js"])
        self.assertEqual(len(F.items), 1)
        self.assertIn("app.js.map#src/original.js", F.items[0]["url"])
        self.assertNotIn(_GHP_MAP, json.dumps(F.items))

    def test_inline_script_and_clean_bundle(self):
        _srv, base = _serve(self._handler("console.log(1);\n"))
        ctx, F = _ctx(base + "/")
        page = types.SimpleNamespace(
            body=f'<script>const s = "{_STRIPE}";</script>')
        js_mod.js_secrets_check(ctx, [(base + "/", page)], [])
        self.assertEqual(len(F.items), 1)
        self.assertIn("line 1", F.items[0]["detail"])
        ctx2, F2 = _ctx(base + "/")
        r = ctx2.client.fetch(base + "/")
        js_mod.js_secrets_check(ctx2, [(base + "/", r)],
                                [base + "/static/app.js"])
        self.assertEqual(len(F2.items), 0)


# =============================================================== cloud

class TestCloudUnit(unittest.TestCase):
    def test_candidate_names(self):
        names = cloud_mod.candidate_bucket_names("app.example.com")
        self.assertIn("example", names)
        self.assertIn("example-assets", names)
        self.assertIn("app-example", names)
        self.assertIn("example-uploads", names)

    def test_extract_references(self):
        text = ('<img src="https://acme.s3.amazonaws.com/logo.png"> '
                '<a href="https://acme.blob.core.windows.net/public/f.txt">x</a> '
                '<a href="https://example.com/normal">y</a>')
        refs = cloud_mod.extract_cloud_references(text)
        self.assertEqual(len(refs), 2)
        self.assertTrue(refs[0].startswith("https://acme.s3"))

    def test_s3_listing_proven(self):
        def fetcher(url):
            if "acme.s3.amazonaws.com" in url:
                return 200, ("<ListBucketResult><Name>acme</Name>"
                             "<Contents><Key>a.txt</Key></Contents>"
                             "</ListBucketResult>")
            return 404, "<Error><Code>NoSuchBucket</Code></Error>"

        ctx, F = _ctx("http://example.com/")
        cloud_mod.check_cloud_buckets(ctx, ["acme"], fetcher=fetcher)
        self.assertEqual(len(F.items), 1)
        self.assertEqual(F.items[0]["severity"], "High")
        self.assertIn("acme", F.items[0]["detail"])

    def test_gcs_fallthrough_after_s3_miss(self):
        def fetcher(url):
            if "storage.googleapis.com/acme/" in url:
                return 200, ('{"kind": "storage#objects", "items": '
                             '[{"name": "a.txt"}]}')
            return 404, "<Error><Code>NoSuchBucket</Code></Error>"

        ctx, F = _ctx("http://example.com/")
        cloud_mod.check_cloud_buckets(ctx, ["acme"], fetcher=fetcher)
        self.assertEqual(len(F.items), 1)
        self.assertIn("storage.googleapis.com", F.items[0]["url"])

    def test_denied_and_missing_are_not_findings(self):
        def fetcher(url):
            if "denied" in url:
                return 403, "<Error><Code>AccessDenied</Code></Error>"
            return 404, "<Error><Code>NoSuchBucket</Code></Error>"

        ctx, F = _ctx("http://example.com/")
        cloud_mod.check_cloud_buckets(ctx, ["denied", "gone"],
                                      fetcher=fetcher)
        self.assertEqual(len(F.items), 0)

    def test_azure_container_listing(self):
        def fetcher(url):
            if "acme.blob.core.windows.net/public?resttype" in url:
                return 200, ("<?xml version=\"1.0\"?><EnumerationResults>"
                             "<Blobs><Blob><Name>f.txt</Name></Blob>"
                             "</Blobs></EnumerationResults>")
            return 404, "<Error><Code>ContainerNotFound</Code></Error>"

        ctx, F = _ctx("http://example.com/")
        cloud_mod.check_azure_containers(ctx, ["acme"], ["public"],
                                         fetcher=fetcher)
        self.assertEqual(len(F.items), 1)
        self.assertIn("public", F.items[0]["param"])

    def test_bare_200_without_listing_marker_is_not_proof(self):
        ctx, F = _ctx("http://example.com/")
        cloud_mod.check_cloud_references(
            ctx, ["https://acme.s3.amazonaws.com/"],
            fetcher=lambda u: (200, "<html>welcome to our site</html>"))
        self.assertEqual(len(F.items), 0)


class TestCloudReferencedFiles(unittest.TestCase):
    def test_public_and_sensitive_files_via_stub(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/files/report.txt":
                    _send(self, 200, "public report contents", "text/plain")
                elif self.path == "/files/.env":
                    _send(self, 200, "DB_PASS=hunter2", "text/plain")
                elif self.path == "/files/denied.txt":
                    _send(self, 403,
                          "<Error><Code>AccessDenied</Code></Error>",
                          "application/xml")
                else:
                    _send(self, 404, "nope")

            def log_message(self, *a):
                pass

        _srv, base = _serve(H)
        ctx, F = _ctx(base + "/")
        cloud_mod.check_cloud_references(
            ctx, [base + "/files/report.txt",
                  base + "/files/.env",
                  base + "/files/denied.txt",
                  base + "/files/missing.txt"])
        by_url = {f["url"]: f for f in F.items}
        self.assertEqual(len(F.items), 2)
        self.assertEqual(by_url[base + "/files/report.txt"]["severity"],
                         "Medium")
        self.assertEqual(by_url[base + "/files/.env"]["severity"], "High")


if __name__ == "__main__":
    unittest.main(verbosity=2)
