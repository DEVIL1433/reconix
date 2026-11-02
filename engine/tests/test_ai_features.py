"""Automated tests for the 3.32 AI features: the model SUGGESTS, the
engine PROVES. The LLM client is stubbed in every test, so the suite
never needs a live Ollama instance.

Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import re
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import ai, checks, report3  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.core import Findings  # noqa: E402
from wscan.engine import Ctx, run_scan  # noqa: E402


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


def _ctx(base, opts=None, cookie=None):
    F = Findings()
    ctx = Ctx(Client(cookie=cookie), F, None, base, opts or {},
              lambda m: None)
    return ctx, F


class _StubPost:
    """Stand-in for ai._post: dispatches on prompt keywords, counts calls."""

    def __init__(self):
        self.calls = []

    def __call__(self, prompt, num_predict):
        self.calls.append(prompt)
        if "test payloads" in prompt:
            if "XSS" in prompt:
                return json.dumps(["<svg onload=alert('AI9')>",
                                   "\"'><img src=x onerror=alert('AI9')>"])
            return json.dumps(["' AIOR 1=1", "\" AIOR 1=1"])
        if "business-logic" in prompt:
            return json.dumps([
                {"type": "anon_access", "target": "PLACEHOLDER",
                 "method": "GET", "note": "may not need login"},
                {"type": "bogus", "target": "http://example.com/x",
                 "method": "GET", "note": "invalid type, must be dropped"},
            ])
        if "already-proven" in prompt:
            n = len([ln for ln in prompt.splitlines()
                     if re.match(r"^\d+\. ", ln)])
            return json.dumps(list(reversed(range(n))))
        if "security briefing" in prompt:
            return ("What was found: proven issues listed. What matters "
                    "most: the critical ones. What to fix first: patch "
                    "injection flaws.")
        return ""


# ------------------------------------------------------- budget / breaker

class TestBudget(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_generate_none_without_budget(self):
        self.assertIsNone(ai.generate("hi", 10, None))

    def test_circuit_breaker_trips_on_error(self):
        calls = []
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        b = ai.AIBudget()
        self.assertIsNone(ai.generate("hi", 10, b))
        self.assertTrue(b.dead)
        self.assertIsNone(ai.generate("hi", 10, b))
        self.assertEqual(b.calls, 1)  # dead: no second network attempt

    def test_budget_caps_calls(self):
        ai._post = lambda p, n: "ok"
        b = ai.AIBudget(max_calls=2)
        self.assertEqual(ai.generate("a", 10, b), "ok")
        self.assertEqual(ai.generate("b", 10, b), "ok")
        self.assertIsNone(ai.generate("c", 10, b))
        self.assertEqual(b.calls, 2)


# ------------------------------------------------------- payload ideas

class TestPayloadIdeas(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_json_parsed_deduped_capped(self):
        ai._post = lambda p, n: json.dumps(
            ["<svg onload=1>", "<svg onload=1>", "x" * 301, "  '><b>  "])
        out = ai.payload_ideas("xss", "http://x/?q=1", ai.AIBudget())
        self.assertEqual(out, ["<svg onload=1>", "'><b>"])

    def test_line_fallback(self):
        ai._post = lambda p, n: "- <svg onload=2>\n* plain\nnot json"
        out = ai.payload_ideas("xss", "http://x/?q=1", ai.AIBudget())
        self.assertIn("<svg onload=2>", out)
        self.assertIn("plain", out)

    def test_failure_returns_empty(self):
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        self.assertEqual(ai.payload_ideas("xss", "http://x/", ai.AIBudget()),
                         [])

    def test_cached_per_url(self):
        stub = _StubPost()
        ai._post = stub
        ctx, _F = _ctx("http://x/", {"ai": True})
        ai.payload_ideas_for(ctx, "xss", "http://x/?q=1")
        ai.payload_ideas_for(ctx, "xss", "http://x/?q=1")
        ai.payload_ideas_for(ctx, "xss", "http://x/?q=2")
        self.assertEqual(len(stub.calls), 2)

    def test_default_off_never_calls(self):
        stub = _StubPost()
        ai._post = stub
        ctx, _F = _ctx("http://x/", {})
        self.assertEqual(ai.payload_ideas_for(ctx, "xss", "http://x/?q=1"), [])
        self.assertEqual(stub.calls, [])


# ------------------------------------------------------- logic ideas

class TestLogicIdeas(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_validates_and_caps(self):
        ai._post = lambda p, n: json.dumps([
            {"type": "anon_access", "target": "http://x/a", "method": "GET"},
            {"type": "bogus", "target": "http://x/b"},
            {"type": "id_tamper", "target": "  "},
            {"type": "id_tamper", "target": "http://x/c?id=1"},
        ])
        out = ai.logic_ideas("surface", ai.AIBudget())
        self.assertEqual([o["type"] for o in out],
                         ["anon_access", "id_tamper"])
        self.assertEqual(out[1]["target"], "http://x/c?id=1")

    def test_failure_empty(self):
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        self.assertEqual(ai.logic_ideas("surface", ai.AIBudget()), [])


# ------------------------------------------------------- ranking / narrative

class TestRankingNarrative(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def _items(self):
        return [
            {"severity": "Low", "title": "A", "url": "http://x/a"},
            {"severity": "High", "title": "B", "url": "http://x/b"},
            {"severity": "Medium", "title": "C", "url": "http://x/c"},
        ]

    def test_permutation_reorders(self):
        ai._post = lambda p, n: "[2, 0, 1]"
        out = ai.rank_items(self._items(), ai.AIBudget())
        self.assertEqual([f["title"] for f in out], ["C", "A", "B"])

    def test_bad_permutation_keeps_object(self):
        items = self._items()
        ai._post = lambda p, n: "[0, 0, 1]"
        self.assertIs(ai.rank_items(items, ai.AIBudget()), items)
        ai._post = lambda p, n: "[0, 1]"
        self.assertIs(ai.rank_items(items, ai.AIBudget()), items)

    def test_failure_keeps_object(self):
        items = self._items()
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        self.assertIs(ai.rank_items(items, ai.AIBudget()), items)

    def test_narrative_text_and_empty(self):
        ai._post = lambda p, n: "Fix the big ones first."
        self.assertEqual(ai.report_narrative("http://x/", self._items(),
                                             ai.AIBudget()),
                         "Fix the big ones first.")
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        self.assertEqual(ai.report_narrative("http://x/", self._items(),
                                             ai.AIBudget()), "")
        self.assertEqual(ai.report_narrative("http://x/", [], ai.AIBudget()),
                         "")


# ------------------------------------------------------- logic check live

def _logic_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.urlparse(self.path)
            cookie = self.headers.get("Cookie", "")
            if q.path == "/open-private":
                _send(self, 200, "SECRET account data")
            elif q.path == "/gated":
                if "session=owner" in cookie:
                    _send(self, 200, "SECRET account data")
                else:
                    _send(self, 200, "<form>log in <input name=password>"
                                     "</form>")
            elif q.path == "/item":
                _send(self, 200, "record %s private data"
                      % dict(urllib.parse.parse_qsl(q.query)).get("id", "?"))
            else:
                _send(self, 404, "not found")

        def log_message(self, *a):
            pass

    return H


class TestLogicCheck(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_anon_proven_and_unproven_discarded(self):
        _srv, base = _serve(_logic_handler())
        ai._post = lambda p, n: json.dumps([
            {"type": "anon_access", "target": base + "/open-private",
             "method": "GET", "note": ""},
            {"type": "anon_access", "target": base + "/gated",
             "method": "GET", "note": ""},
            {"type": "anon_access", "target": "http://other.example/x",
             "method": "GET", "note": "off-host, must be skipped"},
        ])
        ctx, F = _ctx(base, {"ai": True}, cookie="session=owner")
        attempted, proven = ai.logic_check(ctx, [(base + "/x", None)], [])
        self.assertEqual(proven, 1)
        self.assertEqual(attempted, 2)
        self.assertEqual(len(F.items), 1)
        self.assertIn("Access Control", F.items[0]["title"])
        self.assertEqual(F.items[0]["url"], base + "/open-private")

    def test_id_tamper_needs_second_session(self):
        _srv, base = _serve(_logic_handler())
        ai._post = lambda p, n: json.dumps([
            {"type": "id_tamper", "target": base + "/item?id=5",
             "method": "GET", "note": ""},
        ])
        # No second session: idea cannot be proven, must be discarded.
        ctx, F = _ctx(base, {"ai": True}, cookie="session=owner")
        attempted, proven = ai.logic_check(ctx, [], [])
        self.assertEqual((attempted, proven), (0, 0))
        self.assertEqual(F.items, [])
        # With a second session, the tampered id proves the flaw.
        ctx, F = _ctx(base, {"ai": True}, cookie="session=owner")
        ctx.client_b = Client(cookie="session=other")
        attempted, proven = ai.logic_check(ctx, [], [])
        self.assertEqual(proven, 1)
        self.assertEqual(F.items[0]["param"], "id")
        self.assertIn("Direct Object", F.items[0]["title"])

    def test_disabled_returns_zero(self):
        ctx, F = _ctx("http://x/", {})
        self.assertEqual(ai.logic_check(ctx, [], []), (0, 0))


# ------------------------------------------------------- check integration

def _echo_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            body = "<html><body>echo: %s</body></html>" % q.get("q", [""])[0]
            _send(self, 200, body)

        def log_message(self, *a):
            pass

    return H


def _sqli_ai_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.urlparse(self.path).query
            if "AIOR" in q:
                _send(self, 200, "You have an error in your SQL syntax "
                                 "near 'AIOR'")
            else:
                _send(self, 200, "<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    return H


class TestCheckIntegration(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_xss_calls_model_only_when_enabled(self):
        _srv, base = _serve(_echo_handler())
        stub = _StubPost()
        ai._post = stub
        ctx, F = _ctx(base, {"ai": True})
        checks.xss_url(ctx, base + "/search?q=test")
        self.assertGreaterEqual(len(stub.calls), 1)
        self.assertTrue(any("Cross-Site Scripting" in f["title"]
                            for f in F.items))
        stub.calls.clear()
        ctx2, F2 = _ctx(base, {})
        checks.xss_url(ctx2, base + "/search?q=test")
        self.assertEqual(stub.calls, [])
        self.assertTrue(any("Cross-Site Scripting" in f["title"]
                            for f in F2.items))

    def test_sqli_ai_probe_only_path(self):
        _srv, base = _serve(_sqli_ai_handler())
        stub = _StubPost()
        ai._post = stub
        ctx, F = _ctx(base, {"ai": True})
        checks.sqli_url(ctx, base + "/item?id=1")
        self.assertTrue(any("SQL Injection" in f["title"]
                            and "AIOR" in f["payload"] for f in F.items))
        # Without AI, the fixed probes find nothing on this stub.
        ctx2, F2 = _ctx(base, {})
        checks.sqli_url(ctx2, base + "/item?id=1")
        self.assertEqual(F2.items, [])


# ------------------------------------------------------- PDF + engine

class TestReportAndEngine(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post

    def tearDown(self):
        ai._post = self._orig

    def test_pdf_includes_narrative_only_when_present(self):
        result = {"target": "http://x/", "findings": [], "counts": {},
                  "ai_narrative": "AI says fix the big ones first."}
        self.assertIn(b"AI says fix the big ones first.",
                      report3.to_pdf(result))
        result["ai_narrative"] = ""
        self.assertNotIn(b"AI narrative", report3.to_pdf(result))

    def test_engine_ai_plumbing(self):
        class H2(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    _send(self, 200, '<html><body><a href="/search?q=test">'
                                     "go</a></body></html>")
                else:
                    q = urllib.parse.parse_qs(
                        urllib.parse.urlparse(self.path).query)
                    _send(self, 200, "<html><body>echo: %s</body></html>"
                          % q.get("q", [""])[0])

            def log_message(self, *a):
                pass

        _srv2, base2 = _serve(H2)
        stub = _StubPost()
        ai._post = stub
        res = run_scan(base2, {"checks": ["xss"], "ai": True,
                               "max_pages": 5, "threads": 2})
        self.assertTrue(res["ai"]["enabled"])
        self.assertGreater(res["ai"]["llm_calls"], 0)
        self.assertTrue(res["ai_narrative"])
        self.assertTrue(any("Cross-Site Scripting" in f["title"]
                            for f in res["findings"]))
        stub.calls.clear()
        res2 = run_scan(base2, {"checks": ["xss"], "max_pages": 5,
                                "threads": 2})
        self.assertFalse(res2["ai"]["enabled"])
        self.assertEqual(res2["ai_narrative"], "")
        self.assertEqual(stub.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
