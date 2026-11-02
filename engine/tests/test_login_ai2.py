"""Tests for the two VM-only features: login recorder
(wscan/loginrec.py) and AI phase 2 (wscan/ai.py sections 5–6).

Self-contained: a fake browser driver, loopback stub servers, and a
stubbed ai._post. No live model, no live browser, no external network.

Run:  python3 -m unittest discover -s tests -v
"""
import copy
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
from wscan import ai, loginrec  # noqa: E402
from wscan.client import Client  # noqa: E402
from wscan.retest import retest_finding  # noqa: E402

PASSWORD = "hunter2-secret-value"


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _send(h, code, body, ctype="text/html", extra=None):
    data = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    for k, v in (extra or {}).items():
        h.send_header(k, v)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


# ------------------------------------------------------- fake driver

class FakeDriver(loginrec.Driver):
    """Simulates a browser login: clicking #login sets a session
    cookie. Also plants traps a correct recorder must NOT keep: a
    cookie echoing the password, and a password-named localStorage
    key."""

    def __init__(self, base):
        self.base = base
        self.current = base + "/login"
        self.filled = {}
        self.visited = []
        self._cookies = [{"name": "pre", "value": "1", "domain": "",
                          "path": "/", "expires": -1}]

    def goto(self, url):
        self.current = url
        self.visited.append(url)

    def fill(self, selector, value):
        self.filled[selector] = value

    def click(self, selector):
        if selector in ("#login", "button[type=submit]"):
            self.current = self.base + "/account"
            self._cookies = [
                {"name": "session", "value": "valid-session-123",
                 "domain": "", "path": "/", "expires": -1},
                {"name": "trap", "value": PASSWORD, "domain": "",
                 "path": "/", "expires": -1},
            ]

    def wait(self, ms):
        pass

    def cookies(self):
        return list(self._cookies)

    def local_storage(self):
        return {"authToken": "tok-abc-1", "password": PASSWORD,
                "user": "devil"}

    def url(self):
        return self.current


LOGIN_STEPS = [
    {"action": "goto", "url": "PLACEHOLDER/login"},
    {"action": "fill", "selector": "username", "value": "devil"},
    {"action": "fill", "selector": "password", "value": PASSWORD,
     "type": "password"},
    {"action": "click", "selector": "#login"},
    {"action": "wait", "ms": 100},
]


def _steps_for(base):
    steps = copy.deepcopy(LOGIN_STEPS)
    steps[0]["url"] = base + "/login"
    return steps


# ------------------------------------------------------- stub apps

def _protected_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            if self.path == "/account":
                if "session=valid-session-123" in cookie:
                    _send(self, 200, "<html><body>welcome, account "
                                     "page</body></html>")
                else:
                    _send(self, 200, "<html><body><form>log in "
                                     "<input type=password name=pw>"
                                     "</form></body></html>")
            elif self.path == "/search":
                q = urllib.parse.urlparse(self.path).query
                if "PAYLOAD" in q:
                    _send(self, 403, "blocked")
                else:
                    _send(self, 200, "ok")
            else:
                _send(self, 404, "not found")

        def log_message(self, *a):
            pass

    return H


# ------------------------------------------------------- login recorder

class TestLoginRecorder(unittest.TestCase):
    def test_record_session_out(self):
        _srv, base = _serve(_protected_handler())
        session = loginrec.record_session(_steps_for(base),
                                          FakeDriver(base))
        self.assertEqual(session["origin"], base)
        names = {c["name"] for c in session["cookies"]}
        self.assertIn("session", names)
        self.assertEqual(session["tokens"].get("authToken"), "tok-abc-1")
        self.assertEqual(session["version"], 1)

    def test_password_stripped_everywhere(self):
        _srv, base = _serve(_protected_handler())
        session = loginrec.record_session(_steps_for(base),
                                          FakeDriver(base))
        blob = json.dumps(session)
        self.assertNotIn(PASSWORD, blob)
        # Password step kept in shape, value gone.
        pw_step = [s for s in session["steps_recorded"]
                   if s.get("selector") == "password"][0]
        self.assertEqual(pw_step["value"], "")
        self.assertTrue(pw_step.get("redacted"))
        # Traps dropped: password-echo cookie, password storage key.
        self.assertNotIn("trap", {c["name"] for c in session["cookies"]})
        self.assertNotIn("password", session["tokens"])

    def test_save_load_roundtrip_no_password_on_disk(self):
        _srv, base = _serve(_protected_handler())
        session = loginrec.record_session(_steps_for(base),
                                          FakeDriver(base))
        with tempfile.TemporaryDirectory() as d:
            path = loginrec.save_session(session, name="main",
                                         base_dir=d)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn(PASSWORD, fh.read())
            loaded = loginrec.load_session("main", base_dir=d)
            self.assertEqual(loaded["cookies"], session["cookies"])
            self.assertEqual(loaded["tokens"], session["tokens"])
            self.assertEqual(loginrec.list_sessions(d), ["main"])
            loginrec.delete_session("main", base_dir=d)
            self.assertEqual(loginrec.list_sessions(d), [])

    def test_session_name_path_traversal_rejected(self):
        with self.assertRaises(loginrec.RecorderError):
            loginrec.session_path("../evil")
        with self.assertRaises(loginrec.RecorderError):
            loginrec.session_path("a/b")

    def test_unknown_step_action_rejected(self):
        _srv, base = _serve(_protected_handler())
        with self.assertRaises(loginrec.RecorderError):
            loginrec.record_session([{"action": "dance"}],
                                    FakeDriver(base))

    def test_replay_attaches_and_authenticates(self):
        srv, base = _serve(_protected_handler())
        session = loginrec.record_session(_steps_for(base),
                                          FakeDriver(base))
        client = loginrec.client_from_session(session)
        self.assertEqual(client.fetch(base + "/account").status, 200)
        self.assertIn("welcome",
                      client.fetch(base + "/account").body)
        plain = Client()
        self.assertIn("log in", plain.fetch(base + "/account").body)

    def test_capture_from_driver_is_interactive_path(self):
        _srv, base = _serve(_protected_handler())
        driver = FakeDriver(base)
        driver.click("#login")  # user logged in by hand, then capture
        session = loginrec.capture_from_driver(driver)
        self.assertEqual(session["origin"], base)
        self.assertIn("session",
                      {c["name"] for c in session["cookies"]})

    def test_token_headers_opt_in_only(self):
        session = {"cookies": [], "tokens": {"access_token": "tok-9"}}
        self.assertEqual(loginrec.token_headers(session),
                         {"Authorization": "Bearer tok-9"})
        client = Client()
        loginrec.attach_to_client(client, session)
        # attach applies cookies only, never a token header by itself
        self.assertNotIn("Authorization", client.headers)

    def test_roles_primary_second_and_anon_refused(self):
        session = {"cookies": [{"name": "session", "value": "v",
                                "expires": -1}], "role": "primary"}
        self.assertEqual(loginrec.opts_for_session(session),
                         {"cookie": "session=v"})
        self.assertEqual(loginrec.opts_for_session(session, "second"),
                         {"cookie_b": "session=v"})
        with self.assertRaises(loginrec.RecorderError):
            loginrec.opts_for_session(session, "anon")
        out = loginrec.apply_to_opts({"profile": "full"}, session)
        self.assertEqual(out["cookie"], "session=v")
        self.assertEqual(out["profile"], "full")


class TestSessionExpiry(unittest.TestCase):
    def test_alive_session(self):
        _srv, base = _serve(_protected_handler())
        session = loginrec.record_session(
            _steps_for(base), FakeDriver(base))
        result = loginrec.check_session(session, base + "/account")
        self.assertTrue(result["alive"])
        self.assertFalse(result["needs_rerecord"])
        self.assertEqual(result["signal"], "")

    def test_dead_session_login_form_signal(self):
        _srv, base = _serve(_protected_handler())
        stale = {"version": 1, "origin": base, "cookies":
                 [{"name": "session", "value": "stale", "expires": -1}],
                 "tokens": {}}
        result = loginrec.check_session(stale, base + "/account")
        self.assertFalse(result["alive"])
        self.assertTrue(result["needs_rerecord"])
        self.assertEqual(result["signal"], "session expired, re-record")
        with self.assertRaises(loginrec.SessionExpired) as cm:
            loginrec.assert_alive(stale, base + "/account")
        self.assertIn("session expired, re-record", str(cm.exception))

    def test_expired_cookies_offline(self):
        import time as _t
        session = {"cookies": [{"name": "session", "value": "v",
                                "expires": _t.time() - 60}],
                   "tokens": {}}
        self.assertTrue(loginrec.is_expired_offline(session))
        result = loginrec.check_session(session, probe=False)
        self.assertTrue(result["needs_rerecord"])
        self.assertEqual(result["signal"], "session expired, re-record")

    def test_unreachable_probe_is_not_expiry(self):
        session = {"cookies": [{"name": "session", "value": "v",
                                "expires": -1}], "tokens": {},
                   "origin": "http://127.0.0.1:1"}
        result = loginrec.check_session(session, "http://127.0.0.1:1/")
        self.assertFalse(result["needs_rerecord"])
        self.assertEqual(result["signal"], "")


# ------------------------------------------------------- AI phase 2

class TestAIPhase2(unittest.TestCase):
    def setUp(self):
        self._orig = ai._post
        self.calls = []

    def tearDown(self):
        ai._post = self._orig

    def _stub(self, prompt, num_predict):
        self.calls.append(prompt)
        if prompt.startswith("Summarize this fix"):
            return "The fix switches to prepared statements with bound " \
                   "parameters for the login query."
        if "fix code snippet" in prompt:
            return json.dumps({
                "snippet": "cursor.execute(\"SELECT * FROM users WHERE "
                           "id = ?\", (user_id,))",
                "explanation": "Bind the parameter instead of "
                               "concatenating it into SQL."})
        return ""

    def _sqli_finding(self, base):
        return {"title": "SQL Injection", "url": base + "/item?id=1",
                "param": "id", "cwe": "CWE-89",
                "proof": "database error returned",
                "request": "GET /item?id=1 HTTP/1.1\r\nHost: x\r\n\r\n"}

    def test_fix_retest_verdict_from_engine_not_ai(self):
        ai._post = lambda p, n: "This fix completely resolves the issue."
        finding = self._sqli_finding("http://x")
        still = lambda c, f: {"verdict": "Still vulnerable",
                              "detail": "proof still reproduces"}
        out = ai.retest_with_fix(finding, "switched to prepared "
                                 "statements", ai.AIBudget(),
                                 client=object(), retest_fn=still)
        self.assertEqual(out["verdict"], "still vulnerable")
        self.assertEqual(out["engine_verdict"], "Still vulnerable")
        # And the reverse: a doubting model cannot overrule a fix.
        ai._post = lambda p, n: "This fix looks incomplete and risky."
        fixed = lambda c, f: {"verdict": "Fixed",
                              "detail": "endpoint now rejects it"}
        out = ai.retest_with_fix(finding, "patched", ai.AIBudget(),
                                 client=object(), retest_fn=fixed)
        self.assertEqual(out["verdict"], "fixed")

    def test_fix_retest_real_engine_proof(self):
        _srv, base = _serve(_protected_handler())
        ai._post = self._stub
        finding = {"title": "Cross-Site Scripting",
                   "url": base + "/search?q=PAYLOAD", "param": "q",
                   "proof": "payload reflected unescaped: PAYLOAD",
                   "request": "GET /search?q=PAYLOAD HTTP/1.1\r\n"
                              "Host: x\r\n\r\n"}
        out = ai.retest_with_fix(finding, "output encoding added",
                                 ai.AIBudget(), client=Client(),
                                 retest_fn=retest_finding)
        self.assertEqual(out["verdict"], "fixed")
        self.assertTrue(out["ai_available"])
        self.assertIn("prepared statements", out["fix_summary"])

    def test_fix_retest_summary_maps_to_finding(self):
        ai._post = self._stub
        out = ai.summarize_fix(self._sqli_finding("http://x"),
                               "use prepared statements", ai.AIBudget())
        self.assertIn("prepared statements", out["summary"])
        self.assertEqual(out["retest_target"]["url"],
                         "http://x/item?id=1")
        self.assertEqual(out["retest_target"]["param"], "id")

    def test_fix_snippet_advisory_and_finding_untouched(self):
        ai._post = self._stub
        finding = self._sqli_finding("http://x")
        before = copy.deepcopy(finding)
        out = ai.fix_snippet(finding, ai.AIBudget())
        self.assertTrue(out["advisory"])
        self.assertIn("cursor.execute", out["snippet"])
        self.assertEqual(finding, before)  # snippet never mutates it
        rendered = ai.format_suggested_fix(out)
        self.assertIn("advisory only", rendered)
        self.assertIn("cursor.execute", rendered)
        self.assertEqual(ai.format_suggested_fix(None), "")

    def test_fix_snippet_context_from_evidence(self):
        ai._post = self._stub
        xss = {"title": "Cross-Site Scripting",
               "url": "http://x/search?q=1", "param": "q",
               "cwe": "CWE-79", "proof": "payload reflected"}
        ai.fix_snippet(xss, ai.AIBudget())
        self.assertIn("output encoding", self.calls[-1])
        self.assertIn("parameterized", ai._detect_fix_context(
            self._sqli_finding("http://x"))["guidance"])

    def test_model_absent_silent_degradation(self):
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        budget = ai.AIBudget()
        self.assertIsNone(ai.fix_snippet(self._sqli_finding("http://x"),
                                         budget))
        self.assertIsNone(ai.summarize_fix(self._sqli_finding("http://x"),
                                           "patched", budget))
        self.assertTrue(budget.dead)
        # Re-test still judges the proof, with no AI claim attached.
        budget2 = ai.AIBudget()
        ai._post = lambda p, n: (_ for _ in ()).throw(RuntimeError("down"))
        out = ai.retest_with_fix(
            self._sqli_finding("http://x"), "patched", budget2,
            client=object(),
            retest_fn=lambda c, f: {"verdict": "Fixed", "detail": "gone"})
        self.assertEqual(out["verdict"], "fixed")
        self.assertEqual(out["fix_summary"], "")
        self.assertFalse(out["ai_available"])

    def test_no_budget_no_model_call(self):
        ai._post = self._stub
        self.assertIsNone(ai.fix_snippet(self._sqli_finding("http://x"),
                                         None))
        self.assertIsNone(ai.summarize_fix(self._sqli_finding("http://x"),
                                           "patched", None))
        self.assertEqual(self.calls, [])
        # Engine re-test still runs without a budget.
        out = ai.retest_with_fix(
            self._sqli_finding("http://x"), "patched", None,
            client=object(),
            retest_fn=lambda c, f: {"verdict": "Still vulnerable",
                                    "detail": "still there"})
        self.assertEqual(out["verdict"], "still vulnerable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
