"""Automated tests for the 3.21 loopback API token auth (Android v1.5
fix, shared by desktop + Android since both serve the same app.py):

  * a token is minted on first run and kept in the app's private data
    directory (the settings table — never in the repo, never in git);
  * the token reaches the browser only by injection into the served
    HTML page — no API endpoint hands it out;
  * state-changing calls without (or with a wrong) token get 403,
    with the right token they get 200.

The tests run the real Handler against a throwaway database file by
pointing app.DB at a temp path; the real scans.db is never touched.
Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
import app as app_mod  # noqa: E402


def _req(base, path, method="GET", body=None, token=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=(json.dumps(body).encode()
                                       if body is not None else None))
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-Api-Key", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


class TestLoopbackAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db = app_mod.DB
        fd, cls._tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        app_mod.DB = cls._tmp
        # First run: mint the token, exactly like main() does.
        cls.token = app_mod.ensure_api_token()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app_mod.Handler)
        threading.Thread(target=cls.srv.serve_forever,
                         daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        app_mod.DB = cls._orig_db
        os.unlink(cls._tmp)

    def test_token_minted_and_stable(self):
        self.assertTrue(len(self.token) >= 32)
        self.assertEqual(app_mod.ensure_api_token(), self.token)
        self.assertEqual(app_mod.get_setting("api_token"), self.token)

    def test_post_without_token_403(self):
        code, _ = _req(self.base, "/api/projects", "POST",
                       {"name": "x", "client": "y"})
        self.assertEqual(code, 403)

    def test_post_wrong_token_403(self):
        code, _ = _req(self.base, "/api/projects", "POST",
                       {"name": "x", "client": "y"}, token="wrong-token")
        self.assertEqual(code, 403)

    def test_post_with_token_200(self):
        code, body = _req(self.base, "/api/projects", "POST",
                          {"name": "auth-test", "client": "t"},
                          token=self.token)
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(body).get("ok"))

    def test_delete_without_token_403(self):
        code, _ = _req(self.base, "/api/scans", "DELETE",
                       token=None)
        self.assertEqual(code, 403)

    def test_get_without_token_401(self):
        code, _ = _req(self.base, "/api/scans")
        self.assertEqual(code, 401)

    def test_get_with_token_200(self):
        code, _ = _req(self.base, "/api/scans", token=self.token)
        self.assertEqual(code, 200)

    def test_token_injected_into_html_only(self):
        code, body = _req(self.base, "/")
        self.assertEqual(code, 200)
        self.assertIn("localStorage.setItem('wscan_token'", body)
        self.assertIn(self.token, body)
        # No endpoint hands the token out: settings has no GET route.
        code, _ = _req(self.base, "/api/settings", token=self.token)
        self.assertEqual(code, 404)

    def test_blank_token_setting_ignored(self):
        code, _ = _req(self.base, "/api/settings", "POST",
                       {"api_token": "   "}, token=self.token)
        self.assertEqual(code, 200)
        self.assertEqual(app_mod.get_setting("api_token"), self.token)
        # Still locked: a no-token POST must stay 403.
        code, _ = _req(self.base, "/api/projects", "POST",
                       {"name": "x", "client": "y"})
        self.assertEqual(code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
