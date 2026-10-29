"""Automated tests for the Reconix one-click Full VAPT run: the Run
Full VAPT button, the full-profile preset, and the automatic PDF
download when the run finishes.

The page JavaScript syntax check runs only when node is available.
Run:  python3 -m unittest discover -s tests -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "app.py")


def _app_text():
    with open(APP, encoding="utf-8") as fh:
        return fh.read()


class TestVaptRun(unittest.TestCase):
    def test_vapt_button_present(self):
        t = _app_text()
        self.assertIn('id="vaptBtn"', t)
        self.assertIn("Run Full VAPT", t)
        self.assertIn("startVapt", t)

    def test_vapt_sets_full_profile(self):
        t = _app_text()
        self.assertIn("document.getElementById('profile').value='full'", t)

    def test_vapt_auto_downloads_pdf_on_done(self):
        t = _app_text()
        self.assertIn("window._vaptAutoPdf=true", t)
        self.assertIn("if(window._vaptAutoPdf&&j.status==='done')", t)
        self.assertIn("a.href='/api/scans/'+cur+'/pdf'", t)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_page_js_syntax(self):
        t = _app_text()
        blocks = re.findall(r"<script>(.*?)</script>", t, re.S)
        checked = 0
        for b in blocks:
            if len(b.strip()) < 50 or "%s" in b:
                continue  # template filled by Python at runtime
            with tempfile.NamedTemporaryFile("w", suffix=".js",
                                             delete=False) as fh:
                fh.write(b)
                path = fh.name
            try:
                r = subprocess.run(["node", "--check", path],
                                   capture_output=True, text=True)
            finally:
                os.unlink(path)
            self.assertEqual(r.returncode, 0, r.stderr[:500])
            checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
