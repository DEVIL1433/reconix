"""Regression tests for the 3.19 history/asset-inventory cleanup.

Bug (reported 2026-10-20): deleting scan history left the Attack
Surface page fully populated, because assets live in their own table
(a persistent inventory for cross-scan diffing) and the delete paths
only ever removed rows from `scans`. `_asset_cleanup` now prunes the
inventory that no stored scan covers anymore.

Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))
import app as reconix_app  # noqa: E402


class AssetCleanupTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._old_db = reconix_app.DB
        reconix_app.DB = self.path
        self.conn = reconix_app.db()

    def tearDown(self):
        self.conn.close()
        reconix_app.DB = self._old_db
        os.unlink(self.path)

    def _scan(self, sid, target):
        self.conn.execute(
            "INSERT INTO scans (id, target, status) VALUES (?,?,?)",
            (sid, target, "done"))

    def _asset(self, domain, host):
        self.conn.execute(
            "INSERT INTO assets VALUES (?,?,?,?,?)",
            (domain, host, "{}", "2026-10-16 19:03:12",
             "2026-10-16 19:03:12"))

    def _domains(self):
        return sorted(r[0] for r in
                      self.conn.execute("SELECT domain FROM assets"))

    def test_clear_all_wipes_whole_inventory(self):
        # Devil's exact case: scans already gone, stale assets remain.
        self._asset("isoeh.com", "isoeh.com")
        self._asset("isoeh.com", "www.isoeh.com")
        n = reconix_app._asset_cleanup(self.conn, [])
        self.assertEqual(n, 2)
        self.assertEqual(self._domains(), [])

    def test_delete_one_domain_keeps_the_other(self):
        self._scan("s1", "https://www.isoeh.com/")
        self._scan("s2", "https://example.org/")
        self._asset("isoeh.com", "www.isoeh.com")
        self._asset("example.org", "example.org")
        self.conn.execute("DELETE FROM scans WHERE id='s1'")
        n = reconix_app._asset_cleanup(self.conn, ["https://www.isoeh.com/"])
        self.assertEqual(n, 1)
        self.assertEqual(self._domains(), ["example.org"])

    def test_assets_kept_while_sibling_scan_remains(self):
        self._scan("s1", "isoeh.com")
        self._scan("s2", "https://www.isoeh.com/")
        self._asset("isoeh.com", "mail.isoeh.com")
        self.conn.execute("DELETE FROM scans WHERE id='s1'")
        n = reconix_app._asset_cleanup(self.conn, ["isoeh.com"])
        self.assertEqual(n, 0)
        self.assertEqual(self._domains(), ["isoeh.com"])


if __name__ == "__main__":
    unittest.main()
