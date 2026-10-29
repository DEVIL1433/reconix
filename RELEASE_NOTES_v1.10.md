## Reconix v1.10 — engine 3.28

The full Reconix scanner (engine **3.28**) as a standalone Android app.
Install it, open it, scan — everything runs on the phone.

### New in v1.10

- **Notification permission, proper flow** — the app now follows the full
  flow: check, explain why with a dialog, ask, and if denied permanently
  it guides you to the app Settings page to turn notifications back on.
  Before, a denied answer was silently ignored and the running-engine
  notification stayed invisible.
- **Crash log capped** — the on-device crash log is trimmed to the newest
  48 KB once it passes 64 KB, so the startup read stays fast no matter
  how many crashes accumulate. Before, it grew without limit.

### Since v1.5

- **Six Android fixes (v1.9)** — report downloads work on the phone now
  (the download manager sends the loopback API token as a header, fixing
  the 401s); pages never serve stale after an update (no-store); the
  back button switches tabs instead of exiting the app; a watchdog
  restarts the engine if it dies while the app is open; notification taps
  no longer open a second copy of the app; pinch-zoom is off, so the app
  stops feeling like a browser.
- **Looks-like-a-browser fixes (v1.8)** — doubled target URLs (from a
  pasted-twice target) are collapsed to one, and the WebView now honours
  the mobile viewport, so findings lay out full-width like an app.
- **Mobile progress-ring fix (v1.7)** — the ring label no longer runs off
  the screen on small phones.
- **Engine 3.22–3.28** — permission-matrix fixes and matrix table in the
  PDF report; every injection finding records its exact payload, shown
  in all reports; one-click Full VAPT run with automatic PDF download;
  a query-string append variant in the 403 Tester.

### Requirements

- Android 7.0 or newer (arm64 or 32-bit ARM)
- ~35 MB free space

### Verify your download

- Size: **30,301,790 bytes** (~30.3 MB)
- SHA-256:
  `d97f3d85f75bbf05e86b37d7b5c0c1c90aaafa68093cb09b01e8e2f4d4452d2c`

If the size or checksum doesn't match, the download was corrupted — fetch
it again. Never install an APK that arrives truncated; a corrupted
download fails to parse on install.
