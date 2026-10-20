## Reconix v1.4 — first public release

The full Reconix scanner (engine **3.20**) as a standalone Android app.
Install it, open it, scan — everything runs on the phone.

### Highlights

- **New mobile interface** — bottom tab bar (Home / Scan / Findings /
  History / More), a scanner screen with a live progress ring and phase
  feed, and findings as readable cards: What / Where / Why / Fix
- **Working report exports** — HTML, JSON, CSV, PDF, DOCX and HAR now save
  to the phone's Downloads folder
- **Self-recovering engine** — if the scanner process ever stops, the app
  restarts it and takes you back in automatically
- **Release hardening** — non-debuggable build, app backup disabled
- **Scan reliability** — the engine holds a wakelock during scans, so long
  assessments keep running with the screen off

### Requirements

- Android 7.0 or newer (arm64 or 32-bit ARM)
- ~35 MB free space

### Verify your download

- Size: **30,295,601 bytes** (~30.3 MB)
- SHA-256:
  `72005ed95118e9dcc07810d7f6570505aa13c4e258bf7612711cd73f4eb38094`

If the size or checksum doesn't match, the download was corrupted — fetch
it again before installing.

### Notes

- Only scan targets you own or are explicitly authorized to test.
- The browser-based screenshot engine and nuclei integration from the
  desktop build are not included in the Android build.
