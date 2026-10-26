## Reconix v1.5 — engine 3.21

The full Reconix scanner (engine **3.21**) as a standalone Android app.
Install it, open it, scan — everything runs on the phone.

### Highlights

- **Loopback API authentication (security fix)** — the app's local API
  used to accept requests from any local process because no token ever
  existed. Now a per-install random token is minted on first run, is
  injected into the app's own pages only (no endpoint serves it), and
  is required on every state-changing request. Requests without it are
  rejected. The desktop app gets the same protection.
- **Two new check classes** — JavaScript prototype pollution (proven two
  ways: server JSON-merge and real browser DOM check, never pattern
  alone) and insecure deserialization probes (benign payloads only,
  with a control-response guard against false positives).
- **Payload refresh fixed** — the update marker now forces a fresh copy
  of the engine on update, so an upgrade can never keep old code.

### Requirements

- Android 7.0 or newer (arm64 or 32-bit ARM)
- ~35 MB free space

### Verify your download

- Size: **30,300,194 bytes** (~30.3 MB)
- SHA-256:
  `9a256b9505755592768ec8a5467ce36e2f2c1140fa83bb66c0a2efe2bcd8b158`

If the size or checksum doesn't match, the download was corrupted — fetch
it again. Never install an APK that arrives truncated; a corrupted
download fails to parse on install.
