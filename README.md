<p align="center">
  <img src="img/reconix-lockup.png" alt="RECONIX — Discover · Scan · Secure" width="520">
</p>

<h1 align="center">Reconix</h1>

<p align="center">
  Proof-based web vulnerability scanner &amp; attack-surface mapper —
  on desktop, and as a <b>fully standalone Android app</b>.
</p>

<p align="center">
  <img alt="Engine" src="https://img.shields.io/badge/engine-3.21-blue">
  <img alt="Android" src="https://img.shields.io/badge/Android-v1.5-green">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-yellow">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-zero-brightgreen">
</p>

---

## A recon tool & web vulnerability scanner in one

Looking for a **recon tool** that also scans? Or a **vulnerability scanner
APK** that runs entirely on an Android phone — no server, no root, no
account? That is exactly what Reconix is: a free reconnaissance and
web vulnerability scanning tool for **bug bounty hunters, penetration
testers and defenders**, on Android and on the desktop.

## What is Reconix?

Reconix performs authorized security assessments of web applications and
external attack surface. Every finding ships with **proof**, and is explained
in plain language — *What is it? Where is it? Why does it matter? What can be
done with it? How do I fix it?*

- **Vulnerability scanning** — 50+ check classes: SQL injection, XSS, SSRF,
  IDOR & access-control, authentication attacks, request smuggling,
  GraphQL / JWT / WebSocket issues, security headers, CORS, TLS, and more
- **False-positive hunter** — candidate findings are replayed and verified;
  unproven results are flagged, never silently sold as fact
- **External reconnaissance** — subdomains, DNS & email security
  (SPF / DMARC / DKIM), certificates, cloud exposure, tech fingerprinting
- **Attack-surface inventory** — assets tracked across scans, with diffs
- **Verify-Fix retests** — one click replays every finding against the live
  target and reports *Fixed / Still vulnerable*
- **Scan comparison** — diff any two scans of a target
- **Reports** — HTML, JSON, CSV, PDF, DOCX and HAR exports
- **Extras** — HTTP repeater, 403-bypass tester, scheduled scans, role-matrix
  (admin / user / anonymous) access testing, WAF-adaptive pacing

The engine is benchmarked on its built-in test range at **100% detection
recall with 0 false positives**.

## Two ways to run it

### 🖥️ Desktop / server (the engine)

Zero-dependency Python 3.11+ — standard library only.

```bash
cd engine
python3 app.py            # UI on http://127.0.0.1:8777
python3 webscan.py https://target.example --help   # CLI mode
```

### 📱 Android (standalone app)

The complete scanner — engine, Python runtime and a mobile-native UI —
inside a single APK. No server, no Termux, no account; scan data never
leaves the phone.

**Download the latest APK from [Releases](../../releases)** and verify it:
v1.5 is **30,300,194 bytes**, SHA-256
`9a256b9505755592768ec8a5467ce36e2f2c1140fa83bb66c0a2efe2bcd8b158`.
A different size means a corrupted download — fetch it again.

<p align="center">
  <img src="img/app-home.png" alt="Reconix Android — home" width="300">
  &nbsp;&nbsp;
  <img src="img/app-scan.png" alt="Reconix Android — scanner" width="300">
</p>

## Repository layout

| Path | Contents |
|---|---|
| `engine/` | The scanner: `app.py` (web UI + API), `wscan/` (check engine), `rules/`, `tests/`, CLI in `webscan.py` |
| `android/` | The Android app (Kotlin-free: Java + Chaquopy) that packages the engine into the standalone APK |
| `img/` | Branding and screenshots |
| `RELEASE_NOTES_v1.5.md` | Notes for the current release |
| `RELEASE_NOTES_v1.4.md` | Notes for the previous release |

## Building the Android app

Requirements: JDK 17, Gradle 8.9, Android SDK 34.

```bash
cd android
./prepare-assets.sh   # copies ../engine into the app assets
gradle assembleRelease
```

Release builds in this repository are unsigned; sign with your own keystore
for distribution. The maintainer's release key is private and is never
committed here.

## Common questions

**Is there a vulnerability scanner APK for Android that works standalone?**
Yes — Reconix. The scanner engine, its Python runtime and the UI are all
inside the APK. Install it from [Releases](../../releases), type a target
you are authorized to test, and scan. Nothing runs on a server; your scan
data never leaves the phone.

**Is Reconix a recon tool or a vulnerability scanner?**
Both. The reconnaissance stage maps the external attack surface
(subdomains, DNS, certificates, cloud exposure, technologies), and the
scanning stage then tests everything found with 50+ proof-based check
classes.

**Is Reconix free?**
The Android APK is free to download and use for authorized testing. The
source code is published for review under a source-available license
(see [LICENSE](LICENSE)).

**How is Reconix different from a simple port scanner?**
Port scanners tell you a door exists. Reconix tests the application behind
the door — injection, access control, authentication, misconfiguration —
and shows you the proof for every finding, in plain language.

## ⚠️ Authorized use only

Reconix is a professional security-assessment tool. **Only scan systems you
own or are explicitly authorized to test** — a signed engagement, a
bug-bounty program's in-scope assets, or your own infrastructure.
Unauthorized scanning may be illegal in your jurisdiction. See
[SECURITY.md](SECURITY.md). The author accepts no responsibility for misuse.

## License

Source-available for review and audit — see [LICENSE](LICENSE). This is not
an open-source license; redistribution and commercial use require the
author's written permission.

---

---

**Keywords:** recon tool · reconnaissance tool · web vulnerability scanner ·
vulnerability scanner APK · Android security scanner · attack surface
management · VAPT tool · bug bounty recon · pentesting tool · OSINT recon ·
external recon · security assessment

<p align="center"><i>RECONIX — Discover · Scan · Secure</i></p>
