# Reconix Android v1.11 — engine 3.31

Reconix Android app v1.11 carries engine 3.31.

## What is new in engine 3.31

- **Third-party Subresource Integrity scan (CWE-829, passive only).**
  Checks every crawled page for cross-origin scripts and stylesheets
  loaded without a usable `integrity` hash (missing, malformed, or
  present without `crossorigin`, which makes the browser skip the
  check). OWASP Top 10:2025 A03/A08 supply-chain coverage.
- **XPath injection check.** Error-based detection plus a boolean
  differential test, both proof-guarded: no proof means no finding.

## Also in this app version

Engine 3.31 includes the 3.29/3.30 file-upload bypass variants
(`.php5`, `.phtml`, uppercase `.PHP`, content-type bypass, and
magic-byte bypass), each its own Critical finding on the same
harmless proof. The app therefore now carries everything from
engine 3.28 through 3.31.

## Install

Install the APK from the release asset over USB. Do not install APKs
received as chat attachments: large chat downloads can arrive
truncated and fail to parse. This build is signed with the same
signer as v1.5–v1.10, so it updates in place.
