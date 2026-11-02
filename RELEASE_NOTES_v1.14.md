# Reconix Android v1.14 — engine 4.2

Reconix Android app v1.14 carries engine 4.2.

## What is new in engine 4.2

- **Phone-shell redesign (from a phone mockup).** Home now has a
  risk-gauge ring with a findings-by-severity breakdown, Scan has mode
  pills bound to the real profile select, Findings has severity filter
  pills with real counts plus finding cards carrying a path tag and a
  one-line plain description, and the More menu is grouped — Assess
  (VAPT, Attack surface, 403 assessment, HTTP repeater), Automate
  (Schedules, Custom rules), App (Settings). The VAPT tab stays
  separate, and the mint accent is phone-only: the desktop UI is
  unchanged.
- **Since the last published engine (3.31), this app also carries the
  unpublished range:** 3.32 (four local-only AI features, off by
  default, AI suggests and the engine proves), 3.33 (SCAN and VAPT SCAN
  cards), 4.0 (fourteen features in full: subdomain takeover, JS
  secrets, GraphQL, WebSocket, CMS packs, Nuclei templates, exposed
  cloud storage, CVE matching, scan diff, Word/Excel/JSON/Jira/GitHub
  reports, false-positive marking with reason, custom check builder,
  login recorder, AI phase 2, plus a major professional redesign), and
  4.1 (Scan and VAPT as entirely separate tabs).

## Note on skipped versions

App versions v1.12 (engine 3.33) and v1.13 (engine 4.1) were built but
never published: no source push and no release was made for either, so
there are no release notes for them. v1.14 supersedes both.

## Install

Install the APK from the release asset over USB. Do not install APKs
received as chat attachments: large chat downloads can arrive
truncated and fail to parse. This build is signed with the same
signer as v1.5–v1.13, so it updates in place.
