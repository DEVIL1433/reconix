# Reconix Android v1.16 — engine 4.3

Reconix Android app v1.16 carries engine 4.3.

## What is new in engine 4.3

- **Mass assignment / BOPLA (CWE-915).** The API fuzzer now tries
  undeclared fields such as `role`, `is_admin` and `price` with test
  values, and only reports a finding when a read-back confirms the
  value was really saved. No proof, no finding.
- **Cloud-metadata SSRF: IBM and OpenStack.** The server-side request
  forgery probes now cover IBM Cloud and OpenStack metadata addresses
  alongside the existing AWS probe. Google and Azure are not probed:
  they need headers no SSRF probe can send.
- **Phone shell, render fixes.** The phone Home/Scan/Findings/Tools
  shell now carries the fixes found by rendering it on a real phone:
  the header row is truly left/right, Scan and Tools button labels are
  readable, and the Findings clutter above the cards is hidden on
  phone only. Desktop UI is unchanged.

## Note on skipped versions

App version v1.15 (engine 4.2 + phone shell) was built but never
published: no source push and no release was made for it, so there
are no release notes for it. v1.16 supersedes it.

## Install

Install the APK from the release asset over USB. Do not install APKs
received as chat attachments: large chat downloads can arrive
truncated and fail to parse. This build is signed with the same
signer as v1.5–v1.15, so it updates in place.
