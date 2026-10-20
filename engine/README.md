# Reconix 3.17 — Deep Web Vulnerability Scanner + EASM

3.5 renames the tool to **Reconix** and adds two analyst-experience
features: every finding now carries a plain-language "What is it?"
explanation (1-2 simple lines per vulnerability type, shown in the UI,
HTML and DOCX reports), and scans report real progress — the UI shows a
live progress bar with percentage and current activity, driven by the
engine's crawl/check completion counters.

3.4 is a full-codebase audit release: ~50 bugs found by a three-way
parallel audit + runtime probing and fixed — a dead CRLF check
(double-encoded probe), API fuzzer sending GET for every method and
literal {id} path params, JWT cracking ignoring HS384/HS512, LDAP probes
2-3 unable to fire, default-credential tests poisoning the shared
session (now a throwaway client), a process-global socket timeout set
by subdomain enumeration, OOB listener socket leak + token parsing on
query strings, subdomain sources accepting foreign domains
(evilexample.com), takeover findings on bare 404s, Chromium leaks,
dedupe/scan-view/download races in the UI server, LIVE memory leak,
scheduler overlap, unauthenticated DELETE endpoints, report exports
ignoring analyst statuses, illegal XML control chars in DOCX, PDF
control bytes, unbounded request bodies, benchmark CWD/port fragility,
and a thread-unsafe sqlite connection in the test target. Benchmark
after the audit: recall 100% (20/20), precision 100% (0 FP).

New in 3.3 (Accuracy Pack): per-target calibration (soft-404 fingerprint
+ page-noise profile), volatile-aware response similarity, DBMS
fingerprint-first SQLi with context payload families (string / LIKE /
numeric) and statistical time-based confirmation, SQLi stage priority
(error → UNION → boolean → time) with SQL-concatenated UNION markers
that reflection cannot fake, contrast-based boolean detection, XSS
two-payload reproducibility (Confirmed vs Tentative), WAF-block
detection with evasion variants + coverage warnings, session watchdog
with automatic re-login, smart form filling (type-aware values),
content-validated sensitive-file discovery (SQL keywords, archive
content types), JS/source-map API endpoint extraction fed back into the
crawl, banner-CVE confidence labels with distro-backport caveats,
root-cause grouping (result groups + UI toggle), and a benchmark mode
(`--benchmark`) scoring recall on the vulnerable target and precision
on a false-positive bait server — current score: recall 100% (20/20),
precision 100% (0 FP).

New in 3.2: dedicated External Reconnaissance / EASM module (profile
"recon", also inside Full scans for domain targets) — multi-source
subdomain enumeration (CT logs, CertSpotter, HackerTarget, RapidDNS,
urlscan + DNS brute force + permutations + recursion, wildcard-aware),
full DNS intelligence over DNS-over-HTTPS (A/AAAA/MX/NS/TXT/SOA/CAA,
SPF/DKIM/DMARC analysis, DNSSEC), IP/ASN/geolocation intelligence,
certificate intelligence (expiry, reuse, weak-TLS acceptance),
subdomain-takeover and dangling-DNS detection, cloud-endpoint discovery
from page source with public-listing checks, public email harvesting,
exposure probes (admin/API docs/GraphQL/status pages), and a
risk-prioritised asset inventory with cross-scan change tracking
(inventory.json + the Attack Surface view). UI redesigned with a sidebar:
Dashboard, Scanner, Attack Surface, Findings, Repeater, Schedules &
Rules, History, Settings.

New in 3.1: browser engine (Playwright/Chromium — SPA crawl, DOM-XSS
execution proof, screenshots; optional: `pip install playwright` +
`playwright install chromium`, scanner works without it), Nuclei + OWASP
ZAP bridges with cross-tool dedupe, Verify-Fix retesting (UI button or
`--retest report.json`), HAR import (`--har`) and export, permission
matrix (anonymous vs user vs second user vs admin), client report pack
(company branding, cover page, scope & methodology, remediation tracker,
DOCX export), attack-surface change alerts on scheduled scans (webhook),
and a visual rule builder in the UI.

An Acunetix-class scanner you run on your own machine. Zero dependencies
(Python 3.8+ stdlib only). Findings are **proof-based**: a bug is only
reported when the tool has evidence — a database error, a computed marker
executed server-side, a differential timing proof, or an **out-of-band
callback** to its built-in listener (like AcuMonitor).

## Run it

```bash
python3 app.py                     # web UI -> http://127.0.0.1:8777
python3 webscan.py http://127.0.0.1:8080 --profile full -o report.html --json out.json --csv out.csv --pdf out.pdf
```

**New in 3.12 (VAPT Automation Pack):** the scanner now works like the
pentester who used to babysit it. **Role-matrix upgrades** — the
permission matrix also flags horizontal privilege escalation (a second
user reading the owner’s data — BOLA) and unauthenticated API data
exposure, all with calibrated similarity. **Auto-proof** — confirmed
SQL injections are upgraded from “detected” to “proven” by extracting
real data (database name / first table) character-by-character through
the boolean channel, read-only and capped; command injection is
re-proven with a fresh computed canary, SSRF is pushed at cloud
metadata, uploads and browser-XSS are marked execution-proven.
**Attack chaining** — findings are correlated into end-to-end paths
(XSS + readable session cookie → hijack; credentialed CORS + broken
access control → cross-site data theft; SSRF + the recon map →
internal pivot; forgeable JWT + API flaws → full API access).
**Business-logic attacks** — feed it a HAR of a real workflow and it
tries to skip steps, replay one-time steps (coupons/OTPs) and tamper
prices/quantities, judging success against the recorded responses.
**WAF-adaptive mode** — once a WAF engages, benign traffic routes
around blocks with evasion encodings, everything slows to human pace,
and WAF-blocked checks get a quiet second pass at 1s+ intervals.
**Evidence screenshots** — serious findings get a Chromium screenshot
of the vulnerable page attached. **Scan queue + dedupe guard** — the
same target+profile can never run twice (extra Start clicks return the
existing scan), at most two scans run at once with the rest queued,
crashed scans are marked *interrupted* on startup and can be **resumed**
from History (re-seeded with the last known site map). **Retest-all** —
one click replays every finding of a finished scan against the live
target and reports Fixed / Still vulnerable per finding, with the run
saved in History. Benchmark after the pack: recall 100% (29/29),
precision 100% (0 FP); unit tests: `python3 -m unittest discover -s tests`.

**New in 3.17 (Minimal Dark UI + simple finding view):** the whole
interface moves to a Minimal Dark theme — near-black surfaces, hairline
borders, small-caps labels, and colour used only where it means
something (severity, proof, fix). Findings now open in a simple
four-question layout — **What** is the vulnerability, **Where** is it,
**Why** is it vulnerable, **What attacks can be performed** — followed
by Proof and Fix; the request/response and PoCs move under a collapsed
"Technical details" section. The attack lines are generated per
weakness class (`wscan/report3.py` `ATTACKS`/`attacks_for`, matched by
title keyword then CWE) and are added to findings when they are served,
so old scans get them too. The exported HTML and PDF reports use the
same simple structure (and the HTML report the same dark theme).

**New in 3.16 (smarter scheme handling + Repeater guard):** a bare
domain typed without a scheme is now probed on **https first** and
only falls back to http when https does not answer (any HTTP response,
even 403/404, counts as alive). Previously the target defaulted to
http, and a site that redirects everything to https was scanned as an
empty shell — 1 page crawled, 0 parameters, 10 findings where the same
site over https produced 483. As a second layer, an http target whose
root redirects to https on the same host is **rebased to https** at
scan start (logged in the scan output), so crawl scope follows the
site's real scheme even for explicitly typed http URLs and old
scheduled scans. The Repeater (`/api/repeat`) uses the same scheme
resolution and now returns a clean JSON error for bad or unreachable
URLs instead of crashing the request handler with a traceback.

**New in 3.15 (ExtRecon DNS speed + live progress):** the DNS stages of
external recon no longer look frozen. Resolution now reuses keep-alive
DNS-over-HTTPS connections per thread (a fresh TLS handshake per query
made a 136-word brute stage take ~9 minutes on a home connection;
enumeration of the same target now completes in about a quarter of the
time), an endpoint that fails twice is backed off for 30 s instead of
taxing every lookup, and every resolution stage (brute force,
permutations, recursive, discovered-host resolution) reports live
`done/total` progress in the scan log. The wildcard-DNS probe also
resolves once instead of three times. No detection logic changed.

**New in 3.14 (Bypass Attempt Engine + verdict model v2):** Mode B now
runs as three explicit phases. **Baseline** establishes ground truth —
the resource as the authorized identity receives it, *fingerprinted*
(body SHA-256, title, marker, content-type, size, canonical
redirect), the stripped-credential denial, and a known-public control
resource as a sanity check (a WAF-blocked public control warns that
the edge may be blocking the test client generally). **Probe** fires
the full bypass matrix from a technique catalog with toggleable
groups: (A) path & URL normalization (24 spellings incl. double slash,
trailing dot, parent traversal, case forms, single/double encoding,
%2e/%2f/%c0%ae forms, matrix params, extensions), (B) route-override
headers (X-Original-URL, X-Rewrite-URL, X-Original-Path,
X-Forwarded-Prefix, self-Referer), (C) host & proxy headers and host
spellings (case, explicit port, trailing dot), (D) client-IP headers
in single/list/multi-hop forms across internal ranges — authoritative
only when an IP ACL exists, and never assumed to work, (E) methods &
verbs (full verb set, method-override headers, lowercase/custom/
empty verbs, HEAD judged with correct no-body semantics), (F)
protocol & connection via a raw-socket channel (HTTP/1.0,
absolute-form request lines, no-Host requests; HTTP/2 is out of reach
of the stdlib client and is not faked), (G) auth-context variation
(anonymous vs accounts A/B, plus truncated and stale-mutated session
cookies), (H) cache-deception spellings — plus owner-supplied
equivalents, direct-origin and alternate-port comparisons. **Verify**
re-runs every candidate to 3 total observations with a
nonexistent-path control and demands a fingerprint match. The verdict
model gains **BYPASS_VERIFIED** (technique-based; all gating
conditions must hold: protected baseline, fingerprint match,
attribution to the technique, 3-of-3 reproduction, clean control) and
**BYPASS_CANDIDATE** (content returned but the chain is incomplete),
alongside ACCESS_CONTROL_WEAKNESS_VERIFIED for front-door policy
violations; confidence is now CONFIRMED / LIKELY / SPECULATIVE.
Access to a resource that was never protected is explicitly NOT a
bypass (capped at SUSPECTED). F5 diagnostics can now correlate a
pasted ASM log excerpt against the extracted support ID and name the
triggered rule, flagging confirmed false positives. Every record
carries its group, timing, body hashes and verification stats;
identical requests are deduplicated by hash and rate limits apply
per host. In Mode A the write verbs stay behind an opt-in; in Mode B
they run against the declared harmless resources only. Tests grew to
77 (verdict-gating truth table, catalog/dedupe units, raw-channel
tests, and mock-app cases for host-header, cache-deception, flaky,
weak-session and never-protected resources).

**New in 3.13 (403 Access-Control Assessment Engine):** the 403 Tester
is now an active assessment engine with two modes. **Mode A —
Diagnostics** identifies *who* denied the request (F5 BIG-IP ASM,
Cloudflare/Akamai/Imperva/CloudFront, reverse proxy, application, or
authentication layer), captures the full original response (headers,
body, redirects, request IDs — including the **F5 ASM support ID** for
event-log correlation), and infers the likely rejection reason before
comparing documented variants against that preserved original.
**Mode B — Authorized Validation** starts from a policy *you* define:
test identities (anonymous + two owner test accounts), the access each
identity should have, and a **harmless test resource** identified by a
marker string. The engine builds an expected-vs-observed matrix and
checks enforcement consistency across equivalent spellings, identities
and HTTP methods (write methods are opt-in and only ever touch the
harmless resource), trusted headers and edge-vs-origin. Classifications
are now **ACCESS_CONTROL_WEAKNESS_VERIFIED /
ACCESS_CONTROL_MISCONFIGURATION_SUSPECTED / WAF_BLOCK_DETECTED /
AUTHENTICATION_REQUIRED / BLOCK_CONFIRMED / INCONCLUSIVE**. VERIFIED
requires the full controlled proof — the harmless resource served to a
policy-denied identity, reproducible, catch-all guard passed; a status
change alone is only ever *suspected*, a HEAD success can never verify
(HEAD has no body), and a trusted header is only a weakness when the
content actually comes back. Every test records its hypothesis,
expected outcome, original-vs-test comparison, evidence and confidence;
identical planned tests are deduplicated and a minimum request
interval is enforced. F5 reports include a diagnostics table (support
ID, timestamp, URL) plus policy-tuning guidance for confirmed false
positives. Integration tests run against a local mock application with
known access-control rules (`tests/mock_acl_app.py`: correctly
enforced canary, planted trailing-slash / trusted-header / HEAD flaws,
an F5 block page, an auth vault).

#### Safe authorized validation (Mode B) — read before first use

1. **Authorization first.** Only run Mode B against systems you own or
   are explicitly authorized to test, with the scope (hosts/paths)
   defined in the UI. The authorization tick is required to start.
2. **Use dedicated test accounts.** Create throwaway accounts for
   role A (allowed) and role B (must be denied). Never use real
   customer accounts or credentials; session cookies are never stored
   in run results or reports (they are redacted / not persisted).
3. **Plant a harmless resource.** Create a test page/file that only
   the allowed identity may open, containing a unique marker string
   (e.g. `CANARY-TEST-RESOURCE-2026`). The engine treats *only* that
   marker as proof. Never point validation at real customer data.
4. **Set the policy honestly.** Expected access per identity is the
   ground truth the engine judges against — a wrong policy produces
   wrong verdicts (an expected-allow identity that is denied is
   flagged as a mismatch too).
5. **Stay non-destructive.** Default tests are read-only.
   PUT/PATCH/DELETE checks are opt-in, send empty bodies, and must
   only target the harmless resource.
6. **Interpret verdicts correctly.** BYPASS_VERIFIED = a technique
   defeated the denial and the whole verification chain held
   (protected baseline, fingerprint match, 3-of-3 reproduction,
   clean control). ACCESS_CONTROL_WEAKNESS_VERIFIED = the front door
   itself serves the wrong identity — no technique needed.
   BYPASS_CANDIDATE = content came back but the chain is incomplete;
   confirm manually before reporting. SUSPECTED = an inconsistency
   that needs a human look. If the plain anonymous baseline already
   returns the resource, it was never protected — the engine says so
   and never calls it a bypass. WAF_BLOCK_DETECTED says the *WAF*
   enforced — it says nothing about the application's own ACL, and
   may be a false positive for legitimate users (correlate the F5
   support ID in the ASM event log before tuning — or paste the log
   excerpt into the run and let the engine correlate it for you).

**New in 3.11:** **403 Access Control Tester** — a standalone module
(new "403 Tester" tab in the UI; `wscan/access403.py`) that is NOT part
of any scan profile and can be enabled/disabled in Settings → Modules.
For each URL that answers 403 it builds a baseline profile (original vs
a nonexistent control path, redirect/auth signals, proxy/CDN headers,
custom-error-page detection) and then runs a diagnostic battery: path
spellings, URL-override and trusted-proxy headers, HEAD/POST method
comparison, an optional supplied-session comparison, and an optional
direct-origin (edge vs origin) comparison. Results are classified
**Confirmed unauthorized resource exposure / Potential inconsistency /
Access correctly denied / Inconclusive** — a status change alone never
counts as a bypass: content must come back, differ from the 403 page,
not be the soft-404 or a login wall, reproduce on a second fetch, and
fail the catch-all guard. Every record keeps the original vs test
status/size, body similarity, evidence, confidence and remediation;
cookies, authorization headers and token-like values are redacted from
logs and from the exportable JSON/HTML reports. Runs require an
explicit authorization tick, stay inside the target origin allowlist,
and honour configurable concurrency, request budget, timeout and a
stop button. Tests: `python3 -m unittest discover -s tests`.

**New in 3.10:** **403 Forbidden bypass.** Every page a scan finds
answering 403 gets the standard evasion battery — path mutations
(trailing slash, dot segments, `..;`, case, URL-encoding, backslash),
URL-override headers (X-Original-URL / X-Rewrite-URL), trusted-proxy
IP headers (X-Forwarded-For and friends) and a method change. A
finding is only raised when the protected content actually comes
back and passes the anti-false-positive guards (not the block page,
not a soft-404, not a login wall, and a nonexistent control path
fetched the same way must not serve the same content).

**New in 3.9:** History has a **Clear old results** button (plus a
per-scan delete link) — it wipes stored scans with their findings and
reports; scans still running are kept. Projects, schedules and
false-positive verdicts are not touched. (An access-key lock shipped
briefly in 3.8 and was removed the same day at the owner's call — the
UI is open; the optional API token in Settings remains, off by
default.)

CLI options: `--profile quick|full|api|passive`, `--checks a,b,c`,
`--cookie`, `--cookie-b` + `--idor-anon` (IDOR), `--auth-user/--auth-pass/
--auth-login-url` (authenticated scan), `--auth-test` (default creds),
`--proxy http://127.0.0.1:8080` (Burp), `--delay`, `--openapi URL`,
`--rules-dir rules/`, `--payloads-xss file`, `--fail-on High` (CI exit code).

## What's inside

- **Recon**: DNS, subdomains (CT logs + brute), port scan + banners, tech/CMS
  fingerprint with version->CVE map, TLS analysis, WHOIS, WAF/CDN detection.
- **Crawl**: BFS with forms/params/JS discovery, robots/sitemap-aware link
  extraction, full site-map graph, broken-link report.
- **Passive**: secrets in pages/JS (AWS keys, private keys, DB strings),
  source-map exposure, HTTP methods (OPTIONS/TRACE), HTTPS-redirect posture,
  redirect chains, stack traces, cache-control, excessive JSON data exposure.
- **Active checks**: SQLi (error/boolean/time/UNION), XSS (reflected, stored,
  blind-OOB, DOM source->sink), OS command injection (computed marker),
  SSTI, LFI/traversal, RFI, SSRF (OOB + cloud metadata), XXE (in-band +
  blind), file upload (storage + PHP RCE), JWT (alg=none, weak-secret crack),
  GraphQL introspection, CORS, open redirect, CRLF, host-header injection,
  CSRF (no-token + auto-submit PoC), NoSQL operator injection, LDAPi,
  session pre-auth issuance, cache poisoning, rate-limit burst, race burst,
  sensitive-path discovery.
- **Access control**: IDOR via dual-session replay (second cookie and/or
  anonymous) + sequential-ID enumeration.
- **API**: OpenAPI/Swagger discovery + import, endpoint fuzzing, JSON SQLi
  and NoSQL operator injection, excessive data exposure.
- **Management**: projects, risk score, finding status/notes, false-positive
  management (FPs auto-suppressed in future scans), scan diffing
  (new/fixed/still-open), trends, HTTP repeater with history, scheduled
  scans with webhook alerts on Critical, optional API token.
- **Custom rules**: drop JSON rule files in a folder (`rules/` has examples)
  and pass `--rules-dir`; extra payloads via `--payloads-xss`.
- **Reports**: HTML (with executive summary), JSON, CSV, PDF — each finding
  carries severity, CWE, confidence, the vulnerable parameter, the exact
  request that found it, response excerpt, proof, remediation, curl +
  Python PoC.

## Files

```
webscan.py            CLI
app.py                web UI + API + scheduler (SQLite: scans.db)
wscan/client.py       HTTP client (cookies, proxy, raw req/resp, timing)
wscan/core.py         findings store, PoC builder, crawler, fingerprints
wscan/recon.py        DNS/subdomains/ports/tech/TLS/WHOIS/WAF
wscan/passive.py      secrets, source maps, methods, exposure analysis
wscan/checks.py       core active checks (SQLi..JWT)
wscan/checks2.py      CSRF, RFI, NoSQL, LDAP, session, creds, IDOR, cache, race
wscan/api_scan.py     OpenAPI import + API fuzzing
wscan/auth.py         programmatic login for authenticated scans
wscan/rules.py        custom JSON detection rules + payload files
wscan/oob.py          out-of-band callback listener (127.0.0.1:8891)
wscan/report3.py      risk score, plain-language explains, CSV, PDF
wscan/engine.py       orchestration, profiles, cancellation
rules/                custom rules (examples + UI-built)
wscan/browser.py      Chromium engine (XSS execution proof, screenshots)
wscan/integrations.py Nuclei / ZAP bridges
wscan/har.py          HAR import/export
wscan/retest.py       Verify-Fix replay engine
wscan/matrix.py       permission matrix
wscan/report_docx.py  DOCX client reports
wscan/extrecon.py     external recon / EASM engine (DoH DNS, CT, IP intel)
wscan/calibrate.py    accuracy layer (calibration, similarity, confirm)
wscan/explain.py      plain-language 'What is it?' text for every finding
wscan/benchmark.py    precision/recall benchmark (--benchmark)
Dockerfile            container build
test_target.py        intentionally vulnerable local target (port 8899)
webscan_v1.py         the original v1 scanner (kept for reference)
```

## Honest limits

DOM XSS is static source->sink analysis (labelled "needs confirmation");
CSRF/IDOR/NoSQL findings are marked "Needs manual confirmation" where the
scanner cannot know ground truth (e.g. object ownership). Playwright-based
browser execution, Nuclei/ZAP bridges and multi-user RBAC are not built in —
this is a single-operator localhost tool by design.

Only scan targets you own or are authorized to test.
