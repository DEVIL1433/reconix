"""Business-logic attacks on a recorded workflow.

Scanners test inputs; pentesters test the PROCESS. Given a HAR of a
real multi-step flow (checkout, onboarding, redemption...), this module
attacks the flow itself:

* step-skip  — call the final step directly, in a fresh session that
  never performed the earlier steps, and see whether the server
  accepts it anyway.
* replay     — submit a one-time step (coupon / OTP / redeem / confirm)
  twice and see whether both submissions succeed.
* value tampering — resend a step with price/amount/quantity fields
  set to -1, 0 or 0.01 and see whether the server honours them.

A step counts as "accepted" only when the response looks like the
recorded success: same status class, no failure language, and (when a
recorded body exists) real similarity to it. Anything ambiguous is
reported as nothing — business-logic FPs are worse than silence.
"""
import re
import urllib.parse

from .calibrate import similarity
from .client import Client

FAIL_RX = re.compile(
    r"(invalid|error|failed|failure|required|already\s+(used|applied|"
    r"redeemed|exists)|expired|denied|not\s+allowed|unauthori[sz]ed|"
    r"please\s+(log|sign)\s+in|session\s+expired)", re.I)
ONETIME_RX = re.compile(r"(otp|coupon|voucher|redeem|apply|verify|"
                        r"confirm|promo|token|activate)", re.I)
NUMERIC_NAMES = ("price", "amount", "qty", "quantity", "total",
                 "discount", "fee", "cost", "mrp", "rate", "sum")
MAX_STEPS = 12


def _success_like(resp, recorded):
    if resp is None or resp.status is None:
        return False
    if not (200 <= resp.status < 400):
        return False
    body = resp.body or ""
    if FAIL_RX.search(body):
        return False
    if recorded is not None:
        if recorded.get("status") and \
                not (200 <= recorded["status"] < 400):
            return False  # the recorded step itself was not a success
        rbody = recorded.get("resp_body") or ""
        if rbody and similarity(body, rbody) < 0.45:
            return False
    return True


def _send(client, step, params=None):
    url = step["url"]
    method = step["method"]
    data = params if params is not None else step.get("params")
    if data:
        return client.fetch(url, method=method, data=data)
    if step.get("body_text"):
        return client.fetch(url, method=method,
                            raw_body=step["body_text"].encode(),
                            content_type=step.get("content_type") or None)
    return client.fetch(url, method=method)


def run(ctx, steps):
    """steps: output of har.parse_har_steps (same-origin, ordered)."""
    F = ctx.findings
    base_host = urllib.parse.urlsplit(ctx.base).netloc
    flow = [s for s in steps
            if urllib.parse.urlsplit(s["url"]).netloc == base_host
            and s["method"] in ("POST", "PUT", "PATCH", "DELETE")][:MAX_STEPS]
    if not flow:
        return 0
    made = 0
    ctx.emit(f"Business logic: attacking a recorded workflow of "
             f"{len(flow)} state-changing step(s) — skip, replay, "
             "value tampering.")

    # ---- 1) step-skip: final step, fresh session, no prior steps ----
    if len(flow) >= 2 and not ctx.stop.is_set():
        final = flow[-1]
        fresh = Client(cookie=ctx.opts.get("cookie"),
                       proxy=ctx.opts.get("proxy"))
        r = _send(fresh, final)
        if _success_like(r, final):
            f = F.add("High",
                      "Business Logic: Workflow Step Can Be Skipped",
                      final["url"],
                      f"The final step of a {len(flow)}-step workflow "
                      "was accepted in a fresh session that never "
                      "performed the earlier steps (cart / verification "
                      "/ payment stages can be bypassed by calling the "
                      "completion endpoint directly).",
                      proof=f"Direct {final['method']} to the final step "
                            f"returned HTTP {r.status} matching the "
                            "recorded success response.",
                      param="", resp=r, cwe="CWE-837")
            made += 1 if f else 0

    # ---- 2) replay of one-time steps ---------------------------------
    for step in flow:
        if ctx.stop.is_set():
            break
        hay = step["url"] + " " + " ".join((step.get("params") or {}).keys())
        if not ONETIME_RX.search(hay):
            continue
        r1 = _send(ctx.client, step)
        if not _success_like(r1, step):
            continue
        r2 = _send(ctx.client, step)
        if _success_like(r2, step) and \
                similarity(r1.body or "", r2.body or "") > 0.7:
            f = F.add("Medium",
                      "Business Logic: One-Time Step Is Replayable",
                      step["url"],
                      "A step that should work exactly once (coupon / "
                      "verification / redemption semantics) was submitted "
                      "twice and BOTH submissions were accepted with "
                      "equivalent success responses — the one-time "
                      "control is missing or not enforced.",
                      proof=f"Two identical submissions -> HTTP "
                            f"{r1.status} and HTTP {r2.status}, bodies "
                            f"{similarity(r1.body or '', r2.body or ''):.0%} "
                            "similar, no 'already used' rejection.",
                      param="", resp=r2, cwe="CWE-837")
            made += 1 if f else 0

    # ---- 3) value tampering on money/quantity fields -----------------
    for step in flow:
        if ctx.stop.is_set():
            break
        params = step.get("params") or {}
        targets = [k for k in params
                   if any(n in k.lower() for n in NUMERIC_NAMES)]
        for field in targets[:2]:
            for bad in ("-1", "0", "0.01"):
                if ctx.stop.is_set():
                    break
                tampered = dict(params)
                tampered[field] = bad
                r = _send(ctx.client, step, params=tampered)
                if _success_like(r, step):
                    f = F.add("High",
                              "Business Logic: Price/Quantity Tampering "
                              "Accepted",
                              step["url"],
                              f"The workflow step accepted "
                              f"'{field}={bad}' and returned the recorded "
                              "success response — order values are "
                              "trusted from the client instead of being "
                              "recomputed server-side.",
                              proof=f"{step['method']} with "
                                    f"{field}={bad} -> HTTP {r.status}, "
                                    "matching the recorded success.",
                              param=field, resp=r, cwe="CWE-472")
                    made += 1 if f else 0
                    break  # one bad value per field is proof enough
    if made:
        ctx.emit(f"Business logic: {made} workflow weakness(es) found.")
    return made
