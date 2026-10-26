"""Fifth-wave checks (Reconix 3.21): JavaScript prototype pollution and
insecure deserialization.

Both are proof-only, like every other Reconix check: no finding is
emitted unless the probe demonstrably changes server or browser state.

Prototype pollution is proven two ways:
  * server-side merge: a JSON ``{"__proto__": {...}}`` body is POSTed,
    then a fresh object serialization is fetched — if the marker shows
    up in an object that should not contain it, the merge polluted the
    shared prototype;
  * browser (DOM) proof: when Playwright is available, a page is loaded
    with a ``__proto__`` query parameter and the page's own JavaScript
    context is asked whether ``({}).<marker>`` now exists. If the app's
    query parsing + deep merge polluted the prototype, it does.

Insecure deserialization is proven by marker reflection (a benign
serialized object whose marker comes back in a response) or by a
deserializer error string that appears in the probe response but not in
a benign control response — the error text proves attacker-controlled
input reached a deserializer (CWE-502). No payload here executes
attacker code: the pickle is a harmless dict, the PHP object is an
empty stdClass with a marker property, and the Java probe is a bare
magic prefix that can only produce an error, never an object.
"""
import base64
import json
import pickle
import re
import urllib.parse

from .core import params_of, with_param

PP_MARKER = "reconixpp7x"
DESER_MARKER = "reconixd7x"

# Error strings that prove user input reached a real deserializer.
_DESER_ERRORS = (
    # PHP unserialize()
    "unserialize():", "unserialize() [", "failed to unserialize",
    # Python pickle
    "UnpicklingError", "pickle.UnpicklingError", "_pickle.UnpicklingError",
    "Can't get attribute", "No module named",
    # Java ObjectInputStream
    "InvalidClassException", "StreamCorruptedException",
    "ClassNotFoundException", "OptionalDataException",
    "NotSerializableException", "ObjectInputStream",
    # .NET
    "SerializationException", "BinaryFormatter",
    # Ruby Marshal
    "incompatible marshal", "Marshal",
)

_PP_QUERY_VARIANTS = (
    lambda m: "__proto__[%s]=%s" % ("reconixpp", m),
    lambda m: "__proto__.reconixpp=%s" % m,
    lambda m: "constructor[prototype][reconixpp]=%s" % m,
)


def _is_json_body(resp):
    if not resp or not resp.body:
        return False
    body = resp.body.strip()
    return body.startswith("{") or body.startswith("[")


def _pp_server_side(ctx, target_url):
    """JSON-merge prototype pollution proof. Returns True on proof."""
    client = ctx.client
    base = target_url.split("?")[0]
    ctrl = client.fetch(base)
    if not _is_json_body(ctrl) or PP_MARKER in (ctrl.body or ""):
        return False
    payload = json.dumps({"__proto__": {"reconixpp": PP_MARKER}}).encode()
    client.fetch(base, method="POST", raw_body=payload,
                 content_type="application/json")
    again = client.fetch(base)
    if _is_json_body(again) and PP_MARKER in (again.body or ""):
        return True
    # Node-style query-parser merge (qs extended): pollute via query,
    # then read a fresh serialization back.
    for variant in _PP_QUERY_VARIANTS:
        probe = base + ("&" if "?" in base else "?") + variant(PP_MARKER)
        client.fetch(probe)
        again = client.fetch(base)
        if _is_json_body(again) and PP_MARKER in (again.body or ""):
            return True
    return False


def _pp_browser(ctx, url):
    """DOM prototype-pollution proof via real Chromium. Returns True
    on proof, False when the browser is unavailable or no pollution
    happened. Any browser error is a silent skip, never a finding."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            try:
                for variant in _PP_QUERY_VARIANTS:
                    probe = url.split("?")[0] + (
                        "&" if "?" in url else "?") + variant(PP_MARKER)
                    try:
                        page.goto(probe, wait_until="load", timeout=15000)
                        page.wait_for_timeout(500)
                        val = page.evaluate(
                            "() => { try { return ({}).reconixpp; "
                            "} catch (e) { return null; } }")
                    except Exception:
                        continue
                    if val == PP_MARKER:
                        return True
            finally:
                browser.close()
    except Exception:
        return False
    return False


def protopollution_check(ctx, pages):
    """Prototype pollution: server-side merge proof first (stdlib
    client only), then browser DOM proof when Playwright exists."""
    client, F = ctx.client, ctx.findings
    targets = []
    for url, _resp in pages:
        if url not in targets:
            targets.append(url)
    for url in targets[:5]:
        if _pp_server_side(ctx, url):
            F.add("Critical", "JavaScript Prototype Pollution", url,
                  "A JSON merge on the server polluted the shared object "
                  "prototype: a marker sent inside a __proto__ key showed "
                  "up in a fresh object serialization that should not "
                  "contain it. Polluted properties reach every object in "
                  "the process and can flip prices, roles, or security "
                  "flags — and in server-side cases escalate to code "
                  "execution.",
                  proof="__proto__ merge marker %s reflected in fresh "
                        "object serialization" % PP_MARKER,
                  param="__proto__", cwe="CWE-1321")
            return
    for url in targets[:3]:
        if _pp_browser(ctx, url):
            F.add("High", "JavaScript Prototype Pollution", url,
                  "The page's own JavaScript merged a __proto__ query "
                  "parameter into the shared object prototype: after "
                  "loading the page, ({}).reconixpp returned the "
                  "injected marker. Any script that reads settings from "
                  "merged objects can now be steered by an attacker.",
                  proof="({}).reconixpp == %s in page JavaScript "
                        "context" % PP_MARKER,
                  param="__proto__", cwe="CWE-1321")
            return


def _php_object(marker):
    inner = 's:12:"reconixmark";s:%d:"%s";' % (len(marker), marker)
    return 'O:8:"stdClass":1:{%s}' % inner


def _py_dict_pickle(marker):
    return base64.b64encode(pickle.dumps(
        {"reconixmark": marker})).decode()


def _py_global_miss_pickle():
    # Protocol-0 GLOBAL opcode naming a module/attribute that cannot
    # exist. If the server unpickles it, the error names the missing
    # module — proof of unpickling, with no code executed.
    return base64.b64encode(
        b"creconixprobe_nonexistent\nreconixmarker\n.").decode()


def _java_magic():
    return base64.b64encode(b"\xac\xed\x00\x05junkjunk").decode()


def deser_url(ctx, url):
    """Insecure deserialization: marker reflection or deserializer
    error text that appears only in the probe response, never in a
    benign control response."""
    client, F = ctx.client, ctx.findings
    probes = [
        (_php_object(DESER_MARKER), "PHP serialized object"),
        (_py_dict_pickle(DESER_MARKER), "Python pickle"),
        (_py_global_miss_pickle(), "Python pickle (missing global)"),
        (_java_magic(), "Java serialized stream"),
    ]
    for name, orig in params_of(url):
        ctrl = client.fetch(with_param(url, name, "reconixcontrol"))
        ctrl_body = ctrl.body or ""
        for payload, kind in probes:
            r = client.fetch(with_param(url, name, payload))
            if not r.status or not r.body:
                continue
            if DESER_MARKER in r.body and DESER_MARKER not in ctrl_body:
                F.add("Critical", "Insecure Deserialization", url,
                      f"Parameter '{name}' feeds a {kind} into a "
                      f"deserializer and the crafted object's marker "
                      f"came back in the response: user-controlled "
                      f"serialized data is rebuilt without checking, "
                      f"which can lead to remote code execution.",
                      proof=f"{kind} marker {DESER_MARKER} reflected "
                            f"in response",
                      param=name, resp=r, cwe="CWE-502")
                return
            for err in _DESER_ERRORS:
                if err in r.body and err not in ctrl_body:
                    F.add("Critical", "Insecure Deserialization", url,
                          f"Parameter '{name}' feeds a {kind} into a "
                          f"deserializer: the server answered with a "
                          f"deserializer error ({err}) that the benign "
                          f"control request did not produce. "
                          f"User-controlled serialized data reaching a "
                          f"deserializer can lead to remote code "
                          f"execution.",
                          proof=f"{kind} -> deserializer error: {err}",
                          param=name, resp=r, cwe="CWE-502")
                    return
