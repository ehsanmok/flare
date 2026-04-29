"""Example 28: ``application/x-www-form-urlencoded`` forms.

Demonstrates the v0.6 form-parsing surface:

- ``parse_form_urlencoded`` — bytes -> ``FormData`` multimap.
- ``urldecode`` / ``urlencode`` — WHATWG form encoding (``+``->space).
- ``Form`` extractor — typed-handler integration.

Run:
    pixi run example-forms
"""

from flare.http import (
    Form,
    Method,
    Request,
    Response,
    parse_form_urlencoded,
    ok,
    urldecode,
    urlencode,
)


def main() raises:
    print("=== flare Example 28: Forms ===")
    print()

    # ── 1. Parse a urlencoded body ─────────────────────────────────────────
    print("── 1. parse_form_urlencoded ──")
    var body = "user=alice+smith&age=30&interests=mojo&interests=rust"
    var f = parse_form_urlencoded(body)
    print("  bindings :", f.len())
    print("  user     :", f.get("user"))
    print("  age      :", f.get("age"))
    var hobbies = f.get_all("interests")
    print("  interests:", len(hobbies))
    for i in range(len(hobbies)):
        print("    -", hobbies[i])
    print()

    # ── 2. Encode / decode helpers ─────────────────────────────────────────
    print("── 2. urlencode / urldecode ──")
    var raw = "a&b=c d/e"
    var enc = urlencode(raw)
    var dec = urldecode(enc)
    print("  raw     :", raw)
    print("  encoded :", enc)
    print("  decoded :", dec)
    print()

    # ── 3. Form extractor (typical /login handler shape) ───────────────────
    print("── 3. Form extractor ──")
    var req = Request(method=Method.POST, url="/login")
    req.headers.set("Content-Type", "application/x-www-form-urlencoded")
    req.body = List[UInt8]("user=alice&pw=secret".as_bytes())
    var form = Form.extract(req)
    print("  user     :", form.value.get("user"))
    print("  pw       :", form.value.get("pw"))
    print()

    # Build the response a real handler might send.
    var resp = ok("welcome " + form.value.get("user"))
    print("  response :", resp.text())
    print()

    print("=== Example 28 complete ===")
