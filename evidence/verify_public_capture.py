#!/usr/bin/env python3
"""
Independent validation of the cab_meshd key and wire format against a public,
third-party artefact that predates this research.

In March 2023 John McEleney published two gists containing hex frames captured
from a genuine mesh negotiation between two Xiaomi AX3200 (RB01) routers, to
flip a router into netmode4 for OpenWrt flashing. The frames were replayed
blindly; no protocol analysis accompanied them.

    https://gist.github.com/jmceleney/33c626a33960ac8a1764614cf57420cd
    https://gist.github.com/jmceleney/890532f8924e1e17048a0b427577ddd3

They are also embedded verbatim in xmir-patcher's connect4.py (line ~91), which
credits both gists.

This script parses those frames against the wire format documented in
../technical-appendix.md (SS3-SS5) and recomputes the captured authentication
token from the hard-coded key documented in SS2. Nothing is sent anywhere; the
frames are constants and the script is pure computation.

Run:  python3 verify_public_capture.py
"""

import base64
import hashlib
import hmac

# The hard-coded, firmware-global HMAC key compiled into cab_meshd, with byte 0
# overwritten by role ('q' = the variant a CAP verifies an incoming peer with).
KEY_BASE = "838d364d8ed3bd085e150211ea6b3715"

# Frames as published in 2023. Captured from two Xiaomi AX3200 (RB01) routers --
# different model and SoC generation from the RD03v2 analysed in this report.
FRAMES = [
    # type-4 auth_req  (gist frame 1 / connect4.py line ~91)
    "100100a3000438633a64653a66393a62663a35643a6236000038633a64653a66393a62663a35643a6237000061646435353662636461303730380000503151527567767a6d78746b35502f70316b2b46566a724a4c716d6568494546424a6563477062516a76383d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033433a43443a35373a32323a31433a36310000",
    # type-5 auth_reply (gist frame 2)
    "10010020000538633a64653a66393a62663a35643a6236000038633a64653a66393a62663a35643a623700000100000000000000000000000000000000000000000000000000000000000000",
    # type-7 sync_reply (gist frame 3)
    "10010020000738633a64653a66393a62663a35643a6236000038633a64653a66393a62663a35643a62370000017265637620636f6e6669672073796e6320636f72726563746c792e0a000000",
]

TYPE_NAMES = {4: "auth_req", 5: "auth_reply", 6: "sync_req", 7: "sync_reply"}


def cstr(b: bytes) -> str:
    return b.split(b"\x00")[0].decode("ascii", "replace")


def parse(frame: bytes) -> dict:
    """Header is a fixed 44 bytes (0x2c), big-endian; see technical-appendix SS3."""
    return {
        "version": int.from_bytes(frame[0x00:0x02], "big"),
        "body_len": int.from_bytes(frame[0x02:0x04], "big"),
        "type": int.from_bytes(frame[0x04:0x06], "big"),
        "field_a": cstr(frame[0x06:0x19]),   # 19 B -> conn+0xe8
        "field_b": cstr(frame[0x19:0x2C]),   # 19 B -> conn+0xfb
        "body": frame[0x2C:],
    }


def main() -> int:
    ok = True
    parsed = []

    print("=" * 72)
    print("Frame decode vs technical-appendix.md SS3 (44-byte header, big-endian)")
    print("=" * 72)
    for i, hexs in enumerate(FRAMES, 1):
        f = bytes.fromhex(hexs)
        p = parse(f)
        parsed.append(p)
        vok = "OK" if p["version"] == 0x1001 else "MISMATCH"
        lok = "OK" if p["body_len"] == len(p["body"]) else "MISMATCH"
        print(f"\nframe {i}:")
        print(f"  version   0x{p['version']:04x}  ({vok}, expect 0x1001)")
        print(f"  body len  {p['body_len']:<5} ({lok}, actual {len(p['body'])})")
        print(f"  type      {p['type']} ({TYPE_NAMES.get(p['type'], '?')})")
        print(f"  field A   {p['field_a']!r}")
        print(f"  field B   {p['field_b']!r}")
        if p["version"] != 0x1001 or p["body_len"] != len(p["body"]):
            ok = False

    types = [p["type"] for p in parsed]
    print(f"\nmessage sequence: {types}  (technical-appendix SS5: send 4 -> 5 -> 7)")
    if types != [4, 5, 7]:
        ok = False

    # SS5: type-5 and type-7 both carry body[0] == 1.
    for i, p in zip((2, 3), parsed[1:]):
        flag = p["body"][0]
        print(f"  frame {i} body[0] = {flag} (expect 1)")
        if flag != 1:
            ok = False

    # SS5: in the type-4 frame, body[0x00] = id, body[0x10] = base64(HMAC(key, id)).
    body = parsed[0]["body"]
    peer_id = cstr(body[0x00:0x10])
    captured = cstr(body[0x10:0x10 + 44])

    print()
    print("=" * 72)
    print("Authentication token vs technical-appendix.md SS2")
    print("=" * 72)
    print(f"  body[0x00] id    = {peer_id!r}")
    print(f"  body[0x10] pass  = {captured!r}")
    print("\n  pass = base64(HMAC-SHA256(key, id)), key byte 0 overwritten by role:")

    matched_role = None
    for role in ("q", "x", "8"):
        key = (role + KEY_BASE[1:]).encode()
        calc = base64.b64encode(
            hmac.new(key, peer_id.encode(), hashlib.sha256).digest()
        ).decode()
        mark = ""
        if calc == captured:
            mark = "   <<< MATCH"
            matched_role = role
        print(f"    key={key.decode()}  ->  {calc}{mark}")

    if matched_role != "q":
        ok = False

    print()
    print("=" * 72)
    if ok:
        print("RESULT: PASS")
        print()
        print("  The wire format documented in technical-appendix.md SS3/SS5 parses a")
        print("  third-party 2023 capture cleanly, and the hard-coded key in SS2")
        print("  reproduces that capture's authentication token byte-for-byte using")
        print("  the 'q' role variant -- on a different router model (AX3200/RB01)")
        print("  than the one reverse-engineered here (AX3000T/RD03v2).")
    else:
        print("RESULT: FAIL -- see mismatches above")
    print("=" * 72)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
