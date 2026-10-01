#!/usr/bin/env python3
"""Minimally initialize a factory-fresh RD03v2 for an owned-device test.

Why this exists
---------------
`/etc/init.d/cab_meshd` only starts the CAP/server instance when
`xiaoqiang.common.INITTED` is `YES`:

    INITTED=$(uci -q get xiaoqiang.common.INITTED)
    ...
    elif [ "$INITTED" = "YES" ]; then
        procd_set_param command "$PROG" -S -i br-lan

Out of the box `init_info` reports `"inited":0`, so the inbound CAP listener on
`br-lan` is absent. The factory router can instead run `cab_meshd -C` on its WAN
interface, broadcast UDP/19553 discovery, and connect outbound to a CAP; this
helper does not prepare or use that RE/WAN path. It flips the initialization bit
through the device's own web API, using only what is recoverable from the firmware
image.
It is **not** equivalent to the normal Xiaomi web wizard: that wizard can call
`mesh_connect.sh init_cap 2` and set `NETMODE=whc_cap`, closing the CAP root sink.
This helper leaves `NETMODE` unset while opening the CAP listener.

What it deliberately does NOT do
--------------------------------
`api/xqsystem/router_init` -> `setRouter()` treats every configuration block as
optional, but calls `setSPwd()` and `setInited()` *unconditionally* at the end:

    if not isStrNil(newPwd) and not isStrNil(oldPwd) -> _savePassword(...)
    if not isStrNil(wanType)                        -> setWanPPPoE / setWanStaticOrDHCP
    if not isStrNil(wifiPwd) and checkSSID(..) == 0  -> setWifiBasicInfo(1/2, ...)
    setSPwd(); setInited()          <-- always

So we submit the SSID only. No `wifiPwd`, no `newPwd`, no `wanType` means the
Wi-Fi radios, the admin password and the WAN are left as they are --
which matters, because this script is normally run over that same Wi-Fi and
changing the key would disconnect the caller mid-request.  `forkRestartWifi()`
is likewise gated on a config actually having changed, so the radios never bounce.
The router becomes initialized, its name may change, the mesh listener opens
after reboot, and the factory admin verifier remains. Proceed on an isolated
network and complete the intended test or installation promptly.

Setting a new admin password is not implemented: `_savePassword` feeds `newPwd`
to `saveCiphertextPwd` -> `decCiphertext`, which shells out to a decrypt helper
keyed on a device-side secret, so `newPwd` has to be a ciphertext produced the
way the web UI's JavaScript produces it.  It is not needed to reach `setInited`.

Authentication
--------------
`node("api","xqsystem").sysauth_authenticator = "jsonauth"`, and
`dispatcher.authenticator.jsonauth` reads `username`/`password`/`nonce`, then:

    checkUser(username, nonce, password)   -- XQSecureUtil.lua:354
    checkNonce(nonce, getremotemac())      -- XQSecureUtil.lua:383

`checkUser` with `getEncryptMode() == 1` (true whenever `account.legacy` exists,
which it does in the shipped image) reduces to:

    sha256(nonce .. <stored account value>) == password

and the stored value on an un-initialised unit is still the one shipped in
`/etc/config/account`:

    config core 'common'
        option 'admin' '73a1d6d0...fa8cdfa24'

`checkNonce` requires `<type>_<mac>_<time>_<rand>` -- exactly four `_`-separated
fields, `type <= 4`, and `time` strictly greater than the last value seen for
that (type, mac) pair.  A live UNIX timestamp satisfies the replay guard.

Reboot
------
`setInited()` restarts `meshd`, but *not* `cab_meshd`, whose init script only
runs at boot (`START=99`).  So the daemon does not appear until the box reboots.
`--reboot` does that and then waits for 19553 to open.

Usage
-----
    ./init_router.py --dry-run                  # show every request, send nothing
    ./init_router.py                            # flip INITTED, leave Wi-Fi alone
    ./init_router.py --reboot                   # ... then reboot and wait for 19553
"""

import argparse
import hashlib
import json
import random
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# /etc/config/account, "config core 'common'" -> option 'admin'.  Factory value,
# identical in every 2.0.28 image; only valid until an admin password is set.
FACTORY_ADMIN_HASH = "73a1d6d01003067844cd148b1502a24bb8a305c93dfef55f983da80fa8cdfa24"

MESH_PORT = 19553
# The LuCI Lua backend behind nginx is slow and serialises requests: a cold
# `init_info` on an idle RD03v2 measured ~9s, and repeated probes can wedge it
# for a while even though nginx keeps answering static paths instantly. Be
# patient here rather than half-sending a state-changing POST.
TIMEOUT = 45
RETRIES = 4
RETRY_DELAY = 8


class Fail(Exception):
    pass


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- http


def _once(url, data=None, timeout=TIMEOUT):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    req.add_header("User-Agent", "Mozilla/5.0")
    req.add_header("Connection", "close")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _request(url, data=None, timeout=TIMEOUT, retries=RETRIES):
    """Retry on transport errors. Every call site here is idempotent -- login
    just mints a stok, and setInited() is a no-op the second time -- so a
    replayed request cannot compound."""
    last = None
    for attempt in range(1, retries + 1):
        try:
            return _once(url, data, timeout)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last = exc
            if attempt < retries:
                log(f"    [{attempt}/{retries}] {type(exc).__name__}, retrying in {RETRY_DELAY}s")
                time.sleep(RETRY_DELAY)
    raise Fail(f"{url} unreachable after {retries} attempts: {last}")


def get_json(url, data=None, timeout=TIMEOUT):
    raw = _request(url, data, timeout)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise Fail(f"non-JSON reply from {url}:\n{raw[:400]}")


# --------------------------------------------------------------------------- auth


def local_mac(host):
    """MAC of the interface that routes to `host`, for the nonce's mac field.

    checkNonce only uses this to pick a storage slot -- it compares it against
    the real remote MAC purely to emit a log line -- so an approximation is fine.
    """
    try:
        out = subprocess.run(
            ["ip", "-o", "route", "get", host],
            capture_output=True, text=True, timeout=5,
        ).stdout
        dev = re.search(r"\bdev\s+(\S+)", out)
        if dev:
            with open(f"/sys/class/net/{dev.group(1)}/address") as fh:
                return fh.read().strip()
    except Exception:
        pass
    return "00:00:00:00:00:00"


def make_nonce(mac, ntype=0):
    """<type>_<mac>_<time>_<rand>; type <= 4, time beats the stored mark."""
    return f"{ntype}_{mac}_{int(time.time())}_{random.randint(0, 9999)}"


def login(host, admin_hash, mac):
    """jsonauth: sha256(nonce + stored account value). Returns the stok."""
    nonce = make_nonce(mac)
    password = hashlib.sha256((nonce + admin_hash).encode()).hexdigest()
    log(f"[*] nonce    {nonce}")
    log(f"[*] password sha256(nonce + stored) = {password[:16]}...")

    res = get_json(
        f"http://{host}/cgi-bin/luci/api/xqsystem/login",
        {"username": "admin", "password": password, "nonce": nonce},
    )
    if res.get("code") != 0 or not res.get("token"):
        raise Fail(
            f"login rejected: {res}\n"
            "    code 401 = banned; otherwise the stored admin hash is not the\n"
            "    factory one (already initialised?). Override with --admin-hash."
        )
    log(f"[+] logged in, stok={res['token']}")
    return res["token"]


# --------------------------------------------------------------------------- steps


def read_init_info(host):
    info = get_json(f"http://{host}/cgi-bin/luci/api/xqsystem/init_info")
    log(
        f"[*] {info.get('hardware')} rom {info.get('romversion')} "
        f"inited={info.get('inited')} encryptMode={info.get('newEncryptMode')} "
        f"name={info.get('routername')!r}"
    )
    return info


def router_init(host, stok, ssid, dry_run):
    """POST SSIDs only; the backend still sets INITTED and router metadata."""
    params = {"wifi24Ssid": ssid, "wifi50Ssid": ssid}
    url = f"http://{host}/cgi-bin/luci/;stok={stok}/api/xqsystem/router_init"
    if dry_run:
        log(f"[dry-run] POST {url}")
        log(f"[dry-run]      {urllib.parse.urlencode(params)}")
        return None
    res = get_json(url, params)
    # setSPwd()/setInited() run even when `code` reports a validation error on a
    # block we did not submit, so a non-zero code here is informational.
    log(f"[+] router_init -> {res}")
    return res


def port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def reboot(host, stok, dry_run):
    url = f"http://{host}/cgi-bin/luci/;stok={stok}/api/xqsystem/reboot"
    if dry_run:
        log(f"[dry-run] POST {url}")
        return
    log("[*] rebooting")
    try:
        _once(url, {}, timeout=10)
    except Exception:
        pass  # expected: the box drops the connection as it goes down


def wait_for_mesh(host, deadline_s=240):
    log(f"[*] waiting up to {deadline_s}s for tcp/{MESH_PORT}")
    end = time.time() + deadline_s
    while time.time() < end:
        if port_open(host, MESH_PORT):
            log(f"[+] tcp/{MESH_PORT} OPEN -- cab_meshd is in CAP mode")
            return True
        time.sleep(5)
    log(f"[-] tcp/{MESH_PORT} still closed after {deadline_s}s")
    log("    check NETMODE: the init script skips whc_re / wifiapmode / cpe_bridgemode")
    return False


# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="192.168.31.1")
    ap.add_argument("--ssid", help="SSID to submit (default: current router name)")
    ap.add_argument("--admin-hash", default=FACTORY_ADMIN_HASH,
                    help="stored account value if not the factory default")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the requests without sending the state-changing ones")
    ap.add_argument("--reboot", action="store_true",
                    help="reboot afterwards so cab_meshd starts, then wait for 19553")
    args = ap.parse_args()

    host = args.host
    log(f"[*] target {host}")

    if port_open(host, MESH_PORT):
        log(f"[!] tcp/{MESH_PORT} is already open -- nothing to do")
        return 0

    info = read_init_info(host)
    if info.get("inited") == 1:
        log("[!] already initialised; INITTED is set. If inbound CAP TCP/19553 is closed, reboot")
        log("    or check NETMODE.")
        if args.reboot:
            pass  # fall through: we still need a stok to reboot
        else:
            return 0
    if info.get("newEncryptMode") != 1:
        raise Fail(
            f"newEncryptMode={info.get('newEncryptMode')}; this script assumes the "
            "sha256 scheme (getEncryptMode()==1)."
        )

    ssid = args.ssid or info.get("routername")
    if not ssid:
        raise Fail("could not determine an SSID; pass --ssid")
    log(f"[*] submitting SSID {ssid!r} (Wi-Fi key/admin/WAN unchanged; INITTED changes)")

    mac = local_mac(host)
    log(f"[*] local MAC for nonce: {mac}")

    if args.dry_run:
        nonce = make_nonce(mac)
        pwd = hashlib.sha256((nonce + args.admin_hash).encode()).hexdigest()
        log(f"[dry-run] POST http://{host}/cgi-bin/luci/api/xqsystem/login")
        log(f"[dry-run]      username=admin&nonce={nonce}&password={pwd}")
        router_init(host, "<stok>", ssid, True)
        if args.reboot:
            reboot(host, "<stok>", True)
        return 0

    stok = login(host, args.admin_hash, mac)
    router_init(host, stok, ssid, False)

    time.sleep(2)
    after = read_init_info(host)
    if after.get("inited") == 1:
        log("[+] INITTED is set")
    else:
        log(f"[-] inited is still {after.get('inited')} -- setInited() did not take")
        return 1

    if args.reboot:
        reboot(host, stok, False)
        time.sleep(20)
        return 0 if wait_for_mesh(host) else 1

    log(f"[*] cab_meshd only starts at boot; reboot to bring up tcp/{MESH_PORT}")
    log("    (re-run with --reboot, or power-cycle)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as exc:
        log(f"[-] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
