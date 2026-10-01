# Technical appendix — shared primitives

V1 and the implemented CAP-side V2 PoCs share the inbound listener and forgeable
HMAC exchange. V1 stops after receiving the CAP's type-6 sync and never invokes
the root `eval`. The CAP PoCs then use type-7, although its handler does not require
`ST_RUNNING`. The factory RE/WAN path uses the same protocol and key with the peer
roles and connection direction reversed, then receives type-6 into `re_init`. This
document specifies those shared primitives once. All offsets are file offsets / virtual addresses in the shipped
`/usr/sbin/cab_meshd` (32-bit ARM, little-endian) from `romversion 2.0.28`.

## 1. Transport: TLS with no client certificate

`cab_meshd`'s TLS server calls `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)` on
both context-init paths (`0x32b4`, `0x3394`). Any client completes the handshake
with **no certificate**. Observed on hardware: `TLSv1.2`,
`ECDHE-RSA-AES256-GCM-SHA384`, server cert `CN=xiaoqiang` / issuer
`CN=xiaoqiang-cn`.

Listener: TCP **and** UDP **19553**, bound to `br-lan` when the daemon runs as CAP
(`cab_meshd -S -i br-lan`), started by `/etc/init.d/cab_meshd` when
`xiaoqiang.common.INITTED == "YES"`.

On a factory-reset RD03v2, boot-time port assignment populates the selected DHCP
WAN as `eth1.4` before `START=99`; the same init script starts
`cab_meshd -C -i eth1.4`. This RE broadcasts UDP discovery and initiates outbound
TLS to the first CAP response. That startup path and the full connection were
observed on hardware.

## 2. Authentication: a hard-coded, firmware-global HMAC key

The "authentication" is an HMAC-SHA256 over the peer id, keyed by a **32-byte
string compiled into the binary** — identical on every RD03v2 of this firmware.

- Key literal at `0xcabb`: `838d364d8ed3bd085e150211ea6b3715`
- Loader `0x3bb0`–`0x3c14` copies it to the stack and **overwrites byte 0 by
  role**: `'x'` (`0x78`) or `'q'` (`0x71`).
- The role is chosen by the caller: at `0x499c` the verify path computes
  `r0 = 1 - mode` before the byte-select at `0x3c0c`. Consequently a **server
  (mode=1) verifies an incoming peer with the `'q'` variant** — key
  `q38d364d8ed3bd085e150211ea6b3715` — while `'x'` is what a CAP uses for the auth
  it *sends*. The inverse was confirmed live: a mode-0 RE accepted a rogue CAP's
  token generated with `x38d364d8ed3bd085e150211ea6b3715`.
- HMAC computed at `0x3b58`: `HMAC-SHA256(key, id)`, then base64-encoded.

So a peer authenticates to a CAP with:

```
pass = base64( HMAC_SHA256("q38d364d8ed3bd085e150211ea6b3715", id) )
```

`id` is any short ASCII string the attacker picks. This was reproduced in Python
and matches the daemon's own debug log (which prints the incoming peer's key as
`q38d364d…` and the exact `pass`).

## 3. Wire protocol

Fixed **44-byte (`0x2c`) header**, read whole at `0x6670`, big-endian; the message
body is then read into the *same* buffer, so handler offsets are body-relative.

| Offset | Field |
|---|---|
| `0x00` | version — must be `0x1001` (checked at `0x6748`) |
| `0x02` | body length — `read_full()` blocks for exactly this many bytes |
| `0x04` | message type |
| `0x06`–`0x18` | field A (19 B) → `strncpy(conn+0xe8, …)` at `0x67e4` — becomes a `cap_init` MAC arg |
| `0x19`–`0x2b` | field B (19 B) → `strncpy(conn+0xfb, …)` at `0x6818` |

Message type is dispatched by a jump table at `0x688c`–`0x6894`; only types **4,
5, 6, 7** are accepted.

## 4. State machine

Enum (strings at `0x386…`):

```
0 ST_NONE   1 ST_STOP   2 ST_TCP_DONE   3 ST_SSL_DONE
4 ST_AUTH_SENT   5 ST_AUTH_SENT_2   6 ST_RUNNING
```

| Type | Handler | Role / state requirement | Effect |
|---|---|---|---|
| 4 | `process_auth_req` `0x5f04` | CAP: 3 `ST_SSL_DONE`; RE: 5 `ST_AUTH_SENT_2` | verifies the role-specific `pass` (§2); CAP plants `body[0x90]` (19 B) → `conn+0x10e` at `0x6058` and enters state 4; RE enters state 6 `ST_RUNNING` |
| 5 | `process_auth_reply` `0x56ec` | 4 `ST_AUTH_SENT`, `body[0]==1` | CAP enters state 6 and sends its config as type-6 via `send_sync_req` `0x5420`; RE enters state 5 and waits for the CAP's type-4 |
| 6 | `process_sync_req` | RE/client role in state 6 `ST_RUNNING` (checked by helper `0x6130`) | parses the received config; the working RE/WAN path calls the `re_init` builder `0xa950` → `system()` `0xae94` |
| 7 | `process_sync_reply` `0x63e0` | CAP/server role, `body[0]==1`; **no connection-state comparison** | runs the `cap_init` builder `0xa3bc` → `snprintf` `0xa590` → `system()` `0xa598` |

**Type-4 is accepted in `ST_SSL_DONE` — immediately after the TLS handshake, before
any authentication.** That is what makes the V1 exchange pre-auth: the only gate is
the §2 HMAC, whose key is public knowledge (it is in the firmware).

**Type-7 is even less gated than the PoC sequence suggests.** The current CAP PoCs
send `4→5→7`, but `process_sync_reply` does not test `conn+0xe0` for
`ST_RUNNING` or validate an HMAC. The later shell `NETMODE` gate still controls
whether `do_cap_init` reaches `mimesh_init`.

## 5. Minimal handshake to `ST_RUNNING`

```
TLS connect (no cert)
send type-4:  body[0x00]=id,  body[0x10]=base64(HMAC("q38d364d…", id))
              (for direct CAP V2, leave header fields empty and put the
               positional plant in body[0x90])
recv type-5 (server's auth reply) + type-4 (server's own auth req)   [ignored]
send type-5:  body[0]=1
recv type-6:  the CAP's config JSON  <-- contains web_passwd256  (V1 stops here)
send type-7:  body[0]=1              <-- triggers cap_init         (V2 sink)
```

The factory RE/WAN direction reverses the peers:

```
RE broadcasts MIROUTE_RE_DDv1.0\0 over UDP/19553
rogue CAP replies MIROUTE_CAP_DDv1.0 + CAP IP at offset 0x12
RE opens TLS and sends type-4 using the q-key
rogue CAP sends type-5 success + type-4 using the x-key
RE sends type-5 success -> ST_RUNNING
rogue CAP sends type-6 -> re_init builder -> root shell sink
```

## 6. The `cap_init` `system()` template

```
/usr/sbin/mesh_connect.sh cap_init '%s' '%s' '%s' '%s' '%s' '%s' '%s' %d
```

Built at `0xa3bc`; the seven `%s` are checked by `check_injection` (`0x9308`) at
`0xa4f8` before `snprintf`. Its exact 18-byte blacklist is:

```text
@`$#,;'\"[]&*()|<>
```

Space and the base64 alphabet are not included. The working direct CAP/LAN path
uses the first `%s`, sourced from the type-4 plant at `conn+0x10e`: the attacker
places a five-word pad followed by an already-base64-encoded shell expression there.
The check sees only permitted pad/base64 characters; unquoted `$@` later makes the
token `do_cap_init` `$6`, which is decoded before `eval`. The builder also computes
base64 for two later `%s` values, but those are not the payload channel used by the
working CAP/LAN PoC.

### RE `re_init` template

The RE type-6 handler calls builder `0xa950`, which produces:

```
/usr/sbin/mesh_connect.sh re_init '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' %d
```

Raw body fields at `0xe6` and `0x107` are base64-encoded into the seventh and
eighth string positions. Four earlier factory fields are empty; because
`run_with_lock` later invokes unquoted `$@`, those empty words must be populated
or the controlled values shift away from `do_re_init` `$7/$8`. With positions
preserved, `base64 -d` restores the payload before `mimesh_init.sh` evaluates it.

The encoder destinations impose 36/66-byte limits. The adjacent wire fields have
32/64-byte reliable non-overlapping capacities; overlap layouts can use some
additional encoder headroom.

## 7. Web-login verifier (V1)

- Stored at `account.core[common].admin` (UCI) — on a factory/un-mesh-configured
  unit this is the shipped value `73a1d6d0…fa8cdfa24`; on a configured unit it is
  `sha256(admin_password)`.
- The same value is emitted as `web_passwd256` in the type-6 sync JSON.
- `api/xqsystem/login` (authenticator `jsonauth`, `luci/dispatcher.lua`) accepts
  `password == sha256(nonce ‖ stored)` with `nonce = "<type>_<mac>_<time>_<rand>"`,
  `type ≤ 4`, `time` strictly greater than the last value seen for that (type,mac).

## 8. Summary of root causes

1. **Firmware-global shared secret** used as the sole mesh authenticator (§2).
2. **TLS server accepts any client** (`SSL_VERIFY_NONE`) (§1).
3. **Secret material (admin hash) shipped to peers** in the sync config (§7) →
   **V1**, the confirmed admin takeover.
4. **Attacker-controlled mesh initialization values are reparsed by a root
   `eval`.** The combined V1 → V2 CAP/UCI route supplies raw UCI `encryption` values;
   direct CAP/LAN uses an attacker-preencoded type-4 plant, unquoted `$@` splitting,
   and `base64 -d`; the RE/WAN builder base64-encodes raw type-6 fields before
   `do_re_init` decodes them. These are V2 inputs; V1 itself ends at the type-6
   verifier leak. The type-7 handler is limited to CAP/server role and
   `body[0] == 1`, but has no connection-state, HMAC, or `NETMODE` check; the
   later shell gate
   (`NETMODE=whc_cap`, or `NETMODE=lanapmode` with `CAP_MODE=ap`) can block the
   CAP/LAN path before the sink. The factory RE/WAN path reaches
   `re_init` without that gate and is confirmed on hardware. See
   `v2-root-rce.md` for the prerequisites and evidence of each exploit route.
