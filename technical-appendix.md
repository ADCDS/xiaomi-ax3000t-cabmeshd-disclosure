# Technical appendix — shared primitives

The primary finding (V1) and the secondary injection sink (V2) enter through the
same unauthenticated surface. This document specifies it once. All offsets are file offsets / virtual addresses in the shipped
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
  it *sends*.
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

Length and type must be NUL-free for the string copies not to stop early
(≥ `0x0100`).

Message type is dispatched by a jump table at `0x688c`–`0x6894`; only types **4,
5, 6, 7** are accepted.

## 4. State machine

Enum (strings at `0x386…`):

```
0 ST_NONE   1 ST_STOP   2 ST_TCP_DONE   3 ST_SSL_DONE
4 ST_AUTH_SENT   5 ST_AUTH_SENT_2   6 ST_RUNNING
```

| Type | Handler | Requires state | Effect |
|---|---|---|---|
| 4 | `process_auth_req` `0x5f04` | 3 `ST_SSL_DONE` (i.e. right after TLS — **pre-auth**) | verifies `pass` (§2); plants `type-4 body[0x90]` (19 B) → `conn+0x10e` at `0x6058`; → `ST_AUTH_SENT` |
| 5 | `process_auth_reply` `0x56ec` | 4 `ST_AUTH_SENT`, `body[0]==1` | `change_state(6)` → `ST_RUNNING`; CAP runs `send_sync_req` `0x5420` and pushes its config as a type-6 message |
| 6 | `process_sync_req` | — | carries a config JSON |
| 7 | `process_sync_reply` `0x63e0` | `ST_RUNNING`, `body[0]==1` | runs the `cap_init` builder `0xa3bc` → `snprintf` `0xa590` → `system()` `0xa598` |

**Type-4 is accepted in `ST_SSL_DONE` — immediately after the TLS handshake, before
any authentication.** That is what makes the whole chain pre-auth: the only gate is
the §2 HMAC, whose key is public knowledge (it is in the firmware).

## 5. Minimal handshake to `ST_RUNNING`

```
TLS connect (no cert)
send type-4:  body[0x00]=id,  body[0x10]=base64(HMAC("q38d364d…", id))
              (put attacker MAC bytes in header[6:0x19] for the V2 sink)
recv type-5 (server's auth reply) + type-4 (server's own auth req)   [ignored]
send type-5:  body[0]=1
recv type-6:  the CAP's config JSON  <-- contains web_passwd256  (V1 stops here)
send type-7:  body[0]=1              <-- triggers cap_init         (V2 sink)
```

## 6. The `cap_init` `system()` template

```
/usr/sbin/mesh_connect.sh cap_init '%s' '%s' '%s' '%s' '%s' '%s' '%s' %d
```

Built at `0xa3bc`; the seven `%s` are checked by `check_injection` (`0x9308`,
blacklist at `0xe2c9`) at `0xa4f8` before `snprintf`. Two of the `%s` are
`base64`-encodings the daemon computes from wire data (encoder `0x2bf8`), which is
the laundering channel the V2 sink abuses.

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
4. **`base64`-launderable C blacklist** feeding a shell consumer that
   **re-splits + `base64 -d` → `eval`** (§6) → **V2**, confirmed remote root RCE. The
   `type-7` handler has no `NETMODE`/state gate in the C code; the shell gate
   (`NETMODE=whc_cap`, self-set by the first `cap_init`) only bounds the CAP/LAN path
   to a one-shot. See `chain2-root-rce.md` for reachability, scope, and the RE/WAN
   variant.
