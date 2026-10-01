# Xiaomi AX3000T (RD03v2) — `cab_meshd` admin takeover and pre-auth root RCE

An adjacent client that can reach Xiaomi's mesh commissioning daemon, `cab_meshd`,
on an initialized CAP (Central Access Point: the root/controller mesh node) can
obtain **web-admin access without the admin password** (V1). V2 is a separate root
command injection in Xiaomi's mesh initialization scripts. On RD03v2 stock 2.0.28
it was confirmed on hardware through three exploit routes: direct V2 RE/WAN
(Range Extender: the satellite/client mesh node) against a factory-reset router,
combined V1 → V2 CAP/UCI against a deliberately prepared gate-open CAP, and the
direct V2 CAP/LAN short-command primitive in that same CAP laboratory state.
On the tested physical unit, normal Xiaomi setup set `NETMODE=whc_cap`: V1
remained exploitable, both CAP-side V2 root routes were blocked, and Direct V2
RE/WAN was unavailable after the router became an initialized CAP. See
[`evidence/hardware-validation.md`](evidence/hardware-validation.md#normal-web-wizard-state-v1-survives-v2-root-routes-unavailable).

> ### Published 2026-09-28
>
> This is the public release of a coordinated-disclosure package, first reported to
> Xiaomi on **2026-08-14** on a stated 45-day timeline. Nothing is patched.
>
> **It ships working proof-of-concept code for all three hardware-confirmed root
> routes** — direct factory RE/WAN, direct gate-open CAP/LAN, and the combined
> V1 → V2 CAP/UCI exploit —
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
| Service | TCP/UDP **19553** on `br-lan` (wired LAN and main Wi-Fi) in CAP mode; outbound discovery and TLS on the selected WAN port in factory RE mode |

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

## V1 — pre-auth admin takeover (confirmed)

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
  valid admin session, read back real admin data). → [`v1-admin-takeover.md`](v1-admin-takeover.md)

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

## V2 — root command injection in mesh initialization

V2 is one vulnerability: attacker-controlled mesh initialization values reach
`mimesh_init.sh:717`'s root shell `eval`. The repository demonstrates three
exploit routes to that sink. Two are V2-only; the third deliberately combines V1
and V2.

### One sink, three exploit routes

| Exploit route | Relationship | Target state and attacker position | Validation |
|---|---|---|---|
| **Direct V2 RE/WAN** (`re_wan_rce.py`) | V2 only; no V1, admin session, or `init_router.py` | Factory-reset router; attacker on the selected WAN-side L2 segment | Hardware: direct `uid=0(root)` callback |
| **Combined V1 → V2 CAP/UCI** (`ota_rce.py`) | V1 obtains admin for the API/UCI plant; V2 executes the stored values | Deliberately prepared, gate-open CAP; attacker on main LAN / Wi-Fi | Hardware: root callback and interactive shell |
| **Direct V2 CAP/LAN** (`rce_poc.py`) | V2-only short-command primitive | Initialized, gate-open CAP; attacker on main LAN / Wi-Fi | Hardware: `id` evaluated as `uid=0(root)`; about four command characters |

V1 never reaches the root `eval`: it ends after the type-6 verifier leak. Only the
combined route uses V1, and there it supplies the admin session for a later UCI
payload plant. See [`v2-root-rce.md`](v2-root-rce.md) for the complete mechanisms,
payload construction, and evidence boundaries.

### Direct V2 RE/WAN exploit

A factory-reset RD03v2 starts `cab_meshd -C` after runtime port assignment gives
the DHCP WAN a nonempty interface name. A rogue CAP on that L2 segment can answer
discovery, complete the reversed mesh authentication, and deliver a type-6
`re_init` payload. The hardware test executed `` `id|nc ATTACKER 80` `` as
`uid=0(root)`.

This is the simplest confirmed root route. It is effectively one-shot per factory
reset because a completed `re_init` sets `INITTED=YES` and stops the RE daemon. The
reliable non-overlapping payload capacities are 32 bytes in `bh_ssid` and 64 bytes
in `bh_pswd`; the encoders permit 36/66 bytes.

### Combined V1 → V2 CAP/UCI exploit

The hardware demonstration first factory-reset the router and ran
`poc/init_router.py --host 192.168.31.1 --reboot`, producing an initialized CAP
with `NETMODE` unset. This is explicit laboratory preparation, not an attacker
capability demonstrated against a normally configured router. In a separate
hardware test, Xiaomi's normal wizard set `NETMODE=whc_cap` and blocked both
CAP-side V2 root routes; no non-reset bypass from that state was demonstrated.

After preparation, `ota_rce.py` uses two separate mesh connections:

1. **V1** leaks `web_passwd256` and mints an admin `stok`.
2. The admin API stores full-length payloads in Wi-Fi `encryption` UCI values.
3. A later V2 type-7 trigger invokes `cap_init`, which reads those values into the
   root `eval`.

The physical test produced a root callback and interactive shell. `cap_init`
briefly drops Wi-Fi; the payload repairs the AP as WPA2 with the PoC's fixed key
and starts a process-lifetime reconnecting shell. It installs no boot persistence.

### Direct V2 CAP/LAN short-command primitive

An initialized CAP in the same gate-open laboratory state also accepts a direct
type-4 plant without V1 or an admin API call. The 19-byte field leaves room for
roughly four command characters after positional padding and base64, so this route
is documented as a constrained primitive. On physical hardware, an `` `id` ``
payload reached the stock root `eval`; the diagnostic archive recorded
`uid=0(root) gid=0(root)` in `bh_ssid` and the resulting wireless configuration.

**CWE-78.** Full writeup: [`v2-root-rce.md`](v2-root-rce.md).

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
ADVISORY.md                  formal advisory (CVSS, CWEs, affected versions)
v1-admin-takeover.md         V1 — admin takeover, full writeup
v2-root-rce.md               V2 sink, three exploit routes, prerequisites and evidence
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
  init_router.py             prepares the gate-open CAP laboratory state
  handshake.py               mesh protocol driver (auth to ST_RUNNING; dumps sync config)
  extract_admin.py           PRIMARY PoC — leak verifier -> mint admin session
  ota_rce.py                 combined V1 -> V2 CAP/UCI route, confirmed on hardware
  re_wan_rce.py              direct V2 RE/WAN exploit, confirmed on hardware
  rce_poc.py                 direct V2 CAP/LAN short-command primitive, hardware confirmed
```

## Disclosure

| Date (UTC) | Event |
|---|---|
| **2026-08-14** | **Day 0** — initial notification to `security@xiaomi.com`: 45-day timeline, publication date stated |
| 2026-08-14 | Priority anchored with OpenTimestamps (Bitcoin-confirmed 2026-08-15) |
| 2026-08-17 | Xiaomi Security Center acknowledged (**day 3**). Full technical package sent, encrypted to the MiSRC PGP key |
| 2026-09-11 | **Day 28** — no substantive technical response in the 25 days since acknowledgement. Report filed with CERT/CC via VINCE: **`VRF#26-09-SFWHW`** |
| **2026-09-28** | **Day 45 — publication.** Technical advisory *and* weaponised proof-of-concept, together |

The initial notification said weaponised PoC code would be withheld for a further
**30 days after a fix**. That plan was **changed on 2026-09-11**, and the change is
recorded in the coordination log. The reasoning: Xiaomi has not confirmed
reproduction, has committed to no timeline, and its published policy allows 180 days
*after a fix plan is complete*. Verified-affected RD05 and RA82, plus unconfirmed
RD13, appear to have no update channel at all. Holding the exploit indefinitely
would leave owners of unpatched devices with nothing they can act on — the opposite
of the point.

**Why the PoC ships with the advisory.** The objective is to let owners of the
analysed model — the **Xiaomi AX3000T (`RD03v2`)** — install OpenWrt **over the air**,
without opening the case or attaching UART. That capability depends on the exploit code, so
the installer and the exploit cannot be separated. The installer is **`RD03v2`-only**:
it does not apply to any other affected model code, and OpenWrt support across the rest
of the range is model-specific — see [Mitigations for owners](mitigations.md) §4 and
[`evidence/cross-model/`](evidence/cross-model/). The installer itself is
[`ADCDS/xiaomi-ota-install`](https://github.com/ADCDS/xiaomi-ota-install).

All testing was performed by the reporter on devices purchased for this purpose. No
third-party or production systems were involved.

**Credit:** Adriel Santos. CVE handling is with CERT/CC and the Xiaomi CNA
(`CNA-2020-0019`).

---

## Xiaomi/mesh-specific terminology

| Term | Meaning in this firmware |
|---|---|
| **CAP** | Central Access Point: the root/controller mesh node |
| **RE** | Range Extender: the satellite/client mesh node |
| **WHC / `xqwhc`** | Xiaomi/Qualcomm whole-home mesh subsystem; the firmware does not clearly spell out the expansion |
| **BH** | Backhaul: the link between CAP and RE |
| **NBH** | Non-backhaul band or interface |
| **APSTA** | Concurrent access-point and station mode |
| **BSD** | Band-steering or unified-Wi-Fi configuration mode flag; the exact vendor expansion is unclear |
| **XQ** | XiaoQiang, used in internal firmware names such as `XQSecureUtil` |
| **`cab`** | Internal component tag in `cab_meshd`; no reliable expansion was found |
| **MiMesh** | Xiaomi's mesh feature name rather than an acronym |
