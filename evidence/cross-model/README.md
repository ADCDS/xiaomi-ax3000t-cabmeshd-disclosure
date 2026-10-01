# The `cab_meshd` key across the Xiaomi router line

The hard-coded HMAC key documented in
[`../../technical-appendix.md`](../../technical-appendix.md) §2 —

```
838d364d8ed3bd085e150211ea6b3715
```

— is **not specific to the AX3000T**. It is byte-identical in **28 distinct Xiaomi
and Redmi router model codes**, across **three CPU architectures** (ARM64, ARM32,
MIPS32el), spanning **Wi-Fi 5, Wi-Fi 6 and Wi-Fi 7 generations**, in firmware that
Xiaomi is **still building and shipping today**.

Every confirmed row below comes from an exact source pinned in
[`sources.tsv`](sources.tsv): 26 Xiaomi CDN images and two public filesystem dumps.
The sweep extracts `/usr/sbin/cab_meshd` and tests for the key. No hardware is
required to reproduce it.

## Results

28 of 28 model codes with an obtainable image contain the key. **Zero exceptions.**

| Model code | Product | Firmware | Arch | Key | `cab_meshd` SHA-256 (first 16) | Source |
|---|---|---|---|---|---|---|
| `RD03` | Xiaomi AX3000T (CN) | 1.0.98 | ARM64 (aarch64) | **YES** | `7538c7488b3c78ca` | Xiaomi CDN |
| `RD23` | Xiaomi AX3000T (International) | 1.0.91_INT | ARM64 (aarch64) | **YES** | `38e08797d614d404` | public dump |
| `RD15` | Xiaomi BE3600 2.5G | 1.0.87 | ARM32 (EABI5) | **YES** | `d053cd869e3ac872` | Xiaomi CDN |
| `RD16` | Xiaomi BE3600 | 1.0.41 | ARM32 (EABI5) | **YES** | `d053cd869e3ac872` | Xiaomi CDN |
| `RD18` | Xiaomi BE5000 | 1.0.91 | ARM32 (EABI5) | **YES** | `af6e619c54c07c32` | Xiaomi CDN |
| `RD08` | Xiaomi BE6500 Pro | 1.1.96 | ARM64 (aarch64) | **YES** | `7515cdaa1cc17ed7` | Xiaomi CDN |
| `RC06` | Xiaomi BE7000 | 1.1.38 | ARM64 (aarch64) | **YES** | `855b4a1feb478e7c` | Xiaomi CDN |
| `RC01` | Xiaomi Router BE10000 | 1.1.56 | ARM64 (aarch64) | **YES** | `855b4a1feb478e7c` | Xiaomi CDN |
| `RN02` | Xiaomi BE6500 | 1.0.42 | ARM32 (EABI5) | **YES** | `e56411092ee9bff2` | Xiaomi CDN |
| `RD05` | Mi Router 4A Gigabit Ed. | (dump) | **MIPS32el** | **YES** | `0565ff99854d3b3e` | public dump |
| `RD01` | Xiaomi (RD01) | 1.0.31 | ARM32 (EABI5) | **YES** | `277df051dffc0f6b` | Xiaomi CDN |
| `RD02` | Xiaomi (RD02) | 1.0.23 | ARM32 (EABI5) | **YES** | `277df051dffc0f6b` | Xiaomi CDN |
| `RB01` | Xiaomi AX3200 | 1.0.83_INT | ARM64 (aarch64) | **YES** | `40637c8250e5a1cb` | Xiaomi CDN (eu.bigota) |
| `RB03` | Redmi AX6S | 1.0.57 | ARM64 (aarch64) | **YES** | `40637c8250e5a1cb` | Xiaomi CDN |
| `RB04` | Xiaomi (RB04) | 1.0.95 | ARM32 (EABI5) | **YES** | `1c5fce20ce5981bc` | Xiaomi CDN |
| `RB06` | Redmi AX6000 | 1.0.67 | ARM64 (aarch64) | **YES** | `10101dcfad7f33c1` | Xiaomi CDN |
| `RB08` | Xiaomi (RB08) | 1.0.75 | ARM32 (EABI5) | **YES** | `bbc66409bba6d1ce` | Xiaomi CDN |
| `RA67` | Redmi AX5 | 1.0.105 | ARM32 (EABI5) | **YES** | `805bc8018d2950fa` | Xiaomi CDN |
| `RA69` | Redmi AX6 | 1.1.17 | ARM64 (aarch64) | **YES** | `5b3fc6e8d496d087` | Xiaomi CDN |
| `RA70` | Xiaomi AX9000 | 1.0.168 | ARM64 (aarch64) | **YES** | `2ca21e2f9b3f2cd6` | Xiaomi CDN |
| `RA71` | Redmi AX1800 | 1.0.93 | **MIPS32el** | **YES** | `09786328a21404ab` | Xiaomi CDN |
| `RA72` | Xiaomi AX6000 | 1.0.122 | ARM64 (aarch64) | **YES** | `c2d21369614f1d8a` | Xiaomi CDN |
| `RA74` | Redmi AX5400 | 1.0.63 | ARM64 (aarch64) | **YES** | `c2d21369614f1d8a` | Xiaomi CDN |
| `RA80` | Xiaomi AX3000 | 1.0.58 | ARM32 (EABI5) | **YES** | `67e3a431b892a964` | Xiaomi CDN |
| `RA81` | Redmi AX3000 | 1.0.68 | ARM32 (EABI5) | **YES** | `67e3a431b892a964` | Xiaomi CDN |
| `RA82` | Xiaomi Mesh System AX3000 | 1.4.31_INT | ARM32 (EABI5) | **YES** | `388e143875070f3b` | Xiaomi CDN |
| `RM1800` | Redmi AX1800 (RM1800) | 1.0.399 | ARM32 (EABI5) | **YES** | `805bc8018d2950fa` | Xiaomi CDN |
| `R3600` | Xiaomi AIoT Router AX3600 | 1.1.25 | ARM64 (aarch64) | **YES** | `5b3fc6e8d496d087` | Xiaomi CDN |

Full detail — complete hashes, sizes, and the exact source used for each row — is in
[`results.tsv`](results.tsv).

### Not confirmed

**One** model code remains without an obtainable image, so it is **unconfirmed, not
negative**: `RD13` (Mesh System AC1200). Given that its closest siblings `RD05` and
`RA82` both carry the key, it very likely does too.

### The Wi-Fi 5 result changes the scope

`RD05` — the **Mi Router 4A Gigabit Edition**, a MIPS, sub-$25, mass-market
**Wi-Fi 5** device — carries the key. This matters more than the raw count:

- The affected set is **not** confined to the post-2020 Wi-Fi 6/7 line. It reaches
  back into Xiaomi's highest-volume product era.
- Budget devices of this class are rarely retired; they stay powered on for years.
- `RD05` is one of the few Xiaomi router lines sold in volume **outside China**,
  which widens the geographic footprint well beyond the CN-only 2.0.x models.

Any estimate of affected units built on "Wi-Fi 6 and newer only" is therefore a
floor, not a central figure.

`RD05` was checked beyond mere key presence, because a binary on disk is not the same
as a running service. Its `/etc/init.d/cab_meshd` is functionally identical to the
current models — `S99` symlink present, and `INITTED=YES` → `cab_meshd -S -i br-lan`
with **no feature flag on the CAP branch** (`meshSupportRE` gates only the RE branch).
Its binary carries the same protocol strings and debug format string. The V2 sink and
its input path are present too, at `mimesh_init.sh:593` and `mesh_connect.sh:920`.
This supports a V1 candidate on `RD05`; complete web-admin login was not
tested on that hardware. Complete V2 exploitation was demonstrated only on `RD03v2`
`2.0.28`: the combined CAP/UCI, direct RE/WAN, and direct CAP/LAN routes on
hardware. See the advisory for their distinct prerequisites and payload limits.

### These devices may have no route to a patch

`RD05`, `RD13` and `RA82` return **no upgrade record at all** from Xiaomi's own update
service, across 22 probe firmware versions, while `RN02` (a current model) returns one
normally. That is consistent with these product lines being end-of-life with no
active update channel.

If so, the affected population includes devices that **cannot be patched even if
Xiaomi wishes to** — which is a further argument that the remediation has to be
architectural (retire the shared key, require per-device secrets) rather than a
firmware bump on each affected model.

**`RD03v2` — the analysed device — has an official public 2.0.28 image.** Xiaomi's
signed [`miwifi_rd03v2_firmware_31bf9_2.0.28.bin`](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rd03v2/miwifi_rd03v2_firmware_31bf9_2.0.28.bin)
has SHA-256 `3138342e564c7d7482fde4a90e1778830180f0eac15e1de5f3ad269f9ba9940f`.
Static analysis of that image complements the physical results in
[`../hardware-validation.md`](../hardware-validation.md).

### OpenWrt is model-specific, not a line-wide escape

The over-the-air OpenWrt installer shipped with this disclosure
([`ADCDS/ax3000t-ota-install`](https://github.com/ADCDS/ax3000t-ota-install)) targets
the analysed model, **`RD03v2`, only**. It does not run on the other 28 verified model
codes and must not be read as a general remedy for the affected range.

OpenWrt support across that range is **model-specific**, and so is the install method.
Checking the 25.12.5 release and the 2026-09-14 snapshot device profiles (all targets
and subtargets), the OpenWrt tree, the PR tracker and the hardware pages gives the
following split across the 30 codes (the 28 verified, `RD03v2`, and the unconfirmed
`RD13`):

| OpenWrt status | Codes |
|---|---|
| **Upstream-supported** | `RD03`, `RD23`, `RB01`, `RB03`, `RB06`, `RA69`, `RA70`, `RA72`, `R3600`, and `RA74` (snapshot/main only) |
| **Community / vendor fork only** | `RA67`, `RA80`, `RA81`, `RA82`, **`RD03v2`** |
| **In progress, not merged** | `RD18` (PR #23960), `RC06` (PRs #20604 / #24209 / #24471) |
| **No known port** | `RD15`, `RD16`, `RD08`, `RC01`, `RN02`, **`RD05`**, `RD01`, `RD02`, `RB04`, `RB08`, `RA71`, `RM1800`, `RD13` |

Two results deserve emphasis:

- **`RD03v2` — the analysed model — is not upstream-supported either.** Its OpenWrt
  port is the community tree maintained alongside this disclosure. Upstream, a first
  install needs UART and TFTP; the installer published here exists to provide a
  **no-serial, over-the-air** first install instead.
- **`RD05` — the mass-market Wi-Fi 5 model this package highlights — has no known
  OpenWrt port.** It is Realtek RTL8197F, unrelated to the MediaTek MT7621 "Mi Router
  4A Gigabit" (R4A) that OpenWrt does support
  ([forum 214980](https://forum.openwrt.org/t/xiaomi-4a-gigabit-rd05-edition-or-something-else/214980)).
  For `RD05`, containment or replacement is the only option.

Where a port does exist, several mainstream models can be installed **without serial**
through a stock-firmware web/API exploit that enables SSH or telnet — for `RD03`/`RD23`,
`RB01`/`RB03`, `RB06`, `RA69`, `R3600`, and `RA70` with caveats — each by its own
documented procedure. Others (`RA72`, some revisions of `RA70`) need UART or TFTP.
Owners of any other affected model should check the OpenWrt device page for their exact
model before assuming an escape path exists; where one exists, replacing the vendor
firmware removes the vulnerable daemon outright and is preferable to waiting for a
vendor fix — see [`../../mitigations.md`](../../mitigations.md) §4.

This is a **point-in-time snapshot (2026-09-15)** and support moves quickly. Hardware
revisions matter more than product names: `RD03` (MediaTek MT7981) and `RD03v2`
(Qualcomm IPQ5018) share the AX3000T name with opposite OpenWrt status, and `RD05` is
not the supported `R4A`.

## What this establishes

1. **The key is firmware-global across the surveyed product line, not per-model.**
   28 model codes, 3 architectures, both CN and international builds, MediaTek and
   Qualcomm and MIPS silicon, spanning Wi-Fi 5 through Wi-Fi 7. A single
   extraction gives the key embedded in the other surveyed images. Functional
   handshake evidence exists for RD03v2 and the public RB01 capture; complete
   login was not tested on every model.
2. **It is present in current, actively-shipped firmware**, including
   `RC01` (Router BE10000) at `1.1.56` and `RD08` (BE6500 Pro) at `1.1.96` — Xiaomi's
   present-generation Wi-Fi 7 flagships. This is not a legacy branch.
3. **The daemon is not being maintained.** `RD03`'s `cab_meshd` is byte-identical
   (`7538c7488b3c…`) across firmware `1.0.47`, `1.0.64`, `1.0.91` and `1.0.98` —
   four releases spanning July 2023 to August 2025. The same binary is shared
   outright between distinct products: `RD15`/`RD16`, `RD01`/`RD02`, `RB01`/`RB03`,
   `RA72`/`RA74`, `RA80`/`RA81`, `RA67`/`RM1800`, `RC06`/`RC01`, `RA69`/`R3600`.
4. **Sampled models share the CAP exposure condition.** `/etc/init.d/cab_meshd`
   was read on models unrelated to the analysed device (`RA71`, `RC01`) and gates
   the listener the same way in each: `NETMODE` not `whc_re`/`wifiapmode`, and
   `INITTED = YES` → `cab_meshd -S -i br-lan` for an initialized CAP. This
   does not prove every deployed router runs in that role or that the full
   admin-login sequence succeeds on each model.
5. **The key is the sole long hex literal** in every binary examined, and in each it
   is adjacent to the daemon's own debug format string
   `INF: id: %s, pass: %s , key: %s` — the log line that prints the peer's key and
   computed `pass`.

Independently of this string-presence sweep, the key is confirmed *functionally* on
`RB01` (AX3200): a 2023 third-party packet capture from that model carries an
authentication token that this key reproduces byte-for-byte. See
[`../independent-validation.md`](../independent-validation.md).

## Why remediation must be line-wide

Xiaomi documents cross-model mesh interoperability across this product generation:
product generation: *"Routers released after Mi AIoT Router AX3600 support mesh
networking with different models of routers"*
(<https://www.mi.com/global/support/article/KA-08474/>), with a maintained
compatibility list at <https://www.miwifi.com/mesh_device/index.html>.

Those public materials do not establish why Xiaomi chose a global key. The binary
evidence itself establishes why **a per-model patch does not resolve this**: any
model left on the shared key keeps the authenticator exposed across the remaining
line. The fix has to be architectural — see
[`../../remediation.md`](../../remediation.md).

## Method / reproduction

[`sweep.sh`](sweep.sh) performs the whole sweep from [`sources.tsv`](sources.tsv).
For CDN rows it downloads the exact image and handles bare SquashFS and UBI layouts.
For the RD23 and RD05 public dumps it fetches the pinned Git commit and selects the
recorded extracted-file path. It emits the same nine-column schema as the committed
[`results.tsv`](results.tsv).

```sh
./sweep.sh
# writes results.generated.tsv + results.generated.log
# exits nonzero and prints a diff command if it differs from results.tsv

# optional isolated output/work locations or a subset:
OUTPUT_TSV=/tmp/results.tsv LOG_FILE=/tmp/sweep.log \
  WORK_DIR=/tmp/cabmeshd-work ONLY_CODES="RD23 RD05" ./sweep.sh
```

Requires `curl`, `git`, `file`, `binwalk`, `unsquashfs`, and `ubireader` (for UBI
images). To spot-check a single model without the script:

```sh
curl -O https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/ra70/miwifi_ra70_firmware_cc424_1.0.168.bin
binwalk miwifi_ra70_firmware_cc424_1.0.168.bin          # find the squashfs offset
tail -c +<offset+1> miwifi_ra70_*.bin > root.sqfs
unsquashfs -d rootfs root.sqfs usr/sbin/cab_meshd
grep -c 838d364d8ed3bd085e150211ea6b3715 rootfs/usr/sbin/cab_meshd    # -> 1
```

Firmware images and extracted binaries are **not** committed to this repository:
they are Xiaomi's copyrighted material and are re-downloadable from the URLs in
[`results.tsv`](results.tsv). The SHA-256 of each extracted `cab_meshd` is recorded
there so any reproduction can be checked against this run.
