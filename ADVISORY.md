# Security advisory

## Title
Xiaomi Router AX3000T (RD03v2) — `cab_meshd` unauthenticated admin takeover (V1) and
root command execution (V2)

| | |
|---|---|
| **Published** | 2026-09-28 |
| **Status** | **Unpatched** — no fix, fix plan or timeline committed by the vendor as of publication |
| **Reported** | 2026-08-14 to `security@xiaomi.com`; with CERT/CC via VINCE `VRF#26-09-SFWHW` |
| **Credit** | Adriel Santos |
| **PoC** | **Included** — the weaponised chain publishes with this advisory; see [`poc/`](poc/) and [Mitigations for owners](mitigations.md) |

> **Scope clarification, 2026-09-28:** The root-shell hardware test used minimal
> initialization that left `NETMODE` unset. Normal Xiaomi web setup can set
> `whc_cap` and block the demonstrated CAP root path. V1 remains independent of
> that gate. See [`CORRECTIONS.md`](CORRECTIONS.md).

## Affected
- **Analysed product:** Xiaomi Router AX3000T, model `xiaomi.router.rd03v2`
  (`RD03v2`), firmware MiWiFi/XiaoQiang `2.0.28` — where V1 and V2 are confirmed on
  hardware.
- **Shared key — 28 further model codes verified in firmware.** The hard-coded key of V1
  is byte-identical in stock firmware for **28 Xiaomi/Redmi router model codes**
  across **three CPU architectures** (ARM64, ARM32, MIPS32el), CN and international
  builds, and **three Wi-Fi generations**: `RD03 RD23 RD15 RD16 RD18 RD08 RC06 RC01
  RN02 RD05 RD01 RD02 RB01 RB03 RB04 RB06 RB08 RA67 RA69 RA70 RA71 RA72 RA74 RA80
  RA81 RA82 RM1800 R3600`. **28 of 28 obtainable images contain it; zero
  exceptions.** One code (`RD13`, Mesh System AC1200) has no obtainable image and is
  unconfirmed rather than negative. Per-model hashes, firmware URLs and a
  reproduction script: [`evidence/cross-model/`](evidence/cross-model/).

- **The affected range spans Wi-Fi 5 to Wi-Fi 7, and current to end-of-life.** It
  includes currently-shipping flagships (`RC01` BE10000 `1.1.56`, `RD08` BE6500 Pro
  `1.1.96`) — so this is not a legacy branch — and it also includes `RD05`, the
  **Mi Router 4A Gigabit Edition**, a MIPS, mass-market **Wi-Fi 5** device from a
  much higher-volume era and one of the few Xiaomi router lines sold in volume
  outside China. Any scoping that assumes "post-2020 Wi-Fi 6 and newer" understates
  the affected population.

- **Some affected models appear to have no update channel.** `RD05`, `RD13` and
  `RA82` return no upgrade record from Xiaomi's own update service across 22 probe
  firmware versions, while a current model (`RN02`) returns one normally. If those
  lines are end-of-life, the affected population includes devices that cannot be
  patched by a firmware release at all — which is a further argument for retiring
  the shared key architecturally rather than shipping a per-model fix.

- **The OpenWrt escape hatch is `RD03v2`-only.** The over-the-air installer published
  with this advisory targets the analysed model, the Xiaomi AX3000T (`RD03v2`). The
  other 28 verified model codes are **not** served by it, and OpenWrt support across
  them is model-specific — some have upstream ports and some do not. See
  [`mitigations.md`](mitigations.md) §4 and [`evidence/cross-model/`](evidence/cross-model/).

### What is established per model, for V1 versus V2

These two findings have different evidentiary reach, and we state them separately
rather than asserting the stronger one everywhere.

**V1's shared key appears in all 28 surveyed model codes.** The firmware sweep
directly verifies that key in each `cab_meshd` binary, together with matching
protocol/state strings. Listener scripts inspected on unrelated models
(`RA71`, `RC01`) use the same `INITTED=YES` → `cab_meshd -S -i br-lan` CAP
branch. The chain was executed through web-admin login on hardware on
`RD03v2` / `2.0.28`; a public RB01 capture independently confirms the key and
handshake. Complete listener behavior and login were not tested on every
surveyed model.

**V2 is confirmed end-to-end only on `RD03v2` / `2.0.28`.** Its two components are
nonetheless present across generations — the `eval "$key=\"$(json_get_value …)\""`
sink and the raw `mgmt_2g=$(uci -q get wireless.<iface>.encryption)` read that feeds
it appear in `RD05` (Wi-Fi 5, at `mimesh_init.sh:593` / `mesh_connect.sh:920`) and in
`RD03` `1.0.91` (Wi-Fi 6) just as they do in `2.0.28` (`:717` / `:1007`). Two links
were **not** verified outside `2.0.28`: whether those firmwares' admin API exempts
`encryption` from `hackCheck`, and whether the payload survives their `parse_json`
quoting identically. We therefore claim **the sink and its input path are present
across the line; the full chain is demonstrated on `RD03v2` `2.0.28` only.**

The practical consequence for the analysed device is unchanged: V1 alone gives
administrative control. The shared key and listener code call for line-wide
remediation, while complete V1 login on the other models remains inferred.
- **Component:** `/usr/sbin/cab_meshd` and the mesh scripts
- **Exposure:** TCP/UDP 19553 on `br-lan` (LAN + Wi-Fi) when the device runs an
  initialized CAP listener (`INITTED=YES`). The
  `/etc/init.d/cab_meshd` gate producing this exposure was read on unrelated models
  (`RA71`, `RC01`) and is identical.

> **A per-model fix does not resolve V1.** Because the key is global, any model left
> on it keeps the key valid against every other. Remediation must be line-wide; see
> [`remediation.md`](remediation.md). Xiaomi's published cross-model mesh
> interoperability commitment (support article `KA-08474`, compatibility list at
> `miwifi.com/mesh_device/`) is why a single shared key exists in the first place.

## Primary vulnerabilities

### V1 — unauthenticated admin-credential disclosure → takeover
An attacker on the same L2 network completes a mesh handshake authenticated only by
a **hard-coded, firmware-global HMAC key**, over a **TLS server that requires no
client certificate**, and receives the router's **web-admin login verifier**
(`web_passwd256`) in the config-sync message. `sha256(nonce ‖ web_passwd256)` then
logs the attacker in as `admin`.

- **CWEs:** CWE-798 (hard-coded credential/key), CWE-295 (improper certificate
  validation — `SSL_VERIFY_NONE`), CWE-522 / CWE-200 (exposure of the credential
  verifier to a peer).
- **CVSS 3.1:** `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **8.8 (High)**
  (network-adjacent, no privileges, full admin control).
- **Status:** confirmed end-to-end on physical hardware. The key, the wire format
  and the handshake are additionally corroborated by a **third-party packet capture
  published in March 2023 from a different model** (AX3200 / RB01): the key
  documented here reproduces that capture's authentication token byte-for-byte, on
  the `'q'` role variant. See
  [`evidence/independent-validation.md`](evidence/independent-validation.md).

### V2 — unauthenticated OS command execution as root
The `cap_init` handler drives a root shell `eval` with attacker-controlled input. In
the **OTA combined chain** (V1 → V2), the admin session minted by V1 plants a
command-injection payload into Wi-Fi `encryption` UCI keys (exempt from the web input
sanitizer `hackCheck`); a `type-7` trigger then fires `cap_init`, whose
`mimesh_init.sh:717` `eval` executes the raw `encryption` value as root. The direct
injection variants (base64-laundered via the type-4 plant or RE builder) also reach
the same sink in emulation. The physical OTA test used `poc/init_router.py` to
initialize stock while leaving `NETMODE` unset. The normal web wizard can set
`NETMODE=whc_cap`; `do_cap_init` skips this sink in that mode. We have not
demonstrated a non-reset transition from V1 admin to V2 root on such a unit.
- **CWE-78** (OS command injection).
- **CVSS 3.1 for the demonstrated gate-open state:**
  `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **8.8 (High)**. This is not a claim
  that the root path is reachable after ordinary web setup. The RE/WAN variant
  would require a separate exposure assessment if dynamically confirmed.
- **Status: confirmed end-to-end on physical hardware in the gate-open state** via the OTA combined chain
  (V1 admin takeover → plant `encryption` payloads → V2 `cap_init` trigger → root
  callback `uid=0_user=root_host=XiaoQiang` → interactive root shell via reverse
  shell). The device stays online through the exploit (self-repairing payload restores
  valid Wi-Fi encryption). The direct CAP/LAN path (~4-char one-shot) and RE/WAN path
  (~36/66-byte, ungated) are confirmed in emulation. See `poc/ota_rce.py`.

## Secondary findings
- **V3 — weak root-credential design.** Static shared placeholder in `/etc/shadow`
  across models/firmware; the real root password is `md5(SN ‖ salt)[:8]`, derivable
  from the label serial (publicly-reversed `mkxqimage`). Telnet/SSH are locked in
  2.0.x (no network login surface), so this is a hygiene finding today. **CWE-798 /
  CWE-1394.**
- **V4 — latent shared-code RCE `misystem/download_search`.** A `?string` verifier
  bypasses the web filter into an unquoted root `forkExec`; doubly closed on RD03v2
  (feature off + realpath/`/mnt` validator) but exploitable on SKUs with
  `apps.download="1"`. **CWE-78**, shared-code risk.

## Attack prerequisites (V1)
Same-L2 reach to port 19553 on an initialized CAP listener (wired LAN or main
Wi-Fi; any other segment only if its firewall permits that port). No
router-admin or mesh credentials, no user interaction during V1, and no prior
foothold beyond network access. The
authenticating key is public (extractable from any unit's firmware).

## Impact (V1)
Complete administrative control of the router: DNS/WAN/firewall changes and traffic
interception, Wi-Fi password recovery, and lateral movement to LAN devices. The
hard-coded key is identical across **28 surveyed model codes**, so one
extraction exposes a shared authenticator line-wide. Complete web-admin login
was verified on RD03v2 hardware, not separately on every surveyed model.

The disclosure is also not recent: the type-6 sync message carrying `web_passwd256`
has been retrievable by public, working, unauthenticated code since **March 2023**
(see [`evidence/independent-validation.md`](evidence/independent-validation.md)).

## Status of validation
V1 validated end-to-end on physical hardware. V2 validated end-to-end on **physical
hardware after minimal, gate-open initialization** via the OTA combined chain: V1 mints admin → plants `encryption` payloads
→ V2 trigger fires root `eval` → interactive root shell over Wi-Fi. Root callback
(`uid=0_user=root_host=XiaoQiang`) captured repeatedly; interactive BusyBox ash shell
with full device enumeration (`netstat -tlnp`, `uname -a`, model `RD03v2`). The
direct injection paths (CAP/LAN, RE/WAN) are confirmed in emulation. See
[`evidence/hardware-validation.md`](evidence/hardware-validation.md).

Two further lines of evidence, both reproducible by the vendor without hardware:

- **Cross-model key sweep** — stock firmware for 29 model codes downloaded from
  Xiaomi's CDN and searched for the key: 28 of 28 obtainable images contain it, 0
  exceptions, 1 unobtainable.
  [`evidence/cross-model/`](evidence/cross-model/) (`sweep.sh` reproduces it).
- **Independent third-party corroboration** — the key, wire format, role-byte
  derivation and handshake all reproduce a March 2023 packet capture from a
  *different* model (AX3200 / RB01), published three years before this research.
  [`evidence/independent-validation.md`](evidence/independent-validation.md)
  (`verify_public_capture.py` reproduces it; pure computation, sends nothing).

## Prior art and novelty

Stated plainly so that it need not be re-derived in triage.

**Port 19553 was known.** In March 2023 John McEleney published hex frames captured
from a mesh negotiation between two Xiaomi AX3200 (RB01) routers
([gist](https://gist.github.com/jmceleney/33c626a33960ac8a1764614cf57420cd)), later
embedded in `xmir-patcher`'s `connect4.py`. That work establishes public knowledge of
the port, of the service being unauthenticated and network-reachable, and of its TLS
accepting any client. It contains no message-format documentation, no field parsing,
no protocol model, no identification of the credential field, and no code execution;
its purpose is to flip `netmode`→4 so that a *separate, `stok`-authenticated*
injection becomes reachable.

We note explicitly that **parts of the wire format are derivable from those published
frames** — the `0x1001` version, the 44-byte big-endian header, the MAC-string fields,
the 4/5/7 sequence, and the presence of a base64'd 32-byte token are all recoverable by
inspection of the public hex. What the public material does not yield is the key that
makes the token forgeable, the identification of `web_passwd256` in the type-6 reply,
or the `cap_init` sink. In three years of public exposure — 13 gist comments through
2026-07 and four forks, all byte-identical bar an SSL cipher fix — no derivative
mentions a key, an HMAC, field parsing, or a credential.

**Nearest prior CVEs.** `CVE-2020-14109` (command injection in `meshd`, AX3600
≤ 1.1.12, CWE-77, `AV:N/AC:L/**PR:H**/UI:N/S:U/C:H/I:H/A:H` = 7.2) and
`CVE-2020-14119` (`addMeshNode` in `xqnetwork.lua`, AX3600 < 1.1.12) are the only
mesh-related CVEs Xiaomi has published. Per Xiaomi's own advisory text both are
**post-authentication** — CVE-2020-14109 reads
「路由系统中的meshd程序存在命令注入, 导致**管理员权限下的**命令执行」.

Two clarifications to pre-empt, since both cut against a naive reading:

- **`meshd` and `cab_meshd` are different binaries.** They ship separate init scripts
  with mutually exclusive start conditions — `meshd` runs only when
  `INITTED != "YES"`, `cab_meshd`'s CAP server only when `INITTED == "YES"`.
  CVE-2020-14109 is not this daemon.
- **NVD scores CVE-2020-14119 as `PR:N` / 9.8**, contradicting Xiaomi's own
  post-auth description. A reviewer working from NVD alone will see an existing
  pre-auth 9.8 mesh CVE and may assume overlap. It is a different component
  (`xqnetwork.lua`, the Lua web API), a different device generation, and fixed in
  2020. No CVE has been issued for the AX3000T under any of its model
codes (`RD03`, `RD23`, `RD03v2`), and no public advisory or writeup analyses
`cab_meshd`. The only public mentions of the daemon are incidental — `ps`/`netstat`
pastes in forum threads showing `cab_meshd -S -i br-lan`, and a hobbyist patch that
disables it for attack-surface reduction. None treats it as a vulnerability.

The publicly documented state of the art for rooting this product line is
**post-authentication and confined to the MediaTek 1.0.x branch**: the widely-circulated
tutorials (e.g. 恩山 thread 8321180, and its verbatim reposts) chain
`misystem/arn_switch` or `xqsystem/start_binding` using a `stok` obtained by entering
the admin password, and instruct users to downgrade firmware first. They do not
mention the mesh daemon, port 19553, or `web_passwd256`, and they do not cover the
Qualcomm RD03v2 hardware or the 2.0.x branch at all. On 2.0.x, `xmir-patcher`'s entire
exploit set is reported non-functional (`hackCheck version = 3`), with UART the only
remaining route.

**Why this survived the 2.0.x hardening.** Every publicly documented software root
path on this product line requires the admin password: `xmir-patcher`'s exploit
modules all call `web_login()` and derive a `stok` first. Those web-API exploits were
closed on 2.0.x by `hackCheck` v3
(`XQSecureUtil.filterChars = "[=[\n[`;|$&\n]]=]"`) — a **Lua web-API** filter. A
native C daemon on its own socket was never in its scope, which is why `cab_meshd`
came through that hardening pass untouched. V2 compounds this: the `encryption` UCI
field it injects into is *exempt* from the same sanitizer.

**Closest analogue in another vendor's product.** `SYSS-2025-002` /
`CVE-2026-27846` (Christian Zäske, 2026-02-12) describes missing authentication in
Linksys MR9600/MX4200 mesh onboarding, which returns the web admin password and the
Wi-Fi passwords — conceptually very close to V1. It is a different vendor and
protocol, and critically it **requires physical access** (five reset presses to enter
BLE onboarding), where V1 is reachable over Wi-Fi with no interaction. Cited here
because it is the natural comparison, and because it shows this class of mesh-
onboarding credential leak is live in the wider market.

**Claimed as new here:** the extraction of the firmware-global mesh key and the
demonstration that it is shared across 28 model codes; the identification of
`web_passwd256` in the type-6 sync reply as a directly usable login verifier; the
`cap_init` → `eval` root sink; and the conversion of the 19553 surface into a
pre-authentication admin takeover (V1) and root command execution (V2).

**Not claimed:** discovery of port 19553, of the daemon's existence, or of the fact
that its TLS accepts any client — all public since 2023.

**Discoverability — why this should be treated as urgent.** The V1 credential flow is
not buried in the binary. It is **plaintext shell in public GitHub firmware mirrors**
and has been for years:

```
lib/mimesh/mimesh_sync.sh:298    web_passwd256="$(uci -q get account.common.admin)"
lib/mimesh/mimesh_sync.sh:354    …json_str_append … "\"web_passwd256\":\"$web_passwd256\""
usr/sbin/mesh_connect.sh:300     local web_passwd256=$(json_get_value "$jsonbuf" "web_passwd256")
usr/sbin/mesh_connect.sh:337     uci set account.common.admin="$web_passwd256"
```

(verified in `bakabtw/miwifi_rd03_firmware`, fw 1.0.91; the same flow is present across
the dumps listed in [`evidence/cross-model/`](evidence/cross-model/)). Anyone who
opened these files could have seen the router hands its admin verifier to a peer. The
binary supplies only the key needed to become that peer — and it is the sole long hex
literal in the file, sitting next to the daemon's own debug string
`INF: id: %s, pass: %s , key: %s`.

Combined with the fact that the type-6 message has been retrievable by public working
code since March 2023, the barrier to independent rediscovery is low. Absence of a
public report is not evidence that the issue is unknown.

**Two further Xiaomi precedents.** `CVE-2020-14140` — a pre-authentication (`PR:N`)
API leaking the Wi-Fi password, described by Xiaomi as enabling an attacker to "enter
the background". Closest in *shape* to V1 in Xiaomi's own history: a pre-auth secret
disclosure escalating to administrative access. Different component, different secret,
fixed by firmware 2023.2. And `CVE-2020-14099` — hard-coded keys in Xiaomi router
backup-file encryption (CWE-798) — establishes that Xiaomi has previously accepted,
assigned and published a CVE for exactly this weakness class in its router line.

## Remediation
See `remediation.md`. In brief: replace the firmware-global key with a
per-device/enrollment secret and require client-cert TLS; stop shipping
`web_passwd256` to peers; quote `$@` and never `base64 -d`→`eval` peer data; and
salt/rework the root credential.

## Disclosure timeline

| Date (UTC) | Event |
|---|---|
| 2026-08-14 | **Day 0** — initial notification to `security@xiaomi.com`; 45-day timeline, publication date stated |
| 2026-08-14 | Priority anchored with OpenTimestamps (Bitcoin-confirmed 2026-08-15) |
| 2026-08-17 | Xiaomi Security Center acknowledged (**day 3**); full technical package sent, encrypted to the MiSRC PGP key |
| 2026-09-11 | **Day 28** — no substantive technical response in the preceding 25 days; filed with CERT/CC via VINCE as **`VRF#26-09-SFWHW`** |
| **2026-09-28** | **Day 45 — publication** of this advisory **and** the weaponised proof-of-concept |

The PoC is released simultaneously and deliberately, not by omission. The initial
notification proposed withholding it for 30 days after a fix; that plan was changed
on 2026-09-11 because no fix, fix plan or timeline has been committed to. Full
reasoning: [`README.md` § Disclosure](README.md#disclosure).

## Mitigations for owners
The product is **unpatched as of publication**. Owners of the analysed model — the
**Xiaomi AX3000T (`RD03v2`)** — can install OpenWrt over the air using the chain
documented in this advisory; the installer is **`RD03v2`-only**. For the other 28
verified model codes, OpenWrt support is model-specific: ten have upstream ports,
four exist only as community forks, two are in progress and twelve have no known port.
Owners should check the OpenWrt device page for their exact model; where a port
exists, moving to OpenWrt is the durable fix, and where none exists the options are
network-level containment or replacement — see [`mitigations.md`](mitigations.md) §4
and [`evidence/cross-model/`](evidence/cross-model/).

## Credit
Adriel Santos. CVE handling is with CERT/CC and the Xiaomi CNA (`CNA-2020-0019`).
