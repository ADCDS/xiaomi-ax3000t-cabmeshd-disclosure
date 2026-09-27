# Mitigations for owners

**The product is unpatched as of 2026-09-28.** There is no vendor fix, no fix plan,
and no committed timeline. This document is what you can actually do about it.

If you are a vendor or a defender looking for the code fixes, they are in
[`remediation.md`](remediation.md). This file is for people who own one of these
routers.

---

## 1. Are you affected?

The vulnerability class is **firmware-global and line-wide**, not specific to one
model. The hard-coded mesh key is byte-identical across **28 Xiaomi and Redmi router
model codes** spanning three CPU architectures and three Wi-Fi generations — from the
sub-$25 Mi Router 4A Gigabit Edition to the current BE10000 flagship. Full table and
hashes: [`evidence/cross-model/`](evidence/cross-model/).

The analysed and hardware-confirmed target is the **Xiaomi Router AX3000T
(`RD03v2`)** on MiWiFi/XiaoQiang **2.0.28**. Other models share the flaw; they have
not each been confirmed on hardware, and the over-the-air OpenWrt installer in this
package does **not** apply to them — see §4.

You can check your model from the router's web UI or the Mi Home / Mi WiFi app.

## 2. What is actually exposed

Be precise about the threat model, because it determines what helps:

- The daemon listens on **TCP/UDP 19553 on the LAN bridge (`br-lan`)** — and only
  when the device is initialised and running as a mesh CAP (`INITTED=YES`, which is
  the normal state of a router in use).
- It is **not exposed to the WAN.** A remote attacker on the internet cannot reach it
  directly.
- **The attacker must already be on your LAN or Wi-Fi.** That is the whole
  prerequisite: no credentials, no user interaction, no physical access.

So the question that decides your risk is: **who else can join your network?**

## 3. What does NOT help

Worth stating plainly, because these are the intuitive moves:

- **Changing the admin password.** V1 harvests the stored login *verifier* over the
  mesh protocol regardless of what the password is. A strong password does not stop
  it, and after exploitation the password is known to the attacker anyway.
- **Disabling remote/web management, UPnP, or WAN access.** The flaw is not
  WAN-facing. Closing WAN features changes nothing here.
- **Hiding the SSID, MAC filtering, or a longer Wi-Fi password.** These raise the
  cost of *joining* the network. They do nothing once someone is on it — and the
  attack needs no credentials at all.
- **Guest-network isolation on the same router.** The mesh daemon listens on the LAN
  bridge and is reachable from the guest Wi-Fi too. Putting devices on the guest
  network does not contain this; **if you run guest Wi-Fi for other people, that is
  an exposure path, and turning it off is a real mitigation.**
- **Waiting for a firmware update.** None has been committed to. The vendor's
  published policy allows 180 days *after a fix plan is complete*, and part of the
  affected range appears to have no update channel at all.

## 4. What helps

**Treat the LAN as the security boundary it now is.**

1. **Know who is on your network.** Every client that can reach the router's LAN can
   become root on it. Remove unknown clients.
2. **Turn off guest Wi-Fi** if you cannot guarantee the guests. This is the single
   most effective containment step for a typical home deployment.
3. **Use a strong WPA2/WPA3 key and do not share it.** This does not stop the
   exploit, but it is what keeps the attacker off the LAN in the first place.
4. **Do not deploy this router where untrusted clients share its L2 segment** —
   shared housing, cafés, small business guest access, conference networks. If you
   need public Wi-Fi, serve it from a *different* device on a separate segment, not
   from this router.
5. **If the unit is only an access point or a switch**, remember the daemon still
   runs and still listens on `br-lan`. AP-only operation is not a mitigation.

**The durable fix is to replace the vendor firmware with OpenWrt, where a port
exists.** This is model-specific, and it is the one thing that removes the mesh daemon
entirely rather than merely containing it.

- **Xiaomi AX3000T (`RD03v2`) — over the air.** The exploit chain in this repository
  exists so that owners of this model can install OpenWrt without opening the case or
  attaching UART:

  > [`ADCDS/ax3000t-ota-install`](https://github.com/ADCDS/ax3000t-ota-install) —
  > installer, and the OpenWrt images for `RD03v2`.

  Read [`NOTICE`](NOTICE) first. Two things to know before you start: the install is
  effectively one-way (vendor A/B fallback slots do not survive it — reverting needs an
  initramfs pivot or U-Boot TFTP recovery with a signed stock image), and the installed
  system comes up with **Wi-Fi disabled**, so have an Ethernet cable for the final step
  unless you configure the radios from the RAM system before running `sysupgrade`.

- **Every other affected model — check before you assume.** The installer above is
  **`RD03v2`-only** and will not work on any other model code. OpenWrt support across
  the affected range is **model-specific**. Across the 30 model codes examined, ten
  have upstream OpenWrt support, five more exist only as community forks, two are in
  progress, and **thirteen have no known port at all**. Several of the supported models
  install without serial, through their own stock-firmware web/API exploit; others need
  UART or TFTP. Check the OpenWrt device page for your exact model — the full breakdown
  is in [`evidence/cross-model/`](evidence/cross-model/). Where a port exists, moving
  to OpenWrt is preferable to waiting for a vendor fix.

- **Do not confuse the Wi-Fi 5 `RD05` with the supported "Mi Router 4A Gigabit".**
  They are different silicon: `RD05` is Realtek RTL8197F and has **no known OpenWrt
  port**, while the OpenWrt-supported 4A Gigabit (R4A) is MediaTek MT7621.

- **If your model has no OpenWrt port**, there is no software escape today. Either
  contain the device using the steps above, or replace it. Waiting for a vendor patch
  is not a plan for the part of the range that appears to have no update channel.

## 5. If you think you were compromised

Assume you cannot tell from the device. A successful exploit gives the attacker
`root`; a competent one leaves nothing obvious behind. Absence of indicators is not
evidence of absence.

**Indicators worth checking:**

- **The one-shot gate.** The first successful `cap_init` persists `NETMODE=whc_cap`.
  On a **standalone** router that you never configured as a mesh CAP, that state means
  the trigger has been fired. With an admin session you can read it from the device's
  own API — `api/xqnetwork/get_netmode` — where **`4` means `whc_cap`**. This is the
  closest thing to a reliable tell, and it is a side effect of the exploit's
  one-shot property rather than a designed detection.
- SSH or telnet unexpectedly enabled.
- Admin password changed, or a logged-in session you do not recognise.
- Port-forwarding or DMZ rules you did not create.
- Unexplained reboots, or Wi-Fi configuration that changed on its own (the exploit
  rewrites wireless UCI keys as part of the chain and repairs them afterwards — an
  interrupted run can leave the radios misconfigured).
- Unknown clients in the device list.

**If any of these hold:** factory reset the router, reflash it from a trusted image,
then change the admin password and the Wi-Fi key. Treat **everything that has passed
through the router as disclosed** — including Wi-Fi credentials, any credentials
typed into its admin UI, and DNS traffic. A compromised router is a position from
which to attack everything behind it; rotate accordingly, not just on the router.

## 6. One more thing: your serial number is a credential (V3)

Separately from the above, the per-device root password on this firmware is
`md5(serial + fixed_salt)[:8]`, computed on first boot — **derivable from the serial
number printed on the device label.** On 2.0.x this is not remotely reachable
(telnet and SSH are locked, and the endpoints that would enable them are removed from
this firmware), so it is a hygiene finding today rather than an attack path. But if
you have unlocked SSH or telnet on the unit, treat the label as a secret, because
anyone who can read it can compute your root password. See
[`secondary-findings.md`](secondary-findings.md) § V3.

---

## Reporting

The vulnerability is reported to Xiaomi and is with CERT/CC via VINCE
(`VRF#26-09-SFWHW`). Timeline: [`README.md` § Disclosure](README.md#disclosure).
Vendor fixes proposed: [`remediation.md`](remediation.md).
