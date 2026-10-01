# Mitigations for owners

**The product is unpatched as of 2026-09-28.** There is no vendor fix, no fix plan,
and no committed timeline. This document is what you can actually do about it.

If you are a vendor or a defender looking for the code fixes, they are in
[`remediation.md`](remediation.md). This file is for people who own one of these
routers.

---

## 1. Are you affected?

The shared mesh key is **firmware-global and line-wide**, not specific to one
model. It is byte-identical across **28 Xiaomi and Redmi router
model codes** spanning three CPU architectures and three Wi-Fi generations — from the
sub-$25 Mi Router 4A Gigabit Edition to the current BE10000 flagship. Full table and
hashes: [`evidence/cross-model/`](evidence/cross-model/).

The analysed and hardware-confirmed target is the **Xiaomi Router AX3000T
(`RD03v2`)** on MiWiFi/XiaoQiang **2.0.28**. Other models share the key and
similar listener code; complete admin login and root execution have not each
been confirmed on hardware. The over-the-air OpenWrt installer in this
package does **not** apply to them — see §4.

You can check your model from the router's web UI or the Mi Home / Mi WiFi app.

## 2. What is actually exposed

Be precise about the threat model, because it determines what helps:

- The daemon listens on **TCP/UDP 19553 on the LAN bridge (`br-lan`)** when an
  initialized CAP instance is running (`INITTED=YES`).
- On a **factory-reset RD03v2**, the daemon also runs as an RE client on the
  dynamically selected WAN interface. It broadcasts discovery and connects outbound
  to a CAP on that WAN-side L2 segment. This path is confirmed to execute commands
  as root without V1 or an admin session.
- It is not directly reachable from the routed internet, but an attacker sharing the
  upstream Ethernet segment can answer discovery and impersonate the CAP.
- **The attacker must be able to reach the listener**, ordinarily from your
  wired LAN or main Wi-Fi. V1 needs no router-admin or mesh credentials after
  that network access is obtained.

So the question that decides your risk is: **who else can join your network?**

## 3. What does NOT help

Worth stating plainly, because these are the intuitive moves:

- **Changing the admin password.** V1 harvests the stored login *verifier* over the
  mesh protocol regardless of what the password is. A strong password does not stop
  it, and after exploitation the password is known to the attacker anyway.
- **Disabling remote/web management or UPnP.** Neither closes the LAN CAP listener
  or the factory RE client's outbound mesh connection.
- **Hiding the SSID or MAC filtering.** These do not protect a router from
  clients that already have access to its main LAN or Wi-Fi. A strong Wi-Fi key
  still matters because it limits who can join that network.
- **Waiting for a firmware update.** None has been committed to. The vendor's
  published policy allows 180 days *after a fix plan is complete*, and part of the
  affected range appears to have no update channel at all.

## 4. What helps

**Treat the LAN as the security boundary it now is.**

1. **Know who is on your network.** A client that can reach the CAP listener can
   obtain web-admin access. The demonstrated CAP root path additionally requires a
   gate-open mode; the factory RE/WAN root path has separate prerequisites described
   above. See [`v2-root-rce.md`](v2-root-rce.md). Remove unknown clients.
2. **Keep guest isolation enabled and verify it.** Stock RD03v2 guest Wi-Fi uses
   a separate bridge whose firewall rejects port 19553; a custom bridge or
   firewall rule could change that. This boundary is established from the shipped
   stock firewall rules; guest reachability was not tested live. Do not put
   untrusted clients on the main LAN.
3. **Use a strong WPA2/WPA3 key and do not share it.** This does not stop the
   exploit, but it is what keeps the attacker off the LAN in the first place.
4. **Do not deploy this router where untrusted clients share its main L2 segment** —
   shared housing, cafés, small business guest access, conference networks. If you
   need public Wi-Fi, serve it from a *different* device on a separate segment, not
   from this router.
5. **If the unit is only an access point or a switch**, remember the daemon still
   runs and still listens on `br-lan`. AP-only operation is not a mitigation.
6. **Do factory setup only on a trusted upstream L2 segment.** Do not attach a
   reset unit's Ethernet port to a shared apartment, campus, hotel, or provider
   handoff where another subscriber can answer its mesh discovery broadcasts.

**The durable fix is to replace the vendor firmware with OpenWrt, where a port
exists.** This is model-specific, and it is the one thing that removes the mesh daemon
entirely rather than merely containing it.

- **Xiaomi AX3000T (`RD03v2`) — over the air.** The exploit code in this repository
  exists so that owners of this model can install OpenWrt without opening the case or
  attaching UART:

  > [`ADCDS/ax3000t-ota-install`](https://github.com/ADCDS/ax3000t-ota-install) —
  > installer, and the OpenWrt images for `RD03v2`.

  Read [`NOTICE`](NOTICE) first. Two things to know before you start: the install is
  effectively one-way (vendor A/B fallback slots do not survive it — reverting needs an
  initramfs pivot or U-Boot TFTP recovery with a signed stock image), and the installed
  system comes up with **Wi-Fi disabled**, so have an Ethernet cable for the final step
  unless you configure the radios from the RAM system before running `sysupgrade`.
  On stock 2.0.28 configured through the normal Xiaomi wizard, `NETMODE=whc_cap`
  can block this installer’s root step; the documented route then requires a
  full factory reset (erasing settings) followed by minimal initialization.

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

**`NETMODE=whc_cap` is not a compromise indicator.** The router's
`api/xqnetwork/get_netmode` API reports it as `4`, but normal setup can produce
that value without an exploit. It only tells you that the demonstrated CAP
root path is gated in the current state. The shell also gates the sink when
`NETMODE=lanapmode` and `CAP_MODE=ap`.

**Other indicators worth checking:**
- SSH or telnet unexpectedly enabled.
- Admin password changed, or a logged-in session you do not recognise.
- Port-forwarding or DMZ rules you did not create.
- Unexplained reboots, or Wi-Fi configuration that changed on its own (the exploit
  rewrites wireless UCI keys during the V1-assisted OTA delivery and repairs them
  afterwards — an
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
