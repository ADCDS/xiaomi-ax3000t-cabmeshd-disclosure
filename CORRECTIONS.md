# Scope clarification (2026-09-28)

The RD03v2 2.0.28 root-shell result in this repository is real. Its setup state
needs to be stated alongside it. The physical test used a factory reset followed
by [`poc/init_router.py`](poc/init_router.py), which calls
`/api/xqsystem/router_init` with SSIDs only. That sets `INITTED=YES` and starts
the CAP listener after reboot while leaving `NETMODE` unset. The published V1 →
V2 chain was confirmed in this **gate-open** state.
The helper also retains the shipped admin verifier, so this is a temporary
owned-device test or installation state, not a safe long-term configuration.

The stock Xiaomi web wizard has a different normal-router setup path:
`/api/misystem/set_router_normal` calls `mesh_connect.sh init_cap 2`. On the
analysed firmware that can commit `NETMODE=whc_cap` before the CAP listener
starts. `do_cap_init` skips the demonstrated `mimesh_init` root sink in that
mode. We have **not** demonstrated that the V1 admin session can reliably reopen
this V2 path on a router configured through that wizard without a reset.

This changes the interpretation of several statements in the original
publication:

- **V1 remains a serious, independent admin takeover** wherever an initialized
  CAP listener is reachable. It is not gated by `NETMODE=whc_cap`; [issue #29](https://github.com/ADCDS/openwrt-xiaomi-ax3000t-rd03v2/issues/29)
  also shows a verifier leak and admin session in that mode.
- **V2's demonstrated root path is conditional on a gate-open mode.** Its
  physical proof is preserved in [`evidence/hardware-validation.md`](evidence/hardware-validation.md),
  but that test does not establish routine reachability after normal web setup.
- **`get_netmode=4` is not an indicator of compromise.** Normal CAP initialization
  can set `whc_cap`; it does not prove a prior exploit trigger.
- **Stock RD03v2 guest Wi-Fi is not established as an exposure path.** Its
  separate `br-guest` firewall rules reject router input on port 19553. A live
  guest-network test remains to be done.
- **The RE/WAN variant remains an emulation result.** The shipped WAN interface
  name is empty, while the daemon's uninitialized RE startup branch requires a
  nonempty name. Runtime port assignment on a fresh device remains unverified.

The 28-model firmware sweep proves the shared key in those images; sampled
unrelated models have similar listener code. End-to-end admin login and root
execution were tested on RD03v2;
the public RB01 capture independently corroborates the key and handshake. Other
models' complete login and root paths remain inferences, not hardware results.

The source for this recheck is Xiaomi's signed
[`miwifi_rd03v2_firmware_31bf9_2.0.28.bin`](https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rd03v2/miwifi_rd03v2_firmware_31bf9_2.0.28.bin)
(SHA-256 `3138342e564c7d7482fde4a90e1778830180f0eac15e1de5f3ad269f9ba9940f`).
Its shipped `/etc/config/xiaoqiang` has neither `INITTED` nor `NETMODE`; the
relevant paths are `/etc/init.d/cab_meshd:16-38`,
`/usr/sbin/mesh_connect.sh:712-796,1040-1043`,
`/lib/mimesh/mimesh_init.sh:68-95`, and the Lua
`luci/controller/api/misystem.lua` `setRouterInfo` handler.
