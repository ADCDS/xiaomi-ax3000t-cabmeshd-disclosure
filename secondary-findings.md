# Secondary findings

The two primary findings are V1 (admin takeover, `v1-admin-takeover.md`) and V2
(root RCE, `v2-root-rce.md`). These are the lesser items.

---

## V3 — weak root-credential design (static shared hash + SN-derivable password)

**Status: confirmed by source + a public sibling image; not remotely reachable on
2.0.x (telnet/SSH locked), so a hygiene finding today.**

- The shipped `/etc/shadow` root entry `root:$1$MULfKgY6$rdJYoUcznNYSPtoW5M5I3/` is a
  **static placeholder shared across models/firmware** — byte-identical in a public
  extracted sibling image (RD03, fw 1.0.64). Its plaintext is not in `rockyou` or
  common Xiaomi wordlists; it is a build artifact (`last-changed` = 2019-10-22).
- The **real** per-device root password is set on first boot by
  `/etc/init.d/system:17 set_user()` → `mkxqimage -I` → `passwd root` (verified
  present in 2.0.28). The `mkxqimage -I` algorithm is publicly reverse-engineered:
  ```
  salt   = "6d2df50a-250f-4a30-a5e6-d44fb0960aa0"   # GUID from mkxqimage, group-reversed
  root_pw = md5(SN + salt).hexdigest()[:8]           # 8 lowercase-hex chars
  ```
  This is **derivable from the serial printed on the device label** (verified: the
  published example `SN 37668/A1ZZ16727 → 6f4f0acc` reproduces exactly).
- **Not remotely reachable on 2.0.x:** the web endpoints that enable telnet
  (`get_telnet`/`set_telnet`) are **removed** on this firmware (confirmed live: "No
  page is registered"), and on the tested unit **port 23 is closed** despite an
  `S50telnet` symlink in the extracted rootfs — i.e. telnet is not actually running
  on the running firmware. There is no network login surface for the derived
  password today. It remains reachable via serial console, and the design (a static
  shared placeholder + a serial-derivable root password) is weak.

---

## V4 — latent shared-code RCE: `misystem/download_search`

**Status: doubly closed on RD03v2; live on SKUs where `apps.download="1"`. Reported
as shared-code risk.**

- `misystem/download_search` → `XQDownload.searchBitTorrentFile` takes
  `path = formvalue("path", nil, "?string")`. The `?string` datatype verifier is a
  literal `return true`, so it **bypasses the `hackCheck` web filter**, and `path`
  is concatenated **unquoted** into `forkExec(SEARCH.." search "..path.." "..option)`
  (`XQDownload.lua:480/487`) — a clean root command-injection primitive.
- **Closed on RD03v2 by two independent barriers:** the route is registered only
  under `if FEATURES.apps.download=="1"`, and `apps.download="0"` on RD03v2 (source
  + bytecode confirmed) → not registered; and `path` must pass a
  `realpath`-under-`/mnt` validator, so a metacharacter path fails to resolve and
  bails before the sink.
- **Why Xiaomi should care:** on any SKU that ships `apps.download="1"`, only that
  path validator stands between an unauthenticated-of-the-filter `?string` and root
  RCE. This is shared XiaoQiang code; fix it centrally (quote the argv; do not rely
  on `?string` bypassing the filter).

---

## Note on scope of the negative results

An independent static audit of the LuCI web layer found **no** reachable
authenticated admin→root command-injection on RD03v2 2.0.28: the DDNS second-order
chain is closed (attacker fields are urlencoded / shell-quote-escaped / `tonumber`'d
before the root `eval`; the only raw-substituted fields have no writer), config
backup/restore is closed, `upgradeRom` is filtered, and all other shell sinks are
format-constrained, base64, numeric, or filtered. So V1 (admin takeover) does **not**
chain to a root shell through the web layer on this firmware; root command execution
comes from V2 (the mesh path), not the web layer.
