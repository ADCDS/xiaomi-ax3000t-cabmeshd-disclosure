# Remediation

## V1 — the admin takeover (highest priority)

Fixing the shared faults closes the unauthenticated surface:

1. **Replace the hard-coded mesh key with a per-device / per-enrollment secret.**
   `838d364d8ed3bd085e150211ea6b3715` (role byte `q`/`x`) is compiled into every
   unit, so the HMAC authenticates nothing. Derive the mesh secret during pairing
   (per-device factory secret, user-driven enrollment, or an ephemeral key exchange
   bound to physical proximity).

2. **Require mutual TLS.** The daemon already runs TLS but sets `SSL_VERIFY_NONE`.
   Provision mesh peers with certificates at enrollment and set
   `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`.

3. **Stop disclosing the admin verifier.** `send_sync_req` → `mesh_cmd initbuf`
   currently emits `web_passwd`/`web_passwd256` in the peer-visible sync JSON. Remove
   them — a joining node does not need the CAP's web-login verifier.

4. **Bind 19553 to the mesh backhaul only** and firewall it off the client LAN and
   Wi-Fi (including guest).

5. **Salt the stored web password** (`account.core[common].admin` is an unsalted
   `sha256(password)`, so hash possession = login). Move to a salted KDF and make
   the login challenge zero-knowledge w.r.t. the stored secret.

## V2 — the command-injection sink (fix regardless of current reachability)

6. **Quote `$@`** in `run_with_lock` (`mesh_connect.sh:22` → `"$@"`). On direct
   CAP/LAN, unquoted `$@` splits one planted field into the positional pad and
   payload token. On RE/WAN, it drops empty arguments and can shift the later
   backhaul values. Quoting it removes both behaviors, but the decoded-field
   `eval` must still be removed independently.

7. **Remove `eval` from every mesh-initialization input path.** In
   `mimesh_init.sh:717`, `eval "$key=\"`json_get_value …`\""` reparses both raw
   UCI-derived management values and decoded peer fields as shell. Assign without
   `eval`; validate SSIDs, passwords, and management-mode values against strict
   allow-lists first.

8. **Do not rely on the C-level blacklist** (`check_injection`). It is bypassed by
   design on both direct wire paths. CAP/LAN accepts an attacker-preencoded base64
   token that a downstream `base64 -d` restores; RE/WAN checks a daemon-generated
   base64 form and decodes it later. Allow-list, don't deny-list; treat decoded
   values as opaque data end to end.

## V3 — root credential

9. **Remove the static shared placeholder** `$1$MULfKgY6$…` from the base rootfs and
   generate a unique per-device root secret not derivable from the label serial.
   The current `mkxqimage -I` scheme (`md5(SN ‖ salt)[:8]` with a firmware-global
   salt) is publicly reversed, so the root password of any unit is computable from
   its serial. Use a random per-device secret stored in secure factory data.

## V4 — shared-code `download_search`

10. In `XQDownload.searchBitTorrentFile`, **quote the argv** and validate `path`
    with a strict verifier rather than `?string` (which is `return true` and
    bypasses `hackCheck`). Fix centrally: on any SKU where `apps.download="1"`, only
    the `realpath`/`/mnt` check stands between the bypass verifier and root RCE.

## Verification after fixing
- Anonymous TLS to 19553 rejected (no client cert); the ex-hard-coded key fails auth.
- A `type-6` sync capture contains **no** `web_passwd*`.
- `poc/extract_admin.py` fails to obtain a session.
- `poc/rce_poc.py` sink payloads have no effect even via a direct `cap_init` call.
- `poc/re_wan_rce.py` cannot authenticate as a CAP and produces no callback from a
  factory-reset router on an isolated WAN segment.
- `download_search` with a metacharacter `path` is rejected on all SKUs.
