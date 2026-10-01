# V1 — pre-auth admin-password-hash disclosure → admin takeover

**Severity: High (CVSS 3.1: 8.8).** An adjacent client that can reach TCP 19553
obtains the router's web-admin login verifier and logs in as `admin`, without
router-admin or mesh credentials, user interaction during the attack, or memory
corruption. Confirmed end-to-end on physical hardware.

## Root cause in one sentence

`cab_meshd`, after a handshake that any peer can forge (the authenticating key is
hard-coded and identical on every unit — see
[`technical-appendix.md`](technical-appendix.md)), sends the router's own
`web_passwd256` — the SHA-256 that the web login compares against — to that peer
inside the mesh config-sync message.

## Preconditions

- Network reach to TCP 19553 on `br-lan` (wired LAN or main Wi-Fi).
- The device is initialised (`INITTED=YES`) and running as a mesh CAP (`-S`), the
  normal state of a deployed router. The inbound CAP TCP listener on `br-lan` is
  absent until then; on a factory unit the owner's first setup opens it. The
  separate factory RE path uses WAN-side discovery and an outbound connection.

No router-admin password or client certificate is needed after network access.
The `NETMODE=whc_cap` shell guard applies to V2's CAP root sink, not to this
verifier disclosure; V1 remains reachable when the initialized CAP listener is
open.

## The disclosure

The handshake (fully specified in the appendix) is:

1. TLS connect — the server sets `SSL_VERIFY_NONE`, so **no client certificate** is
   required.
2. `type-4` auth request: `pass = base64(HMAC-SHA256(K, id))`, where `K` is the
   firmware-global key. The server verifies and moves to `ST_AUTH_SENT`.
3. `type-5` auth reply with `body[0] = 1`: the server moves to `ST_RUNNING`.

On reaching `ST_RUNNING` the CAP runs `send_sync_req` (`0x5420`), which shells out
to `mesh_cmd initbuf` and pushes the resulting JSON to the peer as a `type-6`
message. That JSON contains, among the Wi-Fi settings:

```json
{ ...,
  "web_passwd":    "b3a4190199d9ee7fe73ef9a4942a69fece39a771",
  "web_passwd256": "73a1d6d01003067844cd148b1502a24bb8a305c93dfef55f983da80fa8cdfa24",
  ... }
```

`web_passwd256` is the value stored at `account.core[common].admin` in UCI — i.e.
the exact stored verifier used by the web login.

## Turning the hash into a session

The web login (`api/xqsystem/login`, authenticator `jsonauth` in
`luci/dispatcher.lua`) validates a request as:

```
checkUser(username, nonce, password):   sha256(nonce .. stored_hash) == password
checkNonce(nonce, remote_mac):          nonce = "<type>_<mac>_<time>_<rand>",
                                         type <= 4, time > last-seen mark
```

(`XQSecureUtil.lua`, `getEncryptMode()==1` — true whenever `account.legacy`
exists, which it does on shipped units.) With `stored_hash = web_passwd256` from
V1, the attacker sets `password = sha256(nonce .. web_passwd256)` and a live
UNIX timestamp for the nonce, and the login succeeds. The response returns a valid
`stok` (session token) for the admin UI.

## Why this is full compromise

`admin` on this firmware controls the router: rewrite **DNS** to intercept/redirect
all LAN traffic, add **port-forwards** and open WAN management, disable the
**firewall**, read/change **Wi-Fi and guest passwords**, and change WAN/routing.
For any realistic threat model that is total compromise of the router and a pivot
into the LAN behind it.

**Note on "root".** Admin is not, by itself, a uid-0 shell on this firmware. The
telnet-enable endpoints (`get_telnet`/`set_telnet`) are removed in 2.0.x (confirmed
live: "No page is registered"), and an independent audit found no authenticated
web request that directly executes a root command (see `secondary-findings.md`).
The separate combined V1 → V2 CAP/UCI route uses an admin API only to store payload
data, then a mesh `cap_init` trigger reaches V2's root `eval`. V1 by itself is scoped as
**unauthenticated → full admin**, rated High; it does not establish a uid-0 shell.

## Proof on physical hardware

`poc/extract_admin.py` run against the tested unit:

```
[A] TLS up on 192.168.31.1:19553 (no client cert)
[A] sent type-4 auth (forged constant-key HMAC) ; type-5 -> ST_RUNNING
[A] leaked web_passwd256 = 73a1d6d0…fa8cdfa24
[B] LOGIN OK  stok=04267c28…            <- valid admin session
```

The PoC stops before the `type-7` that would trigger reconfiguration, so it is
non-destructive to persistent configuration. The login does create session and
nonce/replay state. See
[`evidence/hardware-validation.md`](evidence/hardware-validation.md).

## Note on the leaked hash format

`web_passwd256` is `sha256(plaintext_admin_password)` (unsalted). Because the web
login is a challenge over that stored hash, the attacker does **not** need to crack
it — possession of the hash *is* the ability to authenticate (a pass-the-hash).
Cracking it (to recover the plaintext, e.g. for reuse elsewhere) is an additional,
independent risk of shipping an unsalted SHA-256 to unauthenticated peers.

## Fix summary

Do not place `web_passwd`/`web_passwd256` in a peer-visible sync message; mutually
authenticate mesh peers with a per-device/enrollment secret rather than a
firmware-global key; require a client certificate (the server already speaks TLS).
Full recommendations in [`remediation.md`](remediation.md).
