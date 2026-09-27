# Independent validation from a public 2023 artefact

The key and wire protocol in [`../technical-appendix.md`](../technical-appendix.md)
were derived by static analysis of a single `cab_meshd` binary (RD03v2, `2.0.28`).
They are **also confirmed by a third-party packet capture published three years
earlier, on a different router model** — which this section reproduces.

Run [`verify_public_capture.py`](verify_public_capture.py) to reproduce; it is pure
computation over published constants and sends nothing.

## The artefact

On **2023-03-15**, John McEleney published two gists containing hex frames captured
from a genuine mesh negotiation between two **Xiaomi AX3200 (RB01)** routers:

| | |
|---|---|
| `xiaomi-enable-mesh-telnet.py` | <https://gist.github.com/jmceleney/33c626a33960ac8a1764614cf57420cd> (created `2023-03-15T01:02:55Z`) |
| `unlock_mi.py` | <https://gist.github.com/jmceleney/890532f8924e1e17048a0b427577ddd3> (created `2023-03-15T13:50:36Z`) |

In the author's words: *"This script simply replays one side of an intercepted
conversation between two Xiaomi RB01 (International) AX3200 routers negotiating
meshing. In effect the script poses as a mesh slave, which causes the mesh master to
enable netmode4."* The goal was `netmode4` for OpenWrt flashing; the frames were
replayed **blindly**, with no protocol analysis. The same frames are embedded
verbatim in `xmir-patcher`'s `connect4.py` (line ~91), which credits both gists.

The capture is therefore **independent of this research, predates it, and comes from
different hardware** (RB01, MediaTek-era) than the RD03v2 (Qualcomm IPQ5018)
analysed here.

## Result 1 — the wire format parses cleanly

The three published frames decode exactly against
[`../technical-appendix.md`](../technical-appendix.md) §3 and §5:

| Documented (§3/§5) | Observed in the 2023 capture |
|---|---|
| version `0x1001` | ✅ all three frames |
| fixed 44-byte (`0x2c`) header, big-endian | ✅ declared body length equals actual body in all three (163, 32, 32) |
| field A at `0x06`, 19 B | ✅ `'8c:de:f9:bf:5d:b6'` |
| field B at `0x19`, 19 B | ✅ `'8c:de:f9:bf:5d:b7'` |
| client sends type-4 → type-5 → type-7 | ✅ sequence is `[4, 5, 7]` |
| type-5 and type-7 carry `body[0] == 1` | ✅ both |
| type-4: `id` at `body[0x00]`, `pass` at `body[0x10]` | ✅ `'add556bcda0708'` / a 44-char base64 value |

Frame 3's body is `01` followed by the literal string
`recv config sync correctly.\n`.

## Result 2 — the hard-coded key reproduces the captured token

The 44-character base64 value at `body[0x10]` of the type-4 frame is the `pass`
field — `base64(HMAC-SHA256(key, id))` per §2, **not** a `web_passwd256` value.
Recomputing it from the key documented in §2:

```
body[0x00] id    = 'add556bcda0708'
body[0x10] pass  = 'P1QRugvzmxtk5P/p1k+FVjrJLqmehIEFBJecGpbQjv8='

key=q38d364d8ed3bd085e150211ea6b3715  ->  P1QRugvzmxtk5P/p1k+FVjrJLqmehIEFBJecGpbQjv8=   <<< MATCH
key=x38d364d8ed3bd085e150211ea6b3715  ->  INcuN7/nBm8n80NCtkbroDUMcvbsIUAb1VMOLSPIOL4=
key=838d364d8ed3bd085e150211ea6b3715  ->  NOPjzY9p1wTjt/D5GFByFBgrBmnSFZQ/bl74BGWKJWQ=
```

**Byte-for-byte, on the `'q'` role variant** — precisely as §2 predicts for a peer
authenticating *to* a CAP (the server verifies an incoming peer with `'q'`).

## What this proves

1. **The key is correct, and is not an artefact of one binary or one model.** A
   capture from a real AX3200 in 2023 authenticates under the key extracted from an
   AX3000T in 2026. The key is not merely *present* as a string across models (see
   [`cross-model/`](cross-model/)) — it is the *live authenticator* on another model.
2. **The role-byte derivation is correct.** Only the `'q'` variant matches; `'x'` and
   the unmodified literal do not. This confirms the `r0 = 1 - mode` byte-select at
   `0x499c`/`0x3c0c`.
3. **The wire format and state machine are correct**, independently of the
   reverse-engineering that produced them.
4. **The pre-auth entry is real and was exercised in the wild.** The 2023 script
   opens TLS with `CERT_NONE` and immediately sends type-4 — the `ST_SSL_DONE`
   acceptance described in §4 — and it worked against a stock router.

This forecloses the objection that the key and protocol are speculative products of
static analysis.

## The credential has been on screen since 2023

Traced against §5, the 2023 script performs the V1 handshake in full:

| §5 step | 2023 script |
|---|---|
| send type-4 (forged constant-key auth) | `hex_string` |
| recv type-5 + type-4 | `response1`, `response2` |
| send type-5, `body[0]=1` | `hex_string2` |
| **recv type-6 — the CAP's sync config, containing `web_passwd256`** | **`response3`, which the script `print`s** |
| send type-7, `body[0]=1` (fires `cap_init`) | `hex_string3` |

`response3` is the type-6 sync message. **Every person who has run that script, or
`xmir-patcher`'s `connect4.py`, since March 2023 has had the target router's
web-admin login verifier printed to their terminal.** It was not recognised as a
credential — the author was after `netmode4`, and the value scrolled past as noise.

V1 has therefore been unauthenticated, remotely reachable, and *observable with
public working code* for over three years.

## Scope of this validation — what it does not show

- It validates §2 (key), §3 (wire format), §4 (pre-auth type-4 acceptance) and the
  §5 handshake. It says nothing about **V2**, the `cap_init` → `eval` sink, which
  rests on the hardware confirmation in
  [`hardware-validation.md`](hardware-validation.md).
- The `pass` value above is **not** a secret: it is a function of the (public) key
  and the `id` in the same frame, and is reproduced here only to demonstrate the
  derivation. No credential belonging to the 2023 author is disclosed by it.
- The captured `id` and MACs are those of the 2023 author's own lab devices, as
  published by them.

## Prior art, stated plainly

Port 19553 was **not** unknown before this research. The 2023 gists and
`xmir-patcher`'s `connect4.py` establish public knowledge of: the port, that the
service is unauthenticated and network-reachable, and that its TLS accepts any
client. What they do not contain is any message-format documentation, field
parsing, protocol model, identification of the credential field, or code execution;
their purpose is to flip a config flag so that a *separate, `stok`-authenticated*
injection becomes reachable.

The claims made in this report are: the first protocol-level analysis of
`cab_meshd`, and the first conversion of that surface into pre-authentication admin
takeover (V1) and root command execution (V2).
