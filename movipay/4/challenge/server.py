#!/usr/bin/env python3
import hashlib
import hmac
import os
import socket
import struct
import threading
import time
from pathlib import Path


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "31336"))
MAX_PACKET = 4096
TIMEOUT = 20

MAGIC = b"MV"
VERSION = 1

TYPE_HELLO = 0x01
TYPE_CHALLENGE = 0x02
TYPE_AUTH = 0x03
TYPE_START = 0x04
TYPE_SETTLE = 0x05
TYPE_RESPONSE = 0x06
TYPE_ERROR = 0xFF

TAG_CLIENT_ID = 0x01
TAG_NONCE = 0x02
TAG_HMAC = 0x03
TAG_ACCOUNT_ID = 0x04
TAG_SESSION = 0x07

ROAM_KEY = b"ROAM_KEY_SECRET"


def load_flag() -> str:
    if flag := os.environ.get("FLAG"):
        return flag.strip()

    configured_path = os.environ.get("FLAG_FILE")
    if configured_path:
        candidates = [Path(configured_path)]
    else:
        candidates = [
            Path(__file__).resolve().parents[1] / "admin" / "flag.txt",
            Path(__file__).with_name("flag.txt"),
        ]

    for flag_path in candidates:
        if flag_path.exists():
            return flag_path.read_text(encoding="utf-8").strip()

    return "VeriTransit{local_demo_flag_set_FLAG_in_production}"


FLAG = load_flag()

SUBSCRIBERS = {
    "EVU-1001": {"operator": "EVU", "plan": "PREMIUM", "rate": 10},
    "EVU-2002": {"operator": "EVU", "plan": "BASIC", "rate": 5},
    "0000-PLATFORM": {"operator": "HUB", "plan": "INTERNAL", "rate": 0},
}


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def encode_frame(frame_type: int, payload: bytes = b"") -> bytes:
    return MAGIC + bytes((VERSION, frame_type)) + struct.pack(">H", len(payload)) + payload


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 6)
    if header[:2] != MAGIC or header[2] != VERSION:
        raise ValueError("bad frame header")
    length = struct.unpack(">H", header[4:6])[0]
    if length > MAX_PACKET:
        raise ValueError("packet too large")
    return header[3], recv_exact(sock, length)


def tlv_build(*items: tuple[int, bytes]) -> bytes:
    out = bytearray()
    for tag, value in items:
        if len(value) > 255:
            raise ValueError("TLV value too long")
        out.extend((tag, len(value)))
        out.extend(value)
    return bytes(out)


def tlv_parse(payload: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    pos = 0
    while pos < len(payload):
        if pos + 2 > len(payload):
            raise ValueError("truncated TLV")
        tag, length = payload[pos], payload[pos + 1]
        start = pos + 2
        end = start + length
        if end > len(payload):
            raise ValueError("truncated TLV value")
        fields[tag] = payload[start:end]
        pos = end
    return fields


def proof(client_id: str, nonce: bytes) -> bytes:
    return hmac.new(ROAM_KEY, client_id.encode() + nonce, hashlib.sha256).digest()[:8]


class Session:
    def __init__(self) -> None:
        self.client_id = ""
        self.nonce = os.urandom(16)
        self.session_id = os.urandom(8)
        self.billing_account = ""
        self.authed = False


def fail(sock: socket.socket, message: bytes) -> None:
    sock.sendall(encode_frame(TYPE_ERROR, message))


def settle(session: Session) -> bytes:
    account = session.billing_account
    if account not in SUBSCRIBERS:
        return b"INVALID_ACCOUNT"

    # Vulnerability: authentication binds the session to client_id, but the
    # billing account supplied later in START is never rebound to that identity.
    if account == "0000-PLATFORM":
        return FLAG.encode()
    return f"SETTLED:{account}".encode()


def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    sock.settimeout(TIMEOUT)
    session = Session()
    try:
        frame_type, payload = recv_frame(sock)
        if frame_type != TYPE_HELLO:
            fail(sock, b"HELLO_REQUIRED")
            return
        fields = tlv_parse(payload)
        session.client_id = fields[TAG_CLIENT_ID].decode()
        if session.client_id not in SUBSCRIBERS:
            fail(sock, b"UNKNOWN_CLIENT")
            return

        sock.sendall(
            encode_frame(
                TYPE_CHALLENGE,
                tlv_build((TAG_NONCE, session.nonce), (TAG_SESSION, session.session_id)),
            )
        )

        frame_type, payload = recv_frame(sock)
        if frame_type != TYPE_AUTH:
            fail(sock, b"AUTH_REQUIRED")
            return
        fields = tlv_parse(payload)
        if fields.get(TAG_HMAC) != proof(session.client_id, session.nonce):
            fail(sock, b"BAD_AUTH")
            return
        session.authed = True
        sock.sendall(encode_frame(TYPE_RESPONSE, b"AUTH_OK"))

        frame_type, payload = recv_frame(sock)
        if frame_type != TYPE_START:
            fail(sock, b"START_REQUIRED")
            return
        fields = tlv_parse(payload)
        session.billing_account = fields[TAG_ACCOUNT_ID].decode()
        sock.sendall(encode_frame(TYPE_RESPONSE, b"START_OK"))

        frame_type, payload = recv_frame(sock)
        if frame_type != TYPE_SETTLE or payload:
            fail(sock, b"SETTLE_REQUIRED")
            return
        sock.sendall(encode_frame(TYPE_RESPONSE, settle(session)))
    except Exception:
        try:
            fail(sock, b"BAD_SESSION")
        except OSError:
            return
    finally:
        sock.close()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(64)
        print(f"[+] MoviPay roaming hub listening on {HOST}:{PORT}", flush=True)
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
