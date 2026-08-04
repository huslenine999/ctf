#!/usr/bin/env python3

from struct import pack

KEY = [0x13371337, 0x9e3779b9, 0x41414141, 0xdeadbeef]
EXPECTED = [
    0x0b47fdf5, 0xefa4b3ff, 0x9ef010bb, 0x7404ab9a,
    0xa1ab3dd2, 0x78dcc22b, 0x4b76b54a, 0xe9addf9b,
]


def dec(a, b):
    delta = 0x9E3779B9
    total = (delta * 32) & 0xFFFFFFFF

    for _ in range(32):
        b = (b - (((((a << 4) & 0xFFFFFFFF) + KEY[2]) ^ ((a + total) & 0xFFFFFFFF)) + ((a >> 5) + KEY[3]))) & 0xFFFFFFFF
        a = (a - (((((b << 4) & 0xFFFFFFFF) + KEY[0]) ^ ((b + total) & 0xFFFFFFFF)) + ((b >> 5) + KEY[1]))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF

    return a, b


def main():
    out = b""
    for i in range(0, len(EXPECTED), 2):
        a, b = dec(EXPECTED[i], EXPECTED[i + 1])
        out += pack("<II", a, b)

    print(out.decode())


if __name__ == "__main__":
    main()
