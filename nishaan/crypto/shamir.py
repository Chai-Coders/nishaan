"""Shamir secret sharing over GF(2^8), byte-wise (t-of-n).

Used to split the ledger-committee key layer K_c across ledger nodes so that
no single node (or administrator) can release it on its own.
"""
from __future__ import annotations

import os

# GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1, generator 3
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)
    _x &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def split(secret: bytes, n: int, t: int) -> list[tuple[int, bytes]]:
    """Return n shares (x, y_bytes); any t reconstruct the secret."""
    if not (1 <= t <= n <= 255):
        raise ValueError("need 1 <= t <= n <= 255")
    coeffs = [os.urandom(len(secret)) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        out = bytearray()
        for j, s in enumerate(secret):
            # Horner evaluation of s + c1 x + ... + c_{t-1} x^{t-1}
            acc = 0
            for c in reversed(coeffs):
                acc = _mul(acc, x) ^ c[j]
            acc = _mul(acc, x) ^ s
            out.append(acc)
        shares.append((x, bytes(out)))
    return shares


def combine(shares: list[tuple[int, bytes]]) -> bytes:
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share index")
    length = len(shares[0][1])
    out = bytearray(length)
    for i, (xi, yi) in enumerate(shares):
        # Lagrange basis at 0: prod x_j / (x_j - x_i)   (subtraction == xor)
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = _mul(num, xj)
                den = _mul(den, xj ^ xi)
        li = _div(num, den)
        for k in range(length):
            out[k] ^= _mul(yi[k], li)
    return bytes(out)
