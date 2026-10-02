"""RFC 6962 / RFC 9162-style Merkle trees over SHA3-256 with inclusion proofs."""
from __future__ import annotations

from ..crypto.sym import sha3

EMPTY_ROOT = sha3(b"")


def leaf_hash(data: bytes) -> bytes:
    return sha3(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha3(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_root(leaves: list[bytes]) -> str:
    return _mth(leaves).hex()


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> list[str]:
    return [h.hex() for h in _path(index, leaves)]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[str], root_hex: str) -> bool:
    if index >= size or size == 0:
        return False
    fn, sn = index, size - 1
    r = leaf_hash(leaf)
    for p_hex in proof:
        p = bytes.fromhex(p_hex)
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex
