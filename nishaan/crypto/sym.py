"""Symmetric primitives, hashing, canonical encoding and KEM-DEM sealing."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import pqc


# ---------------------------------------------------------------- encoding

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON used for everything that is hashed or signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


# ---------------------------------------------------------------- hashing (SHA-3 family only)

def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha3_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def shake(data: bytes, n: int) -> bytes:
    return hashlib.shake_256(data).digest(n)


def obj_hash(obj: Any) -> str:
    return sha3_hex(canonical_json(obj))


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


# ---------------------------------------------------------------- AEAD / KDF

def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=salt, info=info).derive(ikm)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Output = nonce(12) || ciphertext || tag(16)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ---------------------------------------------------------------- KEM-DEM (ML-KEM + AES-256-GCM)

def kem_seal(recipient_kem_pk: bytes, plaintext: bytes, aad: bytes, label: str,
             alg: str = pqc.KEM_ALG) -> dict:
    """Encrypt to an ML-KEM public key. ``label`` gives domain separation."""
    kem_ct, ss = pqc.kem_encaps(recipient_kem_pk, alg)
    key = hkdf(ss, info=b"nishaan/kem-seal/" + label.encode() + b"/" + sha3(kem_ct))
    return {"alg": alg, "kem_ct": b64e(kem_ct), "ct": b64e(aead_encrypt(key, plaintext, aad))}


def kem_open(decaps, sealed: dict, aad: bytes, label: str) -> bytes:
    """``decaps`` is a callable kem_ct -> shared secret (keeps the private key inside the token)."""
    kem_ct = b64d(sealed["kem_ct"])
    ss = decaps(kem_ct)
    key = hkdf(ss, info=b"nishaan/kem-seal/" + label.encode() + b"/" + sha3(kem_ct))
    return aead_decrypt(key, b64d(sealed["ct"]), aad)
