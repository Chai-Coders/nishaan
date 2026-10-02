"""Offline identity & key management: local CA, certificates, soft-HSM tokens.

* The CA root signs with SLH-DSA (FIPS 205, hash-based, conservative choice for a
  long-lived root) when liboqs is present, otherwise ML-DSA-87.
* Every other identity holds an ML-DSA-65 signing key and an ML-KEM-768
  decapsulation key.
* ``SoftToken`` stands in for an HSM / TPM / smartcard: private keys are
  encrypted at rest under a PIN (scrypt + AES-256-GCM) and the API only exposes
  ``sign`` and ``decaps`` - private key bytes are never handed to callers.
  Swapping in a PKCS#11 token only requires implementing the same three methods.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .crypto import pqc
from .crypto.sym import (aead_decrypt, aead_encrypt, b64d, b64e, canonical_json, sha3_hex)

CTX_CERT = b"nishaan/v1/cert"

ROLES = {"ca", "sender", "recipient", "node", "forensic"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


# ====================================================================== token

class SoftToken:
    """PIN-protected software key token (HSM/TPM stand-in)."""

    FORMAT = "nishaan.softtoken/v1"

    def __init__(self, meta: dict, secrets: dict):
        self._meta = meta
        self._sig_sk = b64d(secrets["sig_sk"])
        self._kem_sk = b64d(secrets["kem_sk"]) if secrets.get("kem_sk") else None

    # -- creation / persistence ------------------------------------------------
    @classmethod
    def generate(cls, subject_id: str, role: str, sig_alg: str = pqc.SIG_ALG,
                 kem_alg: str | None = pqc.KEM_ALG) -> "SoftToken":
        """Key generation happens 'inside' the token."""
        sig_pk, sig_sk = pqc.sig_keygen(sig_alg)
        meta = {"format": cls.FORMAT, "subject_id": subject_id, "role": role,
                "sig_alg": sig_alg, "sig_pk": b64e(sig_pk), "kem_alg": kem_alg, "kem_pk": None}
        secrets = {"sig_sk": b64e(sig_sk)}
        if kem_alg:
            kem_pk, kem_sk = pqc.kem_keygen(kem_alg)
            meta["kem_pk"] = b64e(kem_pk)
            secrets["kem_sk"] = b64e(kem_sk)
        return cls(meta, secrets)

    def save(self, path: str | Path, pin: str) -> None:
        salt = os.urandom(16)
        key = hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        secrets = {"sig_sk": b64e(self._sig_sk)}
        if self._kem_sk:
            secrets["kem_sk"] = b64e(self._kem_sk)
        blob = aead_encrypt(key, canonical_json(secrets), aad=canonical_json(self._meta))
        doc = dict(self._meta, kdf={"alg": "scrypt", "salt": b64e(salt), "n": 2 ** 14, "r": 8, "p": 1},
                   sealed=b64e(blob))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(doc, indent=1))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: str | Path, pin: str) -> "SoftToken":
        doc = json.loads(Path(path).read_text())
        kdf = doc.pop("kdf")
        blob = b64d(doc.pop("sealed"))
        key = hashlib.scrypt(pin.encode(), salt=b64d(kdf["salt"]), n=kdf["n"], r=kdf["r"],
                             p=kdf["p"], dklen=32)
        try:
            secrets = json.loads(aead_decrypt(key, blob, aad=canonical_json(doc)))
        except Exception:
            raise PermissionError("wrong PIN or corrupted token") from None
        return cls(doc, secrets)

    # -- public info -----------------------------------------------------------
    @property
    def subject_id(self) -> str:
        return self._meta["subject_id"]

    @property
    def role(self) -> str:
        return self._meta["role"]

    @property
    def sig_alg(self) -> str:
        return self._meta["sig_alg"]

    @property
    def sig_pk(self) -> bytes:
        return b64d(self._meta["sig_pk"])

    @property
    def kem_alg(self) -> str | None:
        return self._meta["kem_alg"]

    @property
    def kem_pk(self) -> bytes | None:
        return b64d(self._meta["kem_pk"]) if self._meta.get("kem_pk") else None

    def csr(self, display_name: str) -> dict:
        """Certificate signing request content (public material only)."""
        return {"subject_id": self.subject_id, "display_name": display_name, "role": self.role,
                "sig_alg": self.sig_alg, "sig_pk": self._meta["sig_pk"],
                "kem_alg": self.kem_alg, "kem_pk": self._meta.get("kem_pk")}

    # -- private operations ----------------------------------------------------
    def sign(self, msg: bytes, ctx: bytes) -> bytes:
        return pqc.sign(self._sig_sk, msg, ctx, self.sig_alg)

    def decaps(self, kem_ct: bytes) -> bytes:
        if not self._kem_sk:
            raise ValueError("token has no KEM key")
        return pqc.kem_decaps(self._kem_sk, kem_ct, self.kem_alg)


# ====================================================================== certificates

def fingerprint(sig_pk: bytes) -> str:
    """recipient_pubkey_fingerprint = SHA3-256(ML-DSA public key)."""
    return sha3_hex(sig_pk)


def cert_body(csr: dict, issuer_fpr: str, days: int = 365, supersedes: str | None = None,
              serial: str | None = None, not_before: datetime | None = None) -> dict:
    nb = not_before or utcnow()
    return {
        "type": "nishaan.cert/v1",
        "serial": serial or uuid.uuid4().hex,
        "subject_id": csr["subject_id"],
        "display_name": csr["display_name"],
        "role": csr["role"],
        "sig_alg": csr["sig_alg"], "sig_pk": csr["sig_pk"],
        "kem_alg": csr.get("kem_alg"), "kem_pk": csr.get("kem_pk"),
        "fingerprint": fingerprint(b64d(csr["sig_pk"])),
        "issuer": issuer_fpr,
        "not_before": iso(nb),
        "not_after": iso(nb + timedelta(days=days)),
        "supersedes": supersedes,
    }


def sign_cert(ca_token: SoftToken, body: dict) -> dict:
    return {"body": body, "issuer_sig_alg": ca_token.sig_alg,
            "issuer_sig": b64e(ca_token.sign(canonical_json(body), CTX_CERT))}


def verify_cert(cert: dict, ca_cert: dict, at: datetime | None = None) -> tuple[bool, str]:
    b = cert["body"]
    ca_b = ca_cert["body"]
    if b["issuer"] != ca_b["fingerprint"]:
        return False, "issuer mismatch"
    if cert["issuer_sig_alg"] != ca_b["sig_alg"]:
        return False, "issuer algorithm mismatch"
    if not pqc.verify(b64d(ca_b["sig_pk"]), canonical_json(b), b64d(cert["issuer_sig"]), CTX_CERT,
                      ca_b["sig_alg"]):
        return False, "bad CA signature"
    if b["fingerprint"] != fingerprint(b64d(b["sig_pk"])):
        return False, "fingerprint mismatch"
    if at is not None and not (parse_iso(b["not_before"]) <= at <= parse_iso(b["not_after"])):
        return False, "outside validity period"
    return True, "ok"


def cert_pub(cert: dict) -> tuple[bytes, str]:
    return b64d(cert["body"]["sig_pk"]), cert["body"]["sig_alg"]


def cert_kem(cert: dict) -> tuple[bytes, str]:
    return b64d(cert["body"]["kem_pk"]), cert["body"]["kem_alg"]


# ====================================================================== CA

@dataclass
class Identity:
    token: SoftToken
    cert: dict

    @property
    def subject_id(self):
        return self.cert["body"]["subject_id"]

    @property
    def serial(self):
        return self.cert["body"]["serial"]


class LocalCA:
    """Offline certificate authority (no external CA, no cloud KMS)."""

    def __init__(self, token: SoftToken, cert: dict):
        self.token = token
        self.cert = cert

    @classmethod
    def create(cls, name: str = "Nishaan Offline Root CA", days: int = 3650) -> "LocalCA":
        tok = SoftToken.generate("root-ca", "ca", sig_alg=pqc.root_sig_alg(), kem_alg=None)
        csr = tok.csr(name)
        body = cert_body(csr, issuer_fpr=fingerprint(tok.sig_pk), days=days)
        return cls(tok, sign_cert(tok, body))

    @property
    def fingerprint(self) -> str:
        return self.cert["body"]["fingerprint"]

    def issue(self, csr: dict, days: int = 365, supersedes: str | None = None) -> dict:
        if csr["role"] not in ROLES - {"ca"}:
            raise ValueError("bad role")
        if csr.get("sig_alg") not in ("ML-DSA-65", "ML-DSA-87"):
            raise ValueError("identities must use ML-DSA")
        if csr["role"] in ("recipient", "forensic", "node") and not csr.get("kem_pk"):
            raise ValueError("role requires an ML-KEM key")
        return sign_cert(self.token, cert_body(csr, self.fingerprint, days, supersedes))

    def new_identity(self, subject_id: str, display_name: str, role: str, days: int = 365) -> Identity:
        tok = SoftToken.generate(subject_id, role)
        return Identity(tok, self.issue(tok.csr(display_name), days))
