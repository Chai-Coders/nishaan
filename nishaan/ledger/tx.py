"""Ledger transactions: every transaction is signed by its author with ML-DSA / SLH-DSA."""
from __future__ import annotations

from ..crypto import pqc
from ..crypto.sym import b64d, b64e, canonical_json, sha3_hex

CTX_TX = b"nishaan/v1/tx"

TX_TYPES = {
    "GENESIS",           # chain parameters, CA root, node certificates (signed by CA)
    "ENROLL",            # new or rotated certificate (signed by CA)
    "REVOKE",            # certificate revocation (signed by CA)
    "DISTRIBUTE",        # document distribution manifest (signed by sender)
    "DECRYPT_INTENT",    # signed decryption record, committed BEFORE decryption (recipient)
    "DELIVERY_RECEIPT",  # hash of the exact watermarked copy delivered (recipient)
    "FORENSIC_ACCESS",   # investigator access to a document, also logged (forensic officer)
    "FORENSIC_FINDING",  # the investigation's result, committed before any report is issued
}


def signing_payload(tx_type: str, body: dict, signer: str) -> bytes:
    return canonical_json({"type": tx_type, "body": body, "signer": signer})


def make_tx(tx_type: str, body: dict, token, signer_serial: str) -> dict:
    assert tx_type in TX_TYPES
    sig = token.sign(signing_payload(tx_type, body, signer_serial), CTX_TX)
    return {"type": tx_type, "body": body, "signer": signer_serial,
            "sig_alg": token.sig_alg, "sig": b64e(sig)}


def tx_id(tx: dict) -> str:
    return sha3_hex(canonical_json(tx))


def verify_tx_sig(tx: dict, sig_pk: bytes, sig_alg: str) -> bool:
    if tx.get("sig_alg") != sig_alg:
        return False
    return pqc.verify(sig_pk, signing_payload(tx["type"], tx["body"], tx["signer"]),
                      b64d(tx["sig"]), CTX_TX, sig_alg)
