"""Recipient decryption client: commit-before-decrypt ("no log, no key").

    1. verify the distribution manifest is committed on the ledger
    2. pick a fresh session id and a secret watermark seed
    3. sign the decryption record (ML-DSA) - it binds recipient, document, session
       and a *blind index* SHAKE256(seed) of the watermark; the seed itself is
       escrowed to the forensic custodian with ML-KEM (anti-framing: an insider
       reading the ledger cannot recover anyone's watermark)
    4. commit the record through BFT consensus
    5. collect t threshold shares of this recipient's K_c from ledger nodes (each node
       checks the record is committed, re-encrypts its share to the recipient's ML-KEM
       key); every share is checked against its commitment in the manifest
    6. unwrap K_r, K = K_r xor K_c, decrypt, verify the document hash
    7. embed the session's Tardos fingerprint (word-shift watermark)
    8. commit a delivery receipt with the hash of the exact copy handed over
"""
from __future__ import annotations

import base64
import hashlib
import json
import platform
import time
import uuid
from dataclasses import dataclass, field

from . import pki
from .crypto.sym import (aead_decrypt, b64d, canonical_json, kem_open, kem_seal, random_bytes, shake, sha3_hex)
from .ledger.client import LedgerClient
from .ledger.tx import make_tx, tx_id
from .sender import recover_committee_layer, wrap_aad
from .watermark import engine as W
from .watermark.render import dhash, render_pdf

CLIENT_VERSION = "nishaan-client/0.1"


def watermark_index(seed: bytes) -> str:
    return shake(b"nishaan/wm-index/" + seed, 32).hex()


def device_context() -> dict:
    node = platform.node() or "unknown"
    return {"device_id": hashlib.sha3_256(node.encode()).hexdigest()[:16],
            "os": f"{platform.system()} {platform.release()}", "client_version": CLIENT_VERSION}


@dataclass
class OpenResult:
    pdf: bytes
    session_id: str
    intent_tx_id: str
    receipt_tx_id: str | None
    steps: list = field(default_factory=list)


class DecryptionDenied(Exception):
    pass


def open_package(identity: pki.Identity, package: dict, ledger: LedgerClient,
                 progress=None, ctx: dict | None = None) -> OpenResult:
    steps = []

    def step(name, **info):
        steps.append(dict(step=name, t=round(time.time(), 3), **info))
        if progress:
            progress(steps[-1])

    tx = package["manifest_tx"]
    m = tx["body"]
    doc_id = m["doc_id"]
    me = identity.cert["body"]

    # 1. manifest must be committed and match the package
    proof = ledger.verified_tx(tx_id(tx))
    if proof["tx"] != tx:
        raise DecryptionDenied("package manifest differs from the committed manifest")
    payload = b64d(package["payload"])
    if sha3_hex(payload) != m["ct_hash"]:
        raise DecryptionDenied("ciphertext hash mismatch (package tampered)")
    step("manifest_verified", block=proof["header"]["height"], doc_id=doc_id, title=m["title"])
    wrap = package["wraps"].get(me["subject_id"])
    if wrap is None:
        raise DecryptionDenied(f"{me['subject_id']} is not an authorised recipient")

    # 2-3. session, blind watermark index, escrow, signed record
    session_id = str(uuid.uuid4())
    seed = random_bytes(32)
    forensic = ledger.call_any("cert", serial=m["forensic"]["serial"])["cert"]
    f_pk, f_alg = pki.cert_kem(forensic)
    record = {
        "version": 1,
        "doc_id": doc_id,
        "doc_hash": m["doc_hash"],
        "session_id": session_id,
        "recipient_id": me["subject_id"],
        "recipient_serial": me["serial"],
        "recipient_pubkey_fingerprint": me["fingerprint"],
        "watermark_scheme": m["wm"]["scheme"],
        "watermark_index": watermark_index(seed),
        "watermark_escrow": kem_seal(f_pk, seed, canonical_json({"doc_id": doc_id, "session_id": session_id}),
                                     "wm-seed-escrow", f_alg),
        "timestamp": pki.iso(pki.utcnow()),
        "device_context": ctx or device_context(),
        "ledger_prev_hash": ledger.call_any("head")["hash"],
    }
    intent = make_tx("DECRYPT_INTENT", record, identity.token, me["serial"])
    step("record_signed", alg=identity.token.sig_alg, session_id=session_id,
         watermark_index=record["watermark_index"][:16] + "...")

    # 4. commit BEFORE any key material is released
    log = ledger.submit(intent)
    step("record_committed", block=log["height"], leader=log["leader"], view=log["view"],
         prepare=log["prepare"], commit=log["commit"], tx_id=log["tx_id"])

    # 5. threshold release of this recipient's committee layer K_c[i]
    try:
        K_c, rel = recover_committee_layer(identity.token, m, me["subject_id"], log["tx_id"], session_id, ledger)
    except PermissionError as e:
        raise DecryptionDenied(str(e)) from None
    step("committee_shares", released=rel, threshold=ledger.share_threshold)

    # 6. decrypt
    if wrap["serial"] != me["serial"]:
        raise DecryptionDenied("document was wrapped for a previous key; ask the sender to re-issue")
    K_r = kem_open(identity.token.decaps, wrap["sealed"], wrap_aad(doc_id, me["subject_id"], me["serial"]),
                   "doc-key-wrap")
    K = bytes(a ^ b for a, b in zip(K_r, K_c))
    inner = json.loads(aead_decrypt(K, payload, aad=doc_id.encode()))
    pdf = b64d(inner["pdf"])
    if sha3_hex(pdf) != m["doc_hash"]:
        raise DecryptionDenied("decrypted document hash mismatch")
    step("decrypted", alg="AES-256-GCM", bytes=len(pdf))

    # 7. per-session fingerprint
    wm_secret = b64d(inner["wm_secret"])
    plan = W.make_plan(pdf)
    if plan.hash != m["wm"]["plan_hash"]:
        raise DecryptionDenied("watermark plan mismatch (client version?)")
    code = W.code_for(wm_secret, plan, m["wm"]["code_len"])
    marked = W.embed(pdf, plan, code, seed, m["wm"]["delta_pt"])
    step("watermarked", slots=len(plan.slots), code_length=code.m, delta_pt=m["wm"]["delta_pt"])
    del K, K_r, K_c, wm_secret, seed

    # 8. delivery receipt (exact-copy hash + perceptual hash)
    receipt_id = None
    try:
        rbody = {"session_id": session_id, "intent_tx_id": log["tx_id"], "doc_id": doc_id,
                 "delivered_hash": sha3_hex(marked), "delivered_size": len(marked),
                 "page_dhash": [dhash(r) for r in render_pdf(marked, 72)],
                 "timestamp": pki.iso(pki.utcnow())}
        rlog = ledger.submit(make_tx("DELIVERY_RECEIPT", rbody, identity.token, me["serial"]))
        receipt_id = rlog["tx_id"]
        step("receipt_committed", block=rlog["height"], delivered_hash=rbody["delivered_hash"])
    except Exception as e:  # the intent record alone already attributes the session
        step("receipt_failed", error=str(e))
    return OpenResult(marked, session_id, log["tx_id"], receipt_id, steps)


def open_in_workspace(ws, subject_id: str, doc_id: str, progress=None) -> OpenResult:
    pkg = json.loads(ws.p("packages", f"{doc_id}.nspkg").read_text())
    res = open_package(ws.identity(subject_id), pkg, ws.client(), progress)
    out = ws.p("delivered", subject_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{doc_id}__{res.session_id[:8]}.pdf").write_bytes(res.pdf)
    return res
