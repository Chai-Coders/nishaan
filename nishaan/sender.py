"""Sender / distribution service.

Encrypt once, distribute to many:

* K      = random 256-bit document key; payload = AES-256-GCM_K(pdf + watermark secret)
* K_c[i] = random 256-bit committee layer *per recipient i*, Shamir-split t-of-n across
           the ledger nodes (each share ML-KEM-encrypted to its node, with a public
           SHA3 commitment in the manifest so a bad share is detected)
* K_r[i] = K xor K_c[i], ML-KEM-wrapped to recipient i (and to the forensic custodian)

Recipient i cannot decrypt without the committee releasing K_c[i], nodes only release
it for a committed decryption record signed by i ("no log, no key"), and one
recipient's released layer is useless to any other recipient.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

from . import pki
from .crypto import shamir
from .crypto.sym import (aead_encrypt, b64e, canonical_json, kem_open, kem_seal, random_bytes, sha3_hex)
from .ledger.tx import make_tx, tx_id
from .watermark import engine as W
from .watermark.render import dhash, render_pdf

PACKAGE_FORMAT = "nishaan.package/v1"


def wrap_aad(doc_id: str, subject_id: str, serial: str) -> bytes:
    return canonical_json({"doc_id": doc_id, "subject_id": subject_id, "serial": serial})


def share_aad(doc_id: str, subject_id: str, node_id: str) -> bytes:
    return canonical_json({"doc_id": doc_id, "subject_id": subject_id, "node_id": node_id})


def share_commitment(doc_id: str, subject_id: str, node_id: str, x: int, y: bytes) -> str:
    return sha3_hex(canonical_json({"doc_id": doc_id, "subject_id": subject_id, "node_id": node_id,
                                    "x": x, "y": b64e(y)}))


def recover_committee_layer(token, manifest: dict, subject_id: str, txid: str, session_id: str,
                            ledger) -> tuple[bytes, dict]:
    """Collect t committee shares for a committed record, checking each against its commitment."""
    doc_id = manifest["doc_id"]
    commits = manifest["committee"]["per_recipient"][subject_id]

    def validate(r):
        aad = canonical_json({"doc_id": doc_id, "session_id": session_id, "node_id": r["node_id"], "tx_id": txid})
        y = kem_open(token.decaps, r["sealed"], aad, "share-release")
        if share_commitment(doc_id, subject_id, r["node_id"], r["x"], y) != commits[r["node_id"]]["commit"]:
            raise ValueError("share does not match its commitment in the manifest")
        return (r["x"], y)
    pts, log = ledger.collect_shares(txid, validate)
    if len(pts) < ledger.share_threshold:
        raise PermissionError(f"only {len(pts)} valid committee shares: {log}")
    return shamir.combine(pts), log


def create_package(sender: pki.Identity, pdf: bytes, title: str, recipients: list[dict],
                   forensic_cert: dict, node_certs: dict, share_threshold: int,
                   classification: str = "RESTRICTED", max_decryptions: int = 3,
                   valid_days: int | None = 30, filename: str = "document.pdf",
                   delta_pt: float = W.DEFAULT_DELTA_PT) -> tuple[dict, dict]:
    """Returns (package, DISTRIBUTE transaction). ``recipients`` are certificates."""
    if pdf[:5] != b"%PDF-":
        raise ValueError("only PDF documents are supported in this version")
    doc_id = str(uuid.uuid4())
    plan = W.make_plan(pdf)
    if len(plan.slots) < 64:
        raise ValueError(f"document has only {len(plan.slots)} watermarkable words (need >= 64)")
    wm_secret = random_bytes(32)
    code = W.code_for(wm_secret, plan)

    K = random_bytes(32)

    inner = canonical_json({"doc_id": doc_id, "filename": filename, "pdf": b64e(pdf),
                            "wm_secret": b64e(wm_secret), "delta_pt": delta_pt, "code_len": code.m,
                            "plan_hash": plan.hash})
    payload = aead_encrypt(K, inner, aad=doc_id.encode())

    node_ids = sorted(node_certs)
    committee: dict = {}
    wraps = {}
    for c in recipients + [forensic_cert]:
        b = c["body"]
        sid = b["subject_id"]
        K_c = random_bytes(32)
        K_r = bytes(a ^ k for a, k in zip(K, K_c))
        committee[sid] = {}
        for nid, (x, y) in zip(node_ids, shamir.split(K_c, len(node_ids), share_threshold)):
            n_pk, n_alg = pki.cert_kem(node_certs[nid])
            committee[sid][nid] = {
                "x": x,
                "sealed": kem_seal(n_pk, y, share_aad(doc_id, sid, nid), "committee-share", n_alg),
                "commit": share_commitment(doc_id, sid, nid, x, y)}
        kem_pk, alg = pki.cert_kem(c)
        wraps[sid] = {"serial": b["serial"],
                      "sealed": kem_seal(kem_pk, K_r, wrap_aad(doc_id, sid, b["serial"]), "doc-key-wrap", alg)}

    f_pk, f_alg = pki.cert_kem(forensic_cert)
    now = pki.utcnow()
    renders = render_pdf(pdf, 72)
    manifest = {
        "doc_id": doc_id, "title": title, "classification": classification, "filename": filename,
        "doc_hash": sha3_hex(pdf), "ct_hash": sha3_hex(payload), "size": len(pdf),
        "sender_serial": sender.serial, "created_at": pki.iso(now),
        "recipients": [{"subject_id": c["body"]["subject_id"], "serial": c["body"]["serial"]} for c in recipients],
        "forensic": {"subject_id": forensic_cert["body"]["subject_id"], "serial": forensic_cert["body"]["serial"]},
        "policy": {"max_decryptions": int(max_decryptions),
                   "not_after": pki.iso(now + timedelta(days=valid_days)) if valid_days else None},
        "committee": {"threshold": share_threshold, "per_recipient": committee},
        "wm": {"scheme": W.SCHEME, "code_len": code.m, "delta_pt": delta_pt, "slots": len(plan.slots),
               "plan_hash": plan.hash, "commit": sha3_hex(wm_secret),
               "escrow": kem_seal(f_pk, wm_secret, canonical_json({"doc_id": doc_id}), "wm-secret-escrow", f_alg)},
        "fuzzy": {"pages": len(renders), "page_dhash": [dhash(r) for r in renders]},
    }
    tx = make_tx("DISTRIBUTE", manifest, sender.token, sender.serial)
    package = {"format": PACKAGE_FORMAT, "doc_id": doc_id, "title": title, "manifest_tx": tx,
               "manifest_tx_id": tx_id(tx), "wraps": wraps, "payload": b64e(payload)}
    return package, tx


def distribute(ws, sender_id: str, pdf: bytes, title: str, recipient_ids: list[str],
               forensic_id: str = "forensic-cell", **kw) -> tuple[dict, dict]:
    """Workspace convenience: build the package, commit the manifest, save the .nspkg file."""
    sender = ws.identity(sender_id)
    client = ws.client()
    recips = [ws.identity(r).cert for r in recipient_ids]
    forensic = ws.identity(forensic_id).cert
    pkg, tx = create_package(sender, pdf, title, recips, forensic, client.node_certs,
                             client.share_threshold, **kw)
    log = client.submit(tx)
    path = ws.p("packages", f"{pkg['doc_id']}.nspkg")
    path.write_text(json.dumps(pkg))
    return pkg, log
