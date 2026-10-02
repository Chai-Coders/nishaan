"""Forensic verification pipeline (brief section 9).

Input: a leaked file (PDF, screenshot, photo or scan) and nothing else.

    tier 1  exact copy      SHA3 of the file equals a committed delivery receipt
    tier 2  document match  perceptual page hashes from the distribution manifest
    tier 3  fingerprint     extract word shifts -> Tardos symbols -> score every
                            decryption session of that document -> accuse

The investigation itself is a FORENSIC_ACCESS record on the ledger (who looked,
at what evidence, for which case) and the original is only decryptable after
it commits - investigators are subject to "no log, no key" too.

Output: an attribution report (section 9.3 fields plus scores and error
bounds) and an evidence bundle that tools/verify_evidence.py checks without
trusting this code.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import pki
from .client import watermark_index
from .crypto.sym import aead_decrypt, b64d, b64e, canonical_json, kem_open, sha3_hex
from .ledger import block as B
from .ledger.tx import make_tx, tx_id, verify_tx_sig
from .sender import recover_committee_layer, wrap_aad
from .watermark import engine as W
from .watermark.render import dhash, hamming_hex, load_image, render_pdf

EVIDENCE_FORMAT = "nishaan.evidence/v2"
CTX_BUNDLE = b"nishaan/v1/evidence-bundle"


@dataclass
class Investigation:
    report: dict
    bundle: dict
    case_dir: Path | None


class ForensicError(Exception):
    pass


# ---------------------------------------------------------------------------- helpers

def _page_hashes(data: bytes, filename: str) -> list[str]:
    try:
        if data[:5] == b"%PDF-":
            return [dhash(r) for r in render_pdf(data, 72)]
        return [dhash(load_image(data))]
    except Exception:
        return []


def rank_documents(docs: dict, leaked: bytes, filename: str) -> list[tuple[str, int]]:
    hs = _page_hashes(leaked, filename)
    out = []
    for doc_id, d in docs.items():
        ph = d["manifest"].get("fuzzy", {}).get("page_dhash", [])
        if not hs or not ph:
            out.append((doc_id, 256))
            continue
        out.append((doc_id, min(hamming_hex(a, b) for a in hs for b in ph)))
    return sorted(out, key=lambda x: x[1])


def _forensic_decrypt(ws, officer, client, doc_id: str, case_id: str, purpose: str,
                      leaked_hash: str, filename: str) -> tuple[bytes, bytes, dict, dict, dict]:
    pkg_path = ws.p("packages", f"{doc_id}.nspkg")
    if not pkg_path.exists():
        raise ForensicError(f"package for {doc_id} not in the forensic archive")
    pkg = json.loads(pkg_path.read_text())
    m = pkg["manifest_tx"]["body"]
    me = officer.cert["body"]
    body = {"case_id": case_id, "doc_id": doc_id, "session_id": str(uuid.uuid4()),
            "officer_serial": me["serial"], "purpose": purpose, "evidence_hash": leaked_hash,
            "evidence_name": filename, "timestamp": pki.iso(pki.utcnow())}
    ftx = make_tx("FORENSIC_ACCESS", body, officer.token, me["serial"])
    flog = client.submit(ftx)
    try:
        K_c, rel = recover_committee_layer(officer.token, m, me["subject_id"], flog["tx_id"], body["session_id"], client)
    except PermissionError as e:
        raise ForensicError(str(e)) from None
    wrap = pkg["wraps"][me["subject_id"]]
    K_r = kem_open(officer.token.decaps, wrap["sealed"], wrap_aad(doc_id, me["subject_id"], wrap["serial"]),
                   "doc-key-wrap")
    K = bytes(a ^ b for a, b in zip(K_r, K_c))
    inner = json.loads(aead_decrypt(K, b64d(pkg["payload"]), aad=doc_id.encode()))
    pdf = b64d(inner["pdf"])
    if sha3_hex(pdf) != m["doc_hash"]:
        raise ForensicError("original document hash mismatch")
    wm_secret = kem_open(officer.token.decaps, m["wm"]["escrow"], canonical_json({"doc_id": doc_id}),
                         "wm-secret-escrow")
    if sha3_hex(wm_secret) != m["wm"]["commit"] or wm_secret != b64d(inner["wm_secret"]):
        raise ForensicError("watermark secret does not match its ledger commitment")
    return pdf, wm_secret, m, flog, {"released": rel}


def _header_chain(client, from_height: int) -> list[dict]:
    head = client.height()
    out = []
    for h in range(from_height, head + 1):
        blk = client.call_any("get_block", height=h)
        out.append({"header": blk["header"], "cc": blk["cc"] if h == head else None})
    return out


def verify_session(client, session: dict, seed: bytes | None, manifest: dict, original_hash: str,
                   leaked_hash: str) -> tuple[list[dict], dict, bool]:
    """Every cryptographic check behind an attribution, plus the material for the bundle.
    Returns (checks, material, exact_copy). Checks marked required=False are informational."""
    checks = []

    def chk(name, ok, detail="", required=True):
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "required": required})

    proof = client.call_any("proof", txid=session["tx_id"])
    ok, notes = client.verify_proof(proof)
    chk("Ledger inclusion (Merkle proof to block header)", "Merkle inclusion proof: valid" in notes[0], notes[0])
    chk(f"Block commit certificate ({client.quorum}-of-{len(client.node_ids)} ML-DSA node signatures)",
        ok and "valid node signatures" in notes[1], notes[1])
    tx = proof["tx"]
    rec = tx["body"]
    cert_rec = client.call_any("cert", serial=tx["signer"])
    cert = cert_rec["cert"]
    cok, why = pki.verify_cert(cert, client.ca_cert)
    chk("Recipient certificate issued by offline CA", cok and cert["body"]["subject_id"] == rec["recipient_id"],
        why if cok else why)
    pk, alg = pki.cert_pub(cert)
    chk(f"Recipient {alg} signature over decryption record", verify_tx_sig(tx, pk, alg),
        f"signer {cert['body']['subject_id']} fp {cert['body']['fingerprint'][:16]}...")
    h = proof["header"]["height"]
    revoked_at = cert_rec.get("revoked_at")
    superseded_at = cert_rec.get("superseded_at")
    active = cert_rec["enrolled_at"] <= h and (revoked_at is None or revoked_at > h) and \
        (superseded_at is None or superseded_at > h)
    chk("Key valid at time of decryption (ledger key history)", active,
        f"enrolled at block {cert_rec['enrolled_at']}, record at block {h}"
        + (f", revoked at block {revoked_at}" if revoked_at is not None else ""))
    chk("Record fingerprint matches certificate", rec["recipient_pubkey_fingerprint"] == cert["body"]["fingerprint"])
    chk("Document hash matches manifest and original", rec["doc_hash"] == manifest["doc_hash"] == original_hash)
    receipt_proof, exact = None, False
    if session.get("receipt_tx_id"):
        receipt_proof = client.call_any("proof", txid=session["receipt_tx_id"])
        rok, _ = client.verify_proof(receipt_proof)
        rtx = receipt_proof["tx"]
        rok = rok and rtx["signer"] == tx["signer"] and verify_tx_sig(rtx, pk, alg) \
            and rtx["body"]["session_id"] == rec["session_id"]
        exact = rok and rtx["body"]["delivered_hash"] == leaked_hash
        chk("Delivery receipt signed by the same recipient", rok,
            "leaked file is byte-identical to the delivered copy" if exact
            else "leaked file is a derivative of the delivered copy (not byte-identical)", required=exact)
    if seed is not None:
        chk("Watermark seed matches signed blind index (anti-framing)", watermark_index(seed) == rec["watermark_index"],
            "SHAKE256(seed) == record.watermark_index")
    else:
        chk("Watermark seed escrow opens and matches blind index", False,
            "escrow did not open: this client deviated from the protocol", required=not exact)
    chain = _header_chain(client, h)
    links = all(chain[i + 1]["header"]["prev_hash"] == B.block_hash(chain[i]["header"])
                for i in range(len(chain) - 1))
    head_ok, _ = B.verify_qc(chain[-1]["cc"], client.node_certs, client.chain_id, client.quorum, "COMMIT")
    chk("Hash chain links record block to current head", links and head_ok,
        f"blocks {h}..{chain[-1]['header']['height']}")
    enroll_proof = client.call_any("proof", txid=cert_rec["tx_id"]) if cert_rec.get("tx_id") else None
    material = {"intent_proof": proof, "recipient_cert": cert, "enroll_proof": enroll_proof,
                "receipt_proof": receipt_proof, "seed": b64e(seed) if seed is not None else None, "chain": chain,
                "cert_history": {k: cert_rec.get(k) for k in ("enrolled_at", "revoked_at", "superseded_at", "status")}}
    return checks, material, exact


def bundle_payload(bundle: dict) -> bytes:
    return canonical_json({k: v for k, v in bundle.items() if k not in ("bundle_hash", "officer_signature")})


# ---------------------------------------------------------------------------- main entry

def investigate(ws, officer_id: str, leaked: bytes, filename: str, case_id: str | None = None,
                purpose: str = "Suspected unauthorised disclosure", doc_id: str | None = None,
                eps: float = 1e-6, progress=None, save: bool = True) -> Investigation:
    t0 = time.time()
    steps = []

    def step(name, **info):
        steps.append(dict(step=name, **info))
        if progress:
            progress(steps[-1])

    client = ws.client()
    officer = ws.identity(officer_id)
    case_id = case_id or "CASE-" + time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4].upper()
    leaked_hash = sha3_hex(leaked)
    exact = client.call_any("receipt_by_hash", delivered_hash=leaked_hash)
    step("tier1_exact_hash", match=bool(exact), sha3=leaked_hash)
    docs = client.call_any("docs")
    if not docs:
        raise ForensicError("no documents on the ledger")
    if exact:
        itx = client.call_any("get_tx", txid=exact["intent_tx_id"])
        doc_id = itx["tx"]["body"]["doc_id"]
    ranked = rank_documents(docs, leaked, filename)
    if doc_id is None:
        doc_id = ranked[0][0]
    step("tier2_document", doc_id=doc_id, title=docs[doc_id]["manifest"]["title"],
         ranking=[{"doc_id": d, "title": docs[d]["manifest"]["title"], "dhash_distance": dist}
                  for d, dist in ranked[:5]])

    original, wm_secret, manifest, flog, rel = _forensic_decrypt(
        ws, officer, client, doc_id, case_id, purpose, leaked_hash, filename)
    step("forensic_access_committed", block=flog["height"], tx_id=flog["tx_id"], **rel)

    plan = W.make_plan(original)
    code = W.code_for(wm_secret, plan, manifest["wm"]["code_len"])
    ext = W.extract_any(leaked, filename, original, plan, manifest["wm"]["delta_pt"])
    sym = W.decode(ext, code)
    symbols = "".join("-" if v == -1 else str(int(v)) for v in sym.y)
    step("tier3_extraction", **ext.summary(), **sym.summary())

    sessions = [s for s in client.call_any("sessions_for_doc", doc_id=doc_id) if s["kind"] == "intent"]
    by_sid = {s["session_id"]: s for s in sessions}
    seeds, escrow_issues = {}, []
    for s in sessions:
        rec = s["tx"]["body"]
        try:
            seed = kem_open(officer.token.decaps, rec["watermark_escrow"],
                            canonical_json({"doc_id": doc_id, "session_id": s["session_id"]}), "wm-seed-escrow")
            if watermark_index(seed) != rec["watermark_index"]:
                raise ValueError("blind index mismatch")
            seeds[s["session_id"]] = seed
        except Exception:
            escrow_issues.append({"session_id": s["session_id"], "recipient_id": s["subject_id"], "block": s["height"]})
    acc = W.accuse(sym, code, seeds, eps)
    names = {}
    for row in acc["candidates"]:
        s = by_sid[row["session_id"]]
        names[s["serial"]] = names.get(s["serial"]) or client.call_any("cert", serial=s["serial"])["cert"]["body"]["display_name"]
        row.update(recipient_id=s["subject_id"], block=s["height"], display_name=names[s["serial"]])
    step("tier3_accusation", accused=acc["accused"], threshold=acc["threshold"], m_eff=acc["m_eff"])

    accused_ids = list(acc["accused"])
    if exact and exact["session_id"] not in accused_ids:
        accused_ids.insert(0, exact["session_id"])
    findings, material = [], []
    for sid in accused_ids:
        checks, mat, is_exact = verify_session(client, by_sid[sid], seeds.get(sid), manifest, sha3_hex(original),
                                               leaked_hash)
        row = next((r for r in acc["candidates"] if r["session_id"] == sid), None)
        rec = by_sid[sid]["tx"]["body"]
        if row is None:
            name = client.call_any("cert", serial=by_sid[sid]["serial"])["cert"]["body"]["display_name"]
        findings.append({
            "session_id": sid, "recipient_id": rec["recipient_id"],
            "display_name": row["display_name"] if row else name,
            "recipient_pubkey_fingerprint": rec["recipient_pubkey_fingerprint"],
            "decryption_timestamp": mat["intent_proof"]["header"]["timestamp"],
            "client_timestamp": rec["timestamp"], "device_context": rec["device_context"],
            "ledger_block": mat["intent_proof"]["header"]["height"],
            "ledger_block_hash": B.block_hash(mat["intent_proof"]["header"]),
            "intent_tx_id": by_sid[sid]["tx_id"],
            "merkle_proof": mat["intent_proof"]["path"],
            "score": row["score"] if row else None,
            "false_positive_bound": row["false_positive_bound"] if row else None,
            "bit_agreement": row["bit_agreement"] if row else None, "exact_copy": is_exact,
            "checks": checks, "all_checks_passed": all(c["ok"] for c in checks if c["required"])})
        material.append(dict(mat, session_id=sid))
    for row in acc["candidates"]:
        row["exact_copy"] = any(f["exact_copy"] for f in findings if f["session_id"] == row["session_id"])

    verified = [f for f in findings if f["all_checks_passed"]]
    if len(verified) > 1:
        status = "VERIFIED_COLLUSION"
    elif len(verified) == 1:
        status = "VERIFIED"
    elif findings:
        status = "CHECKS_FAILED"
    elif acc["candidates"] and acc["candidates"][0]["score"] > 0.5 * acc["threshold"]:
        status = "INCONCLUSIVE"
    else:
        status = "NO_ATTRIBUTION"
    warnings = [f"{e['recipient_id']}'s session at block {e['block']} committed a watermark escrow that does not "
                "open: that client deviated from the protocol, so its copy cannot be scored. Investigate the device."
                for e in escrow_issues]

    # commit the finding BEFORE issuing any report: the conclusion itself becomes immutable
    fbody = {"case_id": case_id, "doc_id": doc_id, "forensic_access_tx": flog["tx_id"], "evidence_hash": leaked_hash,
             "status": status, "scheme": manifest["wm"]["scheme"], "code_len": code.m, "eps": eps,
             "threshold": acc["threshold"], "symbols_hash": sha3_hex(symbols.encode()),
             "extraction": {"method": ext.method, "measured": ext.measured, "slots": len(ext.values)},
             "accused": [{"session_id": f["session_id"], "recipient_id": f["recipient_id"], "score": f["score"],
                          "exact_copy": f["exact_copy"]} for f in findings],
             "timestamp": pki.iso(pki.utcnow())}
    finding_log = client.submit(make_tx("FORENSIC_FINDING", fbody, officer.token, officer.serial))
    step("finding_committed", block=finding_log["height"], tx_id=finding_log["tx_id"])

    report = {
        "status": status, "case_id": case_id, "document_id": doc_id, "document_title": manifest["title"],
        "evidence": {"filename": filename, "sha3_256": leaked_hash, "size": len(leaked)},
        "attribution_tier": "exact-copy" if any(f["exact_copy"] for f in findings) else "fingerprint",
        "findings": findings, "warnings": warnings,
        # brief section 9.3 headline fields (first accused recipient)
        **({"watermark_index": by_sid[findings[0]["session_id"]]["tx"]["body"]["watermark_index"],
            "recipient_id": findings[0]["recipient_id"],
            "recipient_pubkey_fingerprint": findings[0]["recipient_pubkey_fingerprint"],
            "session_id": findings[0]["session_id"],
            "decryption_timestamp": findings[0]["decryption_timestamp"],
            "signature_valid": all(c["ok"] for c in findings[0]["checks"] if "signature" in c["check"]),
            "ledger_inclusion_valid": all(c["ok"] for c in findings[0]["checks"] if "Ledger" in c["check"]
                                          or "commit certificate" in c["check"]),
            "ledger_block_hash": findings[0]["ledger_block_hash"],
            "merkle_proof": findings[0]["merkle_proof"]} if findings else {}),
        "fingerprint": {"scheme": manifest["wm"]["scheme"], "extraction": ext.summary(), "symbols": sym.summary(),
                        "threshold": acc["threshold"], "eps_per_innocent": eps,
                        "candidates": acc["candidates"], "escrow_invalid_sessions": escrow_issues},
        "investigation": {"officer": officer.cert["body"]["display_name"], "forensic_access_tx": flog["tx_id"],
                          "forensic_access_block": flog["height"], "purpose": purpose,
                          "finding_tx": finding_log["tx_id"], "finding_block": finding_log["height"]},
        "steps": steps,
        "generated_at": pki.iso(pki.utcnow()),
        "elapsed_s": round(time.time() - t0, 1),
    }

    officer_rec = client.call_any("cert", serial=officer.serial)
    bundle = {
        "format": EVIDENCE_FORMAT,
        "case_id": case_id,
        "trust_anchor": ws.trust_anchor,
        "genesis": ws.genesis,
        "evidence": report["evidence"],
        "document": {"manifest_proof": client.call_any("proof", txid=docs[doc_id]["tx_id"])},
        "forensic_access_proof": client.call_any("proof", txid=flog["tx_id"]),
        "finding_proof": client.call_any("proof", txid=finding_log["tx_id"]),
        "officer": {"cert": officer.cert, "enroll_proof": client.call_any("proof", txid=officer_rec["tx_id"])},
        "fingerprint": {"scheme": manifest["wm"]["scheme"], "code_len": code.m, "c": code.c, "eps": eps,
                        "threshold": acc["threshold"], "delta_pt": manifest["wm"]["delta_pt"],
                        "wm_secret": b64e(wm_secret), "symbols": symbols},
        "sessions": material,
        "report": json.loads(json.dumps(report)),
    }
    bundle["bundle_hash"] = sha3_hex(bundle_payload(bundle))
    bundle["officer_signature"] = b64e(officer.token.sign(bundle_payload(bundle), CTX_BUNDLE))
    report["evidence_bundle_hash"] = bundle["bundle_hash"]

    case_dir = None
    if save:
        case_dir = ws.p("cases", case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "report.json").write_text(json.dumps(report, indent=1))
        (case_dir / "evidence_bundle.json").write_text(json.dumps(bundle))
        (case_dir / ("leaked_" + Path(filename).name)).write_bytes(leaked)
    return Investigation(report, bundle, case_dir)
