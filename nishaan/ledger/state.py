"""Deterministic ledger state machine: validates and applies transactions.

Every node rebuilds this state by replaying its chain, so validation must only
depend on chain contents (block timestamps, never the wall clock).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from .. import pki
from ..crypto.sym import b64d
from .tx import TX_TYPES, tx_id, verify_tx_sig

WM_SCHEMES = {"nishaan-wordshift-tardos/v1"}


class TxInvalid(Exception):
    pass


@dataclass
class LedgerState:
    chain_id: str = ""
    ca_cert: dict | None = None
    params: dict = field(default_factory=dict)
    node_certs: dict = field(default_factory=dict)        # node_id -> cert
    certs: dict = field(default_factory=dict)             # serial -> record
    active_by_subject: dict = field(default_factory=dict)  # subject_id -> serial
    docs: dict = field(default_factory=dict)              # doc_id -> {manifest, tx_id, height}
    sessions: dict = field(default_factory=dict)          # session_id -> {...}
    wm_index: dict = field(default_factory=dict)          # blind index -> session_id
    intent_counts: dict = field(default_factory=dict)     # "doc|subject" -> n
    receipts: dict = field(default_factory=dict)          # session_id -> tx_id
    delivered: dict = field(default_factory=dict)         # delivered_hash -> session_id
    tx_index: dict = field(default_factory=dict)          # tx_id -> (height, idx)
    forensic_access: dict = field(default_factory=dict)   # tx_id -> {doc_id, case_id, evidence_hash, signer}
    findings: dict = field(default_factory=dict)          # forensic_access tx_id -> finding tx_id

    def clone(self) -> "LedgerState":
        return copy.deepcopy(self)

    # ------------------------------------------------------------------ helpers
    def node_ids(self) -> list[str]:
        return sorted(self.node_certs)

    def signer_cert(self, tx: dict) -> dict:
        serial = tx["signer"]
        if self.ca_cert and serial == self.ca_cert["body"]["serial"]:
            return self.ca_cert
        rec = self.certs.get(serial)
        if not rec:
            raise TxInvalid(f"unknown signer {serial}")
        return rec["cert"]

    def _require_active(self, serial: str, role: str | None, at) -> dict:
        rec = self.certs.get(serial)
        if not rec:
            raise TxInvalid(f"unknown certificate {serial}")
        if rec["status"] != "active":
            raise TxInvalid(f"certificate {serial} is {rec['status']}")
        if role and rec["cert"]["body"]["role"] != role:
            raise TxInvalid(f"certificate {serial} has role {rec['cert']['body']['role']}, need {role}")
        ok, why = pki.verify_cert(rec["cert"], self.ca_cert, at)
        if not ok:
            raise TxInvalid(f"certificate {serial}: {why}")
        return rec

    def cert_status_at(self, serial: str, height: int) -> str:
        """Key history: was the certificate usable at a given height?"""
        rec = self.certs.get(serial)
        if not rec:
            return "unknown"
        if rec["enrolled_at"] > height:
            return "not-yet-enrolled"
        if rec.get("revoked_at") is not None and rec["revoked_at"] <= height:
            return "revoked"
        if rec.get("superseded_at") is not None and rec["superseded_at"] <= height:
            return "superseded"
        return "active"

    # ------------------------------------------------------------------ validation
    def validate(self, tx: dict, height: int, block_time) -> None:
        t = tx.get("type")
        if t not in TX_TYPES:
            raise TxInvalid(f"unknown tx type {t}")
        tid = tx_id(tx)
        if tid in self.tx_index:
            raise TxInvalid("duplicate transaction")
        if t == "GENESIS":
            if height != 0:
                raise TxInvalid("GENESIS only allowed at height 0")
            return self._validate_genesis(tx)
        signer = self.signer_cert(tx)
        pk, alg = pki.cert_pub(signer)
        if not verify_tx_sig(tx, pk, alg):
            raise TxInvalid("bad transaction signature")
        getattr(self, "_validate_" + t.lower())(tx, tx["body"], block_time)

    def _validate_genesis(self, tx):
        b = tx["body"]
        ca = b["ca_cert"]
        ok, why = pki.verify_cert(ca, ca)
        if not ok:
            raise TxInvalid("CA root: " + why)
        if tx["signer"] != ca["body"]["serial"]:
            raise TxInvalid("genesis must be signed by CA")
        pk, alg = pki.cert_pub(ca)
        if not verify_tx_sig(tx, pk, alg):
            raise TxInvalid("bad genesis signature")
        for nid, c in b["nodes"].items():
            ok, why = pki.verify_cert(c, ca)
            if not ok or c["body"]["role"] != "node" or c["body"]["subject_id"] != nid:
                raise TxInvalid(f"bad node cert {nid}: {why}")
        n, f = len(b["nodes"]), b["f"]
        if n < 3 * f + 1:
            raise TxInvalid("need n >= 3f+1")

    def _ca_only(self, tx):
        if tx["signer"] != self.ca_cert["body"]["serial"]:
            raise TxInvalid("only the CA may sign this transaction")

    def _validate_enroll(self, tx, b, now):
        self._ca_only(tx)
        cert = b["cert"]
        ok, why = pki.verify_cert(cert, self.ca_cert)
        if not ok:
            raise TxInvalid("cert: " + why)
        cb = cert["body"]
        if cb["serial"] in self.certs:
            raise TxInvalid("serial already enrolled")
        if cb["role"] not in pki.ROLES - {"ca", "node"}:
            raise TxInvalid("role not enrollable")
        cur = self.active_by_subject.get(cb["subject_id"])
        if cb.get("supersedes"):
            if cur != cb["supersedes"]:
                raise TxInvalid("rotation must supersede the subject's active certificate")
        elif cur:
            raise TxInvalid("subject already has an active certificate (use rotation)")

    def _validate_revoke(self, tx, b, now):
        self._ca_only(tx)
        rec = self.certs.get(b["serial"])
        if not rec:
            raise TxInvalid("unknown serial")
        if rec["status"] == "revoked":
            raise TxInvalid("already revoked")

    def _validate_distribute(self, tx, b, now):
        self._require_active(tx["signer"], "sender", now)
        if b["sender_serial"] != tx["signer"]:
            raise TxInvalid("sender mismatch")
        if b["doc_id"] in self.docs:
            raise TxInvalid("doc_id exists")
        if not b["recipients"]:
            raise TxInvalid("no recipients")
        for r in b["recipients"]:
            rec = self._require_active(r["serial"], "recipient", now)
            if rec["cert"]["body"]["subject_id"] != r["subject_id"]:
                raise TxInvalid("recipient subject mismatch")
        self._require_active(b["forensic"]["serial"], "forensic", now)
        com = b["committee"]
        holders = {r["subject_id"] for r in b["recipients"]} | {b["forensic"]["subject_id"]}
        if set(com.get("per_recipient", {})) != holders:
            raise TxInvalid("each recipient and the forensic custodian need their own committee layer")
        for sid, shares in com["per_recipient"].items():
            if set(shares) != set(self.node_certs):
                raise TxInvalid(f"committee shares for {sid} must cover every ledger node")
            if any(not isinstance(v.get("commit"), str) or len(v["commit"]) != 64 for v in shares.values()):
                raise TxInvalid("every committee share needs a SHA3 commitment")
        if not (self.params["f"] + 1 <= com["threshold"] <= len(self.node_certs) - self.params["f"]):
            raise TxInvalid("threshold must be in [f+1, n-f]")
        if b["wm"]["scheme"] not in WM_SCHEMES:
            raise TxInvalid("unknown watermark scheme")
        pol = b["policy"]
        if int(pol.get("max_decryptions", 1)) < 1:
            raise TxInvalid("bad policy")

    def _validate_decrypt_intent(self, tx, b, now):
        rec = self._require_active(tx["signer"], "recipient", now)
        cb = rec["cert"]["body"]
        doc = self.docs.get(b["doc_id"])
        if not doc:
            raise TxInvalid("unknown document")
        m = doc["manifest"]
        if b["recipient_serial"] != tx["signer"] or b["recipient_id"] != cb["subject_id"]:
            raise TxInvalid("record identity does not match signer")
        if b["recipient_pubkey_fingerprint"] != cb["fingerprint"]:
            raise TxInvalid("fingerprint mismatch")
        if cb["subject_id"] not in {r["subject_id"] for r in m["recipients"]}:
            raise TxInvalid("recipient not authorised for this document")
        if b["doc_hash"] != m["doc_hash"]:
            raise TxInvalid("doc_hash mismatch")
        if b["session_id"] in self.sessions:
            raise TxInvalid("session_id reused")
        if b["watermark_index"] in self.wm_index:
            raise TxInvalid("watermark index reused")
        if b["watermark_scheme"] != m["wm"]["scheme"]:
            raise TxInvalid("watermark scheme mismatch")
        pol = m["policy"]
        if pol.get("not_after") and now > pki.parse_iso(pol["not_after"]):
            raise TxInvalid("document access expired (policy)")
        used = self.intent_counts.get(f"{b['doc_id']}|{cb['subject_id']}", 0)
        if used >= int(pol.get("max_decryptions", 1)):
            raise TxInvalid(f"decryption limit reached ({used}/{pol['max_decryptions']})")

    def _validate_delivery_receipt(self, tx, b, now):
        s = self.sessions.get(b["session_id"])
        if not s or s["kind"] != "intent":
            raise TxInvalid("unknown session")
        if b.get("doc_id") != s["doc_id"]:
            raise TxInvalid("receipt document does not match the session")
        self._require_active(tx["signer"], "recipient", now)
        if s["serial"] != tx["signer"] or s["tx_id"] != b["intent_tx_id"]:
            raise TxInvalid("receipt signer must match intent signer")
        if b["session_id"] in self.receipts:
            raise TxInvalid("receipt already recorded")
        if b["delivered_hash"] in self.delivered:
            raise TxInvalid("delivered hash already claimed by another session")

    def _validate_forensic_access(self, tx, b, now):
        rec = self._require_active(tx["signer"], "forensic", now)
        doc = self.docs.get(b["doc_id"])
        if not doc:
            raise TxInvalid("unknown document")
        if doc["manifest"]["forensic"]["subject_id"] != rec["cert"]["body"]["subject_id"]:
            raise TxInvalid("officer is not the document's forensic custodian")
        if b.get("officer_serial") != tx["signer"]:
            raise TxInvalid("officer_serial does not match the signer")
        if b["session_id"] in self.sessions:
            raise TxInvalid("session_id reused")
        if not b.get("case_id") or not b.get("purpose"):
            raise TxInvalid("case_id and purpose required")

    def _validate_forensic_finding(self, tx, b, now):
        self._require_active(tx["signer"], "forensic", now)
        fa = self.forensic_access.get(b.get("forensic_access_tx"))
        if not fa:
            raise TxInvalid("finding must reference a committed FORENSIC_ACCESS record")
        if fa["signer"] != tx["signer"]:
            raise TxInvalid("finding must be signed by the investigating officer")
        for k in ("doc_id", "case_id", "evidence_hash"):
            if fa[k] != b.get(k):
                raise TxInvalid(f"finding {k} does not match the investigation record")
        if b["forensic_access_tx"] in self.findings:
            raise TxInvalid("finding already recorded for this investigation")
        for a in b.get("accused", []):
            s = self.sessions.get(a["session_id"])
            if not s or s["kind"] != "intent" or s["doc_id"] != b["doc_id"]:
                raise TxInvalid("accused session is not a decryption of this document")

    # ------------------------------------------------------------------ apply
    def apply(self, tx: dict, height: int, idx: int) -> None:
        t, b = tx["type"], tx["body"]
        tid = tx_id(tx)
        self.tx_index[tid] = (height, idx)
        if t == "GENESIS":
            self.chain_id = b["chain_id"]
            self.ca_cert = b["ca_cert"]
            self.params = {"f": b["f"], "share_threshold": b["share_threshold"]}
            self.node_certs = dict(b["nodes"])
        elif t == "ENROLL":
            cb = b["cert"]["body"]
            if cb.get("supersedes"):
                old = self.certs[cb["supersedes"]]
                old["status"] = "superseded"
                old["superseded_at"] = height
                old["superseded_by"] = cb["serial"]
            self.certs[cb["serial"]] = {"cert": b["cert"], "status": "active", "enrolled_at": height,
                                        "tx_id": tid, "revoked_at": None, "superseded_at": None}
            self.active_by_subject[cb["subject_id"]] = cb["serial"]
        elif t == "REVOKE":
            rec = self.certs[b["serial"]]
            rec["status"] = "revoked"
            rec["revoked_at"] = height
            rec["revoke_reason"] = b.get("reason", "")
            sid = rec["cert"]["body"]["subject_id"]
            if self.active_by_subject.get(sid) == b["serial"]:
                del self.active_by_subject[sid]
        elif t == "DISTRIBUTE":
            self.docs[b["doc_id"]] = {"manifest": b, "tx_id": tid, "height": height}
        elif t == "DECRYPT_INTENT":
            self.sessions[b["session_id"]] = {"kind": "intent", "tx_id": tid, "height": height,
                                              "doc_id": b["doc_id"], "serial": tx["signer"],
                                              "subject_id": b["recipient_id"]}
            self.wm_index[b["watermark_index"]] = b["session_id"]
            k = f"{b['doc_id']}|{b['recipient_id']}"
            self.intent_counts[k] = self.intent_counts.get(k, 0) + 1
        elif t == "DELIVERY_RECEIPT":
            self.receipts[b["session_id"]] = tid
            self.delivered[b["delivered_hash"]] = b["session_id"]
        elif t == "FORENSIC_FINDING":
            self.findings[b["forensic_access_tx"]] = tid
        elif t == "FORENSIC_ACCESS":
            self.forensic_access[tid] = {"doc_id": b["doc_id"], "case_id": b["case_id"],
                                         "evidence_hash": b["evidence_hash"], "signer": tx["signer"]}
            self.sessions[b["session_id"]] = {"kind": "forensic", "tx_id": tid, "height": height,
                                              "doc_id": b["doc_id"], "serial": tx["signer"],
                                              "subject_id": self.certs[tx["signer"]]["cert"]["body"]["subject_id"]}

    # ------------------------------------------------------------------ serialisable views
    def summary(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "nodes": self.node_ids(),
            "f": self.params.get("f"),
            "certs": {s: {"subject_id": r["cert"]["body"]["subject_id"],
                          "display_name": r["cert"]["body"]["display_name"],
                          "role": r["cert"]["body"]["role"], "status": r["status"],
                          "fingerprint": r["cert"]["body"]["fingerprint"],
                          "enrolled_at": r["enrolled_at"], "revoked_at": r.get("revoked_at"),
                          "superseded_at": r.get("superseded_at")}
                      for s, r in self.certs.items()},
            "docs": {d: {"title": v["manifest"]["title"], "height": v["height"],
                         "recipients": [r["subject_id"] for r in v["manifest"]["recipients"]],
                         "policy": v["manifest"]["policy"]} for d, v in self.docs.items()},
            "sessions": len(self.sessions),
        }
