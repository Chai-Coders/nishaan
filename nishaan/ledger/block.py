"""Blocks, votes and quorum certificates (PQC-signed block headers)."""
from __future__ import annotations

from .. import pki
from ..crypto import pqc
from ..crypto.sym import b64d, b64e, canonical_json, sha3_hex
from .merkle import merkle_root
from .tx import tx_id

CTX_VOTE = b"nishaan/v1/vote"
CTX_PROPOSAL = b"nishaan/v1/proposal"
ZERO_HASH = "00" * 32


def block_hash(header: dict) -> str:
    return sha3_hex(canonical_json(header))


def tx_leaves(txs: list[dict]) -> list[bytes]:
    return [bytes.fromhex(tx_id(t)) for t in txs]


def make_header(chain_id: str, height: int, view: int, prev_hash: str, txs: list[dict],
                timestamp: str, proposer: str) -> dict:
    return {"chain_id": chain_id, "height": height, "view": view, "prev_hash": prev_hash,
            "merkle_root": merkle_root(tx_leaves(txs)), "timestamp": timestamp,
            "proposer": proposer, "tx_count": len(txs)}


def vote_payload(phase: str, chain_id: str, height: int, view: int, bhash: str) -> bytes:
    return canonical_json({"phase": phase, "chain_id": chain_id, "height": height,
                           "view": view, "block_hash": bhash})


def sign_vote(token, node_id: str, phase: str, chain_id: str, height: int, view: int, bhash: str) -> dict:
    return {"node_id": node_id,
            "sig": b64e(token.sign(vote_payload(phase, chain_id, height, view, bhash), CTX_VOTE))}


def verify_qc(qc: dict, node_certs: dict, chain_id: str, quorum: int, phase: str | None = None) -> tuple[bool, str]:
    """A quorum certificate is >= 2f+1 valid ML-DSA signatures from distinct ledger nodes."""
    if phase and qc.get("phase") != phase:
        return False, f"expected {phase} certificate"
    seen = set()
    msg = vote_payload(qc["phase"], chain_id, qc["height"], qc["view"], qc["block_hash"])
    for v in qc.get("votes", []):
        nid = v["node_id"]
        if nid in seen or nid not in node_certs:
            continue
        pk, alg = pki.cert_pub(node_certs[nid])
        if pqc.verify(pk, msg, b64d(v["sig"]), CTX_VOTE, alg):
            seen.add(nid)
    if len(seen) < quorum:
        return False, f"only {len(seen)} valid node signatures, need {quorum}"
    return True, f"{len(seen)} valid node signatures"


def make_qc(phase: str, height: int, view: int, bhash: str, votes: list[dict]) -> dict:
    return {"phase": phase, "height": height, "view": view, "block_hash": bhash, "votes": votes}


def check_block_structure(block: dict) -> tuple[bool, str]:
    h = block["header"]
    if h["tx_count"] != len(block["txs"]):
        return False, "tx_count mismatch"
    if merkle_root(tx_leaves(block["txs"])) != h["merkle_root"]:
        return False, "merkle root mismatch (transactions altered)"
    return True, "ok"


def quorum_size(n: int, f: int) -> int:
    """Smallest quorum such that any two quorums intersect in at least f+1 nodes (>= 1 honest):
    ceil((n + f + 1) / 2). Equals 2f+1 when n = 3f+1."""
    return (n + f + 2) // 2
