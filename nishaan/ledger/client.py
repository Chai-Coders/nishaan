"""Ledger client: submits transactions with leader rotation and verifies reads.

Reads are *trustless*: a Merkle inclusion proof plus the block's commit
certificate (2f+1 ML-DSA node signatures) is checked locally, so a single lying
node cannot fake a record.
"""
from __future__ import annotations

from .. import pki
from . import block as B
from .merkle import verify_inclusion
from .node import verify_share_release
from .transport import NodeUnavailable, RemoteError
from .tx import tx_id


class LedgerUnavailable(Exception):
    pass


class TxRejectedError(Exception):
    pass


class LedgerClient:
    def __init__(self, transport, genesis: dict):
        self.transport = transport
        self.genesis = genesis
        g = genesis["txs"][0]["body"]
        self.chain_id = g["chain_id"]
        self.node_certs = g["nodes"]
        self.f = g["f"]
        self.share_threshold = g["share_threshold"]
        self.ca_cert = g["ca_cert"]
        self.node_ids = sorted(self.node_certs)
        self.quorum = B.quorum_size(len(self.node_ids), self.f)

    # ---------------------------------------------------------------- reads
    def call_any(self, method: str, **kw):
        last = None
        for nid in self.node_ids:
            try:
                return self.transport.call(nid, method, **kw)
            except NodeUnavailable as e:
                last = e
            except RemoteError as e:
                if e.code in ("node_error",) and "failed audit" in str(e):
                    last = e
                    continue
                raise
        raise LedgerUnavailable(f"no ledger node reachable ({last})")

    def heads(self) -> dict:
        out = {}
        for nid in self.node_ids:
            try:
                out[nid] = self.transport.call(nid, "head")
            except (NodeUnavailable, RemoteError) as e:
                out[nid] = {"error": str(e)}
        return out

    def height(self) -> int:
        hs = [h["height"] for h in self.heads().values() if "height" in h and not h.get("corrupted")]
        if not hs:
            raise LedgerUnavailable("no healthy ledger node reachable")
        return max(hs)

    # ---------------------------------------------------------------- writes
    def submit(self, tx: dict, attempts: int = 3) -> dict:
        tid = tx_id(tx)
        n = len(self.node_ids)
        errors = []
        for _ in range(attempts):
            height = self.height() + 1
            for view in range(n):
                leader = self.node_ids[(height + view) % n]
                try:
                    log = self.transport.call(leader, "submit", txs=[tx], view=view)
                except NodeUnavailable as e:
                    errors.append(f"view {view}: leader {leader} unreachable")
                    continue
                except RemoteError as e:
                    if e.code == "tx_invalid":
                        if "duplicate transaction" in str(e):
                            # committed earlier but the reply was lost: return the committed record
                            p = self.verified_tx(tid)
                            return {"tx_id": tid, "tx_ids": [tid], "height": p["header"]["height"],
                                    "leader": p["header"]["proposer"], "view": p["header"]["view"],
                                    "prepare": {}, "commit": {}, "decide": {}, "view_changes": errors,
                                    "timestamp": p["header"]["timestamp"], "recovered": True}
                        raise TxRejectedError(str(e)) from None
                    errors.append(f"view {view}: leader {leader}: {e}")
                    if e.code == "not_leader":
                        break
                    continue
                if tid in log.get("tx_ids", []):
                    log["tx_id"] = tid
                    log["view_changes"] = errors
                    return log
                break  # a locked block was re-proposed; retry at the next height
        raise LedgerUnavailable("could not commit transaction: " + "; ".join(errors[-6:]))

    # ---------------------------------------------------------------- verification
    def verify_proof(self, proof: dict) -> tuple[bool, list[str]]:
        notes = []
        tid = tx_id(proof["tx"])
        ok_m = verify_inclusion(bytes.fromhex(tid), proof["index"], proof["size"], proof["path"],
                                proof["header"]["merkle_root"])
        notes.append(f"Merkle inclusion proof: {'valid' if ok_m else 'INVALID'}")
        bh = B.block_hash(proof["header"])
        cc = proof["cc"]
        ok_c, why = B.verify_qc(cc, self.node_certs, self.chain_id, self.quorum, "COMMIT")
        ok_c = ok_c and cc["block_hash"] == bh and cc["height"] == proof["header"]["height"]
        notes.append(f"Commit certificate on block {proof['header']['height']}: {why}")
        return ok_m and ok_c, notes

    def verified_tx(self, txid: str) -> dict:
        p = self.call_any("proof", txid=txid)
        ok, notes = self.verify_proof(p)
        if not ok:
            raise ValueError("ledger returned an unverifiable record: " + "; ".join(notes))
        return p

    def wait_committed(self, txid: str) -> dict:
        return self.verified_tx(txid)

    # ---------------------------------------------------------------- threshold release
    def collect_shares(self, txid: str, validate=None) -> tuple[list, dict]:
        """Ask nodes (starting at a random one) until t signed shares pass ``validate``."""
        import random
        got, log = [], {}
        order = self.node_ids[:]
        k = random.randrange(len(order))
        order = order[k:] + order[:k]
        for nid in order:
            if len(got) >= self.share_threshold:
                break
            try:
                r = self.transport.call(nid, "release_share", txid=txid)
            except (NodeUnavailable, RemoteError) as e:
                log[nid] = f"refused/unreachable: {e}"
                continue
            if r.get("node_id") != nid or r.get("tx_id") != txid or not verify_share_release(r, self.node_certs[nid]):
                log[nid] = "invalid signature on share release"
                continue
            if validate is not None:
                try:
                    r = validate(r)
                except Exception as e:
                    log[nid] = f"bad share rejected: {e}"
                    continue
            got.append(r)
            log[nid] = "released"
        return got, log
