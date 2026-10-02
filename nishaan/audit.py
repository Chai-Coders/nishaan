"""Ledger audit, offline checkpoints and the tamper lab.

Defence in depth against a privileged insider:

1. Each node re-verifies its own chain from genesis (hash links, Merkle roots,
   every transaction signature, every commit certificate). Editing one node's
   database is detected and that node refuses to vote until healed.
2. Nodes are cross-compared: a node whose head or history diverges from the
   quorum is flagged.
3. Signed checkpoints (head hash + 2f+1 node signatures) are exported to
   removable media for offline witnesses, in the style of Certificate
   Transparency. Even an attacker holding *every* node key, who rewrites history
   and re-signs it consistently, is caught by comparing against an older
   checkpoint.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from . import pki
from .ledger import block as B
from .ledger.merkle import merkle_root
from .ledger.transport import NodeUnavailable, RemoteError

CHECKPOINT_FORMAT = "nishaan.checkpoint/v1"


# ---------------------------------------------------------------------------- audit

def audit_all(ws) -> dict:
    client = ws.client()
    nodes = {}
    for nid in client.node_ids:
        try:
            nodes[nid] = client.transport.call(nid, "audit")
        except (NodeUnavailable, RemoteError) as e:
            nodes[nid] = {"node_id": nid, "ok": None, "error": str(e)}
    healthy = [a for a in nodes.values() if a.get("ok")]
    # majority view of the chain head among healthy nodes
    heads: dict[str, int] = {}
    for a in healthy:
        heads[a["head_hash"]] = heads.get(a["head_hash"], 0) + 1
    consensus_head = max(heads, key=heads.get) if heads else None
    for a in nodes.values():
        if a.get("ok") and consensus_head and a["head_hash"] != consensus_head:
            a["diverged"] = True
    checkpoints = [verify_checkpoint(ws, json.loads(p.read_text()))
                   for p in sorted(ws.p("checkpoints").glob("checkpoint-*.json"))]
    return {"nodes": nodes, "quorum_head": consensus_head,
            "healthy": len(healthy), "total": len(nodes), "checkpoints": checkpoints,
            "ok": all(a.get("ok") for a in nodes.values()) and all(c["ok"] for c in checkpoints)}


# ---------------------------------------------------------------------------- checkpoints

def export_checkpoint(ws, out_dir: str | Path | None = None) -> tuple[dict, Path]:
    client = ws.client()
    h = client.height()
    blk = client.call_any("get_block", height=h)
    ok, why = B.verify_qc(blk["cc"], client.node_certs, client.chain_id, client.quorum, "COMMIT")
    if not ok:
        raise ValueError("head block has no valid commit certificate: " + why)
    cp = {"format": CHECKPOINT_FORMAT, "chain_id": client.chain_id, "height": h,
          "block_hash": B.block_hash(blk["header"]), "header": blk["header"], "cc": blk["cc"],
          "exported_at": pki.iso(pki.utcnow()), "ca_fingerprint": ws.trust_anchor}
    path = Path(out_dir or ws.p("checkpoints")) / f"checkpoint-{h:06d}.json"
    path.write_text(json.dumps(cp, indent=1))
    return cp, path


def verify_checkpoint(ws, cp: dict) -> dict:
    """Does every node still contain exactly the checkpointed block?"""
    client = ws.client()
    ok_sig, why = B.verify_qc(cp["cc"], client.node_certs, client.chain_id, client.quorum, "COMMIT")
    ok_sig = ok_sig and cp["cc"]["block_hash"] == cp["block_hash"] == B.block_hash(cp["header"])
    per_node = {}
    for nid in client.node_ids:
        try:
            blk = client.transport.call(nid, "get_block", height=cp["height"])
            per_node[nid] = "match" if B.block_hash(blk["header"]) == cp["block_hash"] else "MISMATCH"
        except NodeUnavailable:
            per_node[nid] = "unreachable"
        except RemoteError as e:
            per_node[nid] = "MISSING" if "no such block" in str(e) else f"error: {e}"
    ok = ok_sig and all(v in ("match", "unreachable") for v in per_node.values())
    return {"height": cp["height"], "block_hash": cp["block_hash"], "signatures": why if ok_sig else "INVALID",
            "exported_at": cp.get("exported_at"), "nodes": per_node, "ok": ok}


# ---------------------------------------------------------------------------- tamper lab (demo only)

def _db(ws, node_id: str) -> sqlite3.Connection:
    return sqlite3.connect(ws.p("nodes", node_id, "ledger.db"))


def _find_latest(db, tx_type: str):
    for h, raw in db.execute("SELECT height, block FROM blocks ORDER BY height DESC"):
        blk = json.loads(raw)
        for i, t in enumerate(blk["txs"]):
            if t["type"] == tx_type:
                return h, i, blk
    return None


def tamper(ws, node_id: str, kind: str) -> dict:
    """Simulate a privileged administrator with direct database access.

    edit-record      re-attribute the latest decryption record to someone else (one node)
    delete-block     delete the newest block from one node's database
    rewrite-history  with ALL node keys stolen: erase the latest decryption record from
                     every node, recompute Merkle roots and hash links, re-sign every
                     commit certificate. Only an offline checkpoint can expose this.
    """
    if kind == "edit-record":
        db = _db(ws, node_id)
        found = _find_latest(db, "DECRYPT_INTENT")
        if not found:
            raise ValueError("no decryption record to tamper with")
        h, i, blk = found
        before = blk["txs"][i]["body"]["recipient_id"]
        blk["txs"][i]["body"]["recipient_id"] = "someone-else"
        db.execute("UPDATE blocks SET block=? WHERE height=?", (json.dumps(blk), h))
        db.commit()
        return {"kind": kind, "node": node_id, "height": h,
                "change": f"recipient_id '{before}' -> 'someone-else' in block {h}"}
    if kind == "delete-block":
        db = _db(ws, node_id)
        h = db.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
        db.execute("DELETE FROM blocks WHERE height=?", (h,))
        db.commit()
        return {"kind": kind, "node": node_id, "height": h, "change": f"deleted block {h}"}
    if kind == "rewrite-history":
        tokens = {nid: pki.SoftToken.load(ws.p("nodes", nid, "token.json"), ws.pin) for nid in ws.node_ids()}
        db0 = _db(ws, ws.node_ids()[0])
        found = _find_latest(db0, "DECRYPT_INTENT")
        if not found:
            raise ValueError("no decryption record to erase")
        h0, _, blk0 = found
        victim = blk0["txs"][[t["type"] for t in blk0["txs"]].index("DECRYPT_INTENT")]["body"]
        sid = victim["session_id"]
        rows = db0.execute("SELECT height, block FROM blocks WHERE height>=? ORDER BY height", (h0,)).fetchall()
        chain_id = json.loads(db0.execute("SELECT block FROM blocks WHERE height=0").fetchone()[0])["header"]["chain_id"]
        prev = json.loads(db0.execute("SELECT block FROM blocks WHERE height=?", (h0 - 1,)).fetchone()[0])
        new_rows = []
        for h, raw in rows:
            blk = json.loads(raw)
            blk["txs"] = [t for t in blk["txs"] if t["body"].get("session_id") != sid]
            hd = blk["header"]
            hd["prev_hash"] = B.block_hash(prev["header"])
            hd["tx_count"] = len(blk["txs"])
            hd["merkle_root"] = merkle_root(B.tx_leaves(blk["txs"]))
            bh = B.block_hash(hd)
            votes = [B.sign_vote(tok, nid, "COMMIT", chain_id, h, hd["view"], bh) for nid, tok in tokens.items()]
            blk["cc"] = B.make_qc("COMMIT", h, hd["view"], bh, votes)
            new_rows.append((h, bh, json.dumps(blk)))
            prev = blk
        for nid in ws.node_ids():
            db = _db(ws, nid)
            for h, bh, raw in new_rows:
                db.execute("UPDATE blocks SET hash=?, block=? WHERE height=?", (bh, raw, h))
            db.commit()
        return {"kind": kind, "nodes": ws.node_ids(), "from_height": h0,
                "change": f"erased {victim['recipient_id']}'s decryption record (session {sid[:8]}) "
                          f"and re-signed blocks {h0}..{new_rows[-1][0]} with all {len(tokens)} stolen node keys"}
    raise ValueError(f"unknown tamper kind {kind}")


def reload_nodes(ws) -> None:
    """Local mode: make in-process nodes re-read their databases (as a restart would)."""
    t = ws.local_nodes()
    for n in getattr(t, "nodes", {}).values():
        n.reload()
