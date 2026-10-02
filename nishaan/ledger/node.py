"""A permissioned ledger node.

Consensus is a leader-driven PBFT-style protocol (n = 3f+1 nodes, f = 1 by default):

  PREPARE  leader proposes a block; every node independently validates it
           (hash chain, Merkle root, every transaction signature and policy)
           and returns an ML-DSA signed PREPARE vote.
  COMMIT   2f+1 PREPARE votes form a *prepared certificate*; nodes lock on the
           block and return a signed COMMIT vote.
  DECIDE   2f+1 COMMIT votes form the *commit certificate*, stored with the
           block. A block without a valid commit certificate is never accepted.

A crashed or Byzantine leader is replaced by rotating the view
(leader = nodes[(height + view) mod n]); the new leader first collects node
status and must re-propose any block that already has a prepared certificate.
Honest nodes vote at most once per (height, view, phase).

Each node keeps its own SQLite file and its own ML-DSA key; altering a stored
block on any node breaks its hash chain or commit-certificate signatures and is
detected by ``audit`` on load.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import timedelta
from pathlib import Path

from .. import pki
from ..crypto import pqc
from ..crypto.sym import b64d, b64e, canonical_json, kem_open, kem_seal
from . import block as B
from .merkle import inclusion_proof
from .state import LedgerState, TxInvalid
from .transport import NodeUnavailable, RemoteError
from .tx import tx_id

CTX_SHARE = b"nishaan/v1/share-release"
MAX_CLOCK_SKEW = timedelta(seconds=120)


class NodeError(Exception):
    code = "node_error"


class NotLeader(NodeError):
    code = "not_leader"


class TxRejected(NodeError):
    code = "tx_invalid"


class LedgerNode:
    RPC = {"prepare", "commit", "decide", "status", "submit", "head", "get_block", "get_tx",
           "proof", "sessions_for_doc", "receipt_by_hash", "doc", "docs", "summary", "cert",
           "release_share", "audit", "ping", "heal", "sync"}

    def __init__(self, node_id: str, token, data_dir: str | Path, genesis: dict,
                 trust_anchor: str, byzantine: str | None = None):
        self.node_id = node_id
        self.token = token
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.genesis = genesis
        self.trust_anchor = trust_anchor
        self.byzantine = byzantine
        self.transport = None
        self.lock = threading.RLock()
        self.submit_lock = threading.Lock()
        self.pending: dict[str, dict] = {}
        self.db = sqlite3.connect(self.dir / "ledger.db", check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, block TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS votes (height INTEGER, view INTEGER, phase TEXT, block_hash TEXT,
                                              PRIMARY KEY (height, view, phase));
            CREATE TABLE IF NOT EXISTS locks (height INTEGER PRIMARY KEY, lock TEXT);
        """)
        if not self.db.execute("SELECT 1 FROM blocks WHERE height=0").fetchone():
            self.db.execute("INSERT INTO blocks VALUES (0, ?, ?)",
                            (B.block_hash(genesis["header"]), json.dumps(genesis)))
            self.db.commit()
        self.reload()

    # ================================================================== chain loading / audit
    def _scan(self) -> tuple[LedgerState, list[dict], dict | None]:
        state = LedgerState()
        blocks: list[dict] = []
        corrupted = None
        rows = self.db.execute("SELECT height, hash, block FROM blocks ORDER BY height").fetchall()
        for height, stored_hash, raw in rows:
            try:
                blk = json.loads(raw)
                prev = blocks[-1] if blocks else None
                if height != len(blocks):
                    raise NodeError(f"missing block at height {len(blocks)}")
                if B.block_hash(blk["header"]) != stored_hash:
                    raise NodeError("stored block hash does not match header (header altered)")
                state = self._verify_block(blk, prev, state)
                blocks.append(blk)
            except (NodeError, TxInvalid, KeyError, ValueError) as e:
                corrupted = {"height": height, "reason": str(e)}
                break
        return state, blocks, corrupted

    def reload(self) -> None:
        with self.lock:
            self.state, self.blocks, self.corrupted = self._scan()

    def audit(self) -> dict:
        """Re-read this node's storage from disk and verify every block from genesis."""
        with self.lock:
            state, blocks, corrupted = self._scan()
            self.state, self.blocks, self.corrupted = state, blocks, corrupted
            return {"node_id": self.node_id, "ok": corrupted is None, "verified_height": len(blocks) - 1,
                    "head_hash": B.block_hash(blocks[-1]["header"]) if blocks else None,
                    "stored_blocks": self.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],
                    "corrupted": corrupted}

    def _verify_block(self, blk: dict, prev: dict | None, state: LedgerState,
                      require_cc: bool = True) -> LedgerState:
        h = blk["header"]
        ok, why = B.check_block_structure(blk)
        if not ok:
            raise NodeError(why)
        bh = B.block_hash(h)
        st = state.clone()
        if prev is None:
            if h["height"] != 0 or h["prev_hash"] != B.ZERO_HASH:
                raise NodeError("bad genesis header")
            gtx = blk["txs"][0]
            if gtx["type"] != "GENESIS" or len(blk["txs"]) != 1:
                raise NodeError("genesis must contain exactly one GENESIS tx")
            if gtx["body"]["ca_cert"]["body"]["fingerprint"] != self.trust_anchor:
                raise NodeError("genesis CA does not match the configured trust anchor")
            st.validate(gtx, 0, None)
            st.apply(gtx, 0, 0)
        else:
            ph = prev["header"]
            if h["chain_id"] != st.chain_id:
                raise NodeError("chain id mismatch")
            if h["height"] != ph["height"] + 1:
                raise NodeError("height gap")
            if h["prev_hash"] != B.block_hash(ph):
                raise NodeError("prev_hash does not link to previous block (history rewritten)")
            if pki.parse_iso(h["timestamp"]) < pki.parse_iso(ph["timestamp"]):
                raise NodeError("timestamp goes backwards")
            when = pki.parse_iso(h["timestamp"])
            for i, t in enumerate(blk["txs"]):
                st.validate(t, h["height"], when)
                st.apply(t, h["height"], i)
        if not require_cc:
            return st
        cc = blk.get("cc")
        if not cc or cc.get("block_hash") != bh or cc.get("height") != h["height"]:
            raise NodeError("missing or mismatched commit certificate")
        ok, why = B.verify_qc(cc, st.node_certs, st.chain_id, self.quorum(st), "COMMIT")
        if not ok:
            raise NodeError("commit certificate invalid: " + why)
        return st

    def quorum(self, st: LedgerState | None = None) -> int:
        st = st or self.state
        return B.quorum_size(len(st.node_certs), st.params["f"])

    def leader(self, height: int, view: int) -> str:
        ids = self.state.node_ids()
        return ids[(height + view) % len(ids)]

    @property
    def head_height(self) -> int:
        return len(self.blocks) - 1

    @property
    def head_hash(self) -> str:
        return B.block_hash(self.blocks[-1]["header"])

    # ================================================================== RPC dispatch
    def rpc(self, method: str, **kwargs):
        if method not in self.RPC:
            raise RemoteError(f"unknown method {method}", "bad_method")
        try:
            return getattr(self, method)(**kwargs)
        except NodeError as e:
            raise RemoteError(str(e), e.code) from None
        except TxInvalid as e:
            raise RemoteError(str(e), "tx_invalid") from None

    def ping(self):
        return {"node_id": self.node_id, "height": self.head_height}

    # ================================================================== consensus: replica side
    def _vote_once(self, height: int, view: int, phase: str, bh: str) -> None:
        row = self.db.execute("SELECT block_hash FROM votes WHERE height=? AND view=? AND phase=?",
                              (height, view, phase)).fetchone()
        if row and row[0] != bh:
            raise NodeError(f"already voted {phase} for a different block at height {height} view {view}")
        if not row:
            self.db.execute("INSERT INTO votes VALUES (?,?,?,?)", (height, view, phase, bh))
            self.db.commit()

    def _voted_view(self, height: int) -> int:
        row = self.db.execute("SELECT MAX(view) FROM votes WHERE height=?", (height,)).fetchone()
        return row[0] if row and row[0] is not None else -1

    def _get_lock(self, height: int) -> dict | None:
        row = self.db.execute("SELECT lock FROM locks WHERE height=?", (height,)).fetchone()
        return json.loads(row[0]) if row else None

    def prepare(self, block: dict, view: int, justify: dict | None = None,
                reproposal_sig: str | None = None) -> dict:
        if block["header"]["height"] > self.head_height + 1:
            self.sync()
        with self.lock:
            if self.corrupted:
                raise NodeError("local ledger failed audit; refusing to vote until healed")
            h = block["header"]
            height = h["height"]
            bh = B.block_hash(h)
            if height != self.head_height + 1:
                raise NodeError(f"expected height {self.head_height + 1}, got {height}")
            if h["prev_hash"] != self.head_hash:
                raise NodeError("block does not extend my head")
            if view < self._voted_view(height):
                raise NodeError(f"stale view {view}: already voted in view {self._voted_view(height)}")
            if view > max(self._voted_view(height), 0) + 2 * len(self.state.node_certs):
                raise NodeError("view jumps too far ahead")
            if justify is not None:
                ok, why = B.verify_qc(justify, self.state.node_certs, self.state.chain_id,
                                      self.quorum(), "PREPARE")
                if not ok or justify["block_hash"] != bh or justify["height"] != height:
                    raise NodeError("invalid justification for re-proposal")
                lpk, lalg = pki.cert_pub(self.state.node_certs[self.leader(height, view)])
                rmsg = canonical_json({"block_hash": bh, "height": height, "view": view})
                if not reproposal_sig or not pqc.verify(lpk, rmsg, b64d(reproposal_sig), B.CTX_PROPOSAL, lalg):
                    raise NodeError("re-proposal must be signed by the leader of this view")
            else:
                if h["view"] != view or h["proposer"] != self.leader(height, view):
                    raise NodeError(f"{h['proposer']} is not the leader for height {height} view {view}")
                pcert = self.state.node_certs[h["proposer"]]
                pk, alg = pki.cert_pub(pcert)
                if not pqc.verify(pk, canonical_json(h), b64d(block.get("proposer_sig", "")),
                                  B.CTX_PROPOSAL, alg):
                    raise NodeError("bad proposer signature")
                skew = abs(pki.parse_iso(h["timestamp"]) - pki.utcnow())
                if skew > MAX_CLOCK_SKEW:
                    raise NodeError("block timestamp outside trusted clock window")
            lock = self._get_lock(height)
            if lock and lock["block_hash"] != bh and not (justify is not None and justify["view"] > lock["view"]):
                raise NodeError("locked on a different prepared block at this height")
            if self.byzantine != "yes":
                self._verify_candidate(block)
            self._vote_once(height, view, "PREPARE", bh)
            self.pending[bh] = block
            return B.sign_vote(self.token, self.node_id, "PREPARE", self.state.chain_id, height, view, bh)

    def _verify_candidate(self, block: dict) -> None:
        # validate everything except the (not yet existing) commit certificate
        self._verify_block(block, self.blocks[-1], self.state, require_cc=False)

    def commit(self, height: int, view: int, block_hash: str, pc: dict) -> dict:
        with self.lock:
            if self.corrupted:
                raise NodeError("local ledger failed audit")
            ok, why = B.verify_qc(pc, self.state.node_certs, self.state.chain_id, self.quorum(), "PREPARE")
            if not ok or pc["block_hash"] != block_hash or pc["height"] != height or pc["view"] != view:
                raise NodeError("invalid prepared certificate: " + why)
            blk = self.pending.get(block_hash)
            if blk is None:
                raise NodeError("unknown block (no PREPARE seen)")
            if view < self._voted_view(height):
                raise NodeError(f"stale view {view}: already voted in view {self._voted_view(height)}")
            row = self.db.execute("SELECT block_hash FROM votes WHERE height=? AND view=? AND phase='PREPARE'",
                                  (height, view)).fetchone()
            if not row or row[0] != block_hash:
                raise NodeError("did not prepare this block in this view")
            lock = self._get_lock(height)
            if lock and lock["block_hash"] != block_hash and lock["view"] > view:
                raise NodeError("locked on a block from a later view")
            self._vote_once(height, view, "COMMIT", block_hash)
            self.db.execute("INSERT OR REPLACE INTO locks VALUES (?, ?)",
                            (height, json.dumps({"block_hash": block_hash, "view": view, "pc": pc, "block": blk})))
            self.db.commit()
            return B.sign_vote(self.token, self.node_id, "COMMIT", self.state.chain_id, height, view, block_hash)

    def decide(self, block: dict) -> dict:
        if block["header"]["height"] > self.head_height + 1:
            self.sync()
        with self.lock:
            h = block["header"]
            bh = B.block_hash(h)
            if h["height"] <= self.head_height:
                if B.block_hash(self.blocks[h["height"]]["header"]) == bh:
                    return {"status": "already-have", "height": h["height"]}
                raise NodeError("conflicting block for committed height")
            if self.corrupted:
                raise NodeError("local ledger failed audit; heal first")
            if h["height"] != self.head_height + 1:
                raise NodeError("behind; sync required")
            new_state = self._verify_block(block, self.blocks[-1], self.state)
            self.db.execute("INSERT INTO blocks VALUES (?,?,?)", (h["height"], bh, json.dumps(block)))
            self.db.execute("DELETE FROM locks WHERE height<=?", (h["height"],))
            self.db.commit()
            self.blocks.append(block)
            self.state = new_state
            self.pending.clear()
            return {"status": "appended", "height": h["height"]}

    def status(self, height: int) -> dict:
        with self.lock:
            lock = self._get_lock(height)
            return {"node_id": self.node_id, "head_height": self.head_height, "head_hash": self.head_hash,
                    "corrupted": self.corrupted, "lock": lock}

    # ================================================================== consensus: leader side
    def _peers_call(self, nid: str, method: str, **kw):
        if nid == self.node_id:
            return self.rpc(method, **json.loads(json.dumps(kw)))
        return self.transport.call(nid, method, **kw)

    def sync(self) -> int:
        """Catch up from peers (every block is verified, including its commit certificate)."""
        if self.transport is None:
            return 0
        added = 0
        for nid in self.state.node_ids():
            if nid == self.node_id:
                continue
            try:
                head = self.transport.call(nid, "head")
            except (NodeUnavailable, RemoteError):
                continue
            while head["height"] > self.head_height and not self.corrupted:
                try:
                    blk = self.transport.call(nid, "get_block", height=self.head_height + 1)
                    self.decide(blk)
                    added += 1
                except (NodeUnavailable, RemoteError, NodeError, TxInvalid):
                    break
        return added

    def heal(self) -> dict:
        """Discard a corrupted local suffix and re-fetch verified blocks from the quorum."""
        with self.lock:
            if self.corrupted:
                self.db.execute("DELETE FROM blocks WHERE height>=?", (self.corrupted["height"],))
                self.db.commit()
            self.reload()
        added = self.sync()
        return {"node_id": self.node_id, "refetched": added, "audit": self.audit()}

    def submit(self, txs: list[dict], view: int = 0) -> dict:
        with self.submit_lock:
            if self.corrupted:
                raise NodeError("leader ledger failed audit")
            self.sync()
            height = self.head_height + 1
            if self.leader(height, view) != self.node_id:
                raise NotLeader(f"leader for height {height} view {view} is {self.leader(height, view)}")
            ids = self.state.node_ids()
            q = self.quorum()
            block, justify, reproposed = None, None, False
            if view > 0:
                # view change: learn any prepared-but-undecided block before proposing
                best = None
                answers = 0
                for nid in ids:
                    try:
                        st = self._peers_call(nid, "status", height=height)
                    except (NodeUnavailable, RemoteError):
                        continue
                    answers += 1
                    lk = st.get("lock")
                    if lk:
                        ok, _ = B.verify_qc(lk["pc"], self.state.node_certs, self.state.chain_id, q, "PREPARE")
                        if ok and (best is None or lk["view"] > best["view"]):
                            best = lk
                if answers < q:
                    raise NodeError(f"view change needs {q} status replies, got {answers}")
                if best:
                    block, justify, reproposed = best["block"], best["pc"], True
            if block is None:
                trial = self.state.clone()
                now = pki.utcnow()
                for i, t in enumerate(txs):
                    try:
                        trial.validate(t, height, now)
                    except TxInvalid as e:
                        raise TxRejected(str(e)) from None
                    trial.apply(t, height, i)
                txs = self._byzantine_tamper(txs)
                header = B.make_header(self.state.chain_id, height, view, self.head_hash, txs,
                                       pki.iso(now), self.node_id)
                block = {"header": header, "txs": txs,
                         "proposer_sig": b64e(self.token.sign(canonical_json(header), B.CTX_PROPOSAL))}
            bh = B.block_hash(block["header"])
            log = {"height": height, "view": view, "leader": self.node_id, "block_hash": bh,
                   "prepare": {}, "commit": {}, "reproposed": reproposed}

            def gather(phase, method, **kw):
                votes = []
                for nid in ids:
                    try:
                        v = self._peers_call(nid, method, **kw)
                        votes.append(v)
                        log[phase.lower()][nid] = "signed"
                    except (NodeUnavailable,) as e:
                        log[phase.lower()][nid] = "unreachable"
                    except RemoteError as e:
                        log[phase.lower()][nid] = "rejected: " + str(e)
                qc = B.make_qc(phase, height, view, bh, votes)
                ok, why = B.verify_qc(qc, self.state.node_certs, self.state.chain_id, q, phase)
                if not ok:
                    raise NodeError(f"{phase} quorum not reached ({why}); votes: {log[phase.lower()]}")
                return qc

            rsig = None
            if justify is not None:
                rsig = b64e(self.token.sign(canonical_json({"block_hash": bh, "height": height, "view": view}),
                                            B.CTX_PROPOSAL))
            pc = gather("PREPARE", "prepare", block=block, view=view, justify=justify, reproposal_sig=rsig)
            cc = gather("COMMIT", "commit", height=height, view=view, block_hash=bh, pc=pc)
            block = dict(block, cc=cc)
            decided = {}
            for nid in ids:
                try:
                    decided[nid] = self._peers_call(nid, "decide", block=block)["status"]
                except (NodeUnavailable, RemoteError) as e:
                    decided[nid] = "missed (will sync)"
            log["decide"] = decided
            log["tx_ids"] = [tx_id(t) for t in block["txs"]]
            log["timestamp"] = block["header"]["timestamp"]
            return log

    def _byzantine_tamper(self, txs: list[dict]) -> list[dict]:
        """Demo only: a malicious leader rewrites a record to frame someone else."""
        if self.byzantine != "forge" or not txs:
            return txs
        forged = json.loads(json.dumps(txs))
        b = forged[0]["body"]
        if "cert" in b:
            b = b["cert"]["body"]
        for key in ("recipient_id", "delivered_hash", "purpose", "title", "display_name", "reason"):
            if key in b:
                b[key] = "FORGED-" + str(b[key])[:12]
                break
        return forged

    # ================================================================== queries
    def head(self) -> dict:
        with self.lock:
            h = self.blocks[-1]["header"]
            return {"node_id": self.node_id, "height": h["height"], "hash": B.block_hash(h),
                    "timestamp": h["timestamp"], "corrupted": self.corrupted}

    def get_block(self, height: int) -> dict:
        with self.lock:
            if not 0 <= height <= self.head_height:
                raise NodeError("no such block")
            return self.blocks[height]

    def _locate(self, tid: str):
        loc = self.state.tx_index.get(tid)
        if not loc:
            raise NodeError("transaction not found")
        h, i = loc
        return self.blocks[h], h, i

    def get_tx(self, txid: str) -> dict:
        with self.lock:
            blk, h, i = self._locate(txid)
            return {"tx": blk["txs"][i], "height": h, "index": i, "block_hash": B.block_hash(blk["header"]),
                    "block_timestamp": blk["header"]["timestamp"]}

    def proof(self, txid: str) -> dict:
        """Merkle inclusion proof + the header and its commit certificate."""
        with self.lock:
            blk, h, i = self._locate(txid)
            leaves = B.tx_leaves(blk["txs"])
            return {"tx": blk["txs"][i], "index": i, "size": len(leaves),
                    "path": inclusion_proof(leaves, i), "header": blk["header"], "cc": blk["cc"]}

    def sessions_for_doc(self, doc_id: str) -> list[dict]:
        with self.lock:
            out = []
            for sid, s in self.state.sessions.items():
                if s["doc_id"] == doc_id:
                    blk, h, i = self._locate(s["tx_id"])
                    out.append(dict(s, session_id=sid, tx=blk["txs"][i],
                                    receipt_tx_id=self.state.receipts.get(sid)))
            return sorted(out, key=lambda x: x["height"])

    def receipt_by_hash(self, delivered_hash: str) -> dict | None:
        with self.lock:
            sid = self.state.delivered.get(delivered_hash)
            if not sid:
                return None
            return {"session_id": sid, "receipt_tx_id": self.state.receipts[sid],
                    "intent_tx_id": self.state.sessions[sid]["tx_id"]}

    def doc(self, doc_id: str) -> dict:
        with self.lock:
            d = self.state.docs.get(doc_id)
            if not d:
                raise NodeError("unknown document")
            return d

    def docs(self) -> dict:
        with self.lock:
            return {k: {"manifest": v["manifest"], "tx_id": v["tx_id"], "height": v["height"]}
                    for k, v in self.state.docs.items()}

    def cert(self, serial: str) -> dict:
        with self.lock:
            if self.state.ca_cert and serial == self.state.ca_cert["body"]["serial"]:
                return {"cert": self.state.ca_cert, "status": "active", "enrolled_at": 0}
            rec = self.state.certs.get(serial)
            if not rec:
                raise NodeError("unknown certificate")
            return rec

    def summary(self) -> dict:
        with self.lock:
            s = self.state.summary()
            s.update(self.head())
            s["genesis_hash"] = B.block_hash(self.blocks[0]["header"])
            s["ca_fingerprint"] = self.trust_anchor
            s["node_certs"] = self.state.node_certs
            s["ca_cert"] = self.state.ca_cert
            s["quorum"] = self.quorum()
            return s

    # ================================================================== threshold key release
    def release_share(self, txid: str) -> dict:
        """'No log, no key': release this node's share of K_c only for a committed record."""
        with self.lock:
            if self.corrupted:
                raise NodeError("local ledger failed audit")
            blk, h, i = self._locate(txid)
            tx = blk["txs"][i]
            if tx["type"] not in ("DECRYPT_INTENT", "FORENSIC_ACCESS"):
                raise NodeError("shares are only released for decryption or forensic-access records")
            b = tx["body"]
            doc = self.state.docs[b["doc_id"]]["manifest"]
            rec = self.state.certs[tx["signer"]]
            if rec["status"] != "active":
                raise NodeError(f"requester certificate is {rec['status']}")
            now = pki.utcnow()
            ok, why = pki.verify_cert(rec["cert"], self.state.ca_cert, now)
            if not ok:
                raise NodeError("requester certificate: " + why)
            if tx["type"] == "DECRYPT_INTENT" and doc["policy"].get("not_after") \
                    and now > pki.parse_iso(doc["policy"]["not_after"]):
                raise NodeError("document access expired (policy)")    # investigations are never time-barred
            sid = rec["cert"]["body"]["subject_id"]
            entry = doc["committee"]["per_recipient"].get(sid, {}).get(self.node_id)
            if entry is None:
                raise NodeError("no committee share for this requester")
            share = kem_open(self.token.decaps, entry["sealed"],
                             aad=canonical_json({"doc_id": b["doc_id"], "subject_id": sid, "node_id": self.node_id}),
                             label="committee-share")
            if self.byzantine == "badshare":                       # demo: a node handing out garbage
                share = bytes(x ^ 0x5A for x in share)
            kem_pk, _ = pki.cert_kem(rec["cert"])
            aad = canonical_json({"doc_id": b["doc_id"], "session_id": b["session_id"],
                                  "node_id": self.node_id, "tx_id": txid})
            resp = {"node_id": self.node_id, "tx_id": txid, "session_id": b["session_id"],
                    "doc_id": b["doc_id"], "x": entry["x"], "height": h,
                    "sealed": kem_seal(kem_pk, share, aad, "share-release")}
            resp["sig"] = b64e(self.token.sign(canonical_json(resp), CTX_SHARE))
            return resp


def verify_share_release(resp: dict, node_cert: dict) -> bool:
    body = {k: v for k, v in resp.items() if k != "sig"}
    pk, alg = pki.cert_pub(node_cert)
    return pqc.verify(pk, canonical_json(body), b64d(resp["sig"]), CTX_SHARE, alg)


def new_session_id() -> str:
    return str(uuid.uuid4())
