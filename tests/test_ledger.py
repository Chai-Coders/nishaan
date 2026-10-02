import json
import sqlite3
import unittest

from helpers import new_workspace

from nishaan import pki
from nishaan.audit import audit_all, export_checkpoint, tamper
from nishaan.crypto.sym import b64e, canonical_json
from nishaan.ledger import block as B
from nishaan.ledger.node import NodeError
from nishaan.ledger.client import LedgerUnavailable, TxRejectedError
from nishaan.ledger.tx import make_tx


class TestLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = new_workspace()
        cls.c = cls.ws.client()
        cls.t = cls.ws.local_nodes()

    def test_01_all_nodes_agree(self):
        heads = {h["hash"] for h in self.c.heads().values()}
        self.assertEqual(len(heads), 1)

    def test_02_commit_with_one_node_offline(self):
        self.t.offline.add("node-4")
        try:
            log = self.ws.enroll("u1", "User 1", "recipient")
            self.assertEqual(log["prepare"]["node-4"], "unreachable")
        finally:
            self.t.offline.discard("node-4")
        self.ws.enroll("u2", "User 2", "recipient")        # node-4 catches up
        self.assertEqual(self.t.nodes["node-4"].head_height, self.c.height())

    def test_03_no_quorum_with_two_nodes_offline(self):
        self.t.offline.update({"node-3", "node-4"})
        try:
            with self.assertRaises(LedgerUnavailable):
                self.ws.enroll("u3", "User 3", "recipient")
        finally:
            self.t.offline.difference_update({"node-3", "node-4"})

    def test_04_view_change_when_leader_offline(self):
        h = self.c.height() + 1
        leader = self.c.node_ids[h % 4]
        self.t.offline.add(leader)
        try:
            log = self.ws.enroll("u4", "User 4", "recipient")
            self.assertNotEqual(log["leader"], leader)
            self.assertGreaterEqual(log["view"], 1)
        finally:
            self.t.offline.discard(leader)

    def test_05_byzantine_leader_cannot_forge(self):
        h = self.c.height() + 1
        bad = self.c.node_ids[h % 4]
        self.t.nodes[bad].byzantine = "forge"
        try:
            log = self.ws.enroll("u5", "User 5", "recipient")
            self.assertNotEqual(log["leader"], bad)
            tx = self.c.verified_tx(log["tx_ids"][0])["tx"]
            self.assertEqual(tx["body"]["cert"]["body"]["display_name"], "User 5")
        finally:
            self.t.nodes[bad].byzantine = None

    def test_06_invalid_transactions_rejected(self):
        with self.assertRaises(TxRejectedError):
            self.ws.enroll("u5", "dup", "recipient")       # subject already active
        alice = self.ws.identity("alice")                  # non-CA tries to enroll someone
        ca = self.ws.ca()
        from nishaan.pki import SoftToken
        cert = ca.issue(SoftToken.generate("mallory", "recipient").csr("M"))
        with self.assertRaises(TxRejectedError):
            self.c.submit(make_tx("ENROLL", {"cert": cert}, alice.token, alice.serial))

    def test_07_tamper_one_node_detected_and_healed(self):
        tamper(self.ws, "node-2", "delete-block")
        rep = audit_all(self.ws)
        n2 = rep["nodes"]["node-2"]
        self.assertTrue(n2.get("diverged") or not n2["ok"])     # missing block -> diverges from quorum
        healed = self.t.call("node-2", "heal")
        self.assertTrue(healed["audit"]["ok"])
        self.assertEqual(self.t.nodes["node-2"].head_hash, self.t.nodes["node-1"].head_hash)

    def test_08_edit_record_detected(self):
        db = sqlite3.connect(self.ws.p("nodes", "node-3", "ledger.db"))
        h, raw = db.execute("SELECT height, block FROM blocks WHERE height=2").fetchone()
        blk = json.loads(raw)
        blk["txs"][0]["body"]["cert"]["body"]["display_name"] = "Changed"
        db.execute("UPDATE blocks SET block=? WHERE height=2", (json.dumps(blk),))
        db.commit()
        a = self.t.call("node-3", "audit")
        self.assertFalse(a["ok"])
        self.assertEqual(a["corrupted"]["height"], 2)
        # corrupted node refuses to vote but the quorum still commits
        log = self.ws.enroll("u6", "User 6", "recipient")
        self.assertIn("rejected", log["prepare"]["node-3"])
        self.assertTrue(self.t.call("node-3", "heal")["audit"]["ok"])

    def test_09_checkpoint_catches_rewrite_with_stolen_keys(self):
        cp, _ = export_checkpoint(self.ws)
        self.assertTrue(audit_all(self.ws)["ok"])
        # rewrite needs a decryption record: create one quickly via the end-to-end path
        from helpers import sample_pdf
        from nishaan import client, sender
        pkg, _ = sender.distribute(self.ws, "sender-ops", sample_pdf(), "T", ["alice"])
        client.open_in_workspace(self.ws, "alice", pkg["doc_id"])
        cp2, _ = export_checkpoint(self.ws)
        tamper(self.ws, "node-1", "rewrite-history")
        rep = audit_all(self.ws)
        self.assertTrue(all(n["ok"] for n in rep["nodes"].values()))     # self-consistent forgery
        bad = [c for c in rep["checkpoints"] if not c["ok"]]
        self.assertTrue(bad and bad[0]["height"] == cp2["height"])       # ...exposed by the checkpoint


    def test_10_stale_view_commit_refused(self):
        """A leader that withholds a view-0 prepared certificate cannot get it committed after
        the replicas have moved to view 1 (no two blocks can be committed at one height)."""
        nodes = self.t.nodes
        h = self.c.height() + 1
        ids = self.c.node_ids
        ca = self.ws.ca()

        def enroll_tx(sid):
            cert = ca.issue(pki.SoftToken.generate(sid, "recipient").csr(sid))
            from nishaan.ledger.tx import make_tx
            return make_tx("ENROLL", {"cert": cert}, ca.token, ca.cert["body"]["serial"])

        def block(view, txs):
            leader = ids[(h + view) % len(ids)]
            tok = pki.SoftToken.load(self.ws.p("nodes", leader, "token.json"), self.ws.pin)
            hd = B.make_header(self.c.chain_id, h, view, nodes[leader].head_hash, txs, pki.iso(pki.utcnow()), leader)
            return {"header": hd, "txs": txs, "proposer_sig": b64e(tok.sign(canonical_json(hd), B.CTX_PROPOSAL))}

        a, b = block(0, [enroll_tx("stale-a")]), block(1, [enroll_tx("stale-b")])
        ha, hb = B.block_hash(a["header"]), B.block_hash(b["header"])
        pc_a = B.make_qc("PREPARE", h, 0, ha, [nodes[n].prepare(a, 0) for n in ids[:3]])
        votes_b = [nodes[n].prepare(b, 1) for n in ids]                 # replicas move on to view 1
        for n in ids:
            with self.assertRaises(NodeError):
                nodes[n].commit(h, 0, ha, pc_a)                            # stale view-0 commit refused
        pc_b = B.make_qc("PREPARE", h, 1, hb, votes_b)
        cc_b = B.make_qc("COMMIT", h, 1, hb, [nodes[n].commit(h, 1, hb, pc_b) for n in ids])
        for n in ids:
            nodes[n].decide(dict(b, cc=cc_b))
        self.assertEqual(len({nodes[n].head_hash for n in ids}), 1)

    def test_11_quorum_intersection(self):
        self.assertEqual(B.quorum_size(4, 1), 3)
        self.assertEqual(B.quorum_size(5, 1), 4)      # 2f+1 = 3 would let two quorums share one node
        self.assertEqual(B.quorum_size(7, 2), 5)


if __name__ == "__main__":
    unittest.main()
