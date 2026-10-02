import json
import subprocess
import sys
import unittest

import cv2
from helpers import ROOT, new_workspace, sample_pdf

from nishaan import client, forensics, sender
from nishaan.client import DecryptionDenied
from nishaan.ledger.client import TxRejectedError
from nishaan.watermark.render import render_pdf


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = new_workspace()
        cls.pkg, _ = sender.distribute(cls.ws, "sender-ops", sample_pdf(), "Brief", ["alice", "bob", "carol"],
                                       max_decryptions=2)
        cls.doc = cls.pkg["doc_id"]
        cls.res = {who: client.open_in_workspace(cls.ws, who, cls.doc) for who in ("alice", "bob", "carol")}

    def test_copies_unique_and_logged(self):
        hashes = {r.pdf for r in self.res.values()}
        self.assertEqual(len(hashes), 3)
        sessions = self.ws.client().call_any("sessions_for_doc", doc_id=self.doc)
        self.assertEqual({s["subject_id"] for s in sessions}, {"alice", "bob", "carol"})

    def test_unauthorised_recipient_denied(self):
        with self.assertRaises(DecryptionDenied):
            client.open_in_workspace(self.ws, "dev", self.doc)

    def test_policy_max_decryptions(self):
        client.open_in_workspace(self.ws, "carol", self.doc)               # second opening ok
        with self.assertRaises(TxRejectedError):
            client.open_in_workspace(self.ws, "carol", self.doc)           # third refused by committee

    def test_no_log_no_key(self):
        """Nodes refuse to release shares for anything that is not a committed record."""
        from nishaan.ledger.transport import RemoteError
        with self.assertRaises(RemoteError):
            self.ws.client().transport.call("node-1", "release_share", txid="00" * 32)

    def test_pdf_leak_verified_and_bundle_verifies_independently(self):
        inv = forensics.investigate(self.ws, "forensic-cell", self.res["bob"].pdf, "leak.pdf")
        r = inv.report
        self.assertEqual(r["status"], "VERIFIED")
        self.assertEqual(r["recipient_id"], "bob")
        self.assertTrue(r["signature_valid"] and r["ledger_inclusion_valid"])
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_evidence.py"),
                              str(inv.case_dir / "evidence_bundle.json"), "--trust-anchor", self.ws.trust_anchor,
                              "--evidence", str(inv.case_dir / "leaked_leak.pdf")],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIsNotNone(r["investigation"]["finding_block"])            # conclusion committed on ledger
        # independent re-extraction from the original
        orig = inv.case_dir / "original.pdf"
        orig.write_bytes(sample_pdf())
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_evidence.py"),
                              str(inv.case_dir / "evidence_bundle.json"), "--trust-anchor", self.ws.trust_anchor,
                              "--evidence", str(inv.case_dir / "leaked_leak.pdf"), "--original", str(orig)],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("Re-extracted symbols match", out.stdout)
        # tampering with the bundle is detected
        b = json.loads((inv.case_dir / "evidence_bundle.json").read_text())
        b["sessions"][0]["intent_proof"]["tx"]["body"]["recipient_id"] = "alice"
        bad = inv.case_dir / "bad.json"
        bad.write_text(json.dumps(b))
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_evidence.py"), str(bad),
                              "--trust-anchor", self.ws.trust_anchor], capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)

    def test_bad_share_from_malicious_node_is_skipped(self):
        from unittest import mock
        t = self.ws.local_nodes()
        try:
            for n in ("node-1", "node-2"):
                t.nodes[n].byzantine = "badshare"
            with mock.patch("random.randrange", return_value=0):     # ask node-1 first
                res = client.open_in_workspace(self.ws, "bob", self.doc)
            shares = next(s for s in res.steps if s["step"] == "committee_shares")["released"]
            self.assertTrue(any("bad share" in v for v in shares.values()))
        finally:
            for n in ("node-1", "node-2"):
                t.nodes[n].byzantine = None

    def test_committee_layer_is_per_recipient(self):
        """Alice's released layer is useless for Bob's wrapped key."""
        from nishaan.crypto.sym import aead_decrypt, b64d, kem_open
        from nishaan.sender import recover_committee_layer, wrap_aad
        alice, bob = self.ws.identity("alice"), self.ws.identity("bob")
        m = self.pkg["manifest_tx"]["body"]
        rec = next(s for s in self.ws.client().call_any("sessions_for_doc", doc_id=self.doc)
                   if s["subject_id"] == "alice")
        kc_alice, _ = recover_committee_layer(alice.token, m, "alice", rec["tx_id"], rec["session_id"], self.ws.client())
        w = self.pkg["wraps"]["bob"]
        kr_bob = kem_open(bob.token.decaps, w["sealed"], wrap_aad(self.doc, "bob", w["serial"]), "doc-key-wrap")
        with self.assertRaises(Exception):
            aead_decrypt(bytes(x ^ y for x, y in zip(kr_bob, kc_alice)), b64d(self.pkg["payload"]), self.doc.encode())

    def test_screenshot_leak(self):
        img = render_pdf(self.res["alice"].pdf, 120)[0]
        png = cv2.imencode(".png", img)[1].tobytes()
        r = forensics.investigate(self.ws, "forensic-cell", png, "shot.png").report
        self.assertEqual(r["status"], "VERIFIED")
        self.assertEqual([f["recipient_id"] for f in r["findings"]], ["alice"])
        self.assertEqual(r["attribution_tier"], "fingerprint")

    def test_expiry_stops_recipients_not_investigators(self):
        from datetime import timedelta
        from unittest import mock
        from nishaan.ledger.node import NodeError
        from nishaan.pki import utcnow
        r = forensics.investigate(self.ws, "forensic-cell", self.res["carol"].pdf, "late.pdf").report
        fa_tx = r["investigation"]["forensic_access_tx"]
        intent_tx = next(s["tx_id"] for s in self.ws.client().call_any("sessions_for_doc", doc_id=self.doc)
                         if s["subject_id"] == "carol")
        node = self.ws.local_nodes().nodes["node-1"]
        later = utcnow() + timedelta(days=100)          # document valid 30 days, certificates 365
        with mock.patch("nishaan.pki.utcnow", return_value=later):
            self.assertIn("sealed", node.release_share(fa_tx))
            with self.assertRaises(NodeError):
                node.release_share(intent_tx)

    def test_revoked_key_cannot_decrypt(self):
        ws = self.ws
        pkg, _ = sender.distribute(ws, "sender-ops", sample_pdf(), "Brief 2", ["dev"])
        ws.revoke("dev")
        with self.assertRaises(TxRejectedError):
            client.open_in_workspace(ws, "dev", pkg["doc_id"])


if __name__ == "__main__":
    unittest.main()
