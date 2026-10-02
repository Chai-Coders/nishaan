import helpers  # noqa: F401  (puts the project on sys.path)
import os
import unittest

from nishaan import pki
from nishaan.crypto import pqc, shamir
from nishaan.crypto.sym import aead_decrypt, aead_encrypt, kem_open, kem_seal
from nishaan.ledger.merkle import inclusion_proof, merkle_root, verify_inclusion


class TestPQC(unittest.TestCase):
    def test_mldsa_roundtrip_and_context(self):
        pk, sk = pqc.sig_keygen("ML-DSA-65")
        sig = pqc.sign(sk, b"record", b"ctx-a")
        self.assertTrue(pqc.verify(pk, b"record", sig, b"ctx-a"))
        self.assertFalse(pqc.verify(pk, b"record", sig, b"ctx-b"))     # domain separation
        self.assertFalse(pqc.verify(pk, b"recorD", sig, b"ctx-a"))

    def test_mlkem_roundtrip(self):
        pk, sk = pqc.kem_keygen()
        ct, ss = pqc.kem_encaps(pk)
        self.assertEqual(pqc.kem_decaps(sk, ct), ss)

    def test_backends_interoperate(self):
        """liboqs and the pure-Python implementations must produce identical FIPS encodings."""
        if pqc._oqs() is None:
            self.skipTest("liboqs not installed")
        from dilithium_py.ml_dsa import ML_DSA_65
        from kyber_py.ml_kem import ML_KEM_768
        pk, sk = pqc.sig_keygen("ML-DSA-65")              # liboqs
        sig = pqc.sign(sk, b"m", b"c")
        self.assertTrue(ML_DSA_65.verify(pk, b"m", sig, ctx=b"c"))
        ek, dk = ML_KEM_768.keygen()                      # pure python
        ct, ss = pqc.kem_encaps(ek)                       # liboqs
        self.assertEqual(ML_KEM_768.decaps(dk, ct), ss)

    def test_classical_algorithms_rejected(self):
        with self.assertRaises(ValueError):
            pqc.sig_keygen("ECDSA")
        with self.assertRaises(ValueError):
            pqc.kem_keygen("X25519")

    def test_kem_seal_binds_aad(self):
        tok = pki.SoftToken.generate("x", "recipient")
        sealed = kem_seal(tok.kem_pk, b"secret", b"aad-1", "label")
        self.assertEqual(kem_open(tok.decaps, sealed, b"aad-1", "label"), b"secret")
        with self.assertRaises(Exception):
            kem_open(tok.decaps, sealed, b"aad-2", "label")

    def test_aead(self):
        k = os.urandom(32)
        blob = aead_encrypt(k, b"hello", b"a")
        self.assertEqual(aead_decrypt(k, blob, b"a"), b"hello")
        with self.assertRaises(Exception):
            aead_decrypt(k, blob[:-1] + bytes([blob[-1] ^ 1]), b"a")


class TestShamirMerkle(unittest.TestCase):
    def test_shamir_threshold(self):
        secret = os.urandom(32)
        shares = shamir.split(secret, 4, 2)
        for i in range(4):
            for j in range(i + 1, 4):
                self.assertEqual(shamir.combine([shares[i], shares[j]]), secret)
        self.assertNotEqual(shamir.combine([shares[0]]), secret)

    def test_merkle_proofs(self):
        for n in (1, 2, 3, 5, 8, 13):
            leaves = [os.urandom(32) for _ in range(n)]
            root = merkle_root(leaves)
            for i in range(n):
                self.assertTrue(verify_inclusion(leaves[i], i, n, inclusion_proof(leaves, i), root))
            if n > 1:
                self.assertFalse(verify_inclusion(leaves[0], 1, n, inclusion_proof(leaves, 1), root))


class TestPKI(unittest.TestCase):
    def test_token_pin_and_cert(self):
        import tempfile
        ca = pki.LocalCA.create()
        ident = ca.new_identity("alice", "Lt Alice", "recipient")
        ok, _ = pki.verify_cert(ident.cert, ca.cert)
        self.assertTrue(ok)
        other = pki.LocalCA.create()
        self.assertFalse(pki.verify_cert(ident.cert, other.cert)[0])
        with tempfile.TemporaryDirectory() as d:
            ident.token.save(d + "/t.json", "1234")
            tok = pki.SoftToken.load(d + "/t.json", "1234")
            self.assertEqual(tok.sig_pk, ident.token.sig_pk)
            with self.assertRaises(PermissionError):
                pki.SoftToken.load(d + "/t.json", "wrong")


if __name__ == "__main__":
    unittest.main()
