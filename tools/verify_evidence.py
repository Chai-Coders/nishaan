#!/usr/bin/env python3
"""Standalone verifier for Nishaan evidence bundles.

Independent of the Nishaan code base on purpose: it needs only the Python
standard library plus a FIPS 204/205 implementation (liboqs-python, or
dilithium-py for ML-DSA). Give it the bundle, the CA trust-anchor fingerprint
obtained out of band, and optionally the leaked file:

    python tools/verify_evidence.py evidence_bundle.json --trust-anchor <sha3-hex> [--evidence leaked.pdf]

It re-checks: the officer's signature over the bundle; the CA root and every
certificate; the genesis block; every ledger record's Merkle inclusion and its
block's commit certificate (quorum of node signatures); that the investigation
and its finding (symbols, error bound, accused sessions) were committed on the
ledger by that officer; the recipients' signatures on their decryption records
and receipts; the anti-framing blind index; the hash chain to the head; and it
recomputes the Tardos score, the threshold and the false-accusation bound itself.
With --original it also re-extracts the fingerprint from the evidence.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys
import warnings

# ------------------------------------------------------------------ PQC verify (FIPS 204 / 205)
_OQS = {"ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87", "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
        "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F", "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S"}


def pqc_verify(alg: str, pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
    try:
        import contextlib
        import io
        with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()):
            warnings.simplefilter("ignore")
            import oqs  # type: ignore
        with oqs.Signature(_OQS[alg]) as s:
            return bool(s.verify_with_ctx_str(msg, sig, ctx, pk))
    except ImportError:
        pass
    if alg.startswith("ML-DSA"):
        from dilithium_py import ml_dsa  # type: ignore
        return bool(getattr(ml_dsa, alg.replace("-", "_")).verify(pk, msg, sig, ctx=ctx))
    raise RuntimeError(f"no implementation available for {alg} (install liboqs-python)")


# ------------------------------------------------------------------ encoding / hashing
def cj(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def h(o) -> str:
    return hashlib.sha3_256(cj(o)).hexdigest()


def b64(s: str) -> bytes:
    return base64.b64decode(s)


# ------------------------------------------------------------------ ledger structures
def leaf(d): return sha3(b"\x00" + d)
def node(l, r): return sha3(b"\x01" + l + r)


def merkle_ok(leaf_data: bytes, index: int, size: int, path: list, root_hex: str) -> bool:
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf(leaf_data)
    for p in path:
        p = bytes.fromhex(p)
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def tx_signed_ok(tx: dict, cert: dict) -> bool:
    b = cert["body"]
    if tx["sig_alg"] != b["sig_alg"]:
        return False
    msg = cj({"type": tx["type"], "body": tx["body"], "signer": tx["signer"]})
    return pqc_verify(b["sig_alg"], b64(b["sig_pk"]), msg, b64(tx["sig"]), b"nishaan/v1/tx")


def cert_ok(cert: dict, ca: dict) -> bool:
    b, cb = cert["body"], ca["body"]
    return (b["issuer"] == cb["fingerprint"] and cert["issuer_sig_alg"] == cb["sig_alg"]
            and hashlib.sha3_256(b64(b["sig_pk"])).hexdigest() == b["fingerprint"]
            and pqc_verify(cb["sig_alg"], b64(cb["sig_pk"]), cj(b), b64(cert["issuer_sig"]), b"nishaan/v1/cert"))


class Chain:
    def __init__(self, genesis: dict):
        g = genesis["txs"][0]["body"]
        self.chain_id, self.nodes, self.f, self.ca = g["chain_id"], g["nodes"], g["f"], g["ca_cert"]
        self.quorum = (len(self.nodes) + self.f + 2) // 2     # ceil((n+f+1)/2)

    def qc_ok(self, qc: dict, bhash: str, height: int) -> tuple[bool, int]:
        if qc.get("phase") != "COMMIT" or qc["block_hash"] != bhash or qc["height"] != height:
            return False, 0
        msg = cj({"phase": "COMMIT", "chain_id": self.chain_id, "height": qc["height"], "view": qc["view"],
                  "block_hash": qc["block_hash"]})
        good = set()
        for v in qc["votes"]:
            c = self.nodes.get(v["node_id"])
            if c and v["node_id"] not in good and pqc_verify(c["body"]["sig_alg"], b64(c["body"]["sig_pk"]), msg,
                                                             b64(v["sig"]), b"nishaan/v1/vote"):
                good.add(v["node_id"])
        return len(good) >= self.quorum, len(good)

    def proof_ok(self, p: dict) -> tuple[bool, str]:
        tid = hashlib.sha3_256(cj(p["tx"])).digest()
        m = merkle_ok(tid, p["index"], p["size"], p["path"], p["header"]["merkle_root"])
        bh = h(p["header"])
        q, n = self.qc_ok(p["cc"], bh, p["header"]["height"])
        return m and q, f"block {p['header']['height']}: merkle {'ok' if m else 'BAD'}, {n} node signatures"


# ------------------------------------------------------------------ Tardos (re-implemented)
def uniform(key: bytes, label: bytes, n: int) -> list[float]:
    raw = hashlib.shake_256(b"nishaan/tardos/" + label + b"/" + key).digest(8 * n)
    return [(int.from_bytes(raw[8 * i:8 * i + 8], "big") >> 11) / float(1 << 53) for i in range(n)]


def tardos(secret: bytes, seed: bytes, m: int, c: int):
    t = 1.0 / (300.0 * c)
    tp = math.asin(math.sqrt(t))
    p = [math.sin(tp + (math.pi / 2 - 2 * tp) * u) ** 2 for u in uniform(secret, b"bias", m)]
    x = [1 if u < pi else 0 for u, pi in zip(uniform(secret + seed, b"codeword", m), p)]
    return p, x


def score(p, x, y) -> float:
    s = 0.0
    for pi, xi, yi in zip(p, x, y):
        g1, g0 = math.sqrt((1 - pi) / pi), math.sqrt(pi / (1 - pi))
        if yi == 1:
            s += g1 if xi == 1 else -g0
        elif yi == 0:
            s += g0 if xi == 0 else -g1
    return s


def chernoff(p, y, sc: float) -> float:
    terms = []
    for pi, yi in zip(p, y):
        if yi == -1:
            continue
        g1, g0 = math.sqrt((1 - pi) / pi), math.sqrt(pi / (1 - pi))
        terms.append((g1, pi, -g0) if yi == 1 else (g0, 1 - pi, -g1))

    def f(lam):
        tot = 0.0
        for vh, qh, vl in terms:
            a, b = math.log(qh) + lam * vh, math.log1p(-qh) + lam * vl
            mx = max(a, b)
            tot += mx + math.log(math.exp(a - mx) + math.exp(b - mx))
        return tot - lam * sc

    lo, hi = 0.0, 20.0
    gr = (math.sqrt(5) - 1) / 2
    for _ in range(200):
        a, b = hi - gr * (hi - lo), lo + gr * (hi - lo)
        if f(a) < f(b):
            hi = b
        else:
            lo = a
    return min(1.0, math.exp(min(0.0, f((lo + hi) / 2))))


def threshold_for(p, y, eps: float) -> float:
    """Recompute the accusation threshold independently (bisection on the Chernoff bound)."""
    hi = sum((math.sqrt((1 - pi) / pi) if yi == 1 else math.sqrt(pi / (1 - pi))) for pi, yi in zip(p, y) if yi != -1) + 1
    lo = 0.0
    if chernoff(p, y, hi) > eps:
        return float("inf")
    for _ in range(40):
        mid = (lo + hi) / 2
        if chernoff(p, y, mid) <= eps:
            hi = mid
        else:
            lo = mid
    return hi


def reextract(original: str, evidence: str, B: dict) -> str:
    """Optional: re-run the extraction with the Nishaan extractor (needs the original document)."""
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    from nishaan.watermark import engine as W  # noqa: E402
    orig = open(original, "rb").read()
    data = open(evidence, "rb").read()
    plan = W.make_plan(orig)
    F = B["fingerprint"]
    code = W.code_for(b64(F["wm_secret"]), plan, F["code_len"])
    delta = B["document"]["manifest_proof"]["tx"]["body"]["wm"]["delta_pt"]   # from the ledger, not the bundle
    ext = W.extract_any(data, evidence, orig, plan, delta)
    sym = W.decode(ext, code)
    return "".join("-" if v == -1 else str(int(v)) for v in sym.y)


# ------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle")
    ap.add_argument("--trust-anchor", help="CA root fingerprint obtained out of band")
    ap.add_argument("--evidence", help="the leaked file, to check its hash")
    ap.add_argument("--original", help="the original document: re-extract the fingerprint from --evidence "
                                       "with the Nishaan extractor instead of trusting the bundle's symbols")
    ap.add_argument("--max-eps", type=float, default=1e-6,
                    help="largest acceptable false-accusation probability per innocent (default 1e-6)")
    a = ap.parse_args()
    B = json.load(open(a.bundle))
    results = []

    def check(name, ok, detail=""):
        results.append((bool(ok), name, detail))

    anchor = a.trust_anchor or B["trust_anchor"]
    if not a.trust_anchor:
        print("WARNING: no --trust-anchor given; using the one inside the bundle (not independent)")
    G = B["genesis"]
    chain = Chain(G)
    ca = chain.ca
    check("CA root matches trust anchor", ca["body"]["fingerprint"] == anchor, ca["body"]["sig_alg"])
    check("CA root self-signature", cert_ok(ca, ca))
    gtx = G["txs"][0]
    check("Genesis signed by CA", tx_signed_ok(gtx, ca))
    check("Ledger node certificates issued by CA", all(cert_ok(c, ca) for c in chain.nodes.values()),
          f"{len(chain.nodes)} nodes, f={chain.f}, quorum={chain.quorum}")
    gq, gn = chain.qc_ok(G["cc"], h(G["header"]), 0)
    check("Genesis commit certificate", gq, f"{gn} node signatures")

    # who signed this bundle, and is the investigation itself on the ledger?
    off = B["officer"]["cert"]
    payload = cj({k: v for k, v in B.items() if k not in ("bundle_hash", "officer_signature")})
    check("Bundle hash", hashlib.sha3_256(payload).hexdigest() == B["bundle_hash"], B["bundle_hash"][:24] + "...")
    check("Officer certificate issued by CA", cert_ok(off, ca) and off["body"]["role"] == "forensic",
          off["body"]["display_name"])
    ep = B["officer"]["enroll_proof"]
    eok, ed = chain.proof_ok(ep)
    check("Officer certificate enrolled on ledger", eok and ep["tx"]["body"]["cert"] == off, ed)
    check(f"Officer {off['body']['sig_alg']} signature on the whole bundle",
          pqc_verify(off["body"]["sig_alg"], b64(off["body"]["sig_pk"]), payload, b64(B["officer_signature"]),
                     b"nishaan/v1/evidence-bundle"))
    mp = B["document"]["manifest_proof"]
    ok, d = chain.proof_ok(mp)
    manifest = mp["tx"]["body"]
    check("Distribution manifest on ledger", ok and mp["tx"]["type"] == "DISTRIBUTE", d)
    fp = B["forensic_access_proof"]
    ok, d = chain.proof_ok(fp)
    fab = fp["tx"]["body"]
    check("Investigation logged on ledger (FORENSIC_ACCESS)",
          ok and fp["tx"]["type"] == "FORENSIC_ACCESS" and fp["tx"]["signer"] == off["body"]["serial"]
          and tx_signed_ok(fp["tx"], off), d)
    check("Investigation is for this document, case and evidence",
          fab["doc_id"] == manifest["doc_id"] and fab["case_id"] == B["case_id"]
          and fab["evidence_hash"] == B["evidence"]["sha3_256"])
    if a.evidence:
        check("Evidence file hash", hashlib.sha3_256(open(a.evidence, "rb").read()).hexdigest()
              == B["evidence"]["sha3_256"])

    F = B["fingerprint"]
    fdp = B["finding_proof"]
    ok, d = chain.proof_ok(fdp)
    fb = fdp["tx"]["body"]
    check("Finding committed on ledger by the same officer",
          ok and fdp["tx"]["type"] == "FORENSIC_FINDING" and fdp["tx"]["signer"] == off["body"]["serial"]
          and tx_signed_ok(fdp["tx"], off), d)
    check("Finding binds this investigation, evidence and symbols",
          fb["forensic_access_tx"] == hashlib.sha3_256(cj(fp["tx"])).hexdigest()
          and fb["evidence_hash"] == B["evidence"]["sha3_256"] and fb["case_id"] == B["case_id"]
          and fb["symbols_hash"] == hashlib.sha3_256(F["symbols"].encode()).hexdigest()
          and fb["eps"] == F["eps"] and fb["code_len"] == F["code_len"]
          and {x["session_id"] for x in fb["accused"]} == {S["session_id"] for S in B["sessions"]})
    check(f"Error bound within policy (eps <= {a.max_eps:g})", F["eps"] <= a.max_eps, f"eps = {F['eps']:g}")
    secret = b64(F["wm_secret"])
    check("Watermark secret matches manifest commitment", hashlib.sha3_256(secret).hexdigest() == manifest["wm"]["commit"])
    if a.original:
        if not a.evidence:
            check("Re-extraction", False, "--original needs --evidence")
        else:
            orig_ok = hashlib.sha3_256(open(a.original, "rb").read()).hexdigest() == manifest["doc_hash"]
            check("Original document matches manifest hash", orig_ok)
            if orig_ok:
                again = reextract(a.original, a.evidence, B)
                same = sum(x == y for x, y in zip(again, F["symbols"]))
                check("Re-extracted symbols match the committed symbols", again == F["symbols"],
                      f"{same}/{len(again)} positions identical")
    y = [-1 if ch == "-" else int(ch) for ch in F["symbols"]]
    m = F["code_len"]
    for S in B["sessions"]:
        sid = S["session_id"]
        ip = S["intent_proof"]
        rec = ip["tx"]["body"]
        who = rec["recipient_id"]
        ok, d = chain.proof_ok(ip)
        check(f"[{who}] decryption record on ledger", ok and ip["tx"]["type"] == "DECRYPT_INTENT", d)
        cert = S["recipient_cert"]
        check(f"[{who}] certificate issued by CA to this recipient",
              cert_ok(cert, ca) and cert["body"]["subject_id"] == who and cert["body"]["role"] == "recipient",
              cert["body"]["fingerprint"][:16] + "...")
        enp = S.get("enroll_proof")
        eok, ed = chain.proof_ok(enp) if enp else (False, "missing")
        check(f"[{who}] certificate enrolled on ledger before the record",
              eok and enp["tx"]["body"]["cert"] == cert and enp["header"]["height"] <= ip["header"]["height"], ed)
        check(f"[{who}] {cert['body']['sig_alg']} signature on record", tx_signed_ok(ip["tx"], cert)
              and ip["tx"]["signer"] == cert["body"]["serial"]
              and rec["recipient_pubkey_fingerprint"] == cert["body"]["fingerprint"])
        check(f"[{who}] record is for this document", rec["doc_id"] == manifest["doc_id"]
              and rec["doc_hash"] == manifest["doc_hash"] and who in [r["subject_id"] for r in manifest["recipients"]])
        ch = S["chain"]
        links = all(ch[i + 1]["header"]["prev_hash"] == h(ch[i]["header"]) for i in range(len(ch) - 1))
        hq, hn = chain.qc_ok(ch[-1]["cc"], h(ch[-1]["header"]), ch[-1]["header"]["height"])
        check(f"[{who}] hash chain to head", links and hq and h(ch[0]["header"]) == h(ip["header"]),
              f"blocks {ch[0]['header']['height']}..{ch[-1]['header']['height']}, head {hn} signatures")
        exact = False
        if S.get("receipt_proof"):
            rok, rd = chain.proof_ok(S["receipt_proof"])
            rb = S["receipt_proof"]["tx"]["body"]
            rok = rok and rb["session_id"] == sid and tx_signed_ok(S["receipt_proof"]["tx"], cert)
            exact = rok and rb["delivered_hash"] == B["evidence"]["sha3_256"]
            check(f"[{who}] delivery receipt", rok, "evidence is byte-identical to the delivered copy" if exact
                  else "evidence is a derivative of the delivered copy")
        if exact:
            check(f"[{who}] attribution by exact copy", True, "signed receipt of this exact file")
            continue
        if not S.get("seed"):
            check(f"[{who}] fingerprint evidence", False, "no seed revealed and not an exact copy")
            continue
        seed = b64(S["seed"])
        check(f"[{who}] revealed seed matches signed blind index",
              hashlib.shake_256(b"nishaan/wm-index/" + seed).digest(32).hex() == rec["watermark_index"])
        p, x = tardos(secret, seed, m, F.get("c", 2))
        sc = score(p, x, y)
        z = threshold_for(p, y, F["eps"])
        bound = chernoff(p, y, sc)
        check(f"[{who}] fingerprint score above independently recomputed threshold", sc > z,
              f"score {sc:.2f}, threshold {z:.2f} (bundle says {F['threshold']})")
        check(f"[{who}] false-accusation bound <= eps", bound <= F["eps"], f"P(innocent >= score) <= {bound:.2e}")

    width = max(len(n) for _, n, _ in results)
    for ok, name, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    allok = all(ok for ok, _, _ in results)
    print("\nRESULT:", "ALL CHECKS PASSED" if allok else "VERIFICATION FAILED",
          f"- case {B['case_id']}, status in report: {B['report']['status']}")
    if allok and not a.original:
        print("Note: the extracted symbols are the forensic cell's, committed on the ledger before this report;"
              " pass --original and --evidence to re-extract them independently.")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
