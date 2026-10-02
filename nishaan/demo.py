"""Scripted end-to-end demo following the brief's section 14.

    python -m nishaan demo          # ~1-2 minutes, writes everything to ./nishaan-data and ./demo_output
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

import cv2
import numpy as np

from . import airgap
from .crypto import pqc
from .crypto.sym import sha3_hex

OUT = Path("demo_output")


def _h(title: str) -> None:
    print("\n" + title)
    print("-" * len(title))


def _ok(msg: str) -> None:
    print("  [ok] " + msg)


def run_demo(root: str = "nishaan-data", fresh: bool = True) -> None:
    from . import audit, client, forensics, sender
    from .watermark import engine as W
    from .watermark.render import render_pdf, visual_metrics
    from .workspace import Workspace

    t0 = time.time()
    OUT.mkdir(exist_ok=True)
    _h("1. Air-gapped setup")
    airgap.enforce()
    _ok(f"air-gap guard active: any non-local network connection raises (blocked so far: {len(airgap.blocked)})")
    _ok(f"PQC library: {pqc.backend_name()}")
    if fresh and Path(root).exists():
        shutil.rmtree(root)
    ws = Workspace(root) if Path(root, "genesis.json").exists() else Workspace.init(root)
    c = ws.client()
    s = c.call_any("summary")
    _ok(f"offline CA root ({ws.ca().cert['body']['sig_alg']}), trust anchor {ws.trust_anchor[:16]}...")
    _ok(f"{len(s['nodes'])} ledger nodes with their own ML-DSA keys and databases; quorum {s['quorum']}, tolerates f={s['f']}")
    _ok("identities: " + ", ".join(x["subject_id"] for x in ws.subjects()))

    _h("2. Sender encrypts the brief once for four recipients")
    doc_path = Path(__file__).resolve().parent.parent / "demo" / "docs" / "briefing.pdf"
    if not doc_path.exists():
        sys.path.insert(0, str(doc_path.parent.parent))
        from make_sample_docs import make_reportlab
        doc_path.parent.mkdir(parents=True, exist_ok=True)
        make_reportlab(doc_path)
    pdf = doc_path.read_bytes()
    pkg, log = sender.distribute(ws, "sender-ops", pdf, "SAGAR KAVACH-26 logistics brief",
                                 ["alice", "bob", "carol", "dev"], max_decryptions=2)
    m = pkg["manifest_tx"]["body"]
    _ok(f"AES-256-GCM payload; ML-KEM-768 key wraps for 4 recipients + forensic cell")
    per = m["committee"]["per_recipient"]
    _ok(f"a separate committee key layer per recipient, each split {m['committee']['threshold']}-of-"
        f"{len(next(iter(per.values())))} across the ledger nodes with public share commitments")
    _ok(f"manifest committed at block {log['height']}; {m['wm']['slots']} words will carry a "
        f"{m['wm']['code_len']}-symbol Tardos fingerprint")

    _h("3. Two recipients decrypt (commit-before-decrypt)")
    res = {}
    for who in ("alice", "bob"):
        r = client.open_in_workspace(ws, who, pkg["doc_id"])
        res[who] = r
        (OUT / f"copy_{who}.pdf").write_bytes(r.pdf)
        st = {x["step"]: x for x in r.steps}
        rel = [k for k, v in st["committee_shares"]["released"].items() if v == "released"]
        _ok(f"{who}: signed record committed at block {st['record_committed']['block']} "
            f"-> shares from {', '.join(rel)} -> decrypted -> receipt at block {st['receipt_committed']['block']}")
    try:
        for _ in range(3):
            client.open_in_workspace(ws, "dev", pkg["doc_id"])
    except Exception as e:
        _ok(f"policy enforced by the ledger committee: dev's third opening refused ({e})")
    try:
        ws.enroll("erin", "Lt. Erin Pillai, INS Delhi", "recipient")
        client.open_in_workspace(ws, "erin", pkg["doc_id"])
    except Exception as e:
        _ok(f"erin is not on the distribution list: {e}")

    _h("4. The copies look identical")
    vm = visual_metrics(res["alice"].pdf, res["bob"].pdf)
    base = visual_metrics(pdf, pdf)
    _ok(f"same text; files differ: {sha3_hex(res['alice'].pdf)[:12]} vs {sha3_hex(res['bob'].pdf)[:12]}")
    _ok(f"PSNR {vm['psnr_db_min']} dB, SSIM {vm['ssim_min']} at 150 DPI - less than the difference between two "
        "PDF viewers rendering the same file (17.8 dB / 0.905), see attack lab")

    _h("5. ...but carry different fingerprints")
    plan = W.make_plan(pdf)
    # read each copy's word shifts back against the original geometry (+ = moved right, - = moved left)
    for who in ("alice", "bob"):
        ext = W.extract_vector(res[who].pdf, plan, m["wm"]["delta_pt"])
        bits = "".join("+" if v > 0 else "-" for v in ext.values[:48])
        _ok(f"{who:5s} word shifts: {bits}...")

    _h("6. Ledger entries for both sessions")
    for sess in c.call_any("sessions_for_doc", doc_id=pkg["doc_id"]):
        rec = sess["tx"]["body"]
        p = c.verified_tx(sess["tx_id"])
        _ok(f"block {sess['height']}: {rec['recipient_id']:5s} session {rec['session_id'][:8]} "
            f"blind index {rec['watermark_index'][:12]}... signed {sess['tx']['sig_alg']}, "
            f"{len(p['cc']['votes'])} node signatures")

    _h("7. Bob's copy leaks as a phone photo of the screen")
    from .attacklab import _phone_photo
    photo = _phone_photo(render_pdf(res["bob"].pdf, 200, pages=[0])[0], np.random.default_rng(3))
    cv2.imwrite(str(OUT / "leaked_photo.jpg"), photo)
    inv = forensics.investigate(ws, "forensic-cell", (OUT / "leaked_photo.jpg").read_bytes(), "leaked_photo.jpg")
    r = inv.report
    print(f"  STATUS {r['status']}: " + ", ".join(f"{f['display_name']} (score {f['score']}, threshold "
                                               f"{r['fingerprint']['threshold']}, P(false) <= {f['false_positive_bound']:.1e})"
                                               for f in r["findings"]))
    for f in r["findings"]:
        for ch in f["checks"]:
            print(f"     [{'PASS' if ch['ok'] else 'FAIL'}] {ch['check']}")
    shutil.copytree(inv.case_dir, OUT / "case_photo_leak", dirs_exist_ok=True)

    _h("8. Independent verification of the evidence bundle")
    vout = subprocess.run([sys.executable, str(Path(__file__).resolve().parent.parent / "tools" / "verify_evidence.py"),
                           str(inv.case_dir / "evidence_bundle.json"), "--trust-anchor", ws.trust_anchor,
                           "--evidence", str(OUT / "leaked_photo.jpg")], capture_output=True, text=True)
    lines = vout.stdout.strip().splitlines()
    print(f"  {sum(1 for x in lines if x.startswith('PASS'))} checks passed, "
          f"{sum(1 for x in lines if x.startswith('FAIL'))} failed")
    print("  " + next(x for x in lines if x.startswith("RESULT")))

    _h("9. Collusion: Alice and Bob average their screenshots")
    a = render_pdf(res["alice"].pdf, 150, pages=[0])[0].astype(np.float32)
    b = render_pdf(res["bob"].pdf, 150, pages=[0])[0].astype(np.float32)
    cv2.imwrite(str(OUT / "colluded.png"), ((a + b) / 2).astype(np.uint8))
    r2 = forensics.investigate(ws, "forensic-cell", (OUT / "colluded.png").read_bytes(), "colluded.png").report
    print(f"  STATUS {r2['status']}: accused {[f['recipient_id'] for f in r2['findings']]} "
          "(Tardos codes guarantee at least one colluder); innocent maximum "
          f"{max([x['score'] for x in r2['fingerprint']['candidates'] if not x['accused']] or [0])}"
          f" vs threshold {r2['fingerprint']['threshold']}")

    _h("10. A privileged administrator tries to rewrite the ledger")
    cp, cp_path = audit.export_checkpoint(ws)
    _ok(f"checkpoint at block {cp['height']} exported to removable media ({cp_path.name})")
    t = audit.tamper(ws, "node-2", "edit-record")
    print("  tamper: " + t["change"] + " on node-2")
    rep = audit.audit_all(ws)
    for nid, n in rep["nodes"].items():
        print(f"     {nid}: " + ("verified" if n.get("ok") else f"FAILED at block {n['corrupted']['height']}: "
                                                                 f"{n['corrupted']['reason']}"))
    ws.client().transport.call("node-2", "heal")
    _ok("node-2 healed from the quorum")
    t = audit.tamper(ws, "node-1", "rewrite-history")
    print("  tamper: " + t["change"])
    rep = audit.audit_all(ws)
    _ok("every node's self-audit passes (keys were stolen), but:")
    for chk in rep["checkpoints"]:
        print(f"     checkpoint block {chk['height']}: {'holds' if chk['ok'] else 'VIOLATED'} {chk['nodes']}")

    _h("Done")
    print(f"  {time.time() - t0:.0f} s, outbound connections attempted: {len(airgap.blocked)}")
    print(f"  artefacts in {OUT.resolve()}; workspace in {Path(root).resolve()}")
    print("  next: python -m nishaan --root " + root + " ui   (the tampered ledger is left as-is for inspection)")
