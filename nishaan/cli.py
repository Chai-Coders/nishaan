"""Command-line interface.

    python -m nishaan init                      # CA, 4 ledger nodes, genesis, demo identities
    python -m nishaan send brief.pdf --title "..." --to alice,bob,carol
    python -m nishaan open <doc_id> --as bob --out bob.pdf
    python -m nishaan investigate leaked.png
    python -m nishaan verify-bundle <case>/evidence_bundle.json
    python -m nishaan ui                        # local web dashboard
    python -m nishaan demo                      # scripted end-to-end demo (brief section 14)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
os.environ.setdefault("PYTHONWARNINGS", "ignore")

DEFAULT_ROOT = os.environ.get("NISHAAN_HOME", "nishaan-data")


def _ws(a):
    from .workspace import Workspace
    ws = Workspace(a.root)
    if not ws.exists():
        sys.exit(f"no workspace at {a.root}; run `python -m nishaan init` first")
    return ws


def _print(obj):
    print(json.dumps(obj, indent=1, default=str))


def cmd_init(a):
    from .workspace import Workspace
    from .crypto import pqc
    ws = Workspace.init(a.root, n_nodes=a.nodes, f=a.f)
    s = ws.client().call_any("summary")
    print(f"workspace     {Path(a.root).resolve()}")
    print(f"pqc backend   {pqc.backend_name()}")
    print(f"chain         {s['chain_id']}  ({len(s['nodes'])} nodes, f={s['f']}, quorum {s['quorum']})")
    print(f"CA root       {ws.ca().cert['body']['sig_alg']}  trust anchor {ws.trust_anchor}")
    print("identities    " + ", ".join(f"{x['subject_id']} ({x['role']})" for x in ws.subjects()))


def cmd_status(a):
    ws = _ws(a)
    c = ws.client()
    s = c.call_any("summary")
    print(f"chain {s['chain_id']}  mode {ws.mode}  height {s['height']}  head {s['hash'][:16]}...")
    for nid, h in c.heads().items():
        print(f"  {nid}: " + (f"height {h['height']} head {h['hash'][:12]}" + (" CORRUPTED" if h.get("corrupted") else "")
                              if "height" in h else h["error"]))
    print("documents:")
    for d, v in s["docs"].items():
        print(f"  {d}  {v['title']}  -> {', '.join(v['recipients'])}")
    print("certificates:")
    for serial, r in s["certs"].items():
        print(f"  {r['subject_id']:14s} {r['role']:9s} {r['status']:10s} {serial[:12]}")


def cmd_enroll(a):
    ws = _ws(a)
    log = ws.enroll(a.subject, a.name, a.role)
    print(f"enrolled {a.subject} ({a.role}) at block {log['height']}")


def cmd_revoke(a):
    log = _ws(a).revoke(a.subject, a.reason)
    print(f"revoked {a.subject} at block {log['height']}")


def cmd_rotate(a):
    log = _ws(a).rotate(a.subject)
    print(f"rotated key for {a.subject}; new certificate at block {log['height']}")


def cmd_send(a):
    from . import sender
    ws = _ws(a)
    pdf = Path(a.file).read_bytes()
    pkg, log = sender.distribute(ws, a.sender, pdf, a.title or Path(a.file).stem, a.to.split(","),
                                 forensic_id=a.forensic, max_decryptions=a.max_decryptions,
                                 valid_days=a.days, filename=Path(a.file).name,
                                 classification=a.classification)
    m = pkg["manifest_tx"]["body"]
    print(f"doc_id   {pkg['doc_id']}")
    print(f"manifest committed at block {log['height']} (leader {log['leader']})")
    print(f"package  {ws.p('packages', pkg['doc_id'] + '.nspkg')}")
    print(f"recipients {', '.join(r['subject_id'] for r in m['recipients'])}; "
          f"watermark slots {m['wm']['slots']}, code length {m['wm']['code_len']}")


def cmd_open(a):
    from . import client
    ws = _ws(a)

    def show(s):
        extra = {k: v for k, v in s.items() if k in ("block", "leader", "released", "slots", "title")}
        print(f"  {s['step']:20s} {extra}")
    res = client.open_in_workspace(ws, a.who, a.doc_id, progress=show)
    out = Path(a.out or f"{a.who}_{a.doc_id[:8]}.pdf")
    out.write_bytes(res.pdf)
    print(f"watermarked copy -> {out}  (session {res.session_id})")


def cmd_investigate(a):
    from . import forensics
    ws = _ws(a)
    data = Path(a.file).read_bytes()

    def show(s):
        print(f"  {s['step']:26s} " + json.dumps({k: v for k, v in s.items() if k != 'step'}, default=str)[:150])
    inv = forensics.investigate(ws, a.officer, data, Path(a.file).name, a.case, doc_id=a.doc, progress=show)
    r = inv.report
    print(f"\nSTATUS {r['status']}   case {r['case_id']}")
    for f in r["findings"]:
        print(f"  -> {f['display_name']} ({f['recipient_id']}) session {f['session_id'][:8]} "
              f"score {f['score']} (threshold {r['fingerprint']['threshold']}), "
              f"P(false accusation) <= {f['false_positive_bound']:.1e}")
        for c in f["checks"]:
            print(f"     [{'PASS' if c['ok'] else 'FAIL'}] {c['check']}")
    if not r["findings"]:
        for c in r["fingerprint"]["candidates"][:5]:
            print(f"  candidate {c['recipient_id']:10s} score {c['score']}")
    print(f"report + evidence bundle -> {inv.case_dir}")


def cmd_verify_bundle(a):
    tools = Path(__file__).resolve().parent.parent / "tools" / "verify_evidence.py"
    args = [sys.executable, str(tools), a.bundle]
    if a.trust_anchor:
        args += ["--trust-anchor", a.trust_anchor]
    if a.evidence:
        args += ["--evidence", a.evidence]
    os.execv(sys.executable, args)


def cmd_ledger(a):
    ws = _ws(a)
    c = ws.client()
    if a.action == "blocks":
        top = c.height()
        for h in range(max(0, a.start), top + 1):
            b = c.call_any("get_block", height=h)
            hd = b["header"]
            print(f"#{h:<4} {hd['timestamp']}  leader {hd['proposer']:8s} view {hd['view']}  "
                  f"{len(b['cc']['votes'])} sigs  " + ", ".join(t["type"] for t in b["txs"]))
    elif a.action == "audit":
        from .audit import audit_all
        _print(audit_all(ws))


def cmd_checkpoint(a):
    from .audit import export_checkpoint, verify_checkpoint
    ws = _ws(a)
    if a.action == "export":
        cp, path = export_checkpoint(ws, a.out)
        print(f"checkpoint at height {cp['height']} ({cp['block_hash'][:16]}...) -> {path}")
    else:
        _print(verify_checkpoint(ws, json.loads(Path(a.file).read_text())))


def cmd_tamper(a):
    from .audit import tamper
    _print(tamper(_ws(a), a.node, a.kind))


def cmd_heal(a):
    ws = _ws(a)
    _print(ws.client().transport.call(a.node, "heal"))


def cmd_node(a):
    from .ledger.server import serve
    serve(_ws(a), a.id, a.host, a.port)


def cmd_cluster(a):
    from .ledger.server import cluster_down, cluster_up
    ws = _ws(a)
    if a.action == "up":
        _print(cluster_up(ws, a.base_port))
    else:
        print("stopped", cluster_down(ws))


def cmd_ui(a):
    from .web.app import run
    run(a.root, a.host, a.port)


def cmd_attack_lab(a):
    from .attacklab import run_lab
    out = run_lab(a.doc, a.out, deltas=[float(x) for x in a.deltas.split(",")], quick=a.quick)
    print(f"attack lab report -> {out}")


def cmd_demo(a):
    from .demo import run_demo
    run_demo(a.root, fresh=not a.keep)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nishaan", description="Post-quantum leak attribution (offline)")
    ap.add_argument("--root", default=DEFAULT_ROOT, help="workspace directory (default: %(default)s)")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("init", help="create CA, ledger nodes, genesis and demo identities")
    p.add_argument("--nodes", type=int, default=4)
    p.add_argument("--f", type=int, default=1)
    p.set_defaults(fn=cmd_init)
    sp.add_parser("status").set_defaults(fn=cmd_status)

    p = sp.add_parser("enroll")
    p.add_argument("subject")
    p.add_argument("name")
    p.add_argument("role", choices=["recipient", "sender", "forensic"])
    p.set_defaults(fn=cmd_enroll)
    p = sp.add_parser("revoke")
    p.add_argument("subject")
    p.add_argument("--reason", default="key compromise")
    p.set_defaults(fn=cmd_revoke)
    p = sp.add_parser("rotate")
    p.add_argument("subject")
    p.set_defaults(fn=cmd_rotate)

    p = sp.add_parser("send", help="encrypt a PDF once and distribute it")
    p.add_argument("file")
    p.add_argument("--to", required=True, help="comma-separated recipient ids")
    p.add_argument("--title")
    p.add_argument("--sender", default="sender-ops")
    p.add_argument("--forensic", default="forensic-cell")
    p.add_argument("--max-decryptions", type=int, default=3)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--classification", default="RESTRICTED")
    p.set_defaults(fn=cmd_send)

    p = sp.add_parser("open", help="decrypt as a recipient (commit-before-decrypt)")
    p.add_argument("doc_id")
    p.add_argument("--as", dest="who", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_open)

    p = sp.add_parser("investigate", help="attribute a leaked file")
    p.add_argument("file")
    p.add_argument("--officer", default="forensic-cell")
    p.add_argument("--case")
    p.add_argument("--doc", help="document id, if known")
    p.set_defaults(fn=cmd_investigate)

    p = sp.add_parser("verify-bundle", help="independently verify an evidence bundle")
    p.add_argument("bundle")
    p.add_argument("--trust-anchor")
    p.add_argument("--evidence")
    p.set_defaults(fn=cmd_verify_bundle)

    p = sp.add_parser("ledger")
    p.add_argument("action", choices=["blocks", "audit"])
    p.add_argument("--from", dest="start", type=int, default=0)
    p.set_defaults(fn=cmd_ledger)
    p = sp.add_parser("checkpoint", help="export/verify signed checkpoints for offline witnesses")
    p.add_argument("action", choices=["export", "verify"])
    p.add_argument("file", nargs="?")
    p.add_argument("--out", help="directory, e.g. a mounted USB stick")
    p.set_defaults(fn=cmd_checkpoint)
    p = sp.add_parser("tamper", help="DEMO: simulate a malicious administrator")
    p.add_argument("node")
    p.add_argument("--kind", default="edit-record", choices=["edit-record", "delete-block", "rewrite-history"])
    p.set_defaults(fn=cmd_tamper)
    p = sp.add_parser("heal", help="re-sync a node that failed audit from the quorum")
    p.add_argument("node")
    p.set_defaults(fn=cmd_heal)

    p = sp.add_parser("node", help="run one ledger node process")
    p.add_argument("action", choices=["serve"])
    p.add_argument("--id", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=7101)
    p.set_defaults(fn=cmd_node)
    p = sp.add_parser("cluster", help="start/stop all nodes as separate processes")
    p.add_argument("action", choices=["up", "down"])
    p.add_argument("--base-port", type=int, default=7101)
    p.set_defaults(fn=cmd_cluster)

    p = sp.add_parser("ui", help="local web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(fn=cmd_ui)
    p = sp.add_parser("attack-lab", help="robustness & visual-identity measurements")
    p.add_argument("--doc", default=None, help="PDF to test (default: generated sample)")
    p.add_argument("--out", default="attack_lab")
    p.add_argument("--deltas", default="0.2,0.35,0.5")
    p.add_argument("--quick", action="store_true")
    p.set_defaults(fn=cmd_attack_lab)
    p = sp.add_parser("demo", help="scripted end-to-end demo")
    p.add_argument("--keep", action="store_true", help="reuse existing workspace")
    p.set_defaults(fn=cmd_demo)

    a = ap.parse_args(argv)
    from .airgap import enforce
    enforce()
    a.fn(a)


if __name__ == "__main__":
    main()
