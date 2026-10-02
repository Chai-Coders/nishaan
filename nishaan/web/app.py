"""Local web console (no external assets: works fully air-gapped).

    python -m nishaan ui  ->  http://127.0.0.1:8080
"""
from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

import cv2
import numpy as np
import pdfplumber
from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from .. import audit as AUD
from .. import client as CL
from .. import forensics as FX
from .. import sender as SX
from ..crypto import pqc
from ..ledger import block as B
from ..ledger.transport import LocalTransport, NodeUnavailable, RemoteError
from ..watermark.render import render_pdf, visual_metrics
from ..workspace import Workspace

STATIC = Path(__file__).parent / "static"
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
OP_LOCK = threading.Lock()


def _png(img: np.ndarray) -> str:
    ok, buf = cv2.imencode(".png", img)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode()


def create_app(root: str) -> Flask:
    app = Flask(__name__, static_folder=None)
    state = {"ws": None, "lab": {"running": False, "log": [], "error": None}}

    def ws() -> Workspace:
        if state["ws"] is None:
            w = Workspace(root)
            if not w.exists():
                abort(409, "workspace not initialised")
            state["ws"] = w
        return state["ws"]

    @app.errorhandler(Exception)
    def on_error(e):
        code = getattr(e, "code", 500)
        if not isinstance(code, int):
            code = 500
        msg = getattr(e, "description", None) or str(e)
        if code == 500:
            traceback.print_exc()
        return jsonify({"error": msg, "type": type(e).__name__}), code

    # ------------------------------------------------------------------ static
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:p>")
    def static_files(p):
        return send_from_directory(STATIC, p)

    # ------------------------------------------------------------------ workspace
    @app.post("/api/init")
    def api_init():
        with OP_LOCK:
            if Workspace(root).exists():
                return jsonify({"ok": True, "existing": True})
            Workspace.init(root)
            state["ws"] = None
        return jsonify({"ok": True})

    @app.get("/api/state")
    def api_state():
        w = Workspace(root)
        if not w.exists():
            return jsonify({"initialised": False, "root": str(Path(root).resolve())})
        w = ws()
        c = w.client()
        s = c.call_any("summary")
        delivered = []
        for d in sorted(w.p("delivered").glob("*/*.pdf"), key=lambda p: p.stat().st_mtime):
            delivered.append({"id": f"{d.parent.name}/{d.name}", "who": d.parent.name,
                              "doc_id": d.name.split("__")[0], "session": d.stem.split("__")[-1]})
        cases = []
        for d in sorted(w.p("cases").glob("*/report.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            r = json.loads(d.read_text())
            cases.append({"case_id": r["case_id"], "status": r["status"], "title": r["document_title"],
                          "accused": [f["recipient_id"] for f in r["findings"]], "file": r["evidence"]["filename"]})
        g = w.genesis["txs"][0]["body"]
        return jsonify({
            "initialised": True, "root": str(w.root.resolve()), "mode": w.mode,
            "chain_id": s["chain_id"], "height": s["height"], "head": s["hash"], "quorum": s["quorum"], "f": s["f"],
            "trust_anchor": w.trust_anchor, "backend": pqc.backend_name(), "algorithms": g.get("algorithms", {}),
            "share_threshold": g["share_threshold"], "nodes": s["nodes"],
            "certs": s["certs"], "docs": s["docs"], "subjects": w.subjects(),
            "delivered": delivered, "cases": cases,
            "checkpoints": [p.name for p in sorted(w.p("checkpoints").glob("*.json"))],
        })

    # ------------------------------------------------------------------ ledger
    @app.get("/api/lanes")
    def api_lanes():
        w = ws()
        c = w.client()
        t = c.transport
        local = isinstance(t, LocalTransport)
        nodes = []
        tops = []
        for nid in c.node_ids:
            info = {"id": nid, "online": True, "byzantine": None, "blocks": {}}
            if local:
                info["online"] = nid not in t.offline
                n = t.nodes[nid]
                info["byzantine"] = n.byzantine
                info["height"] = n.head_height
                info["corrupted"] = n.corrupted
                info["stored"] = n.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] - 1
            else:
                try:
                    h = t.call(nid, "head")
                    info.update(height=h["height"], corrupted=h.get("corrupted"))
                except (NodeUnavailable, RemoteError):
                    info["online"] = False
                    info["height"] = None
            nodes.append(info)
            if info.get("height") is not None:
                tops.append(info["height"])
        top = max(tops) if tops else 0
        start = max(0, top - 21)
        for info in nodes:
            nid = info["id"]
            hmax = info.get("height")
            if hmax is None:
                continue
            for hgt in range(start, hmax + 1):
                try:
                    blk = (t.nodes[nid].blocks[hgt] if local else t.call(nid, "get_block", height=hgt))
                except (NodeUnavailable, RemoteError, IndexError):
                    break
                info["blocks"][hgt] = {"hash": B.block_hash(blk["header"])[:10],
                                       "types": [x["type"] for x in blk["txs"]],
                                       "sigs": len(blk["cc"]["votes"]), "leader": blk["header"]["proposer"],
                                       "view": blk["header"]["view"]}
        return jsonify({"start": start, "top": top, "nodes": nodes, "mode": w.mode})

    @app.get("/api/blocks")
    def api_blocks():
        c = ws().client()
        top = c.height()
        n = int(request.args.get("n", 15))
        out = []
        for h in range(top, max(-1, top - n), -1):
            b = c.call_any("get_block", height=h)
            hd = b["header"]
            out.append({"height": h, "time": hd["timestamp"], "leader": hd["proposer"], "view": hd["view"],
                        "sigs": len(b["cc"]["votes"]), "hash": B.block_hash(hd),
                        "txs": [{"type": t["type"], "who": (t["body"].get("recipient_id") or t["body"].get("title")
                                                             or (t["body"].get("cert") or {}).get("body", {}).get("subject_id")
                                                             or t["body"].get("serial", "")[:8] or t["body"].get("case_id", ""))}
                                for t in b["txs"]]})
        return jsonify(out)

    @app.get("/api/block/<int:h>")
    def api_block(h):
        return jsonify(ws().client().call_any("get_block", height=h))

    @app.post("/api/node/<nid>/offline")
    def api_offline(nid):
        t = ws().client().transport
        if not isinstance(t, LocalTransport):
            abort(400, "in multi-process mode, stop the node process instead")
        (t.offline.add if request.json.get("on") else t.offline.discard)(nid)
        return jsonify({"offline": sorted(t.offline)})

    @app.post("/api/node/<nid>/byzantine")
    def api_byz(nid):
        t = ws().client().transport
        if not isinstance(t, LocalTransport):
            abort(400, "byzantine simulation is available in single-process mode")
        t.nodes[nid].byzantine = request.json.get("mode") or None
        return jsonify({"node": nid, "byzantine": t.nodes[nid].byzantine})

    # ------------------------------------------------------------------ identities
    @app.post("/api/identity")
    def api_enroll():
        d = request.json
        with OP_LOCK:
            log = ws().enroll(d["subject_id"].strip().lower(), d["display_name"].strip(), d.get("role", "recipient"))
        return jsonify({"block": log["height"]})

    @app.post("/api/identity/<sid>/revoke")
    def api_revoke(sid):
        with OP_LOCK:
            log = ws().revoke(sid, (request.json or {}).get("reason", "key compromise"))
        return jsonify({"block": log["height"]})

    @app.post("/api/identity/<sid>/rotate")
    def api_rotate(sid):
        with OP_LOCK:
            log = ws().rotate(sid)
        return jsonify({"block": log["height"]})

    # ------------------------------------------------------------------ distribute / open
    @app.post("/api/distribute")
    def api_distribute():
        f = request.files.get("file")
        if f:
            pdf, name = f.read(), f.filename
        else:
            sample = ROOT_DIR / "demo" / "docs" / "briefing.pdf"
            if not sample.exists():
                sys.path.insert(0, str(ROOT_DIR / "demo"))
                from make_sample_docs import make_reportlab
                sample.parent.mkdir(parents=True, exist_ok=True)
                make_reportlab(sample)
            pdf, name = sample.read_bytes(), sample.name
        form = request.form
        recips = [r for r in form.get("recipients", "").split(",") if r]
        if not recips:
            abort(400, "choose at least one recipient")
        t0 = time.time()
        with OP_LOCK:
            pkg, log = SX.distribute(ws(), form.get("sender", "sender-ops"), pdf, form.get("title") or name, recips,
                                     max_decryptions=int(form.get("max_decryptions", 3)),
                                     valid_days=int(form.get("days", 30)), filename=name,
                                     classification=form.get("classification", "RESTRICTED"))
        m = pkg["manifest_tx"]["body"]
        return jsonify({"doc_id": pkg["doc_id"], "block": log["height"], "leader": log["leader"],
                        "slots": m["wm"]["slots"], "code_len": m["wm"]["code_len"], "doc_hash": m["doc_hash"],
                        "recipients": [r["subject_id"] for r in m["recipients"]],
                        "threshold": m["committee"]["threshold"], "seconds": round(time.time() - t0, 2)})

    @app.post("/api/open")
    def api_open():
        d = request.json
        t0 = time.time()
        with OP_LOCK:
            try:
                res = CL.open_in_workspace(ws(), d["who"], d["doc_id"])
            except Exception as e:
                return jsonify({"denied": True, "error": str(e)}), 200
        return jsonify({"session_id": res.session_id, "steps": res.steps, "intent_tx_id": res.intent_tx_id,
                        "copy": f"{d['who']}/{d['doc_id']}__{res.session_id[:8]}.pdf",
                        "seconds": round(time.time() - t0, 2)})

    def _copy_path(cid: str) -> Path:
        p = (ws().p("delivered") / cid).resolve()
        if not str(p).startswith(str(ws().p("delivered").resolve())) or not p.exists():
            abort(404)
        return p

    @app.get("/api/copy/<path:cid>")
    def api_copy(cid):
        return send_file(_copy_path(cid), mimetype="application/pdf", as_attachment=False)

    @app.get("/api/thumb/<path:cid>")
    def api_thumb(cid):
        img = render_pdf(_copy_path(cid).read_bytes(), 40, pages=[0])[0]
        ok, buf = cv2.imencode(".png", img)
        return send_file(io.BytesIO(buf.tobytes()), mimetype="image/png")

    # ------------------------------------------------------------------ compare
    @app.post("/api/compare")
    def api_compare():
        d = request.json
        a, b = _copy_path(d["a"]).read_bytes(), _copy_path(d["b"]).read_bytes()
        page = int(d.get("page", 0))
        ra, rb = render_pdf(a, 300, pages=[page])[0], render_pdf(b, 300, pages=[page])[0]
        h, w = ra.shape
        # zoom on a block of body text, cut along blank rows so no line is sliced
        blank = (ra < 200).sum(axis=1) == 0

        def next_blank(y):
            while y < h - 1 and not blank[y]:
                y += 1
            return y
        y0 = next_blank(int(h * 0.30))
        y1 = next_blank(y0 + int(h * 0.055))
        x0, x1 = int(w * 0.11), int(w * 0.60)
        cblank = (ra[y0:y1] < 250).sum(axis=0) == 0
        while x1 < w - 10 and not cblank[x1:x1 + 10].all():
            x1 += 1
        za, zb = ra[y0:y1, x0:x1], rb[y0:y1, x0:x1]
        diff = np.abs(za.astype(int) - zb.astype(int))
        heat = np.full((*diff.shape, 3), 255, np.uint8)
        k = np.clip(diff * 4, 0, 255).astype(np.uint8)
        heat[..., 0] = 255 - (k * 0.70).astype(np.uint8)
        heat[..., 1] = 255 - (k * 0.85).astype(np.uint8)
        heat[..., 2] = 255 - (k * 0.30).astype(np.uint8)
        heat = cv2.cvtColor(heat, cv2.COLOR_RGB2BGR)

        def words(pdf):
            with pdfplumber.open(io.BytesIO(pdf)) as doc:
                return [(wd["text"], wd["x0"]) for wd in doc.pages[page].extract_words(x_tolerance=1)]
        wa, wb = words(a), words(b)
        moved = sum(1 for (ta, xa), (tb, xb) in zip(wa, wb) if ta == tb and abs(xa - xb) > 0.05)
        same_text = [t for t, _ in wa] == [t for t, _ in wb]
        vm = visual_metrics(a, b)
        return jsonify({"a": _png(za), "b": _png(zb), "diff": _png(heat),
                        "full_a": _png(render_pdf(a, 60, pages=[page])[0]),
                        "words_moved": moved, "words": len(wa), "same_text": same_text,
                        "metrics": vm, "identical_bytes": a == b})

    # ------------------------------------------------------------------ forensics
    def _simulate(kind: str, a: Path, b: Path | None) -> tuple[bytes, str]:
        from ..attacklab import _jpeg, _phone_photo, _print_scan
        rng = np.random.default_rng(int(time.time()))
        pdf = a.read_bytes()
        if kind == "pdf":
            return pdf, "forwarded_copy.pdf"
        if kind == "screenshot":
            return cv2.imencode(".png", render_pdf(pdf, 110, pages=[0])[0])[1].tobytes(), "screenshot.png"
        if kind == "photo":
            return cv2.imencode(".jpg", _phone_photo(render_pdf(pdf, 200, pages=[0])[0], rng))[1].tobytes(), "phone_photo.jpg"
        if kind == "printscan":
            return cv2.imencode(".jpg", _print_scan(render_pdf(pdf, 300, pages=[0])[0], rng))[1].tobytes(), "scan.jpg"
        if kind == "crop":
            im = render_pdf(pdf, 150, pages=[0])[0]
            return cv2.imencode(".png", im[: im.shape[0] // 2])[1].tobytes(), "cropped_screenshot.png"
        if kind == "collusion":
            if b is None:
                abort(400, "collusion needs two copies")
            x = render_pdf(pdf, 150, pages=[0])[0].astype(np.float32)
            y = render_pdf(b.read_bytes(), 150, pages=[0])[0].astype(np.float32)
            return cv2.imencode(".png", ((x + y) / 2).astype(np.uint8))[1].tobytes(), "averaged_copies.png"
        abort(400, "unknown leak route")

    @app.post("/api/investigate")
    def api_investigate():
        w = ws()
        f = request.files.get("file")
        form = request.form
        if f:
            data, name = f.read(), f.filename
        else:
            a = _copy_path(form["copy_a"])
            b = _copy_path(form["copy_b"]) if form.get("copy_b") else None
            data, name = _simulate(form.get("kind", "pdf"), a, b)
        try:
            preview = (render_pdf(data, 50, pages=[0])[0] if data[:5] == b"%PDF-"
                       else cv2.imdecode(np.frombuffer(data, np.uint8), 0))
            s = 520 / max(preview.shape)
            preview = cv2.resize(preview, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
        except Exception:
            preview = None
        with OP_LOCK:
            inv = FX.investigate(w, form.get("officer", "forensic-cell"), data, name,
                                 doc_id=form.get("doc_id") or None)
        r = inv.report
        r["preview"] = _png(preview) if preview is not None else None
        return jsonify(r)

    @app.get("/api/case/<case_id>/<fname>")
    def api_case_file(case_id, fname):
        if fname not in ("report.json", "evidence_bundle.json"):
            abort(404)
        p = ws().p("cases", case_id, fname)
        if not p.exists():
            abort(404)
        return send_file(p, mimetype="application/json", as_attachment=True, download_name=f"{case_id}_{fname}")

    @app.get("/api/case/<case_id>")
    def api_case(case_id):
        p = ws().p("cases", case_id, "report.json")
        if not p.exists():
            abort(404)
        return jsonify(json.loads(p.read_text()))

    @app.post("/api/case/<case_id>/verify")
    def api_verify(case_id):
        w = ws()
        d = w.p("cases", case_id)
        ev = next(iter(d.glob("leaked_*")), None)
        cmd = [sys.executable, str(ROOT_DIR / "tools" / "verify_evidence.py"), str(d / "evidence_bundle.json"),
               "--trust-anchor", w.trust_anchor] + (["--evidence", str(ev)] if ev else [])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                             env=dict(os.environ, PYTHONWARNINGS="ignore"))
        return jsonify({"ok": out.returncode == 0, "output": out.stdout + out.stderr})

    # ------------------------------------------------------------------ audit / tamper
    @app.post("/api/audit")
    def api_audit():
        with OP_LOCK:
            return jsonify(AUD.audit_all(ws()))

    @app.post("/api/checkpoint")
    def api_checkpoint():
        with OP_LOCK:
            cp, path = AUD.export_checkpoint(ws())
        return jsonify({"height": cp["height"], "block_hash": cp["block_hash"], "file": path.name,
                        "signatures": len(cp["cc"]["votes"])})

    @app.post("/api/tamper")
    def api_tamper():
        d = request.json
        with OP_LOCK:
            return jsonify(AUD.tamper(ws(), d["node"], d["kind"]))

    @app.post("/api/heal/<nid>")
    def api_heal(nid):
        with OP_LOCK:
            return jsonify(ws().client().transport.call(nid, "heal"))

    # ------------------------------------------------------------------ attack lab
    @app.post("/api/attacklab")
    def api_lab_run():
        lab = state["lab"]
        if lab["running"]:
            return jsonify({"running": True})
        quick = bool((request.json or {}).get("quick", True))
        lab.update(running=True, log=[], error=None)

        def job():
            from ..attacklab import run_lab
            try:
                run_lab(None, str(ws().p("attack_lab")), quick=quick, progress=lab["log"].append)
            except Exception as e:
                lab["error"] = str(e)
            finally:
                lab["running"] = False
        threading.Thread(target=job, daemon=True).start()
        return jsonify({"running": True})

    @app.get("/api/attacklab")
    def api_lab_status():
        lab = state["lab"]
        rep = ws().p("attack_lab", "attack_lab.json")
        return jsonify({"running": lab["running"], "log": lab["log"][-40:], "error": lab["error"],
                        "report": json.loads(rep.read_text()) if rep.exists() else None})

    @app.get("/attacklab/report")
    def lab_report():
        p = ws().p("attack_lab", "attack_lab.html")
        if not p.exists():
            abort(404)
        return send_file(p)

    return app


def run(root: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = create_app(root)
    print(f"Nishaan console on http://{host}:{port}  (workspace {Path(root).resolve()})")
    app.run(host=host, port=port, threaded=True, use_reloader=False)
