"""Run one ledger node as its own process (JSON-RPC over HTTP on the closed network)."""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from flask import Flask, jsonify, request

from .. import pki
from .node import LedgerNode
from .transport import HttpTransport, RemoteError

NETWORK_FILE = "network.json"


def make_app(node: LedgerNode) -> Flask:
    app = Flask(f"nishaan-{node.node_id}")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    @app.post("/rpc/<method>")
    def rpc(method):
        kwargs = request.get_json(force=True, silent=True) or {}
        try:
            return jsonify({"result": node.rpc(method, **kwargs)})
        except RemoteError as e:
            return jsonify({"error": str(e), "code": e.code}), 400
        except TypeError as e:
            return jsonify({"error": f"bad arguments: {e}", "code": "bad_request"}), 400

    @app.get("/health")
    def health():
        return jsonify(node.head())

    return app


def serve(ws, node_id: str, host: str = "127.0.0.1", port: int = 7101) -> None:
    net = json.loads(ws.p(NETWORK_FILE).read_text())
    tok = pki.SoftToken.load(ws.p("nodes", node_id, "token.json"), ws.pin)
    node = LedgerNode(node_id, tok, ws.p("nodes", node_id), ws.genesis, ws.trust_anchor)
    node.transport = HttpTransport(net["nodes"])
    make_app(node).run(host=host, port=port, threaded=True, use_reloader=False)


def cluster_up(ws, base_port: int = 7101, host: str = "127.0.0.1") -> dict:
    """Start every node as a separate OS process and record their addresses."""
    ids = ws.node_ids()
    urls = {nid: f"http://{host}:{base_port + i}" for i, nid in enumerate(ids)}
    ws.p(NETWORK_FILE).write_text(json.dumps({"mode": "http", "nodes": urls}, indent=1))
    pids = {}
    logs = ws.p("logs")
    logs.mkdir(exist_ok=True)
    for i, nid in enumerate(ids):
        out = open(logs / f"{nid}.log", "ab")
        p = subprocess.Popen([sys.executable, "-m", "nishaan", "--root", str(ws.root), "node", "serve",
                              "--id", nid, "--host", host, "--port", str(base_port + i)],
                             stdout=out, stderr=out, env=dict(os.environ, PYTHONWARNINGS="ignore"),
                             start_new_session=True)
        pids[nid] = p.pid
    ws.p("cluster.pids").write_text(json.dumps(pids))
    t = HttpTransport(urls, timeout=2)
    deadline = time.time() + 60
    pending = set(ids)
    while pending and time.time() < deadline:
        for nid in list(pending):
            try:
                t.call(nid, "ping")
                pending.discard(nid)
            except Exception:
                pass
        time.sleep(0.3)
    if pending:
        raise RuntimeError(f"nodes did not start: {sorted(pending)} (see {logs})")
    return {"nodes": urls, "pids": pids}


def cluster_down(ws) -> list[str]:
    f = ws.p("cluster.pids")
    stopped = []
    if f.exists():
        for nid, pid in json.loads(f.read_text()).items():
            try:
                os.kill(pid, signal.SIGTERM)
                stopped.append(nid)
            except ProcessLookupError:
                pass
        f.unlink()
    net = ws.p(NETWORK_FILE)
    if net.exists():
        net.unlink()
    return stopped
