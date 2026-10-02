"""An offline deployment on disk: CA, ledger nodes, identities, packages, cases.

Layout under the workspace root::

    trust_anchor.txt          CA root fingerprint (distributed out of band)
    genesis.json              genesis block (CA-signed, node-certified)
    ca/                       CA soft token + root certificate
    nodes/<node>/             node soft token, certificate, ledger.db
    identities/<subject>/     soft token + certificate per person
    packages/                 encrypted distribution packages (*.nspkg)
    delivered/<subject>/      watermarked copies handed to recipients
    cases/                    forensic reports and evidence bundles
    checkpoints/              signed checkpoints exported to removable media
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from . import pki
from .crypto import pqc
from .crypto.sym import b64e, canonical_json
from .ledger import block as B
from .ledger.client import LedgerClient
from .ledger.node import LedgerNode
from .ledger.transport import HttpTransport, LocalTransport
from .ledger.tx import make_tx

DEFAULT_PIN = os.environ.get("NISHAAN_PIN", "nishaan-demo-pin")

DEMO_PEOPLE = [
    ("sender-ops", "Cdr. R. Menon (Ops Directorate)", "sender"),
    ("forensic-cell", "Forensic Cell, WESEE", "forensic"),
    ("alice", "Lt. Alice Rao, INS Vikrant", "recipient"),
    ("bob", "Lt. Cdr. Bob D'Souza, INS Kolkata", "recipient"),
    ("carol", "Cdr. Carol Iyer, Western Naval Command", "recipient"),
    ("dev", "Lt. Dev Sharma, INS Chennai", "recipient"),
]


class Workspace:
    def __init__(self, root: str | Path, pin: str = DEFAULT_PIN):
        self.root = Path(root)
        self.pin = pin
        self._transport = None
        self._client = None

    # ------------------------------------------------------------------ paths
    def p(self, *parts) -> Path:
        return self.root.joinpath(*parts)

    @property
    def trust_anchor(self) -> str:
        return self.p("trust_anchor.txt").read_text().strip()

    @property
    def genesis(self) -> dict:
        return json.loads(self.p("genesis.json").read_text())

    def node_ids(self) -> list[str]:
        return sorted(d.name for d in self.p("nodes").iterdir() if d.is_dir())

    def exists(self) -> bool:
        return self.p("genesis.json").exists()

    # ------------------------------------------------------------------ setup ceremony
    @classmethod
    def init(cls, root: str | Path, n_nodes: int = 4, f: int = 1, share_threshold: int | None = None,
             people=DEMO_PEOPLE, pin: str = DEFAULT_PIN, enroll: bool = True) -> "Workspace":
        ws = cls(root, pin)
        if ws.exists():
            raise FileExistsError(f"workspace already initialised at {root}")
        if n_nodes < 3 * f + 1:
            raise ValueError("need n >= 3f+1")
        if n_nodes > 3 * f + 1:
            print(f"note: {n_nodes} nodes with f={f}; quorum is ceil((n+f+1)/2) = {(n_nodes + f + 2) // 2}")
        share_threshold = share_threshold or f + 1
        ws.root.mkdir(parents=True, exist_ok=True)
        for d in ("ca", "nodes", "identities", "packages", "delivered", "cases", "checkpoints"):
            ws.p(d).mkdir(exist_ok=True)

        ca = pki.LocalCA.create()
        ca.token.save(ws.p("ca", "token.json"), pin)
        ws.p("ca", "cert.json").write_text(json.dumps(ca.cert, indent=1))
        ws.p("trust_anchor.txt").write_text(ca.fingerprint + "\n")

        nodes = {}
        for i in range(1, n_nodes + 1):
            nid = f"node-{i}"
            ident = ca.new_identity(nid, f"Ledger node {i}", "node", days=3650)
            d = ws.p("nodes", nid)
            d.mkdir(parents=True, exist_ok=True)
            ident.token.save(d / "token.json", pin)
            (d / "cert.json").write_text(json.dumps(ident.cert, indent=1))
            nodes[nid] = ident

        chain_id = "nishaan-" + uuid.uuid4().hex[:8]
        gbody = {"chain_id": chain_id, "ca_cert": ca.cert,
                 "nodes": {nid: i.cert for nid, i in nodes.items()},
                 "f": f, "share_threshold": share_threshold,
                 "algorithms": {"kem": pqc.KEM_ALG, "sig": pqc.SIG_ALG, "root_sig": ca.token.sig_alg,
                                "hash": "SHA3-256 / SHAKE256", "aead": "AES-256-GCM"},
                 "created_at": pki.iso(pki.utcnow())}
        gtx = make_tx("GENESIS", gbody, ca.token, ca.cert["body"]["serial"])
        header = B.make_header(chain_id, 0, 0, B.ZERO_HASH, [gtx], gbody["created_at"], "root-ca")
        bh = B.block_hash(header)
        votes = [B.sign_vote(i.token, nid, "COMMIT", chain_id, 0, 0, bh) for nid, i in nodes.items()]
        genesis = {"header": header, "txs": [gtx], "proposer_sig": "",
                   "cc": B.make_qc("COMMIT", 0, 0, bh, votes)}
        ws.p("genesis.json").write_text(json.dumps(genesis, indent=1))

        if enroll:
            for sid, name, role in people:
                ws.enroll(sid, name, role, ca=ca)
        return ws

    # ------------------------------------------------------------------ CA operations
    def ca(self) -> pki.LocalCA:
        tok = pki.SoftToken.load(self.p("ca", "token.json"), self.pin)
        return pki.LocalCA(tok, json.loads(self.p("ca", "cert.json").read_text()))

    def enroll(self, subject_id: str, display_name: str, role: str, ca: pki.LocalCA | None = None,
               days: int = 365) -> dict:
        """Issue identity on a fresh soft token and record the certificate on the ledger."""
        ca = ca or self.ca()
        tok = pki.SoftToken.generate(subject_id, role)
        cert = ca.issue(tok.csr(display_name), days)
        d = self.p("identities", subject_id)
        d.mkdir(parents=True, exist_ok=True)
        tok.save(d / "token.json", self.pin)
        (d / "cert.json").write_text(json.dumps(cert, indent=1))
        tx = make_tx("ENROLL", {"cert": cert}, ca.token, ca.cert["body"]["serial"])
        return self.client().submit(tx)

    def rotate(self, subject_id: str, days: int = 365) -> dict:
        """Key rotation: new key pair, new certificate that supersedes the old (ledger-anchored history)."""
        ca = self.ca()
        old = self.identity(subject_id)
        tok = pki.SoftToken.generate(subject_id, old.cert["body"]["role"])
        cert = ca.issue(tok.csr(old.cert["body"]["display_name"]), days, supersedes=old.serial)
        tx = make_tx("ENROLL", {"cert": cert}, ca.token, ca.cert["body"]["serial"])
        res = self.client().submit(tx)
        d = self.p("identities", subject_id)
        hist = d / "history"
        hist.mkdir(exist_ok=True)
        (d / "token.json").rename(hist / f"{old.serial}.token.json")
        (d / "cert.json").rename(hist / f"{old.serial}.cert.json")
        tok.save(d / "token.json", self.pin)
        (d / "cert.json").write_text(json.dumps(cert, indent=1))
        return res

    def revoke(self, subject_id: str, reason: str = "key compromise") -> dict:
        ca = self.ca()
        ident = self.identity(subject_id)
        tx = make_tx("REVOKE", {"serial": ident.serial, "reason": reason, "at": pki.iso(pki.utcnow())},
                     ca.token, ca.cert["body"]["serial"])
        return self.client().submit(tx)

    # ------------------------------------------------------------------ identities
    def identity(self, subject_id: str) -> pki.Identity:
        d = self.p("identities", subject_id)
        tok = pki.SoftToken.load(d / "token.json", self.pin)
        return pki.Identity(tok, json.loads((d / "cert.json").read_text()))

    def identity_history(self, subject_id: str) -> list[pki.Identity]:
        d = self.p("identities", subject_id, "history")
        out = []
        if d.exists():
            for c in sorted(d.glob("*.cert.json")):
                serial = c.name.split(".")[0]
                out.append(pki.Identity(pki.SoftToken.load(d / f"{serial}.token.json", self.pin),
                                        json.loads(c.read_text())))
        return out

    def subjects(self) -> list[dict]:
        out = []
        for d in sorted(self.p("identities").iterdir()):
            if (d / "cert.json").exists():
                c = json.loads((d / "cert.json").read_text())["body"]
                out.append({"subject_id": c["subject_id"], "display_name": c["display_name"],
                            "role": c["role"], "serial": c["serial"], "fingerprint": c["fingerprint"]})
        return out

    # ------------------------------------------------------------------ ledger access
    def local_nodes(self, byzantine: dict | None = None) -> LocalTransport:
        """All nodes in-process (separate keys, separate SQLite files)."""
        if self._transport is None:
            byzantine = byzantine or {}
            t = LocalTransport()
            g = self.genesis
            for nid in self.node_ids():
                tok = pki.SoftToken.load(self.p("nodes", nid, "token.json"), self.pin)
                node = LedgerNode(nid, tok, self.p("nodes", nid), g, self.trust_anchor,
                                  byzantine=byzantine.get(nid))
                t.register(node)
            self._transport = t
        return self._transport

    def use_http(self, urls: dict[str, str]) -> None:
        self._transport = HttpTransport(urls)
        self._client = None

    @property
    def mode(self) -> str:
        net = self.p("network.json")
        if net.exists() and json.loads(net.read_text()).get("mode") == "http":
            return "http"
        return "local"

    def client(self) -> LedgerClient:
        if self._client is None:
            if self._transport is None and self.mode == "http":
                self._transport = HttpTransport(json.loads(self.p("network.json").read_text())["nodes"])
            transport = self._transport or self.local_nodes()
            self._client = LedgerClient(transport, self.genesis)
        return self._client
