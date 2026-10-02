"""Transports between ledger nodes / clients.

* LocalTransport - nodes are separate objects (own keys, own SQLite files) in one
  process; used for tests and the single-process demo.
* HttpTransport  - nodes are separate processes on an isolated network
  (``nishaan node serve``); JSON-RPC over HTTP on the closed LAN.

Messages are authenticated at the application layer (every vote, block, share
release and transaction is ML-DSA signed; shares are ML-KEM encrypted), so the
transport itself is untrusted.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class NodeUnavailable(Exception):
    pass


class RemoteError(Exception):
    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


class LocalTransport:
    def __init__(self):
        self.nodes: dict = {}
        self.offline: set[str] = set()

    def register(self, node) -> None:
        self.nodes[node.node_id] = node
        node.transport = self

    def node_ids(self) -> list[str]:
        return sorted(self.nodes)

    def call(self, node_id: str, method: str, **kwargs):
        if node_id in self.offline or node_id not in self.nodes:
            raise NodeUnavailable(node_id)
        node = self.nodes[node_id]
        try:
            # round-trip through JSON so local mode behaves exactly like the network
            kwargs = json.loads(json.dumps(kwargs))
            return json.loads(json.dumps(node.rpc(method, **kwargs)))
        except RemoteError:
            raise
        except NodeUnavailable:
            raise


class HttpTransport:
    def __init__(self, urls: dict[str, str], timeout: float = 30.0):
        self.urls = dict(urls)
        self.timeout = timeout
        self.offline: set[str] = set()

    def node_ids(self) -> list[str]:
        return sorted(self.urls)

    def call(self, node_id: str, method: str, **kwargs):
        if node_id in self.offline or node_id not in self.urls:
            raise NodeUnavailable(node_id)
        req = urllib.request.Request(
            self.urls[node_id].rstrip("/") + "/rpc/" + method,
            data=json.dumps(kwargs).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                resp = json.loads(e.read())
            except Exception:
                raise NodeUnavailable(f"{node_id}: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            raise NodeUnavailable(f"{node_id}: {e}") from None
        if "error" in resp:
            raise RemoteError(resp["error"], resp.get("code", "error"))
        return resp["result"]
